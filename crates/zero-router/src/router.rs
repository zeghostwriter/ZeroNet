//! Ordered rule evaluation.
//!
//! First match wins, and populated selectors inside one rule are ANDed —
//! Xray's semantics. Rules are compiled once into matchers; evaluation never
//! parses a pattern.

use std::net::IpAddr;
use std::sync::Arc;

use zero_config::routing::{PortRange, RuleTarget};
use zero_config::RuntimeConfig;
use zero_core::{Network, SessionContext};

use crate::matcher::{DomainMatcher, GeoData, IpMatcher};

/// What the router decided for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Outbound(Arc<str>),
    Balancer(Arc<str>),
    DirectVia { resolver: Arc<str> },
    Block,
}

struct CompiledRule {
    domains: DomainMatcher,
    ips: IpMatcher,
    source_ips: IpMatcher,
    ports: Vec<PortRange>,
    source_ports: Vec<PortRange>,
    networks: Vec<Network>,
    inbound_tags: Vec<Box<str>>,
    protocols: Vec<Box<str>>,
    target: RuleTarget,
    /// True when every selector this rule declared was unusable (e.g. it was
    /// nothing but geosite tags and no geodata is loaded). Such a rule must
    /// never match, or it would silently become unconditional.
    inert: bool,
}

pub struct Router {
    rules: Vec<CompiledRule>,
    default_outbound: Arc<str>,
    /// Geosite/geoip tags referenced but not loadable. Surfaced once at
    /// startup rather than per session.
    pub unresolved: Vec<Box<str>>,
}

impl Router {
    pub fn build(cfg: &RuntimeConfig) -> Self {
        Self::build_with_geodata(cfg, &GeoData::default())
    }

    pub fn build_with_geodata(cfg: &RuntimeConfig, geodata: &GeoData) -> Self {
        let mut unresolved: Vec<Box<str>> = Vec::new();
        let mut rules = Vec::with_capacity(cfg.routing.rules.len());

        for r in cfg.routing.rules.iter() {
            let domains = DomainMatcher::build_with_geodata(&r.domains, geodata);
            let ips = IpMatcher::build_with_geodata(&r.ips, geodata);
            let source_ips = IpMatcher::build_with_geodata(&r.source_ips, geodata);

            unresolved.extend(domains.unresolved_geosites.iter().cloned());
            unresolved.extend(ips.unresolved_geoips.iter().cloned());
            unresolved.extend(source_ips.unresolved_geoips.iter().cloned());

            // A rule that declared only selectors we cannot evaluate has lost
            // its meaning. Treating it as "matches everything" would send all
            // traffic to, say, `block`.
            let declared_something =
                !r.domains.is_empty() || !r.ips.is_empty() || !r.source_ips.is_empty();
            let usable_something = !domains.is_empty() || !ips.is_empty() || !source_ips.is_empty();
            let other_selectors = !r.ports.is_empty()
                || !r.source_ports.is_empty()
                || !r.networks.is_empty()
                || !r.inbound_tags.is_empty()
                || !r.protocols.is_empty();
            let inert = declared_something && !usable_something && !other_selectors;

            rules.push(CompiledRule {
                domains,
                ips,
                source_ips,
                ports: r.ports.clone(),
                source_ports: r.source_ports.clone(),
                networks: r.networks.clone(),
                inbound_tags: r.inbound_tags.clone(),
                protocols: r.protocols.clone(),
                target: r.target.clone(),
                inert,
            });
        }

        unresolved.sort();
        unresolved.dedup();

        let default_outbound = cfg
            .default_outbound()
            .map(|o| o.tag.clone())
            .unwrap_or_else(|| Arc::from("direct"));

        Router {
            rules,
            default_outbound,
            unresolved,
        }
    }

    /// Evaluate a session. Falls back to the first outbound.
    pub fn route(&self, ctx: &SessionContext, resolved: Option<IpAddr>) -> Decision {
        for rule in &self.rules {
            if rule.inert {
                continue;
            }
            if self.rule_matches(rule, ctx, resolved) {
                return match &rule.target {
                    RuleTarget::Outbound(t) => Decision::Outbound(t.clone()),
                    RuleTarget::Balancer(t) => Decision::Balancer(t.clone()),
                    RuleTarget::DirectVia { resolver } => Decision::DirectVia {
                        resolver: resolver.clone(),
                    },
                    RuleTarget::Block => Decision::Block,
                };
            }
        }
        Decision::Outbound(self.default_outbound.clone())
    }

    fn rule_matches(
        &self,
        rule: &CompiledRule,
        ctx: &SessionContext,
        resolved: Option<IpAddr>,
    ) -> bool {
        if !rule.networks.is_empty() && !rule.networks.contains(&ctx.destination.network) {
            return false;
        }

        if !rule.inbound_tags.is_empty()
            && !rule
                .inbound_tags
                .iter()
                .any(|t| t.as_ref() == ctx.inbound_tag.as_ref())
        {
            return false;
        }

        if !rule.protocols.is_empty() {
            match ctx.sniffed.protocol {
                Some(protocol) if rule.protocols.iter().any(|p| p.as_ref() == protocol) => {}
                _ => return false,
            }
        }

        if !rule.ports.is_empty() && !rule.ports.iter().any(|p| p.contains(ctx.destination.port)) {
            return false;
        }

        if !rule.source_ports.is_empty() {
            let sp = ctx.source.map(|s| s.port());
            match sp {
                Some(p) if rule.source_ports.iter().any(|r| r.contains(p)) => {}
                _ => return false,
            }
        }

        if !rule.source_ips.is_empty() {
            match ctx.source.map(|s| s.ip()) {
                Some(ip) if rule.source_ips.matches(ip) => {}
                _ => return false,
            }
        }

        if !rule.domains.is_empty() {
            match ctx.effective_domain() {
                Some(d) if rule.domains.matches(d) => {}
                _ => return false,
            }
        }

        if !rule.ips.is_empty() {
            // Either a literal destination or, when the strategy resolved one,
            // the resolved address.
            let candidate = ctx.destination.address.as_ip().or(resolved);
            match candidate {
                Some(ip) if rule.ips.matches(ip) => {}
                _ => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zero_config::routing::{DomainPattern, IpPattern, Routing, Rule};
    use zero_config::*;
    use zero_core::{Address, Destination, GenerationId, InboundId};

    fn outbound(tag: &str) -> Outbound {
        Outbound {
            tag: Arc::from(tag),
            protocol: OutboundProtocol::Freedom {
                domain_strategy: DomainStrategy::AsIs,
            },
            stream: StreamSettings::default(),
            mux: MuxConfig::default(),
        }
    }

    fn cfg(rules: Vec<Rule>) -> RuntimeConfig {
        RuntimeConfig {
            inbounds: Box::new([]),
            outbounds: vec![outbound("proxy"), outbound("direct"), outbound("block")]
                .into_boxed_slice(),
            routing: Routing {
                domain_strategy: Default::default(),
                rules: rules.into_boxed_slice(),
                balancers: Box::new([]),
            },
            dns: Default::default(),
            observatory: None,
            assets: None,
            log_level: "warning".into(),
        }
    }

    fn ctx(host: &str, port: u16) -> SessionContext {
        SessionContext::new(
            GenerationId(1),
            InboundId(0),
            Arc::from("mixed-in"),
            Destination::tcp(Address::parse_host(host), port),
        )
    }

    #[test]
    fn falls_back_to_the_first_outbound() {
        let r = Router::build(&cfg(vec![]));
        assert_eq!(
            r.route(&ctx("example.com", 443), None),
            Decision::Outbound(Arc::from("proxy"))
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut a = Rule::new(RuleTarget::Outbound(Arc::from("direct")));
        a.domains = vec![DomainPattern::parse("domain:example.com")];
        let mut b = Rule::new(RuleTarget::Block);
        b.domains = vec![DomainPattern::parse("domain:example.com")];

        let r = Router::build(&cfg(vec![a, b]));
        assert_eq!(
            r.route(&ctx("a.example.com", 443), None),
            Decision::Outbound(Arc::from("direct"))
        );
    }

    #[test]
    fn selectors_within_a_rule_are_anded() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.domains = vec![DomainPattern::parse("domain:example.com")];
        rule.ports = vec![PortRange { start: 80, end: 80 }];

        let r = Router::build(&cfg(vec![rule]));
        // Domain matches but port does not.
        assert_ne!(r.route(&ctx("example.com", 443), None), Decision::Block);
        assert_eq!(r.route(&ctx("example.com", 80), None), Decision::Block);
    }

    #[test]
    fn private_ip_rule_matches_literal_destination() {
        let mut rule = Rule::new(RuleTarget::Outbound(Arc::from("direct")));
        rule.ips = vec![IpPattern::Private];
        let r = Router::build(&cfg(vec![rule]));
        assert_eq!(
            r.route(&ctx("192.168.1.1", 80), None),
            Decision::Outbound(Arc::from("direct"))
        );
        assert_eq!(
            r.route(&ctx("8.8.8.8", 80), None),
            Decision::Outbound(Arc::from("proxy"))
        );
    }

    #[test]
    fn ip_rule_can_use_a_resolved_address() {
        let mut rule = Rule::new(RuleTarget::Outbound(Arc::from("direct")));
        rule.ips = vec![IpPattern::Private];
        let r = Router::build(&cfg(vec![rule]));
        let resolved: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            r.route(&ctx("internal.corp", 80), Some(resolved)),
            Decision::Outbound(Arc::from("direct"))
        );
    }

    #[test]
    fn network_selector_is_honoured() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.networks = vec![Network::Udp];
        let r = Router::build(&cfg(vec![rule]));
        assert_ne!(r.route(&ctx("a.com", 443), None), Decision::Block);

        let mut c = ctx("a.com", 443);
        c.destination.network = Network::Udp;
        assert_eq!(r.route(&c, None), Decision::Block);
    }

    #[test]
    fn inbound_tag_selector_is_honoured() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.inbound_tags = vec!["dns-in".into()];
        let r = Router::build(&cfg(vec![rule]));
        assert_ne!(r.route(&ctx("a.com", 443), None), Decision::Block);
    }

    #[test]
    fn geosite_only_rule_is_inert_not_unconditional() {
        // This is the dangerous case: without geodata, a `block` rule whose
        // only selector is a geosite tag must not swallow all traffic.
        let mut rule = Rule::new(RuleTarget::Block);
        rule.domains = vec![DomainPattern::parse("geosite:category-ads-all")];
        let r = Router::build(&cfg(vec![rule]));

        assert_eq!(
            r.route(&ctx("example.com", 443), None),
            Decision::Outbound(Arc::from("proxy")),
            "an unevaluatable rule must not match"
        );
        assert!(!r.unresolved.is_empty(), "and it must be reported");
    }

    #[test]
    fn geosite_rule_with_other_selectors_still_uses_them() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.domains = vec![DomainPattern::parse("geosite:x")];
        rule.ports = vec![PortRange {
            start: 8080,
            end: 8080,
        }];
        let r = Router::build(&cfg(vec![rule]));
        // The geosite half cannot be evaluated, but the port half can.
        assert_eq!(r.route(&ctx("a.com", 8080), None), Decision::Block);
        assert_ne!(r.route(&ctx("a.com", 443), None), Decision::Block);
    }

    #[test]
    fn sniffed_domain_is_usable_for_routing() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.domains = vec![DomainPattern::parse("domain:sniffed.com")];
        let r = Router::build(&cfg(vec![rule]));

        let mut c = ctx("1.2.3.4", 443);
        c.sniffed.domain = Some(Arc::from("sniffed.com"));
        assert_eq!(r.route(&c, None), Decision::Block);
    }

    #[test]
    fn protocol_selector_requires_the_sniffed_protocol() {
        let mut rule = Rule::new(RuleTarget::Block);
        rule.protocols.push("tls".into());
        let r = Router::build(&cfg(vec![rule]));
        let mut c = ctx("example.com", 443);
        assert_eq!(r.route(&c, None), Decision::Outbound(Arc::from("proxy")));
        c.sniffed.protocol = Some("tls");
        assert_eq!(r.route(&c, None), Decision::Block);
    }
}
