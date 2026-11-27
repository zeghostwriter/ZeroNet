//! What a person must do outside the app, written so the app can show it.
//!
//! The only setup the installer cannot do for them is at their domain
//! registrar: pointing a name at the server. This module works out exactly the
//! records to create (so the screen can show them with copy buttons) and keeps
//! the plain-language steps for Cloudflare, where most people have their domain.

use std::net::IpAddr;

/// Why a domain cannot be used as a tunnel domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    Empty,
    /// A character other than a-z, 0-9, `-` and `.`.
    BadCharacter,
    /// A label that is empty, over 63 characters, or starts/ends with `-`.
    BadLabel,
    /// The tunnel domain must be a subdomain (`t.example.com`), not the whole
    /// site: the name server record cannot share a name with the site's own.
    NeedsSubdomain,
    TooLong,
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DomainError::Empty => "Type your domain name.",
            DomainError::BadCharacter => {
                "A domain can only hold letters, digits, dashes and dots."
            }
            DomainError::BadLabel => {
                "Each part of the domain (between dots) must be 1 to 63 characters and must not start or end with a dash."
            }
            DomainError::NeedsSubdomain => {
                "Use a subdomain, like t.example.com, not the bare domain. The tunnel gets its own name so your website keeps working."
            }
            DomainError::TooLong => "That domain name is too long.",
        })
    }
}

/// Tidy what the person typed (case, spaces, a trailing dot, a pasted URL
/// scheme) into a domain, or say what is wrong with it.
pub fn clean_domain(input: &str) -> Result<String, DomainError> {
    let mut domain = input.trim().to_ascii_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = domain.strip_prefix(prefix) {
            domain = rest.to_string();
        }
    }
    let domain = domain
        .split(['/', ' '])
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if domain.is_empty() {
        return Err(DomainError::Empty);
    }
    if domain.len() > 200 {
        return Err(DomainError::TooLong);
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(DomainError::BadCharacter);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels
        .iter()
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return Err(DomainError::BadLabel);
    }
    if labels.len() < 3 {
        return Err(DomainError::NeedsSubdomain);
    }
    Ok(domain.to_string())
}

/// One DNS record to create.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DnsRecord {
    /// `A` or `NS`.
    pub kind: &'static str,
    /// The name as the registrar's form wants it: just the part before the
    /// parent domain (`ns`, `t`), which is what Cloudflare asks for.
    pub name: String,
    pub value: String,
    /// `true` where the registrar must be told NOT to proxy it (Cloudflare's
    /// orange cloud has to be grey).
    pub dns_only: bool,
}

/// The records that delegate `tunnel_domain` to a server at `server_ip`:
///
/// * an `A` record giving a name server host (`ns.example.com`) the server's
///   address, and
/// * an `NS` record telling the world that the tunnel domain is answered by
///   that host.
///
/// Anyone asking a resolver for a name under the tunnel domain is then sent to
/// the server, which is the whole trick.
pub fn delegation_records(tunnel_domain: &str, server_ip: IpAddr) -> Vec<DnsRecord> {
    let (label, parent) = tunnel_domain.split_once('.').unwrap_or((tunnel_domain, ""));
    let ns_host = ns_host(tunnel_domain);
    let ns_label = ns_host
        .strip_suffix(&format!(".{parent}"))
        .unwrap_or("ns")
        .to_string();
    let kind = if server_ip.is_ipv4() { "A" } else { "AAAA" };
    vec![
        DnsRecord {
            kind,
            name: ns_label,
            value: server_ip.to_string(),
            dns_only: true,
        },
        DnsRecord {
            kind: "NS",
            name: label.to_string(),
            value: ns_host,
            dns_only: true,
        },
    ]
}

/// The name server host for a tunnel domain: `ns.` in front of its parent.
pub fn ns_host(tunnel_domain: &str) -> String {
    let parent = tunnel_domain
        .split_once('.')
        .map_or(tunnel_domain, |(_, p)| p);
    format!("ns.{parent}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_domains_are_tidied() {
        assert_eq!(clean_domain("  T.Example.COM. ").unwrap(), "t.example.com");
        assert_eq!(
            clean_domain("https://t.example.com/path").unwrap(),
            "t.example.com"
        );
        assert_eq!(
            clean_domain("a.b.example.co.uk").unwrap(),
            "a.b.example.co.uk"
        );
    }

    #[test]
    fn unusable_domains_say_why() {
        assert_eq!(clean_domain(""), Err(DomainError::Empty));
        assert_eq!(
            clean_domain("example.com"),
            Err(DomainError::NeedsSubdomain)
        );
        assert_eq!(
            clean_domain("t.exa_mple.com"),
            Err(DomainError::BadCharacter)
        );
        assert_eq!(clean_domain("t..example.com"), Err(DomainError::BadLabel));
        assert_eq!(clean_domain("-t.example.com"), Err(DomainError::BadLabel));
        assert_eq!(
            clean_domain(&format!("{}.example.com", "a".repeat(64))),
            Err(DomainError::BadLabel)
        );
    }

    #[test]
    fn the_two_records_for_a_cloudflare_zone() {
        let records = delegation_records("t.example.com", "203.0.113.7".parse().unwrap());
        assert_eq!(
            records,
            vec![
                DnsRecord {
                    kind: "A",
                    name: "ns".into(),
                    value: "203.0.113.7".into(),
                    dns_only: true
                },
                DnsRecord {
                    kind: "NS",
                    name: "t".into(),
                    value: "ns.example.com".into(),
                    dns_only: true
                },
            ]
        );
    }

    #[test]
    fn a_deeper_tunnel_domain_keeps_its_parent() {
        let records = delegation_records("v.sub.example.com", "203.0.113.7".parse().unwrap());
        assert_eq!(records[0].name, "ns");
        assert_eq!(records[1].name, "v");
        assert_eq!(records[1].value, "ns.sub.example.com");
        assert_eq!(ns_host("v.sub.example.com"), "ns.sub.example.com");
    }
}
