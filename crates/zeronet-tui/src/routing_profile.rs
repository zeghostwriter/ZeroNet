//! Routing profiles: named lists of the user's own rules.
//!
//! A profile says, for the connections it picks out, whether they go through
//! the tunnel, straight out, or nowhere:
//!
//! ```text
//! profile "Work"
//!   direct  domain   geosite:category-ir, keyword:bank
//!   block   process  telemetry-agent
//!   proxy   ip       91.108.0.0/16
//! ```
//!
//! Each rule is a `zero_config::UserRule`, so the syntax is Xray's (domain
//! prefixes `full:`, `keyword:`, `regexp:`, `geosite:`; CIDR ranges and
//! `geoip:`; program names, paths and folders). One profile is active at a
//! time, or none. The active one is put in front of every other rule of the
//! configuration by [`apply`], so it overrides the built-in choices (Iranian
//! sites direct, ads blocked) but nothing that protects the user: the IPv6
//! drop and the DNS capture are added after it and go first.
//!
//! The profiles are kept as one JSON value in the settings
//! (`routing_profiles`), the active one by name (`routing_profile`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_config::{RuleAction, UserRule};

/// One named list of rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingProfile {
    pub name: String,
    pub rules: Vec<UserRule>,
}

/// Read the stored profiles; anything unreadable reads as none, so a damaged
/// setting cannot stop the app from starting.
pub fn load(stored: &str) -> Vec<RoutingProfile> {
    if stored.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str(stored).unwrap_or_default()
}

/// The profiles as they are stored.
pub fn save(profiles: &[RoutingProfile]) -> String {
    serde_json::to_string(profiles).unwrap_or_else(|_| "[]".into())
}

/// The rules of the profile called `active`, or none when no profile has
/// that name (including the empty name, which means "no profile").
pub fn active_rules(profiles: &[RoutingProfile], active: &str) -> Vec<UserRule> {
    profiles
        .iter()
        .find(|profile| !active.is_empty() && profile.name == active)
        .map(|profile| profile.rules.clone())
        .unwrap_or_default()
}

/// Put `rules` in front of the routing rules of `config` (Xray JSON).
///
/// The configuration may be one this app built or one the user imported, so
/// the targets are looked up in it rather than assumed:
///
/// * "through the tunnel" is the catch-all balancer when the routing ends in
///   one, otherwise the first outbound that is a proxy;
/// * "direct" and "block" are its first freedom and blackhole outbounds,
///   added (as `direct` and `block`) when it has none.
///
/// Rules that are switched off or fail `UserRule::check` are skipped.
pub fn apply(config: &mut Map<String, Value>, rules: &[UserRule]) {
    let rules: Vec<&UserRule> = rules
        .iter()
        .filter(|rule| rule.enabled.0 && rule.check().is_ok())
        .collect();
    if rules.is_empty() {
        return;
    }
    let needs = |action: RuleAction| rules.iter().any(|rule| rule.action == action);
    let direct = needs(RuleAction::Direct).then(|| outbound_tag(config, "freedom", "direct"));
    let block = needs(RuleAction::Block).then(|| outbound_tag(config, "blackhole", "block"));
    let proxy = proxy_target(config);
    let Some(routing) = config
        .entry("routing")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return;
    };
    let Some(existing) = routing
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
    else {
        return;
    };
    let mut built: Vec<Value> = rules
        .iter()
        .filter_map(|rule| {
            // A proxy rule in a configuration with no proxy has nowhere to go.
            if rule.action == RuleAction::Proxy && proxy.is_none() {
                return None;
            }
            Some(rule.to_json_with(
                proxy.as_ref().unwrap_or(&Value::Null),
                direct.as_deref().unwrap_or("direct"),
                block.as_deref().unwrap_or("block"),
            ))
        })
        .collect();
    built.append(existing);
    *existing = built;
}

/// The tag of the first outbound speaking `protocol`, giving it `fallback`
/// when it has no tag; or a new outbound of that protocol tagged `fallback`.
fn outbound_tag(config: &mut Map<String, Value>, protocol: &str, fallback: &str) -> String {
    let outbounds = config.entry("outbounds").or_insert_with(|| json!([]));
    let Some(outbounds) = outbounds.as_array_mut() else {
        return fallback.into();
    };
    if let Some(outbound) = outbounds
        .iter_mut()
        .find(|o| o.get("protocol").and_then(Value::as_str) == Some(protocol))
    {
        if let Some(tag) = outbound.get("tag").and_then(Value::as_str) {
            return tag.to_string();
        }
        outbound["tag"] = json!(fallback);
        return fallback.into();
    }
    // Not taken by another outbound, or the rule would go somewhere else.
    let mut tag = fallback.to_string();
    let taken = |tag: &str, outbounds: &[Value]| {
        outbounds
            .iter()
            .any(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
    };
    let mut n = 2;
    while taken(&tag, outbounds) {
        tag = format!("{fallback}-{n}");
        n += 1;
    }
    outbounds.push(json!({"tag": tag, "protocol": protocol}));
    tag
}

/// Where "through the tunnel" goes in `config`, as the part of a rule that
/// names it; `None` when it has no proxy at all.
fn proxy_target(config: &mut Map<String, Value>) -> Option<Value> {
    // A rule with nothing but a balancer and at most a network is the
    // configuration's own catch-all: what its tunnel traffic uses.
    let catch_all = config
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array)
        .and_then(|rules| {
            rules.iter().rev().find_map(|rule| {
                let rule = rule.as_object()?;
                let only_network = rule.keys().all(|key| {
                    matches!(key.as_str(), "type" | "network" | "balancerTag" | "ruleTag")
                });
                only_network.then(|| rule.get("balancerTag")?.as_str())?
            })
        });
    if let Some(balancer) = catch_all {
        return Some(json!({"balancerTag": balancer}));
    }
    let outbounds = config.get_mut("outbounds")?.as_array_mut()?;
    let proxy = outbounds.iter_mut().find(|o| {
        !matches!(
            o.get("protocol").and_then(Value::as_str),
            Some("freedom" | "blackhole" | "dns")
        )
    })?;
    let tag = match proxy.get("tag").and_then(Value::as_str) {
        Some(tag) => tag.to_string(),
        None => {
            proxy["tag"] = json!("proxy");
            "proxy".into()
        }
    };
    Some(json!({"outboundTag": tag}))
}

/// Which list of the editor has the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pane {
    #[default]
    Profiles,
    Rules,
}

/// The fields of the rule form, in the order Tab walks them.
pub const FORM_FIELDS: [&str; 6] = [
    "Action",
    "Domains",
    "Addresses",
    "Programs",
    "Ports",
    "Network",
];

/// A rule being written or changed. The lists are typed as text with commas
/// between entries and split when the rule is saved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleForm {
    /// The rule it replaces; `None` for a new one.
    pub index: Option<usize>,
    pub field: usize,
    pub action: RuleAction,
    pub domain: String,
    pub ip: String,
    pub process: String,
    pub port: String,
    /// "", "tcp" or "udp".
    pub network: String,
    pub enabled: bool,
}

impl RuleForm {
    fn from_rule(index: usize, rule: &UserRule) -> Self {
        Self {
            index: Some(index),
            field: 0,
            action: rule.action,
            domain: rule.domain.join(", "),
            ip: rule.ip.join(", "),
            process: rule.process.join(", "),
            port: rule.port.clone(),
            network: rule.network.clone(),
            enabled: rule.enabled.0,
        }
    }

    /// The rule as written, checked.
    pub fn to_rule(&self) -> Result<UserRule, String> {
        let list = |text: &str| -> Vec<String> {
            text.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        };
        let rule = UserRule {
            action: self.action,
            domain: list(&self.domain),
            ip: list(&self.ip),
            process: list(&self.process),
            port: self.port.trim().to_string(),
            network: self.network.clone(),
            enabled: zero_config::presets::Enabled(self.enabled),
        };
        rule.check().map(|()| rule)
    }

    /// The text of the focused field, when it is one that takes text.
    pub fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            1 => Some(&mut self.domain),
            2 => Some(&mut self.ip),
            3 => Some(&mut self.process),
            4 => Some(&mut self.port),
            _ => None,
        }
    }

    /// Step the focused choice field (Action, Network) by one.
    fn cycle(&mut self, forward: bool) {
        match self.field {
            0 => {
                const ACTIONS: [RuleAction; 3] =
                    [RuleAction::Proxy, RuleAction::Direct, RuleAction::Block];
                let at = ACTIONS.iter().position(|a| *a == self.action).unwrap_or(0);
                self.action = ACTIONS[step(at, ACTIONS.len(), forward)];
            }
            5 => {
                const NETWORKS: [&str; 3] = ["", "tcp", "udp"];
                let at = NETWORKS
                    .iter()
                    .position(|n| *n == self.network)
                    .unwrap_or(0);
                self.network = NETWORKS[step(at, NETWORKS.len(), forward)].to_string();
            }
            _ => {}
        }
    }
}

fn step(at: usize, len: usize, forward: bool) -> usize {
    if forward {
        (at + 1) % len
    } else {
        (at + len - 1) % len
    }
}

/// A profile name being typed: a new profile, or a new name for one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Naming {
    pub buffer: String,
    /// The profile being renamed; `None` for a new one.
    pub renaming: Option<usize>,
}

/// What the editor asks of the app after a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Stay,
    /// Put the clipboard's text in with [`Editor::paste`].
    Paste,
    /// Close the editor and keep what it holds.
    Close,
}

/// The routing profile editor: the profiles on the left, the selected
/// profile's rules on the right, and a form over the rules while one is
/// being written.
///
/// ```text
/// Profiles            Rules of "Work"
///  ● Work              on   DIRECT  domain geosite:category-ir
///    Gaming            on   BLOCK   program telemetry
///                      off  PROXY   address 91.108.0.0/16
/// ```
///
/// Keys, profiles: ↑↓ choose, Enter use (again: stop using), n new,
/// r rename, d delete, → or Tab to the rules. Rules: ↑↓ choose, a add,
/// Enter edit, Space on/off, d delete, Shift+↑↓ move, ← or Tab back. Esc
/// closes, keeping every change. In the form: Tab and ↑↓ between fields,
/// ←→ or Space change a choice, Enter save, Esc drop the changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Editor {
    pub profiles: Vec<RoutingProfile>,
    /// The name of the profile in use; empty for none.
    pub active: String,
    pub pane: Pane,
    pub profile: usize,
    pub rule: usize,
    pub form: Option<RuleForm>,
    pub naming: Option<Naming>,
    /// A line telling the user what just went wrong, if anything did.
    pub message: Option<String>,
}

impl Editor {
    pub fn new(profiles: Vec<RoutingProfile>, active: String) -> Self {
        let profile = profiles.iter().position(|p| p.name == active).unwrap_or(0);
        Self {
            profiles,
            active,
            profile,
            ..Self::default()
        }
    }

    /// The rules of the selected profile.
    pub fn rules(&self) -> &[UserRule] {
        self.profiles
            .get(self.profile)
            .map_or(&[], |profile| profile.rules.as_slice())
    }

    /// Whether the focused place takes typed text, so the app can show a
    /// caret there.
    pub fn typing(&self) -> bool {
        self.naming.is_some()
            || self
                .form
                .as_ref()
                .is_some_and(|f| (1..=4).contains(&f.field))
    }

    /// Put `text` where the user is typing, if they are.
    pub fn paste(&mut self, text: &str) {
        let text: String = text.chars().filter(|c| !c.is_control()).collect();
        if let Some(naming) = self.naming.as_mut() {
            naming.buffer.push_str(&text);
        } else if let Some(field) = self.form.as_mut().and_then(RuleForm::text_mut) {
            field.push_str(&text);
        }
    }

    pub fn on_key(&mut self, key: crossterm::event::KeyEvent) -> Outcome {
        use crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('v')) {
            return Outcome::Paste;
        }
        self.message = None;
        if self.naming.is_some() {
            self.naming_key(key.code, ctrl);
            return Outcome::Stay;
        }
        if self.form.is_some() {
            self.form_key(key.code, ctrl);
            return Outcome::Stay;
        }
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match (self.pane, key.code) {
            (_, KeyCode::Esc) | (_, KeyCode::Char('q')) => return Outcome::Close,
            (Pane::Profiles, KeyCode::Up | KeyCode::Char('k')) => {
                self.profile = self.profile.saturating_sub(1);
                self.rule = 0;
            }
            (Pane::Profiles, KeyCode::Down | KeyCode::Char('j')) => {
                if self.profile + 1 < self.profiles.len() {
                    self.profile += 1;
                    self.rule = 0;
                }
            }
            (Pane::Profiles, KeyCode::Enter | KeyCode::Char(' ')) => {
                if let Some(profile) = self.profiles.get(self.profile) {
                    self.active = if self.active == profile.name {
                        String::new()
                    } else {
                        profile.name.clone()
                    };
                }
            }
            (Pane::Profiles, KeyCode::Char('n')) => self.naming = Some(Naming::default()),
            (Pane::Profiles, KeyCode::Char('r')) => {
                if let Some(profile) = self.profiles.get(self.profile) {
                    self.naming = Some(Naming {
                        buffer: profile.name.clone(),
                        renaming: Some(self.profile),
                    });
                }
            }
            (Pane::Profiles, KeyCode::Char('d') | KeyCode::Delete) => self.delete_profile(),
            (Pane::Profiles, KeyCode::Right | KeyCode::Tab | KeyCode::Char('l')) => {
                if self.profiles.get(self.profile).is_some() {
                    self.pane = Pane::Rules;
                } else {
                    self.message = Some("Make a profile first (n)".into());
                }
            }
            (Pane::Rules, KeyCode::Left | KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('h')) => {
                self.pane = Pane::Profiles
            }
            (Pane::Rules, KeyCode::Up) if shift => self.move_rule(false),
            (Pane::Rules, KeyCode::Down) if shift => self.move_rule(true),
            (Pane::Rules, KeyCode::Char('K')) => self.move_rule(false),
            (Pane::Rules, KeyCode::Char('J')) => self.move_rule(true),
            (Pane::Rules, KeyCode::Up | KeyCode::Char('k')) => {
                self.rule = self.rule.saturating_sub(1)
            }
            (Pane::Rules, KeyCode::Down | KeyCode::Char('j')) => {
                if self.rule + 1 < self.rules().len() {
                    self.rule += 1;
                }
            }
            (Pane::Rules, KeyCode::Char('a') | KeyCode::Char('n')) => {
                self.form = Some(RuleForm {
                    enabled: true,
                    ..RuleForm::default()
                })
            }
            (Pane::Rules, KeyCode::Enter | KeyCode::Char('e')) => {
                if let Some(rule) = self.rules().get(self.rule) {
                    self.form = Some(RuleForm::from_rule(self.rule, rule));
                }
            }
            (Pane::Rules, KeyCode::Char(' ')) => {
                let at = self.rule;
                if let Some(rule) = self.rules_mut().and_then(|rules| rules.get_mut(at)) {
                    rule.enabled.0 = !rule.enabled.0;
                }
            }
            (Pane::Rules, KeyCode::Char('d') | KeyCode::Delete) => {
                let at = self.rule;
                if let Some(rules) = self.rules_mut() {
                    if at < rules.len() {
                        rules.remove(at);
                    }
                }
                self.rule = self.rule.min(self.rules().len().saturating_sub(1));
            }
            _ => {}
        }
        Outcome::Stay
    }

    fn rules_mut(&mut self) -> Option<&mut Vec<UserRule>> {
        self.profiles.get_mut(self.profile).map(|p| &mut p.rules)
    }

    fn move_rule(&mut self, down: bool) {
        let at = self.rule;
        let Some(rules) = self.rules_mut() else {
            return;
        };
        let to = if down { at + 1 } else { at.wrapping_sub(1) };
        if at < rules.len() && to < rules.len() {
            rules.swap(at, to);
            self.rule = to;
        }
    }

    fn delete_profile(&mut self) {
        if self.profile >= self.profiles.len() {
            return;
        }
        let gone = self.profiles.remove(self.profile);
        if self.active == gone.name {
            self.active.clear();
        }
        self.profile = self.profile.min(self.profiles.len().saturating_sub(1));
        self.rule = 0;
    }

    fn naming_key(&mut self, code: crossterm::event::KeyCode, ctrl: bool) {
        use crossterm::event::KeyCode;
        let Some(naming) = self.naming.as_mut() else {
            return;
        };
        match code {
            KeyCode::Esc => self.naming = None,
            KeyCode::Backspace => {
                naming.buffer.pop();
            }
            KeyCode::Char('u') if ctrl => naming.buffer.clear(),
            KeyCode::Char(c) if !ctrl => naming.buffer.push(c),
            KeyCode::Enter => {
                let name = naming.buffer.trim().to_string();
                let renaming = naming.renaming;
                let taken = self
                    .profiles
                    .iter()
                    .enumerate()
                    .any(|(i, p)| p.name == name && Some(i) != renaming);
                if name.is_empty() {
                    self.message = Some("A profile needs a name".into());
                } else if taken {
                    self.message = Some(format!("There is already a profile called {name}"));
                } else {
                    match renaming {
                        Some(at) => {
                            if self.active == self.profiles[at].name {
                                self.active = name.clone();
                            }
                            self.profiles[at].name = name;
                        }
                        None => {
                            self.profiles.push(RoutingProfile {
                                name,
                                rules: Vec::new(),
                            });
                            self.profile = self.profiles.len() - 1;
                            self.rule = 0;
                        }
                    }
                    self.naming = None;
                }
            }
            _ => {}
        }
    }

    fn form_key(&mut self, code: crossterm::event::KeyCode, ctrl: bool) {
        use crossterm::event::KeyCode;
        let Some(form) = self.form.as_mut() else {
            return;
        };
        let fields = FORM_FIELDS.len();
        match code {
            KeyCode::Esc => self.form = None,
            KeyCode::Tab | KeyCode::Down => form.field = (form.field + 1) % fields,
            KeyCode::BackTab | KeyCode::Up => form.field = (form.field + fields - 1) % fields,
            KeyCode::Enter => match form.to_rule() {
                Ok(rule) => {
                    let index = form.index;
                    let Some(rules) = self.rules_mut() else {
                        return;
                    };
                    match index {
                        Some(at) if at < rules.len() => rules[at] = rule,
                        _ => rules.push(rule),
                    }
                    self.rule = index.unwrap_or(self.rules().len().saturating_sub(1));
                    self.form = None;
                }
                Err(why) => self.message = Some(why),
            },
            KeyCode::Left => form.cycle(false),
            KeyCode::Right => form.cycle(true),
            _ => {
                if let Some(text) = form.text_mut() {
                    match code {
                        KeyCode::Backspace => {
                            text.pop();
                        }
                        KeyCode::Char('u') if ctrl => text.clear(),
                        KeyCode::Char(c) if !ctrl => text.push(c),
                        _ => {}
                    }
                } else if code == KeyCode::Char(' ') {
                    form.cycle(true);
                }
            }
        }
    }
}

/// One line describing `rule` for the list: what it matches, shortened to
/// `width` characters.
pub fn summary(rule: &UserRule, width: usize) -> String {
    let mut parts = Vec::new();
    for (label, list) in [
        ("domain", &rule.domain),
        ("address", &rule.ip),
        ("program", &rule.process),
    ] {
        if !list.is_empty() {
            parts.push(format!("{label} {}", list.join(", ")));
        }
    }
    if !rule.port.is_empty() {
        parts.push(format!("port {}", rule.port));
    }
    if !rule.network.is_empty() {
        parts.push(rule.network.clone());
    }
    let line = parts.join(" · ");
    if line.chars().count() <= width {
        line
    } else {
        let mut short: String = line.chars().take(width.saturating_sub(1)).collect();
        short.push('…');
        short
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(value: Value) -> Vec<UserRule> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn profiles_round_trip_and_bad_storage_reads_as_none() {
        let profiles = vec![RoutingProfile {
            name: "Work".into(),
            rules: rules(json!([{"action": "direct", "domain": ["a.example"]}])),
        }];
        assert_eq!(load(&save(&profiles)), profiles);
        assert!(load("").is_empty());
        assert!(load("{not json").is_empty());
        assert_eq!(active_rules(&profiles, "Work").len(), 1);
        assert!(active_rules(&profiles, "").is_empty());
        assert!(active_rules(&profiles, "Home").is_empty());
    }

    /// In an app-built configuration the targets are its own tags, and the
    /// profile goes in front.
    #[test]
    fn a_profile_goes_first_with_the_configs_own_tags() {
        let mut config = json!({
            "outbounds": [
                {"tag": "proxy", "protocol": "vless"},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
        });
        let profile = rules(json!([
            {"action": "proxy", "domain": ["domain:digikala.com"]},
            {"action": "block", "process": ["telemetry"]},
            {"action": "direct", "port": "22"},
            {"action": "direct", "domain": ["off.example"], "enabled": false},
            {"action": "block"},
        ]));
        apply(config.as_object_mut().unwrap(), &profile);
        let built = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(built.len(), 4);
        assert_eq!(built[0]["outboundTag"], json!("proxy"));
        assert_eq!(built[1]["process"], json!(["telemetry"]));
        assert_eq!(built[1]["outboundTag"], json!("block"));
        assert_eq!(built[2]["outboundTag"], json!("direct"));
        assert_eq!(built[3]["ip"], json!(["geoip:private"]));
        assert_eq!(config["outbounds"].as_array().unwrap().len(), 3);
    }

    /// An imported configuration with other tags, a catch-all balancer and
    /// no blackhole: proxy rules use the balancer, and a block outbound is
    /// added under a free tag.
    #[test]
    fn an_imported_config_gets_what_its_profile_needs() {
        let mut config = json!({
            "outbounds": [
                {"tag": "nl-1", "protocol": "trojan"},
                {"tag": "block", "protocol": "vless"},
                {"tag": "out", "protocol": "freedom"},
            ],
            "routing": {"rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "fast"}]},
        });
        let profile = rules(json!([
            {"action": "proxy", "domain": ["x.example"]},
            {"action": "direct", "domain": ["y.example"]},
            {"action": "block", "domain": ["z.example"]},
        ]));
        apply(config.as_object_mut().unwrap(), &profile);
        let built = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(built[0]["balancerTag"], json!("fast"));
        assert_eq!(built[1]["outboundTag"], json!("out"));
        assert_eq!(built[2]["outboundTag"], json!("block-2"));
        assert!(config["outbounds"]
            .as_array()
            .unwrap()
            .contains(&json!({"tag": "block-2", "protocol": "blackhole"})));
        // And it all compiles.
        zero_config::parse_config(&json!({
            "outbounds": [
                {"tag": "nl-1", "protocol": "freedom"},
                {"tag": "out", "protocol": "freedom"},
                {"tag": "block-2", "protocol": "blackhole"},
            ],
            "routing": {"rules": [built[1].clone(), built[2].clone()]},
        }))
        .unwrap();
    }

    fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn typed(editor: &mut Editor, text: &str) {
        for c in text.chars() {
            editor.on_key(key(crossterm::event::KeyCode::Char(c)));
        }
    }

    /// The whole flow by keyboard: make a profile, add a rule through the
    /// form, use the profile, switch the rule off, close.
    #[test]
    fn a_profile_is_made_filled_and_used_from_the_keyboard() {
        use crossterm::event::KeyCode;
        let mut editor = Editor::new(Vec::new(), String::new());
        // Nothing to go right to yet.
        editor.on_key(key(KeyCode::Right));
        assert_eq!(editor.pane, Pane::Profiles);
        assert!(editor.message.is_some());

        editor.on_key(key(KeyCode::Char('n')));
        typed(&mut editor, "Work");
        editor.on_key(key(KeyCode::Enter));
        assert_eq!(editor.profiles.len(), 1);
        editor.on_key(key(KeyCode::Enter));
        assert_eq!(editor.active, "Work");

        editor.on_key(key(KeyCode::Tab));
        editor.on_key(key(KeyCode::Char('a')));
        // An empty rule is refused with a reason.
        editor.on_key(key(KeyCode::Enter));
        assert!(editor.form.is_some() && editor.message.is_some());
        editor.on_key(key(KeyCode::Right)); // action: direct
        editor.on_key(key(KeyCode::Tab));
        typed(&mut editor, "geosite:category-ir, keyword:bank");
        editor.on_key(key(KeyCode::Tab));
        editor.on_key(key(KeyCode::Tab));
        typed(&mut editor, "qbittorrent");
        editor.on_key(key(KeyCode::Enter));
        assert!(editor.form.is_none());
        let rule = &editor.rules()[0];
        assert_eq!(rule.action, RuleAction::Direct);
        assert_eq!(rule.domain, vec!["geosite:category-ir", "keyword:bank"]);
        assert_eq!(rule.process, vec!["qbittorrent"]);

        // `q` typed into a field is text, not "close".
        editor.on_key(key(KeyCode::Enter));
        editor.on_key(key(KeyCode::Tab));
        editor.on_key(key(KeyCode::Tab));
        editor.on_key(key(KeyCode::Tab));
        typed(&mut editor, ",q");
        editor.on_key(key(KeyCode::Enter));
        assert_eq!(editor.rules()[0].process, vec!["qbittorrent", "q"]);

        editor.on_key(key(KeyCode::Char(' ')));
        assert!(!editor.rules()[0].enabled.0);
        assert_eq!(editor.on_key(key(KeyCode::Esc)), Outcome::Close);
    }

    #[test]
    fn rules_move_and_profiles_rename_and_delete_cleanly() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let rule = |d: &str| UserRule {
            domain: vec![d.into()],
            ..UserRule::default()
        };
        let mut editor = Editor::new(
            vec![
                RoutingProfile {
                    name: "A".into(),
                    rules: vec![rule("one"), rule("two")],
                },
                RoutingProfile {
                    name: "B".into(),
                    rules: Vec::new(),
                },
            ],
            "A".into(),
        );
        editor.on_key(key(KeyCode::Right));
        editor.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT));
        assert_eq!(editor.rules()[1].domain, vec!["one"]);
        assert_eq!(editor.rule, 1);

        editor.on_key(key(KeyCode::Left));
        editor.on_key(key(KeyCode::Char('r')));
        editor.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        typed(&mut editor, "B");
        editor.on_key(key(KeyCode::Enter));
        assert!(editor.message.is_some(), "B is taken");
        editor.on_key(key(KeyCode::Backspace));
        typed(&mut editor, "Home");
        editor.on_key(key(KeyCode::Enter));
        assert_eq!(
            editor.active, "Home",
            "the active profile follows its new name"
        );

        editor.on_key(key(KeyCode::Char('d')));
        assert_eq!(editor.profiles.len(), 1);
        assert_eq!(
            editor.active, "",
            "deleting the active profile stops using it"
        );
        assert_eq!(
            editor.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL)),
            Outcome::Paste
        );
    }

    #[test]
    fn a_long_rule_summary_is_cut_to_fit() {
        let rule = UserRule {
            domain: vec!["a.example".into(), "b.example".into()],
            port: "443".into(),
            ..UserRule::default()
        };
        assert_eq!(summary(&rule, 80), "domain a.example, b.example · port 443");
        let short = summary(&rule, 12);
        assert_eq!(short.chars().count(), 12);
        assert!(short.ends_with('…'));
    }
}
