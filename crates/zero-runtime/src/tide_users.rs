//! A Tide server's users, and the small control panel that manages them.
//!
//! How this works: a Tide inbound knows its users from two places. The config
//! lists some; a users file (`usersFile`) holds the ones added later. Both
//! are read into one shared map, which the server checks on every handshake,
//! so a user added or removed here takes effect on the next connection with
//! no restart.
//!
//! The panel is one page served by the Tide server itself under a secret
//! path (`adminPath`). It lists the users, shows each one's share link and a
//! QR code of it, and has a form to add a user and a button to remove one.
//! Anyone who can open that path can manage the server, so the path is the
//! password: keep it long and random (`zray tide init` makes one).
//!
//! The rules it keeps:
//!  * a change is written to the users file before the page says it
//!    happened, and written whole to a temporary file first, so a crash
//!    never leaves half a file;
//!  * names are shown escaped, never as markup;
//!  * the page asks browsers not to send its address onward
//!    (`Referrer-Policy`), since the address is the secret.
//!
//! The surprise: users written in the config itself cannot be removed from
//! the panel. They would come back at the next start, so the page says so
//! instead of pretending.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rand::RngCore;
use serde_json::{json, Value};
use zero_config::TideInboundConfig;
use zero_protocol::tide::{decode_key, encode_key, noise, UserId};
use zero_transport::tide::{Admin, AdminReply};

pub(crate) type Users = Arc<RwLock<HashMap<UserId, String>>>;

/// The users of `config`: its own list, then whatever its users file adds.
pub(crate) fn load(config: &TideInboundConfig) -> Users {
    let mut users: HashMap<UserId, String> = config
        .users
        .iter()
        .map(|user| (user.id, user.name.to_string()))
        .collect();
    if let Some(path) = config.users_file.as_deref() {
        match std::fs::read_to_string(path) {
            Ok(text) => users.extend(parse_file(&text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%path, %error, "Tide users file could not be read; only the users in the config are active")
            }
        }
    }
    Arc::new(RwLock::new(users))
}

fn parse_file(text: &str) -> Vec<(UserId, String)> {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let id = decode_key::<16>(entry.get("id")?.as_str()?)?;
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            Some((id, name.to_string()))
        })
        .collect()
}

/// Write every user that is not in the config to the users file.
fn save(config: &TideInboundConfig, users: &HashMap<UserId, String>) -> Result<(), String> {
    let Some(path) = config.users_file.as_deref() else {
        return Err(
            "this server has no usersFile, so the change lasts only until it restarts".into(),
        );
    };
    let mut kept: Vec<_> = users
        .iter()
        .filter(|(id, _)| !config.users.iter().any(|user| user.id == **id))
        .collect();
    kept.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)));
    let entries: Vec<Value> = kept
        .iter()
        .map(|(id, name)| json!({"id": encode_key(*id), "name": name}))
        .collect();
    let text = serde_json::to_string_pretty(&entries).map_err(|error| error.to_string())?;
    let temporary = format!("{path}.tmp");
    std::fs::write(&temporary, text)
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|error| format!("could not write {path}: {error}"))
}

/// The share link a client needs to connect as `user`.
pub fn share_link(config: &TideInboundConfig, user: &UserId, name: &str) -> Option<String> {
    let host = config.public_host.as_deref()?;
    let public = noise::public_key(&config.secret);
    // A server reached by bare address has no name to put in the handshake;
    // its certificate is checked against the address itself.
    let named = host.parse::<std::net::IpAddr>().is_err();
    let name_part = if named {
        format!("&sni={host}")
    } else {
        String::new()
    };
    // An IPv6 address needs brackets to sit before a port.
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Some(format!(
        "zerov1://{}@{}:{}?key={}&path={}&security=tls{}&fp=chrome#{}",
        encode_key(user),
        authority,
        config.public_port,
        encode_key(&public),
        percent(&config.path),
        name_part,
        percent(name),
    ))
}

/// Percent-encode everything but letters, digits and `-._~`.
fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn unpercent(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' if at + 2 < bytes.len() => match u8::from_str_radix(&text[at + 1..at + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    at += 2;
                }
                Err(_) => out.push(b'%'),
            },
            byte => out.push(byte),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One field of an HTML form body (`a=1&b=2`).
fn field(body: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    text.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| unpercent(value))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A QR code of `text` as an inline SVG, or nothing when this build has no
/// QR encoder (the phone library leaves it out to stay small).
#[cfg(feature = "panel")]
pub fn qr_svg(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    // One path of 1x1 squares, with the four-module quiet zone QR needs.
    let mut path = String::new();
    for (index, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            path.push_str(&format!(
                "M{} {}h1v1h-1z",
                index % width + 4,
                index / width + 4
            ));
        }
    }
    let size = width + 8;
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" width=\"220\" height=\"220\" shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path d=\"{path}\" fill=\"#000\"/></svg>"
    ))
}

#[cfg(not(feature = "panel"))]
pub fn qr_svg(_text: &str) -> Option<String> {
    None
}

/// A QR code of `text` drawn with block characters, for a terminal. Two rows
/// of the code share one line of text, so it comes out roughly square.
#[cfg(feature = "panel")]
pub fn qr_terminal(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let dark = |x: isize, y: isize| {
        let inside = x >= 0 && y >= 0 && (x as usize) < width && (y as usize) < width;
        inside && colors[y as usize * width + x as usize] == qrcode::Color::Dark
    };
    // Drawn dark-on-light with a two-module margin: light is the full block,
    // so it reads the same on a dark terminal as on a light one.
    let mut out = String::new();
    let mut y = -2isize;
    while y < width as isize + 2 {
        out.push_str("  ");
        for x in -2..width as isize + 2 {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (false, false) => '\u{2588}',
                (false, true) => '\u{2580}',
                (true, false) => '\u{2584}',
                (true, true) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Some(out)
}

#[cfg(not(feature = "panel"))]
pub fn qr_terminal(_text: &str) -> Option<String> {
    None
}

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fafafa}h1{font-size:1.4rem}section{background:#fff;border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}textarea{width:100%;box-sizing:border-box;font:13px monospace;height:5.5rem}input[type=text]{font:inherit;padding:.4rem;width:60%}button{font:inherit;padding:.4rem .9rem;border-radius:6px;border:1px solid #888;background:#eee;cursor:pointer}.del{color:#a00;border-color:#a00;background:#fff}.note{color:#555;font-size:.9rem}.err{color:#a00}";

fn page(config: &TideInboundConfig, users: &HashMap<UserId, String>, message: &str) -> String {
    let mut body = String::new();
    body.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>ZeroV1 server</title><style>");
    body.push_str(STYLE);
    body.push_str("</style></head><body><h1>ZeroV1 server</h1>");
    if !message.is_empty() {
        body.push_str(&format!("<p class=\"err\">{}</p>", escape(message)));
    }
    if config.public_host.is_none() {
        body.push_str("<p class=\"err\">This server has no publicHost in its config, so it cannot make links. Add the domain clients reach it by and restart.</p>");
    }
    body.push_str("<section><form method=\"post\" action=\"add\"><label>New user: <input type=\"text\" name=\"name\" maxlength=\"40\" placeholder=\"a name, e.g. phone\" required></label> <button>Add</button></form></section>");
    let mut listed: Vec<_> = users.iter().collect();
    listed.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)));
    if listed.is_empty() {
        body.push_str("<p class=\"note\">No users yet. Add one to get a link.</p>");
    }
    for (id, name) in listed {
        let fixed = config.users.iter().any(|user| user.id == *id);
        body.push_str(&format!("<section><h2>{}</h2>", escape(name)));
        if let Some(link) = share_link(config, id, name) {
            if let Some(svg) = qr_svg(&link) {
                body.push_str(&svg);
            }
            body.push_str(&format!(
                "<p class=\"note\">Scan the code in the app, or copy this link into it:</p><textarea readonly onclick=\"this.select()\">{}</textarea>",
                escape(&link)
            ));
        }
        if fixed {
            body.push_str("<p class=\"note\">This user is written in the server's config file; remove it there.</p>");
        } else {
            body.push_str(&format!(
                "<form method=\"post\" action=\"delete\" onsubmit=\"return confirm('Remove this user? Their link stops working.')\"><input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"del\">Remove</button></form>",
                encode_key(id)
            ));
        }
        body.push_str("</section>");
    }
    body.push_str("</body></html>");
    body
}

/// The panel for `config`, when it names a path to serve it under.
pub(crate) fn admin(config: &TideInboundConfig, users: &Users) -> Option<Admin> {
    let path = config.admin_path.as_deref()?.to_string();
    let (config, users) = (config.clone(), Arc::clone(users));
    let handler = move |method: &str, action: &str, body: &[u8]| -> AdminReply {
        let mut message = String::new();
        match (method, action) {
            ("GET", "") => {}
            ("POST", "add") => {
                let name: String = field(body, "name")
                    .unwrap_or_default()
                    .trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(40)
                    .collect();
                if name.is_empty() {
                    message = "A user needs a name.".into();
                } else {
                    let mut id = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut id);
                    let mut users = users.write().unwrap_or_else(|p| p.into_inner());
                    users.insert(id, name);
                    if let Err(error) = save(&config, &users) {
                        message = error;
                    }
                }
            }
            ("POST", "delete") => {
                let id = field(body, "id").and_then(|id| decode_key::<16>(&id));
                let fixed = id.is_some_and(|id| config.users.iter().any(|user| user.id == id));
                match id {
                    Some(id) if !fixed => {
                        let mut users = users.write().unwrap_or_else(|p| p.into_inner());
                        users.remove(&id);
                        if let Err(error) = save(&config, &users) {
                            message = error;
                        }
                    }
                    _ => message = "That user cannot be removed here.".into(),
                }
            }
            _ => return AdminReply::not_found(),
        }
        // After a change, send the browser back to the list, so a reload
        // does not repeat the change. An error is shown in place instead.
        if method == "POST" && message.is_empty() {
            return AdminReply::see_other("./");
        }
        let users = users.read().unwrap_or_else(|p| p.into_inner());
        AdminReply::html(page(&config, &users, &message))
    };
    Some(Admin {
        path,
        handler: Arc::new(handler),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(users_file: Option<&str>) -> TideInboundConfig {
        TideInboundConfig {
            path: "/app".into(),
            secret: [5; 32],
            users: vec![zero_config::TideUser {
                id: [1; 16],
                name: "fixed".into(),
            }]
            .into_boxed_slice(),
            users_file: users_file.map(Into::into),
            public_host: Some("example.com".into()),
            public_port: 443,
            admin_path: Some("/secret-admin".into()),
        }
    }

    #[test]
    fn a_share_link_parses_back_into_the_same_server_and_user() {
        let config = config(None);
        let link = share_link(&config, &[9; 16], "my phone").unwrap();
        let parsed = zero_config::share_link::parse_link(&link).unwrap();
        let zero_config::OutboundProtocol::Tide(tide) = &parsed.outbound.protocol else {
            panic!("not a Tide link: {link}");
        };
        assert_eq!(tide.user, [9; 16]);
        assert_eq!(tide.server_key, noise::public_key(&config.secret));
        assert_eq!(&*tide.path, "/app");
        assert_eq!(tide.port, 443);
        assert_eq!(parsed.remark, "my phone");
    }

    #[test]
    fn the_panel_adds_and_removes_users_and_keeps_them_on_disk() {
        let directory = std::env::temp_dir().join(format!("tide-users-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("users.json");
        let config = config(Some(file.to_str().unwrap()));
        let users = load(&config);
        let admin = admin(&config, &users).unwrap();

        let page = (admin.handler)("GET", "", b"");
        assert!(String::from_utf8_lossy(&page.body).contains("fixed"));

        let added = (admin.handler)("POST", "add", b"name=Ali%27s+%3Cphone%3E");
        assert_eq!(added.status, 303);
        assert_eq!(users.read().unwrap().len(), 2);
        let listed = String::from_utf8_lossy(&(admin.handler)("GET", "", b"").body).into_owned();
        assert!(
            listed.contains("Ali's &lt;phone&gt;"),
            "the name is escaped"
        );
        assert!(listed.contains("zerov1://"));

        // A fresh start reads the same users back.
        let reloaded = load(&config);
        assert_eq!(reloaded.read().unwrap().len(), 2);
        let (id, _) = reloaded
            .read()
            .unwrap()
            .iter()
            .find(|(_, name)| name.starts_with("Ali"))
            .map(|(id, name)| (*id, name.clone()))
            .unwrap();

        let body = format!("id={}", encode_key(&id));
        assert_eq!(
            (admin.handler)("POST", "delete", body.as_bytes()).status,
            303
        );
        assert_eq!(load(&config).read().unwrap().len(), 1);
        // The config's own user stays.
        let body = format!("id={}", encode_key(&[1u8; 16]));
        assert_eq!(
            (admin.handler)("POST", "delete", body.as_bytes()).status,
            200
        );
        assert_eq!(users.read().unwrap().len(), 1);
        assert_eq!((admin.handler)("GET", "nothing", b"").status, 404);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_server_known_only_by_address_gets_a_link_without_a_name() {
        let mut config = config(None);
        config.public_host = Some("203.0.113.9".into());
        let link = share_link(&config, &[9; 16], "x").unwrap();
        assert!(!link.contains("sni="), "{link}");
        let parsed = zero_config::share_link::parse_link(&link).unwrap();
        assert_eq!(parsed.outbound.endpoint().unwrap().1, 443);

        config.public_host = Some("2001:db8::9".into());
        let link = share_link(&config, &[9; 16], "x").unwrap();
        assert!(link.contains("@[2001:db8::9]:443"), "{link}");
        assert!(zero_config::share_link::parse_link(&link).is_ok(), "{link}");
    }

    #[test]
    fn form_fields_are_decoded() {
        assert_eq!(field(b"a=1&name=x+y%21", "name").as_deref(), Some("x y!"));
        assert_eq!(field(b"a=1", "name"), None);
        assert_eq!(unpercent("100%"), "100%");
    }
}
