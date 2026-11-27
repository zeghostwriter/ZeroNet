//! Client links for what the installer sets up.
//!
//! A link is the one string a person pastes or scans into an app. Each builder
//! here is checked in its tests by parsing the result with the same parser the
//! apps use, so a link that this module makes is a link the apps read.

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// Everything but the unreserved characters is escaped in a link's `#name`.
const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn name(name: &str) -> String {
    utf8_percent_encode(name, FRAGMENT).to_string()
}

/// `host` as a URL authority: an IPv6 address needs its brackets.
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// VLESS over REALITY with Vision flow on a TCP carrier.
pub fn vless_reality(
    host: &str,
    port: u16,
    user_id: &str,
    sni: &str,
    public_key: &str,
    short_id: &str,
    label: &str,
) -> String {
    format!(
        "vless://{user_id}@{}?encryption=none&flow=xtls-rprx-vision&security=reality\
         &sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp#{}",
        authority(host, port),
        name(label)
    )
}

/// VLESS over XHTTP inside REALITY. XHTTP has its own framing, so there is no
/// Vision flow; `path` is the one the server was set up with.
#[allow(clippy::too_many_arguments)]
pub fn vless_xhttp_reality(
    host: &str,
    port: u16,
    user_id: &str,
    sni: &str,
    public_key: &str,
    short_id: &str,
    path: &str,
    label: &str,
) -> String {
    format!(
        "vless://{user_id}@{}?encryption=none&security=reality&sni={sni}&fp=chrome\
         &pbk={public_key}&sid={short_id}&type=xhttp&path={}&mode=auto#{}",
        authority(host, port),
        utf8_percent_encode(path, FRAGMENT),
        name(label)
    )
}

/// A ZeroV1 user id from a VLESS UUID: its sixteen bytes, unpadded URL-safe
/// base64, the form ZeroV1 links and server configs use. `None` for text that
/// is not a UUID.
pub fn zerov1_user_id(uuid: &str) -> Option<String> {
    let bytes: [u8; 16] = hex::decode(uuid.replace('-', "")).ok()?.try_into().ok()?;
    Some(zero_protocol::tide::encode_key(&bytes))
}

/// ZeroV1 inside REALITY. `uuid` is the user's VLESS UUID (their ZeroV1 id is
/// made from it); `server_key` is ZeroV1's public key, `public_key` REALITY's.
#[allow(clippy::too_many_arguments)]
pub fn zerov1_reality(
    host: &str,
    port: u16,
    uuid: &str,
    server_key: &str,
    path: &str,
    sni: &str,
    public_key: &str,
    short_id: &str,
    label: &str,
) -> String {
    format!(
        "zerov1://{}@{}?key={server_key}&path={}&security=reality&sni={sni}&pbk={public_key}\
         &sid={short_id}&fp=chrome&dg=1#{}",
        zerov1_user_id(uuid).unwrap_or_default(),
        authority(host, port),
        utf8_percent_encode(path, NON_ALPHANUMERIC),
        name(label)
    )
}

/// Resolvers the upstream client starts with: well-known public ones. People
/// whose network blocks them add their own provider's, which is why the text
/// says so.
pub const MASTERDNS_RESOLVERS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"];

/// The link the apps import for a MasterDNS server (Zray's own format; the
/// upstream program has none). It carries the key, so it is as secret as the
/// files. When the server was typed as an IP address it is added as a direct
/// resolver, ahead of the public ones: it answers on UDP 53 itself, which works
/// wherever that is not filtered, and the client drops any resolver that does
/// not answer its test queries.
pub fn masterdns(server: &str, service: &crate::record::MasterDns, label: &str) -> String {
    let mut query = String::new();
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        query.push_str(&match ip {
            std::net::IpAddr::V4(ip) => format!("server={ip}&"),
            std::net::IpAddr::V6(ip) => format!("server=[{ip}]&"),
        });
    }
    query.push_str(&format!("resolvers={}", MASTERDNS_RESOLVERS.join(",")));
    if service.method != 5 {
        query.push_str(&format!("&method={}", service.method));
    }
    format!(
        "masterdns://{}@{}?{query}#{}",
        utf8_percent_encode(&service.key, FRAGMENT),
        service.domain,
        name(label)
    )
}

/// The two files the upstream MasterDnsVPN client reads for this server.
pub fn masterdns_client_files(service: &crate::record::MasterDns) -> Vec<crate::record::File> {
    let config = format!(
        "# MasterDnsVPN client config for {domain}\n\
         # Save as client_config.toml next to client_resolvers.txt, then run the\n\
         # MasterDnsVPN client with it. It opens a SOCKS5 proxy on 127.0.0.1:18000.\n\
         DOMAINS = [\"{domain}\"]\n\
         DATA_ENCRYPTION_METHOD = {method}\n\
         ENCRYPTION_KEY = \"{key}\"\n\
         PROTOCOL_TYPE = \"SOCKS5\"\n\
         LISTEN_IP = \"127.0.0.1\"\n\
         LISTEN_PORT = 18000\n",
        domain = service.domain,
        method = service.method,
        key = service.key
    );
    let mut resolvers = String::from(
        "# One DNS resolver per line. Add the DNS servers your own internet provider\n\
         # gives you: on a network that blocks the public ones, those still answer.\n",
    );
    for resolver in MASTERDNS_RESOLVERS {
        resolvers.push_str(resolver);
        resolvers.push('\n');
    }
    vec![
        crate::record::File {
            name: "client_config.toml".into(),
            text: config,
        },
        crate::record::File {
            name: "client_resolvers.txt".into(),
            text: resolvers,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_config::{OutboundProtocol, Security};

    #[test]
    fn a_reality_link_is_read_back_as_reality_with_vision() {
        let link = vless_reality(
            "203.0.113.7",
            443,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "www.microsoft.com",
            "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
            "0123456789abcdef",
            "My server / Ali",
        );
        let parsed = zero_config::parse_link(&link).expect("the apps read it");
        assert_eq!(parsed.remark, "My server / Ali");
        let OutboundProtocol::Vless(vless) = &parsed.outbound.protocol else {
            panic!("expected vless, got {:?}", parsed.outbound.protocol);
        };
        assert_eq!(vless.flow, zero_config::Flow::Vision);
        let Security::Reality(reality) = &parsed.outbound.stream.security else {
            panic!("expected reality");
        };
        assert_eq!(&*reality.server_name, "www.microsoft.com");
        assert_eq!(
            reality.short_id,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn an_xhttp_link_is_read_back_as_xhttp_over_reality_with_the_same_path() {
        let link = vless_xhttp_reality(
            "203.0.113.7",
            8443,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "www.microsoft.com",
            "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
            "0123456789abcdef",
            "/a1b2c3d4",
            "My server / XHTTP",
        );
        let parsed = zero_config::parse_link(&link).expect("the apps read it");
        let OutboundProtocol::Vless(vless) = &parsed.outbound.protocol else {
            panic!("expected vless");
        };
        assert_eq!(vless.flow, zero_config::Flow::None);
        assert!(matches!(
            parsed.outbound.stream.security,
            Security::Reality(_)
        ));
        let zero_config::Transport::Xhttp(x) = &parsed.outbound.stream.transport else {
            panic!("expected xhttp, got {:?}", parsed.outbound.stream.transport);
        };
        assert_eq!(&*x.path, "/a1b2c3d4");
    }

    #[test]
    fn a_zerov1_link_is_read_back_as_zerov1_over_reality_with_the_users_uuid_bytes() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let (_, server_public) = zero_protocol::tide::generate_keypair();
        let server_key = zero_protocol::tide::encode_key(&server_public);
        let link = zerov1_reality(
            "203.0.113.7",
            2083,
            uuid,
            &server_key,
            "/static/9f8e7d6c5b4a",
            "www.microsoft.com",
            "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
            "0123456789abcdef",
            "My server / ZeroV1",
        );
        let parsed = zero_config::parse_link(&link).expect("the apps read it");
        let OutboundProtocol::Tide(tide) = &parsed.outbound.protocol else {
            panic!("expected zerov1, got {link}");
        };
        assert_eq!(&*tide.path, "/static/9f8e7d6c5b4a");
        assert_eq!(tide.port, 2083);
        assert_eq!(tide.server_key, server_public);
        let uuid_bytes: [u8; 16] = hex::decode(uuid.replace('-', ""))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            tide.user, uuid_bytes,
            "the same sixteen bytes as the VLESS id"
        );
        let Security::Reality(reality) = &parsed.outbound.stream.security else {
            panic!("expected REALITY");
        };
        assert_eq!(&*reality.server_name, "www.microsoft.com");
        assert_eq!(
            reality.short_id,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(zerov1_user_id("not a uuid"), None);
    }

    fn masterdns_service() -> crate::record::MasterDns {
        crate::record::MasterDns {
            domain: "t.example.com".into(),
            ns_host: "ns.example.com".into(),
            method: 5,
            key: "0123456789abcdef0123456789abcdef".into(),
            release: "v1".into(),
        }
    }

    #[test]
    fn a_masterdns_link_is_read_back_with_the_server_first_then_the_public_resolvers() {
        let link = masterdns("203.0.113.7", &masterdns_service(), "My server");
        let parsed = zero_config::parse_link(&link).expect("the apps read it");
        assert_eq!(parsed.remark, "My server");
        let OutboundProtocol::MasterDns(m) = &parsed.outbound.protocol else {
            panic!("expected masterdns, got {:?}", parsed.outbound.protocol);
        };
        assert_eq!(&*m.domain, "t.example.com");
        assert_eq!(&*m.key, "0123456789abcdef0123456789abcdef");
        assert_eq!(m.method, 5);
        let resolvers: Vec<String> = m.resolvers.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            resolvers,
            [
                "203.0.113.7:53",
                "8.8.8.8:53",
                "8.8.4.4:53",
                "1.1.1.1:53",
                "9.9.9.9:53"
            ]
        );
    }

    #[test]
    fn a_server_typed_as_a_name_is_not_used_as_a_resolver() {
        let link = masterdns("vps.example.com", &masterdns_service(), "n");
        let OutboundProtocol::MasterDns(m) =
            zero_config::parse_link(&link).unwrap().outbound.protocol
        else {
            panic!("expected masterdns");
        };
        assert_eq!(m.resolvers.len(), 4, "only the public resolvers");
    }

    #[test]
    fn an_ipv6_server_is_bracketed_in_the_masterdns_link() {
        let link = masterdns("2001:db8::7", &masterdns_service(), "v6");
        let OutboundProtocol::MasterDns(m) =
            zero_config::parse_link(&link).unwrap().outbound.protocol
        else {
            panic!("expected masterdns");
        };
        assert_eq!(m.resolvers[0].to_string(), "[2001:db8::7]:53");
    }

    #[test]
    fn an_ipv6_server_gets_brackets() {
        let link = vless_reality(
            "2001:db8::7",
            443,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "a.example",
            "JZoEjtfm1Zv3zGd2nGJmGCVZU8EbIn0Wg2EvrQ3VXTA",
            "01",
            "v6",
        );
        assert!(link.contains("@[2001:db8::7]:443?"), "{link}");
        zero_config::parse_link(&link).expect("parses");
    }
}
