//! Bounded, non-consuming protocol sniffing for inbound routing.
//!
//! The inspector only looks at bytes the caller has already buffered. It has
//! no DNS or socket side effects and deliberately returns `None` for malformed
//! or incomplete messages; callers can then replay the same bytes into the
//! actual protocol stream.

use std::sync::Arc;

use crate::Sniffed;

const MAX_HOST: usize = 253;

/// Inspect a bounded prefix for HTTP `Host` or TLS ClientHello SNI.
pub fn inspect(bytes: &[u8], allow_http: bool, allow_tls: bool) -> Sniffed {
    if allow_tls && bytes.first() == Some(&0x16) {
        if let Some(domain) = tls_server_name(bytes) {
            return Sniffed {
                domain: Some(Arc::from(domain)),
                protocol: Some("tls"),
            };
        }
    }
    if allow_http {
        if let Some(domain) = http_host(bytes) {
            return Sniffed {
                domain: Some(Arc::from(domain)),
                protocol: Some("http"),
            };
        }
    }
    Sniffed::default()
}

fn http_host(bytes: &[u8]) -> Option<String> {
    let head_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&bytes[..head_end]).ok()?;
    let request = head.lines().next()?.split_whitespace().next()?;
    if request.is_empty() {
        return None;
    }
    let host = head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("host").then_some(value.trim())
    })?;
    normalize_host(host)
}

fn tls_server_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if record_len + 5 > bytes.len() || record_len < 4 {
        return None;
    }
    let message = &bytes[5..5 + record_len];
    if message[0] != 1 {
        return None;
    }
    let hello_len =
        ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
    if hello_len + 4 > message.len() || hello_len < 34 {
        return None;
    }
    let hello = &message[4..4 + hello_len];
    let mut at = 34;
    let session_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + session_len)?;
    let suites_len = u16::from_be_bytes([*hello.get(at)?, *hello.get(at + 1)?]) as usize;
    at = at.checked_add(2 + suites_len)?;
    let compression_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + compression_len)?;
    let extensions_len = u16::from_be_bytes([*hello.get(at)?, *hello.get(at + 1)?]) as usize;
    at += 2;
    let end = at.checked_add(extensions_len)?;
    if end > hello.len() {
        return None;
    }
    while at + 4 <= end {
        let extension = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let length = u16::from_be_bytes([hello[at + 2], hello[at + 3]]) as usize;
        at += 4;
        let next = at.checked_add(length)?;
        if next > end {
            return None;
        }
        if extension == 0 {
            let names = &hello[at..next];
            if names.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([names[0], names[1]]) as usize;
            if list_len + 2 > names.len() {
                return None;
            }
            let mut name_at = 2;
            while name_at + 3 <= list_len + 2 {
                let kind = names[name_at];
                let name_len =
                    u16::from_be_bytes([names[name_at + 1], names[name_at + 2]]) as usize;
                name_at += 3;
                let name_end = name_at.checked_add(name_len)?;
                if name_end > list_len + 2 {
                    return None;
                }
                if kind == 0 {
                    let name = std::str::from_utf8(&names[name_at..name_end]).ok()?;
                    return normalize_host(name);
                }
                name_at = name_end;
            }
            return None;
        }
        at = next;
    }
    None
}

fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim();
    let host = if let Some(rest) = value.strip_prefix('[') {
        // `[v6]` or `[v6]:port`. Splitting on the first ':' first, as this
        // used to, turned every bracketed IPv6 Host header into "[".
        let (literal, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        literal
    } else {
        match value.rsplit_once(':') {
            // `name:port`. More than one colon without brackets is a bare
            // IPv6 literal, which is kept whole.
            Some((name, port)) if !name.contains(':') => {
                // RFC 3986 allows an empty port (`host:`).
                if !port.is_empty() && !is_port(port) {
                    return None;
                }
                name
            }
            _ => value,
        }
    };
    let host = host.trim_end_matches('.');
    if host.is_empty()
        || host.len() > MAX_HOST
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn is_port(value: &str) -> bool {
    !value.is_empty() && value.len() <= 5 && value.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_headers_with_ports_and_ipv6_literals_normalize_correctly() {
        assert_eq!(
            normalize_host("Example.COM:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_host("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_host("[2001:DB8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(normalize_host("[::1]").as_deref(), Some("::1"));
        assert_eq!(
            normalize_host("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(normalize_host("[::1"), None);
        assert_eq!(normalize_host("[::1]x"), None);
        assert_eq!(normalize_host("[]:443"), None);
    }

    #[test]
    fn inspects_http_host_without_accepting_arbitrary_text() {
        let sniffed = inspect(
            b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n",
            true,
            false,
        );
        assert_eq!(sniffed.protocol, Some("http"));
        assert_eq!(sniffed.domain.as_deref(), Some("example.com"));
        assert!(inspect(b"not a request", true, false).domain.is_none());
    }

    #[test]
    fn inspects_tls_clienthello_sni() {
        let extensions = [
            0, 0, 0, 16, 0, 14, 0, 0, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm',
        ];
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(hello.len() as u16 + 4).to_be_bytes());
        record.extend_from_slice(&[
            1,
            (hello.len() >> 16) as u8,
            (hello.len() >> 8) as u8,
            hello.len() as u8,
        ]);
        record.extend_from_slice(&hello);
        let sniffed = inspect(&record, false, true);
        assert_eq!(sniffed.protocol, Some("tls"));
        assert_eq!(sniffed.domain.as_deref(), Some("example.com"));
    }
}
