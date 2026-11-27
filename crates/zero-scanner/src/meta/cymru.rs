use crate::dns::FastResolver;
use std::net::IpAddr;

pub async fn lookup_cymru_asn(resolver: &FastResolver, ip: IpAddr) -> Option<(u32, String)> {
    let query_domain = match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", d, c, b, a)
        }
        IpAddr::V6(v6) => {
            let mut parts = Vec::new();
            for octet in v6.octets().iter().rev() {
                parts.push(format!("{:x}", octet & 0x0F));
                parts.push(format!("{:x}", (octet >> 4) & 0x0F));
            }
            format!("{}.origin6.asn.cymru.com", parts.join("."))
        }
    };

    let txt = resolver.resolve_txt(&query_domain).await.ok()?;
    // Format: "13335 | 104.16.0.0/12 | US | arin | 2014-03-28"
    let parts: Vec<&str> = txt.split('|').map(|s| s.trim()).collect();
    if parts.len() >= 3 {
        let asn = parts[0].parse::<u32>().ok()?;
        let cc = parts[2].to_string();
        Some((asn, cc))
    } else {
        None
    }
}
