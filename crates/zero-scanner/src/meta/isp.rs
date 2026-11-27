use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::OnceLock;

// The Iranian-ISP table, zstd-compressed into OUT_DIR by build.rs (as text it
// is the largest single piece of read-only data in the shipped binary). It is
// inflated and parsed once, lazily, the first time a lookup needs it; a run
// that never scans never pays for it.
const RAW_IR_ISPS_ZSTD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ir_isps.tsv.zst"));

#[derive(Debug, Clone)]
pub struct IrRange {
    pub start: u32,
    pub end: u32,
    // Owned, so the decompressed table text is freed as soon as parsing is
    // done rather than kept resident for the whole process just to be pointed
    // into. The names stay valid because `IR_DATABASE` itself never drops.
    pub isp: Box<str>,
}

static IR_DATABASE: OnceLock<Vec<IrRange>> = OnceLock::new();

fn init_ir_db() -> Vec<IrRange> {
    let bytes =
        zstd::decode_all(RAW_IR_ISPS_ZSTD).expect("embedded ir_isps.tsv.zst must decompress");
    let text = String::from_utf8(bytes).expect("embedded ir_isps.tsv must be UTF-8");
    let mut ranges = Vec::with_capacity(10000);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() >= 3 {
            if let (Ok(from_ip), Ok(to_ip)) =
                (Ipv4Addr::from_str(parts[0]), Ipv4Addr::from_str(parts[1]))
            {
                ranges.push(IrRange {
                    start: u32::from(from_ip),
                    end: u32::from(to_ip),
                    isp: parts[2].into(),
                });
            }
        }
    }
    ranges.sort_by_key(|r| r.start);
    ranges
}

pub fn lookup_iranian_isp(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let u = u32::from(v4);
            let db = IR_DATABASE.get_or_init(init_ir_db);
            let idx = match db.binary_search_by(|r| {
                if u < r.start {
                    std::cmp::Ordering::Greater
                } else if u > r.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                Ok(i) => i,
                Err(_) => return None,
            };
            Some(&db[idx].isp)
        }
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_ir_isp() {
        // 2.144.0.1 is Iran Cell
        let isp = lookup_iranian_isp(IpAddr::V4(Ipv4Addr::new(2, 144, 0, 1)));
        assert!(isp.is_some());
        assert!(isp.unwrap().contains("Iran Cell"));
    }

    #[test]
    fn embedded_table_decompresses_and_parses() {
        // Guards the build-time zstd blob and the inflate path: a truncated or
        // mis-encoded table would parse to far fewer ranges, or none.
        let db = IR_DATABASE.get_or_init(init_ir_db);
        assert!(
            db.len() > 9000,
            "expected the full IR table, got {} ranges",
            db.len()
        );
        // The binary search in `lookup_iranian_isp` only holds if the table is
        // sorted by start, which `init_ir_db` must guarantee after inflating.
        assert!(
            db.windows(2).all(|w| w[0].start <= w[1].start),
            "IR table is not sorted by range start"
        );
    }

    #[test]
    fn first_range_resolves_after_inflating() {
        // The first row of data/ir_isps.tsv: 2.57.3.0 .. 2.57.3.255.
        let isp = lookup_iranian_isp(IpAddr::V4(Ipv4Addr::new(2, 57, 3, 7)));
        assert!(isp.is_some_and(|s| s.contains("Mahan")), "{isp:?}");
    }

    #[test]
    fn ipv6_is_never_iranian() {
        assert_eq!(
            lookup_iranian_isp(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            None
        );
    }
}
