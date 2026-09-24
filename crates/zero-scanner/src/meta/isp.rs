use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::OnceLock;

const RAW_IR_ISPS: &str = include_str!("../../data/ir_isps.tsv");

#[derive(Debug, Clone, Copy)]
pub struct IrRange {
    pub start: u32,
    pub end: u32,
    pub isp: &'static str,
}

static IR_DATABASE: OnceLock<Vec<IrRange>> = OnceLock::new();

fn init_ir_db() -> Vec<IrRange> {
    let mut ranges = Vec::with_capacity(10000);
    for line in RAW_IR_ISPS.lines() {
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
                    isp: parts[2],
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
            Some(db[idx].isp)
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
}
