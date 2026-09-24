use super::cidr::SubnetV4;
use std::net::Ipv4Addr;

pub const DEFAULT_NEIGHBOR_RADIUS: u32 = 32;
pub const DEFAULT_NEIGHBOR_PER_HIT: usize = 12;

pub fn neighbors_around(
    ip: Ipv4Addr,
    subnets: &[SubnetV4],
    radius: u32,
    limit: usize,
) -> Vec<Ipv4Addr> {
    if limit == 0 || radius == 0 || subnets.is_empty() {
        return Vec::new();
    }

    let base = u32::from(ip);
    let mut out = Vec::with_capacity(limit);

    for delta in 1..=radius {
        for candidate in [base.checked_add(delta), base.checked_sub(delta)] {
            let Some(candidate_u32) = candidate else {
                continue;
            };

            let in_any = subnets.iter().any(|sub| sub.contains(candidate_u32));
            if in_any {
                out.push(Ipv4Addr::from(candidate_u32));
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbors() {
        let subnets = vec![SubnetV4::parse("104.16.0.0/16").unwrap()];
        let base = Ipv4Addr::new(104, 16, 5, 10);
        let n = neighbors_around(base, &subnets, 4, 8);
        assert!(!n.is_empty());
        assert!(n.contains(&Ipv4Addr::new(104, 16, 5, 11)));
        assert!(n.contains(&Ipv4Addr::new(104, 16, 5, 9)));
        assert!(!n.contains(&base));
    }
}
