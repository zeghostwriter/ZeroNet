pub mod cache;
pub mod resolver;

pub use cache::{CompactDnsEntry, DnsCache, DnsCacheKey, DnsFlags};
pub use resolver::{build_dns_query, parse_dns_a_response, parse_dns_txt_response, FastResolver};
