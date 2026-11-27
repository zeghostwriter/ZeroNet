#![no_main]
//! `parse_ip_packet` reads the IPv4 `ihl`/`total` and the IPv6 extension-chain
//! offsets out of the packet it is given, so the payload it returns has to stay
//! within those bytes: an IP header plus a transport header is overhead that
//! cannot be part of the payload.

use libfuzzer_sys::fuzz_target;
use zero_tun::parse_ip_packet;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = parse_ip_packet(data) else {
        return;
    };
    // A parse implies a non-empty packet with a version of 4 or 6, so `data[0]`
    // and the fixed header sizes are both readable here.
    let ip_header = if data[0] >> 4 == 6 { 40 } else { 20 };
    assert!(
        packet.payload.len() + ip_header + 8 <= data.len(),
        "{} byte payload in a {} byte packet: a header length was taken on trust",
        packet.payload.len(),
        data.len()
    );
});
