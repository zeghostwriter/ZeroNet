# Fuzz targets

Coverage-guided fuzzing for the untrusted-input surfaces, built on
`cargo-fuzz` + libFuzzer. These are a separate package (own `[workspace]`)
because they need a nightly toolchain and sanitizer flags that must not leak
into the main build.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run <target> -- -max_total_time=60
```

## Targets

| Target | Surface | Invariant |
| --- | --- | --- |
| `parse_config_array` | JSON config / subscription body → compiled generation | parse+compile never panics; malformed input returns `Err` |
| `parse_link` | a single `vless://` / `vmess://` / `ss://` / … share link | never panics; malformed link returns `Err` |
| `parse_subscription` | base64 multi-line subscription blob | never panics; per-line results returned |
| `shadowsocks2022_header` | SIP022 PSK base64 decode + method parse | never panics or indexes OOB; bad key returns `Err` |
| `tls13_record_header` | a TLS 1.3 record header off the wire | never panics; a returned length is within `MAX_CIPHERTEXT` |
| `tun_ip_packet` | an IPv4/IPv6 TUN datagram | never panics; the payload plus both header lengths fit the input |
| `ws_frame_decode` | WebSocket frames | never panics; an incomplete frame is not consumed; a payload is within the frame limit |
| `xhttp_padding` | XHTTP request padding | never panics or fails to terminate; the result is header-safe ASCII |

A corpus accumulates under `fuzz/corpus/<target>/`; findings, if any, land in
`fuzz/artifacts/<target>/`.
