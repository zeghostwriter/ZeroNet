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

A corpus accumulates under `fuzz/corpus/<target>/`; findings, if any, land in
`fuzz/artifacts/<target>/`.
