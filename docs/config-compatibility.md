# Known divergences from Xray

Everything here is a place where Zray's behaviour is deliberately, knowably
different from the pinned Xray oracle (`v26.7.28`, commit `5ca6f4b`). Each entry
names the test that holds the divergence in place, because an undocumented
divergence and an unnoticed regression look identical from the outside.

## ClientHello cipher-suite list (ordinary TLS only)

**What differs.** uTLS emits a browser's full cipher-suite list, including the
TLS 1.2 ECDHE and RSA/CBC suites a TLS 1.3 connection never uses. Zray's
ordinary-TLS path emits the same list, in the same order, filtered to the suites
rustls implements — roughly half the length.

**Why.** The pinned `shaped-rustls` revision validates the ClientHello plan
against the configured crypto provider and refuses to advertise a suite it could
not negotiate. There is no shape-only advertisement on that path.

**Consequence.** The list length and tail are visible to a classifier comparing
against a real browser. This is the cost PLAN-01 Decision 2 anticipated in
depending on someone else's TLS state machine.

**Not affected: REALITY.** REALITY runs on the TLS 1.3 stack this project owns
(`zero-security/src/tls13/`), which emits the legacy tail verbatim as shape.
That is the path where indistinguishability is load-bearing.

**Pinned by.** `zero-runtime/tests/fingerprint_oracle.rs`, which asserts the
exact relationship (uTLS's list, uTLS's order, filtered to rustls-implemented
suites) rather than skipping the field. If the fork gains shape-only
advertisement, the filter comes out and the assertion tightens to equality.

## Fingerprint profiles that cannot carry REALITY

Profiles with no X25519 key share — the Android/okhttp shape, the 360 shapes,
several archived Chrome/Firefox/iOS versions — cannot carry a REALITY tag,
because REALITY derives its authentication key from the hello's own ephemeral
X25519 secret. These are refused at config-compile time rather than at connect
time, since a REALITY failure is a *silent* relay to the decoy site.

**Pinned by.** `zero-security/src/reality_compat.rs` and the cross-crate parity
test `zero-runtime/tests/reality_compatibility.rs`, which compares the config
compiler's independent copy of the rule against the wire corpus for every
profile in it.

## ECH GREASE payload length

uTLS draws the ECH GREASE payload length from four candidates per connection;
Zray pins the first. Recorded in `utls_profiles.rs` alongside the constant.
Unpinning it requires a fixture per candidate so the shape guard can accept any
of the four.

## Encrypted resolvers behind a private CA

`dns.certificates` accepts the same `usage: "verify"` entries an outbound's
`tlsSettings.certificates` does, and adds them to the trust store every
encrypted resolver transport shares (DoT, DoH, DoH3 and DoQ).

Xray has no equivalent: its DoQ nameserver builds a TLS config with no way to
name a trust anchor, so reaching a self-hosted resolver there means changing
the system store or the process environment. That is a divergence in Zray's
favour and it is deliberate — the alternative operators reach for is disabling
verification, and an anti-sanction or enterprise resolver behind a private CA
is a normal thing to have (PLAN-02 §3.5).

Anchors are additive: naming one never removes the public roots, and never
makes verification optional. An unusable anchor is logged and skipped rather
than taking DNS down for a typo.

**Pinned by.** `zero-runtime/tests/dns_oracle.rs`, which reaches a DoQ server
presenting the test CA, and would fail closed without the anchor.
