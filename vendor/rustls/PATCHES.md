# Local patch to the shaped-rustls fork of rustls 0.23.40

This directory is the `rustls` crate of the shaping fork
(https://github.com/aimalygin/shaped-rustls, revision
`3a131beaef0183b0cb61e5a9070a703b6be39ed3`, MPL-2.0 for the fork's own files,
Apache-2.0 OR ISC OR MIT for rustls), copied without its tests, benchmarks and
test data, and wired in through `[patch.crates-io]` in the workspace
`Cargo.toml` (and in `fuzz/Cargo.toml`, which is a workspace of its own).
The manifest is the fork's with the workspace dependencies written out.

Two changes:

1. **`ClientHelloPlan::with_legacy_version(u16)`.** The `legacy_version` field
   of the ClientHello is always written as 0x0303. With the setting, the plan
   writes another value there (`client/client_hello.rs`, read in
   `client/hs.rs` where the hello payload is built). The field is part of
   the transcript, so it is settled before the hello is hashed, sealed or
   written, and the handshake completes as usual. Servers read the field as
   "TLS 1.2 or later" (the real version is in `supported_versions`); a filter
   that picks hellos out by it does not recognise 0x0304.

2. **The client answers ALPS.** The shaped hello of the Chrome profiles offers
   the `application_settings` extension (ALPS, code points 0x4469 and 0x44cd).
   A server that takes it up echoes the extension in its `EncryptedExtensions`
   and then expects the client's own `EncryptedExtensions` right after the
   server's `Finished`; BoringSSL-based servers (Google's front ends, for one)
   end the connection with `unexpected_message` when it does not come. The
   fork offered the extension and never answered it. `client/tls13.rs` now
   notes in `ClientConnectionData::alps_accepted` that the server took it up
   and sends an `EncryptedExtensions` carrying the same extension with no
   settings, ahead of the client's own Finished (so it is part of the
   transcript). A server that did not take it up sees no change.

Everything else is the fork as pinned. To move to a newer revision, copy its
`rustls/` directory over this one and apply the change above again.
