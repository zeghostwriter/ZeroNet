# tls13-core — Minimal TLS 1.3 Client Spec (REALITY substrate)

Status: research spec (read-only analysis, no code written)
Purpose: implement `tls13-core`, a minimal TLS 1.3 client stack sufficient to (a) emit a
byte-controlled ClientHello (REALITY/uTLS style) and (b) complete the handshake + record
layer against a normal TLS 1.3 server. Scoped to the REALITY substrate only (PLAN-01
Decision 2): no PSK/resumption, no client auth, no renegotiation, no 0-RTT.

Primary source: the working minimal stack in
`/home/parsa/Desktop/Projects/Zray-Stuff/Zray-Core/reference/shoes/src/reality/` (Rust).
Normative cross-check: Go's TLS 1.3 fork in
`/home/parsa/Desktop/Projects/Zray-Stuff/Zray-Core/reference/REALITY/` (this is what Xray
REALITY servers run).

Citations below use:
- `shoes/<file>:<line>` = `reference/shoes/src/reality/<file>`
- `go/<file>:<line>` = `reference/REALITY/<file>`

---

## 1. HANDSHAKE MESSAGE SEQUENCE (client-side state machine)

### 1.1 The wire sequence for a full (non-PSK, no-HRR) TLS 1.3 handshake

```
Client                                            Server
------                                            ------
ClientHello                    -->  [record type 0x16, cleartext, seq n/a]
              [optional dummy ChangeCipherSpec record 0x14 either direction; may be ignored]
                               <--  ServerHello            [record 0x16, cleartext]
                               <--  {EncryptedExtensions*} [record(s) 0x17 outer, inner 0x16,
                               <--   {Certificate*}         encrypted under server_handshake keys]
                               <--   {CertificateVerify*}
                               <--   {Finished}
[client switches WRITE key to app secrets here]     (after verifying server Finished)
Finished                       -->  [one or more 0x17 records, inner 0x16, encrypted under
                                     client_handshake keys; client switches WRITE key to
                                     app secrets immediately after sending it — go/handshake_client_tls13.go:819]
[client switches READ key to app secrets right after verifying server Finished —
 go/handshake_client_tls13.go:712-714 — so server app data may arrive before client
 Finished is sent]
                               <--  [NewSessionTicket, type 4]    (optional, app keys)
                               <--  [KeyUpdate, type 24]          (optional, app keys)
<====== Application Data both directions under app keys (outer 0x17, inner 0x17) =====>
```

- Go client flow (authoritative order): `handshake()` at
  `go/handshake_client_tls13.go:46-160`: checkServerHelloOrHRR → transcript(CH) →
  transcript(SH) (`:119-121`) → processServerHello → sendDummyChangeCipherSpec (line 127; middlebox
  compat — see §3.7) → establishHandshakeKeys → readServerParameters (EncryptedExtensions)
  → readServerCertificate → readServerFinished → sendClientFinished.
- The four encrypted messages (EncryptedExtensions, Certificate, CertificateVerify,
  Finished) are handshake types 8, 11, 15, 20 (`shoes/common.rs:20-24`); they arrive as
  **one or more** `0x17` records whose decrypted inner plaintext is a *stream* of
  handshake messages `type(1) || len_u24(3) || body`. A message may straddle record
  boundaries; the receiver must accumulate plaintext across records and parse out of the
  accumulated buffer (`shoes/reality_client_connection.rs:592-647`).

### 1.2 shoes' exact client state machine

`enum HandshakeState { AwaitingServerHello, ProcessingHandshake, Complete }`
(`shoes/reality_client_connection.rs:65-90`):

1. **Construction** — `RealityClientConnection::new` immediately builds and buffers the
   ClientHello record into the outgoing ciphertext buffer (`:126-153`, `:156-266`).
   State = `AwaitingServerHello { client_hello_bytes, client_private_key, auth_key }`.
   Note `client_hello_bytes` holds the **wire ClientHello** (with the REALITY-encrypted
   SessionId substituted in) — this exact byte string is what feeds the transcript
   (`:244-254`, test at `:1022-1054`).
2. **AwaitingServerHello** — read one full record (header `type,0x0303,len_u16`), parse
   ServerHello: extract server X25519 key_share and selected cipher suite
   (`shoes/reality_util.rs:278-396`), compute `Hash(CH || SH)` (suite's hash),
   do ECDH, derive handshake secrets + master secret (§2), transition to
   `ProcessingHandshake` with an accumulated transcript byte buffer
   (`shoes/reality_client_connection.rs:341-466`).
3. **ProcessingHandshake** — loop over incoming `0x17` records: skip any dummy
   `ChangeCipherSpec` (0x14) records (`:529-537`), require outer type 0x17 otherwise
   (`:539-547`), decrypt each with `server_hs_key/iv` at the per-key sequence counter
   starting at 0 (`:574-582`), append plaintext to `accumulated_plaintext` (hard cap
   `MAX_HANDSHAKE_PLAINTEXT = 4 * 16384` = 65536 bytes, matching Xray's limit,
   `:36-49`), and parse handshake messages out of the accumulation until **4 messages
   found** (`:592-647`):
   - on **Certificate** (type 11): extract first cert DER, verify
     `HMAC-SHA512(auth_key, ed25519_spki) == cert.signature_value`, extract the 32-byte
     Ed25519 public key (`:631-638`; `shoes/reality_client_verify.rs:91-201`),
   - on **CertificateVerify** (type 15): record its offset; after all 4 messages,
     verify Ed25519 sig over `Hash(transcript up to but not including CV)` with the
     RFC 8446 §4.4.3 context string (`:685-708`;
     `shoes/reality_client_verify.rs:288-320`),
   - on **Finished** (type 20): counted into the transcript. NOTE: shoes does **not**
     re-verify the server Finished `verify_data` HMAC (see §6.4).
   Then (`:717-781`): `handshake_hash = Hash(CH..serverFinished)`, compute client
   Finished verify_data from `client_handshake_traffic_secret`, encrypt it as a single
   handshake record under **client_hs_key with a fresh seq = 0**, queue to write buffer
   (`:734-751`); derive app secrets (§2), cache `AeadKey`s for both directions, **reset
   `read_seq = 0` and `write_seq = 0`**, transition to `Complete` (`:758-777`).
4. **Complete** — `process_application_data` decrypts `0x17` records in place with app
   read keys; handles inner content types app-data / alert (`:786-862`).

Handshake is "done" from the client's perspective once server Finished has been decrypted
and the client Finished queued: at that point the client may both send app data (its write
key switched after Finished) and receive app data (read key switched after server
Finished). shoes exposes this via `is_handshaking()` (`:923-925`) and gates encryption of
user plaintext on `Complete` in `write_tls` (`:884-915`).

### 1.3 What the client MUST process vs MAY skip (REALITY scope)

MUST process:
- ServerHello (key_share group x25519 0x001d, selected cipher suite).
- EncryptedExtensions — content can be ignored (shoes never inspects its body; it is
  constructed server-side as "empty extensions", `shoes/reality_tls13_messages.rs:94-116`)
  but the message **bytes must enter the transcript**.
- Certificate — REALITY replaces X.509 CA validation with the HMAC check (§6.5); the
  fields consumed from the message are: certificate_request_context (skip), first entry's
  cert_data DER (`shoes/reality_client_verify.rs:23-82`), then from the DER: the
  SubjectPublicKeyInfo raw key bytes (must be 32-byte Ed25519) and the signatureValue
  bytes (must be 64-byte HMAC-SHA512 tag).
- CertificateVerify — algorithm must be Ed25519 (0x0807), signature exactly 64 bytes
  (`shoes/reality_client_verify.rs:214-275`).
- Finished — must enter the transcript; RFC-correct clients should also verify its HMAC
  (§6.4).

MAY skip (and shoes' behavior):
- ChangeCipherSpec (0x14) records: skipped (`:529-537`).
- NewSessionTicket / KeyUpdate post-handshake: **shoes does NOT handle them — a
  post-handshake record with inner content type 0x16 hits `unreachable!()` and panics**
  (`:849-855`). This is tolerable against Xray REALITY servers (Go fork only sends
  session tickets when the ClientHello advertised `psk_key_exchange_modes: psk_dhe_ke`,
  `go/handshake_server_tls13.go:1040-1052`; shoes' ClientHello does not, and Go never
  sends an unsolicited KeyUpdate — it only reacts to one, `go/conn.go:1400-1433`), but
  tls13-core MUST silently ignore post-handshake inner-type-0x16 records (or implement
  KeyUpdate, §6.2) to survive generic TLS servers.
- HelloRetryRequest: not supported. shoes would fail (no key_share of expected group in
  SH). Safe in the REALITY substrate: the ClientHello offers x25519 and Xray accepts it
  without HRR. tls13-core should return a clear error on HRR (SH random ==
  `helloRetryRequestRandom`, or missing key_share extension).

### 1.4 After server Finished — what the client sends

Exactly one handshake message: its own **Finished** (type 20, body = verify_data, §2.4),
encrypted under `client_handshake_traffic_secret`-derived keys, sequence number 0, in a
record with outer type 0x17 (`shoes/reality_client_connection.rs:740-751`). Nothing else
(no ChangeCipherSpec, no Certificate — client auth skipped; Go would call
sendClientCertificate which is a no-op without a cert, `go/handshake_client_tls13.go:734`).

---

## 2. KEY SCHEDULE (RFC 8446 §7.1, verified against Go fork + shoes)

All operations are keyed by the negotiated suite's HMAC hash: HMAC-SHA256 for 0x1301 and
0x1303, HMAC-SHA384 for 0x1302 (`shoes/reality_cipher_suite.rs:45-64`). `Hash` = the same
hash. `L` = hash output length (32 or 48).

### 2.1 Primitives (exact definitions)

**HKDF-Extract(salt, ikm)** = `HMAC(salt, ikm)` (`shoes/reality_tls13_keys.rs:124-132`).

**HKDF-Expand(prk, info, len)** — RFC 5869 T(1..n) loop with `HMAC(prk, T(n-1) || info || byte(n))`,
n ≤ 255 iterations (`shoes/reality_tls13_keys.rs:25-69`).

**HKDF-Expand-Label(secret, label, context, length)** — info is the DER-ish encoding:
```
uint16 length                      (2 bytes big-endian)
opaque label<7..255>               = "tls13 " ++ label   (1-byte length prefix)
opaque context<0..255>             (1-byte length prefix)
```
i.e. `info = u16be(length) || u8(6+|label|) || "tls13 " ++ label || u8(|context|) || context`
(`shoes/reality_tls13_keys.rs:72-110`; identical to Go `tls13.ExpandLabel`,
`go/tls13/tls13.go:20-41`).

**Derive-Secret(secret, label, transcriptHash)** =
`HKDF-Expand-Label(secret, label, transcriptHash, L)`
(`shoes/reality_tls13_keys.rs:113-121`; `go/tls13/tls13.go:51-56`).

### 2.2 The chain (no PSK — Early Secret has no PSK input)

Given `shared_secret` = raw 32-byte X25519 output and transcript hashes per §5:

```
early_secret          = HKDF-Extract(salt = 0^L,        ikm = 0^L)          # keys.rs:224-227
derived               = Derive-Secret(early_secret, "derived", Hash(""))     # keys.rs:229-237
handshake_secret      = HKDF-Extract(salt = derived,    ikm = shared_secret) # keys.rs:239-241

client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", Hash(CH..SH))
server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", Hash(CH..SH))
                                                                        # keys.rs:243-257

derived2              = Derive-Secret(handshake_secret, "derived", Hash("")) # keys.rs:259-268
master_secret         = HKDF-Extract(salt = derived2,   ikm = 0^L)           # keys.rs:270-271

# AFTER server Finished is in the transcript:
client_application_traffic_secret_0 = Derive-Secret(master_secret, "c ap traffic", Hash(CH..serverFinished))
server_application_traffic_secret_0 = Derive-Secret(master_secret, "s ap traffic", Hash(CH..serverFinished))
                                                                        # keys.rs:294-359
```

Exact label strings (verbatim): `"derived"`, `"c hs traffic"`, `"s hs traffic"`,
`"c ap traffic"`, `"s ap traffic"` — canonical label list at `go/tls13/tls13.go:58-68`.
Hash("") is the hash of the empty string (always compute it, don't use zero bytes).

Two-phase derivation is deliberate: handshake secrets need `Hash(CH..SH)`; app secrets
need `Hash(CH..serverFinished)`, so `master_secret` must be carried in state until server
Finished arrives (struct `Tls13HandshakeKeys`, `shoes/reality_tls13_keys.rs:14-21`).

Not needed for REALITY scope (listed for completeness): `"c e traffic"` (0-RTT),
`"e exp master"`, `"exp master"` (exporters, `go/tls13/tls13.go:148-176`), `"res master"`
(resumption), `"res binder"`; `"traffic upd"` for KeyUpdate
(`go/key_schedule.go:25-27`).

### 2.3 Traffic keys and IV from a traffic secret

```
key = HKDF-Expand-Label(traffic_secret, "key", "", key_len)   # 16 (AES-128) / 32 (AES-256, ChaCha20)
iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)
```
(`shoes/reality_tls13_keys.rs:142-172`; `go/key_schedule.go:30-34`).

### 2.4 Finished verify_data (RFC 8446 §4.4.4)

```
finished_key = HKDF-Expand-Label(base_key, "finished", "", L)
verify_data  = HMAC(finished_key, transcript_hash)
```
(`shoes/reality_tls13_keys.rs:361-383`; `go/key_schedule.go:39-44`).
- Server Finished: `base_key = server_handshake_traffic_secret`,
  `transcript_hash = Hash(CH..CertificateVerify)` (i.e. transcript *before* the Finished
  message itself).
- Client Finished: `base_key = client_handshake_traffic_secret`,
  `transcript_hash = Hash(CH..serverFinished)` (shoes uses the same accumulated hash,
  `shoes/reality_client_connection.rs:717-740`).

### 2.5 Key/IV/secret lengths per suite

| suite | id | AEAD | key_len | nonce | hash | HMAC |
|---|---|---|---|---|---|---|
| TLS_AES_128_GCM_SHA256 | 0x1301 | AES-128-GCM | 16 | 12 | SHA-256 (32) | HMAC-SHA256 |
| TLS_AES_256_GCM_SHA384 | 0x1302 | AES-256-GCM | 32 | 12 | SHA-384 (48) | HMAC-SHA384 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | ChaCha20-Poly1305 | 32 | 12 | SHA-256 (32) | HMAC-SHA256 |

(`shoes/reality_cipher_suite.rs:45-64,110-124`.) **The hash choice is per selected suite**:
if the server picks 0x1302, the *entire* schedule (transcript hash included) is SHA-384.
shoes selects the digest algorithm from the ServerHello's suite before computing any
transcript hash (`shoes/reality_client_connection.rs:381-409`).

---

## 3. RECORD LAYER

### 3.1 Framing

Record header, 5 bytes (`shoes/common.rs:61`):
```
content_type (1) | legacy_version = 0x03 0x03 (2) | length u16 big-endian (2)
```
Content types (`shoes/common.rs:6-9`): CCS 0x14, alert 0x15, handshake 0x16,
application_data 0x17.

- Cleartext ClientHello/ServerHello: outer type **0x16**.
- Everything encrypted (handshake messages, alerts, app data): outer type **0x17**
  always — `make_record_header` hardcodes it (`shoes/reality_records.rs:335-343`).
- Size limits (TLS 1.3, stricter than 1.2 — exceeding them causes "record overflow" in
  uTLS peers): plaintext ≤ **16384** (`MAX_TLS_PLAINTEXT_LEN`, `shoes/common.rs:58`),
  ciphertext ≤ **16640** = 16384 + 256 (`MAX_TLS_CIPHERTEXT_LEN`, `shoes/common.rs:43`;
  rationale comment `:27-41`). The header length field counts ciphertext+tag (+inner
  type +padding), never plaintext.
- Fragmentation: any buffer > 16384 bytes is split into ≤16384-byte records, one AEAD
  seal each, sequence increments per record (`shoes/reality_records.rs:250-261`).

### 3.2 Inner plaintext (TLSInnerPlaintext)

```
inner = content || inner_content_type || zero_padding*
```
The real content type byte is appended AFTER the payload, before encryption
(`shoes/reality_records.rs:149-186`); on decrypt, strip trailing zeros (padding), read the
last non-zero byte as the content type, validate it ∈ {0x16, 0x17, 0x15}
(`shoes/reality_records.rs:306-329`). Padding is optional (RFC 8446 §5.4); the content
type MUST be the last non-zero byte. shoes' sender pads only for REALITY record-size
matching (`encrypt_record_with_padding`, `shoes/reality_records.rs:193-246`), computing
`target_inner = target_total − 5 − 16`. Note: an all-zeros decrypted plaintext is an error
(`:312-314`). (ChaCha20 records: send unpadded; padding is a length-hiding tool for
AES-GCM block alignment.)

### 3.3 Nonce construction (per record)

```
nonce = static_write_iv (12 bytes)
nonce[4..12] ^= u64_be(sequence_number)     # XOR into the LAST 8 bytes
```
(`shoes/reality_aead.rs:118-137`). The 64-bit sequence number is written big-endian and
XORed at offset 4 of the 12-byte nonce.

### 3.4 AAD

The AAD is exactly the 5-byte record header *with the ciphertext length* (plaintext len +
1 inner-type byte + 16 tag [+padding]):
`[0x17, 0x03, 0x03, len_hi, len_lo]` (`shoes/reality_aead.rs:152-159`,
`shoes/reality_records.rs:171`).

### 3.5 Sequence numbers

One u64 per direction **per key epoch**; starts at 0 whenever a new key is installed,
increments by 1 per record; exhaustion (2^64-1) is fatal
(`shoes/reality_records.rs:175-178,301-304`; reset at app-key install:
`shoes/reality_client_connection.rs:774-775`). During the handshake: server-encrypts 0..n
on server hs keys; client-encrypts starting at 0 on client hs keys for its Finished.

### 3.6 Alerts

Alert plaintext = `level(1) || description(1)`. `close_notify` = `[0x01, 0x00]`
(warning level, desc 0) — `shoes/common.rs:12-13`. Receive rules
(`shoes/reality_client_connection.rs:818-847`): desc 0 → clean EOF, stop processing
further data (RFC 8446); level != warning → fatal, connection aborted; other warnings →
log and continue. Sending close_notify after the handshake encrypts `[01 00]` as an inner
alert record under app write keys (`shoes/reality_records.rs:137-140`,
`shoes/reality_client_connection.rs:957-985`). Cleartext alerts may arrive before keys are
installed (pre-ServerHello failures).

### 3.7 ChangeCipherSpec / middlebox compatibility

Go's client sends one dummy CCS record (5 bytes `14 03 03 00 01 01`) after ServerHello
(`go/handshake_client_tls13.go:218-231`, sent at `:79`/`:127`), but Go's *server* does not
require it. shoes does not send it, and Xray REALITY (Go fork server) works fine without
it. Receivers MUST skip any 0x14 record during handshake (`:529-537`). tls13-core can
optionally emit the dummy CCS after ServerHello for middlebox compat; it is not required
for interoperability with the REALITY server.

### 3.8 AEADs required

All three RFC 8446 suites, as above (§2.5). Tag is always 16 bytes, appended to the
buffer on seal (`aws-lc-rs seal_in_place_append_tag`, `shoes/reality_aead.rs:44-60`).
A Chrome-shaped ClientHello offers 0x1301, 0x1302, 0x1303; OpenSSL-nginx servers usually
pick **0x1301** (first server preference), but the implementation must handle all three,
including the SHA-384 transcript/HMAC of 0x1302.

---

## 4. CLIENTHELLO BYTE LAYOUT

### 4.1 shoes' exact emission (`construct_client_hello`, `shoes/reality_tls13_messages.rs:273-414`)

Handshake message (no record header):

| offset | size | content |
|---|---|---|
| 0 | 1 | 0x01 (ClientHello) |
| 1 | 3 | body length u24 (patched at the end, `:408-411`) |
| 4 | 2 | 0x03 0x03 (legacy version TLS 1.2) |
| 6 | 32 | client_random (CSPRNG, `shoes/reality_client_connection.rs:169-170`) |
| 38 | 1 | 0x20 (session_id length = 32) |
| 39 | 32 | session_id (see §4.2 REALITY contents; encrypted before send) |
| 71 | 2 | cipher_suites length u16 (= 2·n) |
| 73 | 2n | suites in offer order (defaults **0x1301, 0x1302, 0x1303** — `shoes/reality_cipher_suite.rs:14-18`; also `0x1301`-only possible, `:202-207`) |
| 73+2n | 2 | 0x01 0x00 (compression: null only) |
| 75+2n | 2 | extensions length u16 (patched, `:400-403`) |
| … | var | extensions, in this exact order |

**Extension order emitted by shoes (verbatim):**

1. **server_name (type 0x0000)** (`:316-328`): ext_len = 5+|host|; list_len = 3+|host|;
   name_type 0x00 (host_name); name_len u16; hostname bytes (no trailing dot handling,
   IDN must be pre-punned by caller).
2. **supported_versions (0x002b)** (`:330-336`): `00 2b 00 03 02 03 04` — offers exactly
   TLS 1.3.
3. **supported_groups (0x000a)** (`:338-344`): `00 0a 00 04 00 02 00 1d` — x25519 only.
4. **key_share (0x0033)** (`:346-356`): ext_len = 2+4+32 = 38; client_shares len =
   4+32 = 36; group 0x001d; key len 0x0020; 32-byte X25519 public key.
5. **signature_algorithms (0x000d)** (`:358-374`): ext_len 0x0012, list len 0x0010, then
   8 algorithms matching the Chrome 133 uTLS fingerprint (comment cites
   `utls u_parrots.go#L935-L944`):
   `04 03` ecdsa_secp256r1_sha256, `08 04` rsa_pss_rsae_sha256, `04 01` rsa_pkcs1_sha256,
   `05 03` ecdsa_secp384r1_sha384, `08 05` rsa_pss_rsae_sha384, `05 01` rsa_pkcs1_sha384,
   `08 06` rsa_pss_rsae_sha512, `06 01` rsa_pkcs1_sha512.
6. **ALPN (0x0010)** (`:376-398`, omitted if list empty): ext_len = 2 + Σ(1+|p|);
   list_len u16; per protocol: u8 len + bytes. Default protocols = `["h2", "http/1.1"]`
   (`DEFAULT_ALPN_PROTOCOLS`, `:260`).

Then the message is wrapped in a cleartext record: `16 03 03 <len_u16> || CH`
(`write_record_header`, `:421-427`; `shoes/reality_client_connection.rs:248-250`).

### 4.2 REALITY-specific session_id (inside the ClientHello)

The 32-byte session_id is not random (`shoes/reality_client_connection.rs:180-198`):
```
[0..4]   version "1.8.0" → 01 08 00 00
[4..8]   u32 big-endian unix timestamp (seconds)
[8..16]  REALITY short_id (8 bytes, hex config right-padded with zeros)
[16..32] zeros
```
Before the record is written, bytes **[39..71] of the handshake message** (the session_id
contents) are replaced with `AES-256-GCM(auth_key, nonce = client_random[20..32], aad =
ClientHello-with-zeroed-session_id)` = 16B ciphertext || 16B tag
(`:217-246`; `encrypt_session_id`, `shoes/reality_auth.rs:129-158`). `auth_key` =
`HKDF-SHA256(extract salt = client_random[0..20], ikm = X25519(ephemeral_priv,
server_static_pub)).expand(info = "REALITY")` (`derive_auth_key`,
`shoes/reality_auth.rs:98-114`). The **transcript uses the wire ClientHello with the
encrypted session_id in place** — not the zeroed AAD form (`:244-254`).

### 4.3 x25519 key generation

32 random bytes → `agreement::PrivateKey::from_private_key(X25519, ..)` →
`compute_public_key()` (`shoes/reality_client_connection.rs:159-167`). The ephemeral
private key is kept in handshake state for the post-ServerHello ECDH
(`:418-433`).

### 4.4 Comparison with a maximally Chrome-shaped ClientHello (utls HelloChrome_133)

Source: `refraction-networking/utls` `u_parrots.go` (commit `aa6edf4`, the exact commit
shoes' sig-algs comment cites). Chrome 133 offers:

- CipherSuites: `GREASE, 1301, 1302, 1303, ...` plus 12 TLS 1.2 suites (16 total).
- Extensions (base order; wrapped in `ShuffleChromeTLSExtensions` so most are shuffled at
  runtime — GREASE, padding, pre_shared_key are pinned): GREASE ext (first), server_name,
  extended_master_secret (23), renegotiation_info (0xff01), supported_groups (10, with
  GREASE group first: `GREASE, X25519MLKEM768, X25519, P-256, P-384`), ec_point_formats
  (11), session_ticket (0x0023), ALPN (16, h2/http/1.1), status_request (5),
  signature_algorithms (13, same 8 as shoes), signed_certificate_timestamp (18),
  key_share (51: GREASE share `{Group:0x0a0a, Data:[0]}`, X25519MLKEM768, X25519),
  psk_key_exchange_modes (45: psk_dhe_ke), supported_versions (43: `GREASE, 0304, 0303`),
  compress_certificate (27: brotli), ALPS (17513), GREASE-ECH (0xfe0d), GREASE ext (last).
- GREASE placements: first cipher suite; first supported_group; first key_share (1-byte
  data); first supported_versions entry; two GREASE extensions (first + second-to-last).
- No early_data (no 0-RTT in Chrome's initial CH without session resumption).

**Deltas of shoes' ClientHello vs Chrome 133 (fingerprint-relevant, functionally
irrelevant to the REALITY handshake):** no GRE anywhere; no TLS 1.2 cipher suites; only
x25519 group/key_share (no X25519MLKEM768 — Chrome's CH is ~1800 bytes vs shoes' ~330);
no extended_master_secret / renegotiation_info / ec_point_formats / session_ticket /
status_request / SCT / psk_key_exchange_modes / compress_certificate / ALPS / ECH-GREASE;
extensions are in fixed (non-Chrome, non-shuffled) order; supported_versions lacks the
GREASE entry and 0303. A middleweight censor can trivially distinguish this from Chrome.
If tls13-core wants Chrome-parity later, keep the functional extensions
(supported_versions, key_share, supported_groups, signature_algorithms, server_name,
ALPN) byte-authoritative and add inert ones (GREASE, padding, compress_certificate,
psk_key_exchange_modes, status_request, ALPS) verbatim from the utls parrot — none of
them change the handshake state machine above (psk_key_exchange_modes WILL make the Go
REALITY server start sending session tickets, §1.3, so only add it together with
post-handshake message tolerance).

---

## 5. TRANSCRIPT HASH

The transcript hashes **handshake message bytes (4-byte header included), never record
headers**, concatenated in order. The hash algorithm = selected suite's digest
(`shoes/reality_cipher_suite.rs:126-130`), instantiated from the raw bytes with
`digest::Context` (incremental) (`shoes/reality_client_connection.rs:395-409`).

Transcript inputs per step (shoes' exact accumulation):

| point | bytes hashed | used for |
|---|---|---|
| T0 | `CH` (wire bytes incl. encrypted session_id) | stored |
| T1 | `CH \|\| SH` (`server_hello_hash`) | c/s hs traffic secrets (`:396-440`) |
| T2 | `CH \|\| SH \|\| EE \|\| Cert \|\| CV` | server Finished verify (not done in shoes) + **CertificateVerify signed content** (`:685-708`) |
| T3 | `CH \|\| SH \|\| EE \|\| Cert \|\| CV \|\| Finished(server)` (`handshake_hash`) | client Finished verify_data + c/s application_traffic_secret_0 (`:717-759`) |

shoes keeps the raw transcript byte buffer (`handshake_transcript_bytes` = CH||SH,
extended by `accumulated_plaintext` = EE||Cert||CV||Fin) and re-hashes from scratch —
simple and correct. It never folds record headers, CCS records, or the client Finished
into the server-side transcript states above. Note the ServerHello slice fed to the
transcript is the record payload *including* its 4-byte handshake header
(`:371,407-408`).

---

## 6. WHAT CAN BE SKIPPED (and what cannot)

1. **Session resumption / PSK / 0-RTT**: skipped entirely. No pre_shared_key,
   psk_key_exchange_modes, early_data in CH; key schedule uses empty-PSK Early Secret
   (§2.2). Consequence: Xray/Go server sends no NewSessionTickets
   (`go/handshake_server_tls13.go:1040-1052`).
2. **KeyUpdate**: shoes does not implement it; post-handshake inner-type-0x16 records
   panic in shoes (`shoes/reality_client_connection.rs:849-855`). tls13-core MUST
   at minimum *ignore* such records. Full support, if ever needed:
   `new_read_secret = HKDF-Expand-Label(read_traffic_secret, "traffic upd", "", L)`,
   same for write; if the peer requested update, reply with a KeyUpdate and roll the
   write secret (`go/conn.go:1400-1433`, `go/key_schedule.go:25-27`); sequence resets
   to 0 on each secret roll.
3. **Post-handshake auth (CertificateRequest)**: ignored (client-auth-less). For
   robustness treat any unexpected post-handshake handshake *message* as ignorable or
   fatal-by-policy, never a crash.
4. **Server Finished HMAC verification**: RFC 8446 requires
   `verify_data == HMAC(finished_key(s hs traffic), Hash(CH..CV))`. shoes does NOT
   check it (only the AEAD tag authenticates it; REALITY's actual server authentication
   is the certificate HMAC). tls13-core for generic servers SHOULD verify it (cheap,
   catches broken key schedules early); it is not load-bearing for REALITY.
5. **OCSP stapling / SCT / certificate chain / hostname / expiry validation**: none.
   The Certificate message is consumed only for: first-entry DER bytes; SPKI raw key
   (32B Ed25519) for CertificateVerify; signatureValue (64B) for the REALITY HMAC
   (`shoes/reality_client_verify.rs:91-201`). X.509 parsing can be replaced by targeted
   DER extraction if the x509-parser dependency is unwanted (the SPKI and signature are
   findable by TLV walk; note the test helper's heuristic of scanning for
   `03 41 00` BIT STRING at `shoes/reality_certificate.rs:97-108` is test-only).
6. **Client Certificate / client auth**: skipped; no CertificateRequest handling.
7. **HelloRetryRequest**: rejected (§1.3).
8. **Renegotiation**: impossible in TLS 1.3; not handled.
9. **Exporters (`exp master`)**: not needed by REALITY; omit.

---

## 7. CRYPTO PRIMITIVES AND CRATES (exactly what shoes uses)

shoes' TLS/REALITY crypto is **entirely `aws-lc-rs`** (no `ring`, no `hkdf`/`rand_core`-
driven custom KDFs, `rustls` is used only by other protocols — see
`reference/shoes/Cargo.toml:30`, which also pins `default-features = false`):

| primitive | use | shoes code | aws-lc-rs API |
|---|---|---|---|
| X25519 ECDH | CH ephemeral key, TLS shared secret, REALITY auth secret | `reality_auth.rs:54-84`, `reality_client_connection.rs:159-167,418-433` | `agreement::{X25519, PrivateKey, UnparsedPublicKey, agree}` |
| HKDF-SHA256 (extract/expand) | REALITY auth_key only | `reality_auth.rs:3,98-114` | `hkdf::{HKDF_SHA256, Salt}` |
| HKDF-Expand/Extract + Expand-Label (TLS 1.3) | full key schedule | `reality_tls13_keys.rs:25-132` | hand-rolled on `hmac` |
| HMAC-SHA256 / SHA384 | key schedule, Finished | `reality_cipher_suite.rs:10`, `reality_tls13_keys.rs:7` | `hmac::{HMAC_SHA256, HMAC_SHA384, Key, Context}` |
| HMAC-SHA512 | REALITY cert HMAC | `reality_client_verify.rs:133-134`, `reality_certificate.rs:64` | `hmac::HMAC_SHA512` |
| SHA-256 / SHA-384 digests | transcript hash | `reality_cipher_suite.rs:9`, `reality_client_connection.rs:396` | `digest::{SHA256, SHA384, Context}` |
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | record layer | `reality_cipher_suite.rs:8`, `reality_aead.rs:4-38` | `aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, UnboundKey, LessSafeKey, Nonce, Aad}` |
| AES-256-GCM | REALITY session_id encryption | `reality_auth.rs:1,129-158` | `aead::AES_256_GCM` |
| Ed25519 sign | CertificateVerify (server side) | `reality_tls13_messages.rs:10,185-231` | `signature::Ed25519KeyPair` |
| Ed25519 verify | CertificateVerify (client side) | `reality_client_verify.rs:6,288-320` | `signature::{ED25519, UnparsedPublicKey}` |
| CSPRNG | ephemeral keys, random | `reality_client_connection.rs:157,169` | `rand` crate (`rand::rng().fill_bytes`) |
| constant-time compare | cert HMAC check | `reality_client_verify.rs:7,152` | `subtle::ConstantTimeEq` |
| X.509 parse (client) | SPKI + signatureValue extraction | `reality_client_verify.rs:8-9` | `x509-parser` (feature `verify-aws`) |
| X.509 generate (server) | REALITY HMAC certificate | `reality_certificate.rs:3,49-88` | `rcgen` (aws_lc_rs backend) |

A tls13-core that mirrors shoes needs exactly: `aws-lc-rs`, `rand`, `subtle`
(optional), and — only if keeping the x509-parser shortcut — `x509-parser`.
Ed25519 is needed by BOTH sides of REALITY's CertificateVerify: the server signs with
the cert's Ed25519 key; the client verifies with the key extracted from the cert. HMAC-
SHA512 appears only in the REALITY substrate (not in TLS 1.3 proper, which uses
SHA-256/384 HMACs only).

---

## 8. SERVER-SIDE CONSTRUCTS THE CLIENT MUST BE ABLE TO PARSE (for cross-checking)

Verbatim shapes produced by the shoes server (useful as test vectors):

- **ServerHello** (`shoes/reality_tls13_messages.rs:20-91`): `02 || len_u24 || 0303 ||
  random32 || sid_len || sid(echo) || suite_u16 || 00 || ext_len_u16 || { 002b 0002 0304,
  0033 <len> 001d <klen=0x20> <key> }`.
- **EncryptedExtensions**: `08 00 00 02 00 00` (type, len=2, empty extensions).
- **Certificate**: `0b || len_u24 || 00 (empty ctx) || list_len_u24 || cert_len_u24 ||
  DER || 0000` (`:122-178`).
- **CertificateVerify**: `0f || len_u24 || 0807 || 0040 || 64-byte sig`, signed content =
  `0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || Hash(CH..Cert)`
  (`:185-231`).
- **Finished**: `14 || 00 00 20 || verify_data` (32B for SHA-256 suites) (`:237-257`).

REALITY certificate = rcgen self-signed Ed25519 cert where signatureValue is replaced by
`HMAC-SHA512(auth_key, ed25519_public_key)` (TBS ignored) — `HmacSigningKey`
(`shoes/reality_certificate.rs:11-34,49-88`).

---

## 9. IMPLEMENTATION CHECKLIST (dependency order)

1. `CipherSuite` (3 const suites; id/hmac/digest/key_len/nonce_len/hash_len).
2. `hkdf_expand`, `hkdf_expand_label`, `hkdf_extract`, `derive_secret`
   (§2.1) — unit-test against RFC 5869 A.1 (`shoes/reality_tls13_keys.rs:392-409`).
3. AEAD wrapper + `make_nonce` (§3.3) + record seal/open (§3.2/3.4).
4. RecordEncryptor/RecordDecryptor with per-epoch seq (§3.1/3.5).
5. ClientHello builder (§4.1) + REALITY session_id/AuthKey (§4.2).
6. ServerHello parser (key_share + cipher suite, §8).
7. Key schedule (§2.2) + Finished (§2.4).
8. Handshake state machine (§1.2) incl. cross-record message accumulation, cert HMAC,
   CV verify, client Finished send, app-key switch, post-handshake tolerance (§6.2).
9. Alerts + close_notify (§3.6).
10. End-to-end test: handshake against (a) the shoes REALITY server and (b) a stock
    `rustls`/OpenSSL TLS 1.3 server (this flushes out §6.2/§6.4 divergences).
