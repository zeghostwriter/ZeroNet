# XTLS Vision (`flow=xtls-rprx-vision`) — CLIENT Implementation Spec

Derived from (local checkouts, line numbers refer to these files):

- **Xray-core v26.9.9-2-gc412e77** (`reference/Xray-core`) — the reference implementation.
  Note: in current Xray-core the Vision codec lives in `proxy/proxy.go`, NOT in
  `proxy/vless/encoding/vision.go` (that file no longer exists).
  - `reference/Xray-core/proxy/proxy.go` — Vision codec: `VisionReader`, `VisionWriter`,
    `XtlsPadding`, `XtlsUnpadding`, `XtlsFilterTls`, `IsCompleteRecord`, `ReshapeMultiBuffer`,
    `UnwrapRawConn`, `TrafficState`.
  - `reference/Xray-core/proxy/vless/outbound/outbound.go` — client-side wiring.
  - `reference/Xray-core/proxy/vless/inbound/inbound.go` — server-side expectations.
  - `reference/Xray-core/proxy/vless/encoding/encoding.go` + `addons.go` — VLESS framing.
  - `reference/Xray-core/proxy/vless/vless.go:10` — `XRV = "xtls-rprx-vision"`.
- **shoes** (`reference/shoes`, commit 2ba0dd8) — Rust impl:
  `src/vless/{vision_pad,vision_unpad,vision_stream,vision_filter,tls_deframer}.rs`,
  `src/vless/vless_client_handler.rs`, `src/vless/vless_util.rs`.
- **xray-rust** (`reference/xray-rust`, commit 80fa58e) — Rust impl:
  `crates/xray-proxy/src/vless/{vision,vision_stream,wire,response_stream}.rs`,
  `crates/xray-core-rs/src/outbound.rs`.

Vision is always used over an outer TLS 1.3 (or REALITY) connection. Everything below is
*inside* the outer TLS ciphertext channel unless explicitly stated ("raw" / "direct mode").

---

## 1. WIRE FORMAT

### 1.1 Command bytes (complete list)

`proxy/proxy.go:56-58` — there are exactly three commands:

```go
const (
    CommandPaddingContinue byte = 0x00
    CommandPaddingEnd      byte = 0x01
    CommandPaddingDirect   byte = 0x02
)
```

| Value | Name               | Meaning for the receiver                                        |
|-------|--------------------|-----------------------------------------------------------------|
| 0x00  | `PaddingContinue`  | more padded frames follow; keep parsing                          |
| 0x01  | `PaddingEnd`       | last padded frame; following bytes are plain payload *inside the outer TLS* |
| 0x02  | `PaddingDirect`    | last padded frame; following bytes are **raw on the TCP socket** (outer TLS layer is bypassed — "XTLS mode") |

Any other value is a protocol error (`xray-rust .../vision.rs:17-28` returns
`VisionError::UnknownCommand`; Xray just logs `"XtlsRead unknown command"` and stops
unpadding — treat unknown as fatal).

### 1.2 Frame layout

Each Vision frame (after any UUID prefix, see 1.3):

```
offset  size  field
0       1     command      (0x00 | 0x01 | 0x02)
1       2     content_len  u16 BIG-endian
3       2     padding_len  u16 BIG-endian
5       N     content      (N = content_len)   -- the actual payload
5+N     P     padding      (P = padding_len)   -- random bytes, ignored by receiver
```

Total frame size = `5 + content_len + padding_len`. Written by `XtlsPadding`
(`proxy/proxy.go:523`):

```go
newbuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)})
```

There is no outer frame length field — frame boundaries are found purely by parsing
command + the two lengths (see section 7).

`content_len` is capped at 65535 (u16). Xray in practice caps frame content+padding at
`buf.Size - 21 = 8192 - 21 = 8171` bytes (`buf.Size = 8192`, `common/buf/buffer.go:13`;
padding cap at `proxy/proxy.go:515-517`). This cap is NOT protocol-mandatory (xray-rust
accepts up to 65535 content) but it is what Xray peers emit; frames from an Xray server are
at most ~8192 bytes of plaintext per TLS record.

### 1.3 The UUID prefix (first frame per direction only)

The **first** frame in each direction is prefixed with the 16-byte VLESS user UUID.
Written once by `XtlsPadding` (`proxy/proxy.go:519-522`):

```go
if userUUID != nil {
    newbuffer.Write(*userUUID)
    *userUUID = nil
}
```

The writer holds `writeOnceUserUUID` (copied from `TrafficState.UserUUID`,
`proxy/proxy.go:305-306`); after the first frame it stays `nil`. The reader validates it:
`XtlsUnpadding` initial state (`proxy/proxy.go:551-558`):

```go
if *remainingCommand == -1 && *remainingContent == -1 && *remainingPadding == -1 { // initial state
    if b.Len() >= 21 && bytes.Equal(s.UserUUID, b.BytesTo(16)) {
        b.Advance(16)
        *remainingCommand = 5
    } else {
        return b
    }
}
```

- Client → server first frame: UUID = the account UUID from the request header
  (`outbound/outbound.go:312`, `NewTrafficState(account.ID.Bytes())`).
- Server → client first frame: the SAME UUID (server stores `userSentID`, the UUID the
  client sent, `inbound/inbound.go:612`).
- So the expected UUID on both legs is the account UUID.

Go quirk: if the first received buffer is < 21 bytes or does not start with the UUID, Go
passes the data through unparsed (compat hack). Rust impls instead WAIT for ≥16 bytes and
error/switch-to-raw on mismatch (shoes `vision_unpad.rs:99-116`; xray-rust
`vision_stream.rs:196-218`). **As a client, make sure your first frame goes out as a single
TLS record (it will: one frame ≈ 900+ bytes) so Go servers see ≥21 bytes at once.**

### 1.4 First packet on the wire (client → server, right after the VLESS request header)

The client ALWAYS emits a Vision frame immediately after the VLESS request header, even
with zero payload data ("first buff" behavior). `outbound/outbound.go:322-354`:

```go
bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil { ... }
serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob) // = VisionWriter
timeoutReader, ok := clientReader.(buf.TimeoutReader)
if ok {
    multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
    if err1 == nil {
        if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil { return err }
    } else if err1 != buf.ErrReadTimeout {
        return err1
    } else if requestAddons.Flow == vless.XRV {
        mb := make(buf.MultiBuffer, 1)
        errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
        if err := serverWriter.WriteMultiBuffer(mb); err != nil { return err }
    }
}
if err := bufferWriter.SetBuffered(false); err != nil { ... } // flush: header + first frame go out together
```

A 1-element MultiBuffer containing `nil` hits the empty-write branch of `VisionWriter`
(`proxy/proxy.go:357-358`):

```go
if len(mb) == 1 && mb[0] == nil {
    mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed) // we do a long padding to hide vless header
}
```

So the very first uplink frame is:

```
[16B user UUID][0x00][content_len=0x0000][padding_len=0x0384..0x0577][padding 900..1399 random bytes]
```

- command = `PaddingContinue` (0x00)
- content_len = 0
- padding_len = `rand(500) + 900 - 0` = 900..1399 (long-padding formula, `longPadding` is
  hardcoded `true` here)
- Purpose: hide the length of the VLESS request header (they flush in one TLS record).

If the local app had data pending within 500 ms, that data is written instead as the first
padded frame(s) — same UUID prefix. Either way **something padded is always the first
thing after the header**.

Both Rust impls reproduce this exactly:
- xray-rust `crates/xray-core-rs/src/outbound.rs:3467-3477`:

```rust
stream.write_all(&header).await?;
if flow.uses_vision() {
    let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
    let mut stream =
        VisionStream::new(stream, *outbound.user().id.as_bytes(), DEFAULT_VISION_SEED);
    stream.queue_empty_padding_frame()?;
    stream.flush().await?;
    return Ok(Box::new(VisionOutboundStream::new(stream)));
}
```

  `queue_empty_padding_frame` (`xray-rust .../vision_stream.rs:148-151`) =
  `queue_padded_write(&[], VisionCommand::Continue, true)` — content empty, long padding.

- shoes writes the VLESS header through the TLS stream, then wraps with
  `VisionStream::new_client` (`shoes/src/vless/vless_client_handler.rs:100-122`); its first
  `poll_write` produces the first UUID-prefixed frame (shoes does not send an empty frame
  proactively; it pads whatever the first write is — including empty writes at the padding
  layer via `pad_with_uuid_and_command`).

### 1.5 Padding length scheme ("padding1000")

`XtlsPadding`, `proxy/proxy.go:496-532`, with seed `[900, 500, 900, 256]`
(`testseed` default: `proxy/proxy.go:307-309`; xray-rust `vision.rs:8`
`DEFAULT_VISION_SEED: [u32;4] = [900, 500, 900, 256]`; shoes `vision_pad.rs:5-7`):

```
if content_len < 900 AND long_padding:
    padding_len = rand_in_[0,500) + 900 - content_len        // total frame ≈ 900..1399+content
else:
    padding_len = rand_in_[0,256)
if padding_len > 8192 - 21 - content_len:
    padding_len = 8192 - 21 - content_len                    // cap
```

Go verbatim:

```go
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var contentLen int32 = 0
	var paddingLen int32 = 0
	if b != nil {
		contentLen = b.Len()
	}
	if contentLen < int32(testseed[0]) && longPadding {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(testseed[1])))
		if err != nil {
			errors.LogDebugInner(ctx, err, "failed to generate padding")
		}
		paddingLen = int32(l.Int64()) + int32(testseed[2]) - contentLen
	} else {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(testseed[3])))
		if err != nil {
			errors.LogDebugInner(ctx, err, "failed to generate padding")
		}
		paddingLen = int32(l.Int64())
	}
	if paddingLen > buf.Size-21-contentLen {
		paddingLen = buf.Size - 21 - contentLen
	}
	newbuffer := buf.New()
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	newbuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)})
	if b != nil {
		newbuffer.Write(b.Bytes())
		b.Release()
		b = nil
	}
	newbuffer.Extend(paddingLen)
	return newbuffer
}
```

Padding bytes are cryptographically random (Go `crypto/rand`; shoes fills random bytes,
`vision_pad.rs:37-41`; xray-rust writes zeros — `vision.rs:115`,
`output.resize(output.len() + padding_len, 0)` — receivers never inspect padding content,
so zeros are interoperable but weaker against any padding-content probing; prefer random).

`longPadding` is `w.trafficState.IsTLS` at write time (`proxy/proxy.go:362`) — i.e. long
padding is applied while the *inner* traffic has been identified as TLS (handshake phase),
plus the hardcoded-true empty first frame. shorthanded: "padding1000" ≈ pad up to ~1000+
bytes during the TLS-handshake phase.

Rust equivalents of the formula:

- shoes `vision_pad.rs:47-67` (`LONG_PADDING_MIN=900`, `LONG_PADDING_RANDOM_MAX=500`,
  `SHORT_PADDING_RANDOM_MAX=256`, `MAX_PADDING_SIZE=8171`) — uses
  `900 - content + rand(0..500)` and `rand(0..256)`, capped at 8171-content.
- xray-rust `vision.rs:120-147`:

```rust
fn padding_len(&self, content_len: usize, long_padding: bool, deterministic_extra_padding: u16) -> usize {
    if deterministic_extra_padding != 0 {
        return deterministic_extra_padding as usize;
    }
    if long_padding && content_len < self.seed[0] as usize {
        let padding_len = (self.seed[2] as usize)
            .saturating_sub(content_len)
            .saturating_add(random_padding_len(self.seed[1]));
        padding_len.min(MAX_CONTENT_LEN)
    } else {
        random_padding_len(self.seed[3]).min(MAX_CONTENT_LEN)
    }
}
```

---

## 2. WHEN PADDING HAPPENS (client write side)

### 2.1 State machine

Per-direction writer state (client uplink uses `TrafficState.Outbound.IsPadding` and
`Outbound.UplinkWriterDirectCopy`, `proxy/proxy.go:326-332` — note the cross-naming:
client uplink shares the "Outbound" state with client downlink READ):

- `is_padding = true` initially (`NewTrafficState`, `proxy/proxy.go:168`).
- `switch_to_direct_copy = false` initially.

`VisionWriter::WriteMultiBuffer` verbatim (`proxy/proxy.go:322-404`, trimmed of splice/stat
noise):

```go
func (w *VisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var isPadding *bool
	var switchToDirectCopy *bool
	if w.isUplink {
		isPadding = &w.trafficState.Outbound.IsPadding
		switchToDirectCopy = &w.trafficState.Outbound.UplinkWriterDirectCopy
	} else {
		isPadding = &w.trafficState.Inbound.IsPadding
		switchToDirectCopy = &w.trafficState.Inbound.DownlinkWriterDirectCopy
	}

	if *switchToDirectCopy {
		rawConn, _, writerCounter := UnwrapRawConn(w.conn)
		w.Writer = buf.NewWriter(rawConn)
		w.directWriteCounter = writerCounter
		*switchToDirectCopy = false
	}
	if !mb.IsEmpty() && w.directWriteCounter != nil {
		w.directWriteCounter.Add(int64(mb.Len()))
	}

	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(mb, w.trafficState, w.ctx)
	}

	if *isPadding {
		if len(mb) == 1 && mb[0] == nil {
			mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed) // we do a long padding to hide vless header
		} else {
			isComplete := IsCompleteRecord(mb)
			mb = ReshapeMultiBuffer(w.ctx, mb)
			longPadding := w.trafficState.IsTLS
			for i, b := range mb {
				if w.trafficState.IsTLS && b.Len() >= 6 && bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete {
					if w.trafficState.EnableXtls {
						*switchToDirectCopy = true
					}
					var command byte = CommandPaddingContinue
					if i == len(mb)-1 {
						command = CommandPaddingEnd
						if w.trafficState.EnableXtls {
							command = CommandPaddingDirect
						}
					}
					mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
					*isPadding = false // padding going to end
					longPadding = false
					continue
				} else if !w.trafficState.IsTLS12orAbove && w.trafficState.NumberOfPacketToFilter <= 1 { // For compatibility with earlier vision receiver, we finish padding 1 packet early
					*isPadding = false
					mb[i] = XtlsPadding(b, CommandPaddingEnd, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
					break
				}
				var command byte = CommandPaddingContinue
				if i == len(mb)-1 && !*isPadding {
					command = CommandPaddingEnd
					if w.trafficState.EnableXtls {
						command = CommandPaddingDirect
					}
				}
				mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
			}
		}
	}
	if err := w.Writer.WriteMultiBuffer(mb); err != nil {
		return err
	}
	return nil
}
```

### 2.2 Inner-TLS detection (`XtlsFilterTls`)

Byte patterns (`proxy/proxy.go:38-58, 619-670`):

```go
Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04} // supported_versions extension (0x002b) len 2, TLS1.3 (0x0304)
TlsClientHandShakeStart = []byte{0x16, 0x03}        // + byte[5]==0x01 (ClientHello)
TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}  // + byte[5]==0x02 (ServerHello)
TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}
```

Algorithm, run on the first 8 buffers of traffic (`NumberOfPacketToFilter` starts at 8 and
decrements per non-nil buffer; shared across read+write paths):

1. Buffer ≥ 6 bytes and starts `16 03 03` with byte[5]==0x02 → **ServerHello**:
   `IsTLS12orAbove = IsTLS = true`; `RemainingServerHello = (u16be(bytes[3..5])) + 5`;
   if buffer ≥ 79 bytes: `session_id_len = byte[43]`,
   `cipher = u16be(bytes[43+session_id_len+1 .. +2])`.
2. Buffer ≥ 6 bytes and starts `16 03` with byte[5]==0x01 → **ClientHello**: `IsTLS = true`.
3. While `RemainingServerHello > 0`, scan the ServerHello bytes for
   `00 2b 00 02 03 04`:
   - found → TLS 1.3; if cipher != 0x1305 (`TLS_AES_128_CCM_8_SHA256`) →
     **`EnableXtls = true`**; stop filtering.
   - ServerHello fully consumed without the pattern → TLS 1.2; stop filtering
     (`EnableXtls` stays false).

Client relevance: the client's DOWNLINK (from server) carries the inner ServerHello, so the
client detects TLS1.3/`EnableXtls` in its read path; the shared state then lets the client's
WRITE side go Direct later. The client's own uplink ClientHello sets `IsTLS` (long padding).

### 2.3 Which writes get padded

While `is_padding == true`, EVERY uplink write is wrapped in a padding frame (possibly
several frames for one large write, after `ReshapeMultiBuffer` splits buffers ≥ 8171 bytes
at the last `17 03 03` boundary, `proxy/proxy.go:460-493`). Padding ENDS when one of:

1. **Inner TLS ApplicationData seen** — the write consists (in full, per
   `IsCompleteRecord`) of complete `17 03 03 ll ll` records:
   - command of the final frame = `PaddingDirect` if `EnableXtls` else `PaddingEnd`
   - if `EnableXtls`: also arm `switch_to_direct_copy` (next write bypasses outer TLS)
   - `is_padding = false`.
2. **Not TLS 1.2+ and filter budget exhausted** — `!IsTLS12orAbove && NumberOfPacketToFilter <= 1`:
   send one last `PaddingEnd` frame, `is_padding = false`. ("finish padding 1 packet early"
   — a non-TLS or TLS1.0/1.1 inner stream stops padding after ~8 writes.)
3. Server-driven end does not exist for the write side; the client writer decides alone.

`IsCompleteRecord` verbatim (`proxy/proxy.go:407-458`) — true iff the buffer is a sequence
of zero or more *complete* TLS 1.2/1.3 ApplicationData records:

```go
func IsCompleteRecord(buffer buf.MultiBuffer) bool {
	b := make([]byte, buffer.Len())
	if buffer.Copy(b) != int(buffer.Len()) {
		panic("impossible bytes allocation")
	}
	var headerLen int = 5
	var recordLen int

	totalLen := len(b)
	i := 0
	for i < totalLen {
		// record header: 0x17 0x3 0x3 + 2 bytes length
		if headerLen > 0 {
			data := b[i]
			i++
			switch headerLen {
			case 5:
				if data != 0x17 { return false }
			case 4:
				if data != 0x03 { return false }
			case 3:
				if data != 0x03 { return false }
			case 2:
				recordLen = int(data) << 8
			case 1:
				recordLen = recordLen | int(data)
			}
			headerLen--
		} else if recordLen > 0 {
			remaining := totalLen - i
			if remaining < recordLen { return false } else {
				i += recordLen
				recordLen = 0
				headerLen = 5
			}
		} else {
			return false
		}
	}
	if headerLen == 5 && recordLen == 0 { return true }
	return false
}
```

Rust equivalent (xray-rust `vision_stream.rs:474-493`):

```rust
fn is_complete_tls_application_data_records(input: &[u8]) -> bool {
    let mut offset = 0;
    while offset < input.len() {
        if input.len() - offset < HEADER_LEN { return false; }
        if input[offset..offset + TLS_APPLICATION_DATA_START.len()] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let record_len = u16::from_be_bytes([input[offset + 3], input[offset + 4]]) as usize;
        offset += HEADER_LEN;
        if input.len() - offset < record_len { return false; }
        offset += record_len;
    }
    !input.is_empty()
}
```

### 2.4 Direct-copy WRITE mode (optional to EMIT, safe to skip)

After the `PaddingDirect` frame is queued, the NEXT write call swaps the underlying writer
to the raw TCP conn (`UnwrapRawConn`, `proxy/proxy.go:673-713` peels stats/TLS/REALITY/
proxyproto wrappers) and writes bytes 1:1 onto TCP — the inner TLS records become the wire
bytes, avoiding double encryption. Rust equivalent: shoes `VisionMode::Direct`
(`vision_stream.rs:287-347, 1459-1471`) writes to `self.tcp`; xray-rust
`poll_write_direct`.

**A minimal compliant client MAY always send `PaddingEnd` instead of `PaddingDirect`**
(never bypass outer TLS on write). The Xray server handles command 0x01 fine — it just
keeps reading through the outer TLS. Both Rust refs do implement Direct-emit when XTLS is
detected (shoes `vision_stream.rs:1172-1178`; xray-rust `vision_stream.rs:426-433`), but it
is a performance optimization, not an interop requirement. What IS mandatory: handling the
server's `PaddingDirect` on the READ side (section 7).

xray-rust client write loop verbatim (`vision_stream.rs:392-447`):

```rust
fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
    let this = &mut *self;
    if !this.pending_write.is_empty() || this.pending_direct_write_mode || this.pending_end_write_mode {
        std::task::ready!(this.poll_drain_pending(cx))?;
    }
    if this.pending_write_len != 0 {
        let accepted_len = this.pending_write_len;
        this.pending_write_len = 0;
        return Poll::Ready(Ok(accepted_len));
    }
    if this.direct_write_mode {
        return Pin::new(&mut this.inner).poll_write_direct(cx, input);
    }
    if !this.padding_write_mode {
        return Pin::new(&mut this.inner).poll_write(cx, input);
    }
    if input.is_empty() { return Poll::Ready(Ok(0)); }

    let accepted_len = cmp::min(input.len(), MAX_CONTENT_LEN);
    let input = &input[..accepted_len];
    this.filter_tls_packet(input);
    if this.is_tls && is_complete_tls_application_data_records(input) {
        if this.enable_xtls {
            this.queue_padded_write(input, VisionCommand::Direct, true)?;
            this.pending_direct_write_mode = true;
        } else {
            this.queue_padded_write(input, VisionCommand::End, true)?;
            this.pending_end_write_mode = true;
        }
    } else if !this.is_tls12_or_above && this.packets_to_filter <= 1 {
        this.queue_padded_write(input, VisionCommand::End, this.is_tls)?;
        this.pending_end_write_mode = true;
    } else {
        this.queue_padded_write(input, VisionCommand::Continue, this.is_tls)?;
    }
    this.pending_write_len = accepted_len;
    std::task::ready!(this.poll_drain_pending(cx))?;
    let accepted_len = this.pending_write_len;
    this.pending_write_len = 0;
    Poll::Ready(Ok(accepted_len))
}
```

(Asymmetry note: Go uses `longPadding := IsTLS` for non-AppData frames; xray-rust passes
`this.is_tls` the same way; shoes passes `self.filter.is_tls()`.)

---

## 3. THE SERVER'S EXPECTATIONS (Xray inbound, flow=xtls-rprx-vision)

Server flow check, `inbound/inbound.go:552-598`:

- `requestAddons.Flow == XRV` and `account.Flow == XRV` (must match, else error
  "account ... is not able to use the flow ...", L588-590):
  - `RequestCommandUDP` → **hard error**: `requestAddons.Flow + " doesn't support UDP"` (L557-558).
  - `Mux`/`Rvs`/`TCP` accepted; TLS/REALITY outer transport REQUIRED — else
    `"XTLS only supports TLS and REALITY directly for now."` (L581); outer TLS must be
    TLS 1.3 (L572-574).
- `requestAddons.Flow == ""` while the account has flow XRV → **connection rejected**
  (L591-595): "account ... is rejected since the client flow is empty. Note that the pure
  TLS proxy has certain TLS in TLS characters."

What the server reads right after the VLESS header: it wraps the remaining stream in
`VisionReader(isUplink=true)` (`inbound/inbound.go:613-616`) with
`NewTrafficState(userSentID)`; unpadding is active from byte 0 and the **first thing it
expects is the 16-byte UUID of your first padding frame**.

If a client sends raw data with NO Vision frame (but DID set the flow addon): the data is
not immediately rejected — `XtlsUnpadding` initial-state mismatch passes the buffer through
unmodified (`proxy/proxy.go:551-558`), and since `CurrentCommand` stays 0 the server
remains in "padding buffers" mode forever, passing every UUID-non-matching chunk through to
the target. It "works" as a plain proxy only by this leniency, BUT:

- it breaks the moment raw data begins with the account's 16-byte UUID (parsed as a frame),
- the server still PADS ITS RESPONSES (its writer `IsPadding` starts true), so a client
  that cannot unpad cannot read the responses,
- it defeats the protocol's purpose and is non-compliant.

**Conclusion: when the server account has `flow=xtls-rprx-vision`, the client MUST send the
flow addon and MUST implement the padding writer and the unpadding reader.** There is no
fallback/fallbacks path for flow accounts (fallbacks only engage on header parse errors).

The server also pads its downlink writes with the identical `VisionWriter` logic
(`inbound/inbound.go:622`, `EncodeBodyAddons` returns `VisionWriter` for XRV), starting its
first frame with the same UUID.

---

## 4. VLESS RESPONSE INTERACTION

- Response header is **plain VLESS, NOT inside a Vision frame**. Server writes
  `EncodeResponseHeader` into the buffered writer, then wraps the *body* writer in
  VisionWriter, then `SetFlushNext()` (`inbound/inbound.go:618-623`). Response addons are
  empty (Flow is deliberately not echoed, `inbound/inbound.go:546-548`):

  ```
  0x00        version (must equal request version 0)
  0x00        addons protobuf length (0)
  ```

  (`encoding/encoding.go:155-173`; addon length byte may be non-zero in theory — read and
  skip `len` bytes.)

- On the client (`outbound/outbound.go:382-391`): `DecodeResponseHeader(conn, request)`
  reads those 2-3 bytes DIRECTLY from the outer TLS stream BEFORE any Vision unpadding;
  everything after that (including the tail of the same TLS record!) feeds the
  `VisionReader`. xray-rust layers `VlessResponseStream` *inside* `VisionStream` so the
  leftover bytes flow into the frame parser (`response_stream.rs:77-121`); shoes reads the
  header first and feeds leftovers via `handle_padded_bytes`
  (`vision_stream.rs:567-700, 1421-1446`).

- "How does the client know padding ended in the response direction": purely via the
  command byte of the last parsed frame:
  - `PaddingEnd` (0x01) → subsequent decrypted bytes are payload inside the outer TLS
    (keep decrypting; stop unpadding).
  - `PaddingDirect` (0x02) → subsequent bytes are RAW TCP below the outer TLS; switch the
    read source to the raw socket (section 7.3).
  Until then, every decrypted byte belongs to `PaddingContinue` frames.

---

## 5. UDP / MUX — VISION IS TCP-ONLY

- Client: `outbound/outbound.go:254-260` — with flow XRV, plain `RequestCommandUDP` is only
  allowed for the `-udp443` flow variant and even then port 443 is rejected unless
  `xtls-rprx-vision-udp443`: `"XTLS rejected UDP/443 traffic"`. Additionally the Xray
  client rewrites any UDP request to Mux/XUDP: command=`Mux` (0x03), address=`v1.mux.cool`,
  port=666, payload framed by XUDP (`outbound/outbound.go:313-317`,
  `xudp.NewPacketWriter`).
- Server: `inbound/inbound.go:557-558` rejects command UDP outright under Vision.
- Recommendation for a Rust client: implement Vision for TCP only; reject UDP ASSOCIATIONS
  under Vision (or implement XUDP framing over the Mux command as a separate feature — the
  Vision padding layer still wraps XUDP packets, but that framing is not Vision-specific).
  xray-rust mirrors this: `blocks_udp443()` (outbound.rs:564-571), UDP path uses
  `VlessCommand::Mux` + XUDP when Vision (`outbound.rs:3530, 3545-3560`), and errors
  `VisionUdp443Rejected` for UDP/443 (outbound.rs:3523-3528). Note xray-rust keeps Mux
  with XUDP; Xray's inbound additionally verifies XUDP-ness for Mux under Vision
  (`isMuxAndNotXUDP`, `inbound/inbound.go:180-191`).
- Mux-with-TCP (command 0x03 carrying multiplexed TCP) is accepted by the server but splice
  is disabled; plain XUDP-over-Mux is the only sanctioned UDP form.

---

## 6. THE CLIENT READER LOOP (after handshake)

### 6.1 State

```
within_padding_buffers = true      // parse frames
remaining_command      = -1        // -1 = initial (expect UUID)
remaining_content      = -1
remaining_padding      = -1
current_command        = 0
direct_read            = false     // DownlinkReaderDirectCopy
// detection state shared with writer:
packets_to_filter      = 8
is_tls / is_tls12_or_above / enable_xtls = false
remaining_server_hello = -1
```

(`proxy/proxy.go:142-172`.)

### 6.2 Algorithm (client, downlink)

```
loop:
  if direct_read: append raw TCP bytes to output; continue         // 7.3
  buf = read decrypted plaintext from outer TLS                    // (may be 1 TLS record's plaintext)
  if within_padding_buffers:
      buf = XtlsUnpadding(buf, state)                              // frame parser, 7.4
      if remaining_content > 0 or remaining_padding > 0 or current_command == 0:
          within_padding_buffers = true
      elif current_command == 1:                                    // PaddingEnd
          within_padding_buffers = false                            // keep reading via outer TLS
      elif current_command == 2:                                    // PaddingDirect
          within_padding_buffers = false
          direct_read = true                                        // + drain any buffered raw bytes
      output += buf
  if packets_to_filter > 0:
      XtlsFilterTls(buf, state)                                    // feed detection (ServerHello!)
  if direct_read: flush TLS-internal buffers into output; switch to raw TCP reads
  emit output to the local app
```

(Go source: `VisionReader.ReadMultiBuffer`, `proxy/proxy.go:203-285`; loop driver
`XtlsRead`, `encoding/encoding.go:176-204`.)

### 6.3 PaddingDirect / raw-read bookkeeping

When switching the read side to raw TCP you must first recover bytes that were already
pulled off the socket by the outer TLS layer but not yet consumed:

- Xray Go reaches into the `tls.Conn` `input` (decrypted, unread) and `rawInput`
  (ciphertext read but unprocessed) fields via unsafe and appends both to the output
  (`proxy/proxy.go:259-271`, wired from `outbound/outbound.go:284-287`).
- shoes keeps an outer TLS deframer and calls `take().into_remaining_data()`
  (`vision_stream.rs:897-915`), appending those bytes to the pending output.
- xray-rust's `VisionTransportStream` reads TCP in TLS-record-aligned chunks so leftover
  ciphertext can be handed back losslessly (`outbound.rs` comment "record-aligned reads";
  `release_record_alignment` after `PaddingEnd`).

**Practical Rust design:** implement the outer TLS read through your own deframer that
(b)uffers complete records; on `PaddingDirect`, any buffered ciphertext that has NOT been
fed to rustls is raw wire data → prepend it to the direct stream and read the socket
directly afterwards. (If you use `PaddingEnd`-only writes this only matters for reads.)

### 6.4 Frame parser (unpadding) — exact algorithm

`XtlsUnpadding` verbatim (`proxy/proxy.go:535-616`; per-buffer, state carried across
buffers):

```go
func XtlsUnpadding(b *buf.Buffer, s *TrafficState, isUplink bool, ctx context.Context) *buf.Buffer {
	// (state pointers selected by direction; for the client downlink use the Outbound set)
	if *remainingCommand == -1 && *remainingContent == -1 && *remainingPadding == -1 { // initial state
		if b.Len() >= 21 && bytes.Equal(s.UserUUID, b.BytesTo(16)) {
			b.Advance(16)
			*remainingCommand = 5
		} else {
			return b
		}
	}
	newbuffer := buf.New()
	for b.Len() > 0 {
		if *remainingCommand > 0 {
			data, err := b.ReadByte()
			if err != nil { return newbuffer }
			switch *remainingCommand {
			case 5: *currentCommand = int(data)
			case 4: *remainingContent = int32(data) << 8
			case 3: *remainingContent = *remainingContent | int32(data)
			case 2: *remainingPadding = int32(data) << 8
			case 1: *remainingPadding = *remainingPadding | int32(data)
			}
			*remainingCommand--
		} else if *remainingContent > 0 {
			len := *remainingContent
			if b.Len() < len { len = b.Len() }
			data, err := b.ReadBytes(len)
			if err != nil { return newbuffer }
			newbuffer.Write(data)
			*remainingContent -= len
		} else { // remainingPadding > 0
			len := *remainingPadding
			if b.Len() < len { len = b.Len() }
			b.Advance(len)
			*remainingPadding -= len
		}
		if *remainingCommand <= 0 && *remainingContent <= 0 && *remainingPadding <= 0 { // this block done
			if *currentCommand == 0 {
				*remainingCommand = 5          // parse next frame header
			} else {
				*remainingCommand = -1         // reset to initial state
				*remainingContent = -1
				*remainingPadding = -1
				if b.Len() > 0 { newbuffer.Write(b.Bytes()) } // trailing raw data (Direct mode)
				break
			}
		}
	}
	return newbuffer
}
```

Key semantics:

- `remainingCommand` counts down the 5 header bytes (command, content_hi, content_lo,
  padding_hi, padding_lo — all BIG-endian assembled from single bytes).
- Multiple frames per buffer and frames split across buffers are both handled (the `for`
  loop plus persistent state).
- On frame completion with command 0 → parse the next header immediately.
- On command 1/2 → reset to initial state and, crucially, any leftover bytes in the current
  buffer are appended to the output VERBATIM (they are outside the padding regime).
- Initial UUID check needs ≥21 bytes; Rust impls should buffer until 16 bytes are available
  and then compare (shoes `vision_unpad.rs:99-116`), treating a mismatch as
  "not-Vision data" (passthrough) or an error.

### 6.5 Rust reference: incremental unpadding state machine

shoes `vision_unpad.rs` implements exactly this as a push-down state machine with
incremental feeding (states: `Initial{expected_uuid}` → `ReadingCommand` →
`ReadingContentLength` → `ReadingPaddingLength` → `ReadingContent` → `ReadingPadding` →
`Done`). Two behaviors worth copying verbatim from `VisionUnpadder::unpad`
(`vision_unpad.rs:87-369`):

1. **Anti-deadlock early return**: if input runs out mid-padding of the FIRST block, return
   the content parsed so far with `command: None`, keeping parser state (the Xray server
   may wait for our response before sending the rest of the padding — comment cites
   Xray-core `proxy/proxy.go`). Do not wait for a complete frame before delivering content.
2. **Command gating**: the End/Direct command is only surfaced after ALL of that frame's
   padding has been consumed, so the caller switches modes only after the padded stream is
   fully drained; any bytes after the final frame's padding belong to the new mode and are
   appended to the returned content.

xray-rust instead parses whole frames from a byte buffer
(`next_frame_len`/`decode_next_frame`, `vision_stream.rs:173-294`): peek the UUID offset,
parse `5+content+padding` length, split the frame, `unpad_vision_block`
(`vision.rs:149-208`), then on `End|Direct` append ALL remaining buffered bytes
(`self.decoded_read.extend_from_slice(&self.raw_read.split())`) since everything after the
final frame is payload.

### 6.6 Buffer management notes

- Xray emits downlink frames ≤ 8192 plaintext bytes per TLS record; a 16 KB read buffer is
  sufficient. shoes uses an 8192-byte TCP read buffer + rustls session buffers
  (`vision_stream.rs:207`); xray-rust reads 8 KiB chunks (`READ_CHUNK_LEN`, L14).
- Keep a `pending_read` output buffer: unpadding may produce data across several TLS
  records before the app's read is satisfied; return partial data promptly (shoes
  `pending_read`, `vision_stream.rs:109`).
- After the final frame, stop running the parser entirely (both `within_padding_buffers`
  flag and shoes' `VisionMode::{Tls,Direct}` / xray-rust's
  `padding_read_mode`/`direct_read_mode`).

---

## 7. IMPLEMENTATION CHECKLIST (client)

1. Outer transport must be TLS 1.3 or REALITY; refuse Vision otherwise (Xray errors:
   `outbound/outbound.go:282, 356-366`).
2. Send VLESS request header with flow addon: protobuf field 1 (string), wire type 2 →
   bytes `0x0A 0x0F "xtls-rprx-vision"`; header writes addon-length byte 0x11 (17)
   (`encoding/addons.go:17-37`; shoes `vless_util.rs:191-212`; xray-rust `wire.rs:77-93`).
3. Immediately after the header, flush a first Vision frame: UUID +
   `00 00 00 03xx..` (empty Continue, padding 900–1399) — or pad the first payload if the
   app already has data (Xray's 500 ms rule).
4. Writer: pad every write while padding active; long padding while inner traffic looks
   like TLS; end padding on complete inner `17 03 03` records (`End`, or `Direct` +
   arm-raw-write if TLS1.3+supported-cipher detected) or after the filter budget with
   `End` when inner traffic is not TLS1.2+.
5. Reader: strip the plain 2–3 byte VLESS response header first; then run the frame parser
   from initial-UUID state; deliver content; on `End` keep reading via outer TLS; on
   `Direct` switch to raw TCP reads preserving buffered raw bytes.
6. Reject UDP (or implement XUDP-over-Mux); never send command UDP under Vision.
7. TLS detection constants: `16 03`+CH(0x01 @byte5), `16 03 03`+SH(0x02 @byte5),
   `17 03 03` AppData, `00 2b 00 02 03 04` TLS1.3 marker, cipher 0x1305 excluded.
8. Padding uses crypto-quality randomness (zeros are wire-compatible but weaker against
   any padding-content probing; prefer random).
