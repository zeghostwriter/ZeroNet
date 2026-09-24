//! RFC 6455 framing, client side.
//!
//! Only what a proxy carrier needs: binary data frames, close, and ping/pong
//! replies. Client frames are always masked, as the RFC requires — an unmasked
//! client frame is both a protocol violation and a distinguishing signal.

use std::io;

use bytes::{Buf, BufMut, BytesMut};

pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Frames larger than this are refused rather than allocated.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    /// Unmasked payload. Decoding splits this straight out of the read
    /// buffer, so handing a data frame to the reader costs no copy.
    pub payload: BytesMut,
}

impl Frame {
    pub fn binary(payload: impl AsRef<[u8]>) -> Self {
        Self {
            fin: true,
            opcode: OP_BINARY,
            payload: BytesMut::from(payload.as_ref()),
        }
    }
    pub fn pong(payload: impl AsRef<[u8]>) -> Self {
        Self {
            fin: true,
            opcode: OP_PONG,
            payload: BytesMut::from(payload.as_ref()),
        }
    }
    pub fn close() -> Self {
        // 1000 = normal closure
        Self::close_with(&[0x03, 0xE8])
    }
    /// A CLOSE frame with an explicit body (status code plus optional reason).
    pub fn close_with(body: &[u8]) -> Self {
        Self {
            fin: true,
            opcode: OP_CLOSE,
            payload: BytesMut::from(body),
        }
    }
    pub fn is_control(&self) -> bool {
        self.opcode & 0x08 != 0
    }
}

/// Which end of the connection is writing.
///
/// RFC 6455 §5.1 is asymmetric and strict about it: a client **must** mask
/// every frame it sends, and a server **must not** mask any. This is not a
/// tunable — a conformant peer closes the connection on a violation, so a
/// server that masks interoperates only with implementations that are equally
/// wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    fn masks(self) -> bool {
        matches!(self, Role::Client)
    }
}

/// Encode a data frame straight from a caller's slice.
///
/// The relay path writes on every chunk, so building a `Frame` first would
/// allocate and copy the payload once per write for no reason.
pub fn encode_slice(role: Role, opcode: u8, payload: &[u8], out: &mut BytesMut) {
    let len = payload.len();
    out.reserve(len + 14);
    out.put_u8(0x80 | (opcode & 0x0F));

    if !role.masks() {
        put_length(len, false, out);
        out.put_slice(payload);
        return;
    }

    let mask: [u8; 4] = rand::random();
    put_length(len, true, out);
    out.put_slice(&mask);

    // Copy once, then mask in place eight bytes at a time.
    let start = out.len();
    out.put_slice(payload);
    apply_mask(&mut out[start..], mask);
}

/// XOR `data` with the RFC 6455 masking key, starting at key phase 0.
///
/// Works on 64-bit words (the key repeated twice); the compiler vectorises
/// the loop. The tail is shorter than a word and starts at a multiple of 8,
/// so its key phase is again 0.
pub fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
    let wide = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let (words, tail) = data.as_chunks_mut::<8>();
    for word in words {
        *word = (u64::from_ne_bytes(*word) ^ wide).to_ne_bytes();
    }
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

/// Encode one frame for the given role.
pub fn encode(role: Role, frame: &Frame, out: &mut BytesMut) {
    let len = frame.payload.len();
    out.reserve(len + 14);
    out.put_u8(if frame.fin { 0x80 } else { 0x00 } | (frame.opcode & 0x0F));

    if !role.masks() {
        put_length(len, false, out);
        out.put_slice(&frame.payload);
        return;
    }

    let mask: [u8; 4] = rand::random();
    put_length(len, true, out);
    out.put_slice(&mask);
    let start = out.len();
    out.put_slice(&frame.payload);
    apply_mask(&mut out[start..], mask);
}

/// Write the payload-length field, with the mask flag in bit 7.
fn put_length(len: usize, masked: bool, out: &mut BytesMut) {
    let flag = if masked { 0x80 } else { 0x00 };
    if len < 126 {
        out.put_u8(flag | len as u8);
    } else if len <= u16::MAX as usize {
        out.put_u8(flag | 126);
        out.put_u16(len as u16);
    } else {
        out.put_u8(flag | 127);
        out.put_u64(len as u64);
    }
}

pub fn encode_client_slice(opcode: u8, payload: &[u8], out: &mut BytesMut) {
    encode_slice(Role::Client, opcode, payload, out)
}

pub fn encode_client(frame: &Frame, out: &mut BytesMut) {
    encode(Role::Client, frame, out)
}

/// Try to decode one frame from the buffer.
///
/// Returns `Ok(None)` when more bytes are needed, leaving the buffer intact so
/// the caller can retry after reading — this makes the decoder cancellation
/// safe.
pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Frame>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;

    let (payload_len, header_len) = match (b1 & 0x7F) as usize {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut n = [0u8; 8];
            n.copy_from_slice(&buf[2..10]);
            // Compare before narrowing: on a 32-bit target `as usize` would
            // truncate a hostile 64-bit length to something under the limit.
            let wide = u64::from_be_bytes(n);
            if wide > MAX_FRAME_PAYLOAD as u64 {
                return Err(oversized(wide));
            }
            (wide as usize, 10)
        }
        n => (n, 2),
    };

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(oversized(payload_len as u64));
    }

    // A control frame must be short and never fragmented.
    if opcode & 0x08 != 0 && (payload_len > 125 || !fin) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed websocket control frame",
        ));
    }

    let mask_len = if masked { 4 } else { 0 };
    if buf.len() < header_len + mask_len + payload_len {
        return Ok(None);
    }

    buf.advance(header_len);
    let mask = if masked {
        let mut m = [0u8; 4];
        m.copy_from_slice(&buf[..4]);
        buf.advance(4);
        Some(m)
    } else {
        None
    };

    let mut payload = buf.split_to(payload_len);
    if let Some(m) = mask {
        apply_mask(&mut payload, m);
    }

    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}

fn oversized(len: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("websocket frame of {len} bytes exceeds the limit"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(payload: Vec<u8>) {
        let f = Frame::binary(payload.clone());
        let mut buf = BytesMut::new();
        encode_client(&f, &mut buf);
        let got = decode(&mut buf).unwrap().expect("one frame");
        assert_eq!(got.payload, payload);
        assert_eq!(got.opcode, OP_BINARY);
        assert!(got.fin);
        assert!(buf.is_empty(), "decoder must consume the whole frame");
    }

    #[test]
    fn roundtrips_small_frame() {
        roundtrip(b"hello".to_vec());
    }

    #[test]
    fn roundtrips_at_the_126_boundary() {
        roundtrip(vec![0xAB; 125]);
        roundtrip(vec![0xAB; 126]);
        roundtrip(vec![0xAB; 127]);
    }

    #[test]
    fn roundtrips_at_the_65535_boundary() {
        roundtrip(vec![7; 65535]);
        roundtrip(vec![7; 65536]);
    }

    #[test]
    fn roundtrips_empty_payload() {
        roundtrip(Vec::new());
    }

    #[test]
    fn client_frames_are_always_masked() {
        let mut buf = BytesMut::new();
        encode_client(&Frame::binary(vec![0, 0, 0, 0]), &mut buf);
        assert_eq!(buf[1] & 0x80, 0x80, "mask bit must be set");
        // A zero payload masked with the key must equal the key.
        assert_eq!(&buf[6..10], &buf[2..6]);
    }

    #[test]
    fn partial_frame_returns_none_without_consuming() {
        let mut full = BytesMut::new();
        encode_client(&Frame::binary(vec![1; 200]), &mut full);
        let mut partial = full.clone();
        partial.truncate(10);
        let before = partial.len();
        assert!(decode(&mut partial).unwrap().is_none());
        assert_eq!(
            partial.len(),
            before,
            "must not consume on incomplete input"
        );
    }

    #[test]
    fn decodes_two_frames_from_one_buffer() {
        let mut buf = BytesMut::new();
        encode_client(&Frame::binary(b"one"), &mut buf);
        encode_client(&Frame::binary(b"two"), &mut buf);
        assert_eq!(&decode(&mut buf).unwrap().unwrap().payload[..], b"one");
        assert_eq!(&decode(&mut buf).unwrap().unwrap().payload[..], b"two");
        assert!(decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x82);
        buf.put_u8(127);
        buf.put_u64(u64::MAX / 2);
        assert!(decode(&mut buf).is_err());
    }

    #[test]
    fn rejects_fragmented_control_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x09); // PING without FIN
        buf.put_u8(0x00);
        assert!(decode(&mut buf).is_err());
    }

    #[test]
    fn slice_encoder_matches_frame_encoder() {
        for len in [0usize, 1, 3, 4, 5, 125, 126, 200, 65535, 65536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut a = BytesMut::new();
            encode_client_slice(OP_BINARY, &payload, &mut a);
            let decoded = decode(&mut a).unwrap().expect("one frame");
            assert_eq!(decoded.payload, payload, "len {len}");
            assert_eq!(decoded.opcode, OP_BINARY);
            assert!(decoded.fin);
        }
    }

    #[test]
    fn slice_encoder_masks_word_and_tail_identically() {
        // Exercises the 4-byte fast path and the 1-3 byte tail together.
        let payload: Vec<u8> = (0..=254u8).collect();
        let mut buf = BytesMut::new();
        encode_client_slice(OP_BINARY, &payload, &mut buf);
        assert_eq!(buf[1] & 0x80, 0x80, "must be masked");
        assert_eq!(decode(&mut buf).unwrap().unwrap().payload, payload);
    }

    #[test]
    fn word_mask_matches_bytewise_reference() {
        let mask = [0x11, 0x22, 0x33, 0x44];
        for len in 0..40usize {
            let original: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut fast = original.clone();
            apply_mask(&mut fast, mask);
            let slow: Vec<u8> = original
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i & 3])
                .collect();
            assert_eq!(fast, slow, "len {len}");
        }
    }

    #[test]
    fn rejects_64_bit_length_just_over_the_limit() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x82);
        buf.put_u8(127);
        buf.put_u64(MAX_FRAME_PAYLOAD as u64 + 1);
        assert!(decode(&mut buf).is_err());
    }

    #[test]
    fn decodes_unmasked_server_frame() {
        // Servers do not mask; the decoder must accept that.
        let mut buf = BytesMut::new();
        buf.put_u8(0x82);
        buf.put_u8(3);
        buf.put_slice(b"abc");
        assert_eq!(&decode(&mut buf).unwrap().unwrap().payload[..], b"abc");
    }
}
