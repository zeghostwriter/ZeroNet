#![no_main]
//! `decode` reads a payload length off the wire before it knows how many bytes
//! are present, so `Ok(None)` has to leave the buffer untouched: that is what
//! lets a caller read more and retry instead of losing the frame.

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use zero_transport::ws::frame::{decode, MAX_FRAME_PAYLOAD};

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    match decode(&mut buf) {
        Ok(None) => assert_eq!(buf.len(), data.len(), "a partial frame was consumed"),
        Ok(Some(frame)) => assert!(
            frame.payload.len() <= MAX_FRAME_PAYLOAD,
            "decoded past the frame limit"
        ),
        // A rejected frame is a legitimate outcome of an untrusted length.
        Err(_) => {}
    }
});
