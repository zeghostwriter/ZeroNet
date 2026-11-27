#![no_main]
//! `tokenish` pushes and pops characters up to 150 times to reach a Huffman
//! length, and what it returns goes into a request header, so the result has to
//! stay printable ASCII and the search has to terminate.

use libfuzzer_sys::fuzz_target;
use zero_transport::xhttp_request::{padding, PaddingMethod};

fuzz_target!(|data: &[u8]| {
    let length = match data.first() {
        Some(first) => *first as usize,
        None => return,
    };

    // The simpler branch is defined to be exact, which is what keeps its length
    // on the wire: HPACK gives `X` an 8-bit code.
    let repeat = padding(PaddingMethod::RepeatX, length);
    assert_eq!(
        repeat.len(),
        length,
        "RepeatX must be exactly the length asked for"
    );
    assert!(repeat.bytes().all(|b| b == b'X'));

    // A zero length is empty by definition, so there is nothing to assert about
    // the contents there.
    if length > 0 {
        let tokenish = padding(PaddingMethod::Tokenish, length);
        assert!(
            tokenish.bytes().all(|b| b.is_ascii_graphic()),
            "padding carries a byte that does not belong in a header value"
        );
    }
});
