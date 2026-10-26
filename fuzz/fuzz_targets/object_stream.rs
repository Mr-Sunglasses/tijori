#![no_main]
//! Object stream reader. The first byte picks the mode:
//! raw object bytes (framing and authentication), or a stream built from the
//! input under the fixed key (length prefix, padding and tag handling behind
//! the AEAD, which random bytes would never reach).

use std::io::Read;

use libfuzzer_sys::fuzz_target;
use tijori_core::crypto::{Key, ObjectKey, StreamPush, StreamTag};
use tijori_core::format::ObjectKind;
use tijori_core::format::object::{OBJECT_VERSION, ObjectReader};

const ID: [u8; 32] = [3; 32];

fn read(data: &[u8], k: &ObjectKey) {
    if let Ok(mut r) = ObjectReader::new(data, k, ObjectKind::File, &ID, None) {
        let declared = r.content_len();
        let mut out = Vec::new();
        if r.read_to_end(&mut out).is_ok() {
            assert_eq!(out.len() as u64, declared);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let k = ObjectKey::from_key(Key::from_bytes(&mut [11u8; 32]));
    if mode & 1 == 0 {
        read(rest, &k);
        return;
    }
    // Chunks: [len_hi, len_lo, tag, bytes...] repeated; small chunks keep
    // the fuzzer fast, and the reader must still reject non-final short ones.
    let (mut push, header) = StreamPush::new(k.key());
    let mut file = vec![OBJECT_VERSION];
    file.extend_from_slice(&header);
    let mut ad = [0u8; 33];
    ad[0] = ObjectKind::File as u8;
    ad[1..].copy_from_slice(&ID);
    let mut input = rest;
    while input.len() >= 3 {
        let len = (usize::from(input[0]) << 8 | usize::from(input[1])).min(input.len() - 3);
        let tag = match input[2] % 4 {
            0 => StreamTag::Message,
            1 => StreamTag::Final,
            2 => StreamTag::Push,
            _ => StreamTag::Rekey,
        };
        push.push(&input[3..3 + len], &ad, tag, &mut file);
        input = &input[3 + len..];
    }
    read(&file, &k);
});
