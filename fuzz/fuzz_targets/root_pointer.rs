#![no_main]
//! Root pointer decrypt + parse. The first byte picks the mode:
//! raw file bytes (exercises framing and AEAD rejection), or fuzzed CBOR
//! sealed under the fixed key (exercises the parser behind the AEAD).

use libfuzzer_sys::fuzz_target;
use tijori_core::crypto::{Key, RootKey};
use tijori_core::format::{RootPointer, RootSlot};
use tijori_core::format::root::ROOT_VERSION;

const UUID: [u8; 16] = [7; 16];

fn key() -> RootKey {
    RootKey::from_key(Key::from_bytes(&mut [42u8; 32]))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let k = key();
    if mode & 1 == 0 {
        let _ = RootPointer::open(rest, &k, &UUID, RootSlot::A);
        return;
    }
    let nonce = [9u8; 24];
    let ad = [&b"TJRI root v1"[..], &UUID, b"a"].concat();
    let ct = tijori_core::crypto::aead_encrypt(k.key(), &nonce, rest, &ad);
    let mut file = vec![ROOT_VERSION];
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ct);
    if let Ok(r) = RootPointer::open(&file, &k, &UUID, RootSlot::A) {
        // Strict decoding means accepted CBOR is already canonical.
        assert_eq!(r.to_cbor(), rest);
    }
});
