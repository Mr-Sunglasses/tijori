#![no_main]
//! Directory CBOR parser: accepted input must re-encode to identical bytes.

use libfuzzer_sys::fuzz_target;
use tijori_core::format::Directory;

fuzz_target!(|data: &[u8]| {
    if let Ok(d) = Directory::decode(data) {
        assert_eq!(d.encode(), data);
    }
});
