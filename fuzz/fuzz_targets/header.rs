#![no_main]
//! Header parser: anything accepted must serialize back to the same bytes.

use libfuzzer_sys::fuzz_target;
use tijori_core::format::Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::parse(data) {
        assert_eq!(h.to_bytes(), data);
    }
});
