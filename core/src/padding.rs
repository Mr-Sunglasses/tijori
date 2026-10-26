//! Padmé padding (spec §7.3).

/// Rounds a plaintext length `l` (at least 8) so that only its top few bits
/// survive. Lengths below 8 are returned unchanged; the format never stores
/// fewer than 8 plaintext bytes.
pub fn padme(l: u64) -> u64 {
    if l < 8 {
        return l;
    }
    let e = l.ilog2(); // floor(log2(L))
    let s = e.ilog2() + 1; // floor(log2(E)) + 1
    let mask = (1u64 << (e - s)) - 1;
    (l + mask) & !mask
}

/// Total plaintext stream length for `content_len` bytes of content (§7.2).
pub fn stream_total(content_len: u64, padding: bool) -> u64 {
    let raw = 8 + content_len;
    if padding { padme(raw) } else { raw }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn spec_examples() {
        for (content, stored) in [
            (0u64, 8u64),
            (92, 104),
            (992, 1024),
            (65_536, 67_584),
            (1_000_000, 1_015_808),
            (1_000_000_000, 1_006_632_960),
        ] {
            assert_eq!(stream_total(content, true), stored, "content {content}");
        }
        assert_eq!(stream_total(92, false), 100);
    }

    proptest! {
        #[test]
        fn overhead_is_bounded(l in 8u64..(1u64 << 62)) {
            let p = padme(l);
            prop_assert!(p >= l);
            // Spec §7.3: worst case about 11.6%; the plan allows at most 11.7%.
            prop_assert!(((p - l) as f64) / (l as f64) <= 0.117);
        }

        #[test]
        fn monotonic(a in 8u64..(1u64 << 62), b in 8u64..(1u64 << 62)) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(padme(lo) <= padme(hi));
        }

        #[test]
        fn idempotent(l in 8u64..(1u64 << 62)) {
            prop_assert_eq!(padme(padme(l)), padme(l));
        }
    }

    #[test]
    fn small_lengths_exhaustive() {
        let mut prev = 0;
        for l in 8..200_000u64 {
            let p = padme(l);
            assert!(p >= prev && p >= l);
            assert!(((p - l) as f64) / (l as f64) <= 0.117, "l = {l}");
            prev = p;
        }
    }
}
