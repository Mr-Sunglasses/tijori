//! secretstream XChaCha20-Poly1305 (spec §3 `STREAM`).

use dryoc::classic::crypto_secretstream_xchacha20poly1305 as ss;
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
};

use super::Key;

pub const STREAM_HEADER_LEN: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
pub const STREAM_ABYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTag {
    Message,
    Push,
    Rekey,
    Final,
    Unknown(u8),
}

impl StreamTag {
    fn to_u8(self) -> u8 {
        match self {
            StreamTag::Message => CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
            StreamTag::Push => CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
            StreamTag::Rekey => CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
            StreamTag::Final => CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            StreamTag::Unknown(t) => t,
        }
    }

    fn from_u8(t: u8) -> Self {
        match t {
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE => StreamTag::Message,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH => StreamTag::Push,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY => StreamTag::Rekey,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL => StreamTag::Final,
            other => StreamTag::Unknown(other),
        }
    }
}

/// Encrypting side of a secretstream.
pub struct StreamPush(ss::State);

impl StreamPush {
    /// Starts a stream; the header is random and must be stored before the chunks.
    pub fn new(key: &Key) -> (Self, [u8; STREAM_HEADER_LEN]) {
        let mut state = ss::State::new();
        let mut header = [0u8; STREAM_HEADER_LEN];
        ss::crypto_secretstream_xchacha20poly1305_init_push(
            &mut state,
            &mut header,
            key.as_bytes(),
        );
        (StreamPush(state), header)
    }

    /// Encrypts one chunk, appending `msg.len() + 17` bytes to `out`.
    pub fn push(&mut self, msg: &[u8], ad: &[u8], tag: StreamTag, out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + msg.len() + STREAM_ABYTES, 0);
        ss::crypto_secretstream_xchacha20poly1305_push(
            &mut self.0,
            &mut out[start..],
            msg,
            Some(ad),
            tag.to_u8(),
        )
        .expect("chunk length is within limits");
    }
}

/// Decrypting side of a secretstream.
pub struct StreamPull(ss::State);

impl StreamPull {
    pub fn new(key: &Key, header: &[u8; STREAM_HEADER_LEN]) -> Self {
        let mut state = ss::State::new();
        ss::crypto_secretstream_xchacha20poly1305_init_pull(&mut state, header, key.as_bytes());
        StreamPull(state)
    }

    /// Decrypts one chunk into `out` (resized to the plaintext length).
    /// `None` means authentication failed or the chunk is shorter than a tag.
    pub fn pull(&mut self, chunk: &[u8], ad: &[u8], out: &mut Vec<u8>) -> Option<StreamTag> {
        let len = chunk.len().checked_sub(STREAM_ABYTES)?;
        out.resize(len, 0);
        let mut tag = 0u8;
        ss::crypto_secretstream_xchacha20poly1305_pull(&mut self.0, out, &mut tag, chunk, Some(ad))
            .ok()?;
        Some(StreamTag::from_u8(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_tags() {
        let key = Key::random();
        let (mut push, header) = StreamPush::new(&key);
        let mut c1 = Vec::new();
        let mut c2 = Vec::new();
        push.push(b"one", b"ad", StreamTag::Message, &mut c1);
        push.push(b"", b"ad", StreamTag::Final, &mut c2);
        assert_eq!(c1.len(), 3 + STREAM_ABYTES);

        let mut pull = StreamPull::new(&key, &header);
        let mut out = Vec::new();
        assert_eq!(pull.pull(&c1, b"ad", &mut out), Some(StreamTag::Message));
        assert_eq!(out, b"one");
        assert_eq!(pull.pull(&c2, b"ad", &mut out), Some(StreamTag::Final));
        assert!(out.is_empty());

        let mut pull = StreamPull::new(&key, &header);
        assert_eq!(
            pull.pull(&c2, b"ad", &mut out),
            None,
            "reordered chunk fails"
        );
    }
}
