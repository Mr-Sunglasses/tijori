//! Thin, typed wrappers over the five primitives of spec §3, all from
//! `dryoc` (libsodium-compatible). Nothing else in the crate calls `dryoc`.

mod keys;
mod stream;

pub use keys::{HeaderMacKey, KEY_LEN, Kek, Key, MasterKey, ObjectKey, ObjectRootKey, RootKey};
pub use stream::{STREAM_ABYTES, STREAM_HEADER_LEN, StreamPull, StreamPush, StreamTag};

use dryoc::classic::crypto_aead_xchacha20poly1305_ietf as aead;
use dryoc::classic::crypto_generichash::{
    GenericHashState, crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update,
};
use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;
use dryoc::classic::crypto_pwhash::{PasswordHashAlgorithm, crypto_pwhash};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const SALT_LEN: usize = 16;
pub const AEAD_NONCE_LEN: usize = 24;
pub const AEAD_TAG_LEN: usize = 16;
pub const HASH_LEN: usize = 32;

/// The `crypto_kdf` context for all Tijori subkeys (spec §3).
const KDF_CONTEXT: &[u8; 8] = b"TJRIv1__";

/// Fills `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) {
    dryoc::rng::copy_randombytes(buf);
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random_bytes(&mut out);
    out
}

/// `ARGON2ID(password, salt, m, t)` with lanes = 1 and a 32-byte output.
/// `password` must already be NFC-normalized.
pub fn argon2id(password: &[u8], salt: &[u8; SALT_LEN], mem_kib: u32, ops: u32) -> Result<Key> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let memlimit = usize::try_from(u64::from(mem_kib) * 1024)
        .map_err(|_| Error::invalid("Argon2id memory does not fit in this address space"))?;
    crypto_pwhash(
        &mut out[..],
        password,
        salt,
        u64::from(ops),
        memlimit,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|e| Error::Other(format!("Argon2id failed: {e}")))?;
    Ok(Key::from_bytes(&mut out))
}

/// `H(key, msg)`: BLAKE2b with a 32-byte output and optional 32-byte key.
/// The message is the concatenation of `parts`.
pub fn blake2b(key: Option<&[u8; KEY_LEN]>, parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Blake2b::new(key);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// Like [`blake2b`], but the output is a key.
pub fn blake2b_key(key: Option<&[u8; KEY_LEN]>, parts: &[&[u8]]) -> Key {
    let mut out = blake2b(key, parts);
    Key::from_bytes(&mut out)
}

/// Incremental `H(key, msg)`.
pub struct Blake2b(GenericHashState);

impl Blake2b {
    pub fn new(key: Option<&[u8; KEY_LEN]>) -> Self {
        let state = crypto_generichash_init(key.map(|k| &k[..]), HASH_LEN)
            .expect("32-byte BLAKE2b output and key are valid");
        Blake2b(state)
    }

    pub fn update(&mut self, data: &[u8]) {
        crypto_generichash_update(&mut self.0, data);
    }

    pub fn finalize(self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        crypto_generichash_final(self.0, &mut out).expect("32-byte BLAKE2b output is valid");
        out
    }
}

/// One-shot unkeyed hash, used for object and root hashes.
pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    crypto_generichash(&mut out, data, None).expect("32-byte BLAKE2b output is valid");
    out
}

/// `KDF(key, id)`: libsodium `crypto_kdf_derive_from_key` with context `TJRIv1__`.
pub fn kdf(key: &Key, id: u64) -> Key {
    let mut out = [0u8; KEY_LEN];
    crypto_kdf_derive_from_key(&mut out, id, KDF_CONTEXT, key.as_bytes())
        .expect("32-byte subkey is valid");
    Key::from_bytes(&mut out)
}

/// XChaCha20-Poly1305 (IETF) encryption; returns ciphertext || tag.
pub fn aead_encrypt(key: &Key, nonce: &[u8; AEAD_NONCE_LEN], msg: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; msg.len() + AEAD_TAG_LEN];
    aead::crypto_aead_xchacha20poly1305_ietf_encrypt(
        &mut out,
        msg,
        Some(ad),
        nonce,
        key.as_bytes(),
    )
    .expect("AEAD message length is within limits");
    out
}

/// XChaCha20-Poly1305 (IETF) decryption. `None` means the tag did not verify
/// (or the input is shorter than a tag); the caller picks the error class.
pub fn aead_decrypt(
    key: &Key,
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    ad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let len = ciphertext.len().checked_sub(AEAD_TAG_LEN)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    aead::crypto_aead_xchacha20poly1305_ietf_decrypt(
        &mut out,
        ciphertext,
        Some(ad),
        nonce,
        key.as_bytes(),
    )
    .ok()?;
    Some(out)
}

/// Constant-time equality for MACs and hashes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip_and_tamper() {
        let key = Key::random();
        let nonce = random_array();
        let ct = aead_encrypt(&key, &nonce, b"secret", b"ad");
        assert_eq!(
            &aead_decrypt(&key, &nonce, &ct, b"ad").unwrap()[..],
            b"secret"
        );
        assert!(aead_decrypt(&key, &nonce, &ct, b"other ad").is_none());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_decrypt(&key, &nonce, &bad, b"ad").is_none());
        assert!(aead_decrypt(&key, &nonce, &ct[..10], b"ad").is_none());
    }

    #[test]
    fn incremental_hash_matches_one_shot() {
        let key = [7u8; 32];
        let parts: [&[u8]; 3] = [b"TJRI", b" obj", b" v1"];
        assert_eq!(
            blake2b(Some(&key), &parts),
            blake2b(Some(&key), &[b"TJRI obj v1"])
        );
        assert_eq!(blake2b(None, &[b"abc"]), hash(b"abc"));
    }

    #[test]
    fn locked_keys_keep_their_bytes() {
        let mut bytes = [9u8; 32];
        let key = Key::from_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; 32], "caller copy is wiped");
        let locked = key.into_locked();
        assert_eq!(locked.as_bytes(), &[9u8; 32]);
        assert_eq!(locked.duplicate().as_bytes(), &[9u8; 32]);
    }

    #[test]
    fn ct_eq_checks_length() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
