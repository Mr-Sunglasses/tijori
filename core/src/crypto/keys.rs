//! Key types. Every key is wiped on drop and has no `Debug`, `Clone` or
//! serialization, so it cannot be logged or copied by accident.

use dryoc::protected::{HeapByteArray, Locked, NewLocked};
use dryoc::types::{ByteArray, MutBytes};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;

enum KeyMem {
    /// `mlock`ed, guard-paged memory (and `MADV_DONTDUMP` on Linux).
    Locked(Locked<HeapByteArray<KEY_LEN>>),
    /// Ordinary heap memory, zeroized on drop.
    Heap(Box<Zeroizing<[u8; KEY_LEN]>>),
}

/// A 32-byte secret key.
pub struct Key(KeyMem);

impl Key {
    /// Takes the bytes and wipes the caller's copy.
    pub fn from_bytes(bytes: &mut [u8; KEY_LEN]) -> Self {
        let key = Key(KeyMem::Heap(Box::new(Zeroizing::new(*bytes))));
        bytes.zeroize();
        key
    }

    /// A fresh key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut key = Key(KeyMem::Heap(Box::new(Zeroizing::new([0u8; KEY_LEN]))));
        if let KeyMem::Heap(b) = &mut key.0 {
            super::random_bytes(&mut b[..]);
        }
        key
    }

    /// Moves the key into locked memory if the OS allows it. Used for keys
    /// that live for the whole unlocked session. Falls back to the heap when
    /// the locked-memory limit is reached.
    pub fn into_locked(self) -> Self {
        if matches!(self.0, KeyMem::Locked(_)) {
            return self;
        }
        match HeapByteArray::<KEY_LEN>::new_locked() {
            Ok(mut locked) => {
                locked.as_mut_slice().copy_from_slice(self.as_bytes());
                Key(KeyMem::Locked(locked))
            }
            Err(_) => self,
        }
    }

    pub fn is_locked_in_memory(&self) -> bool {
        matches!(self.0, KeyMem::Locked(_))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        match &self.0 {
            KeyMem::Locked(l) => l.as_array(),
            KeyMem::Heap(b) => b,
        }
    }

    /// An independent copy (for example to keep a key across a re-key).
    pub fn duplicate(&self) -> Self {
        let mut bytes = *self.as_bytes();
        let copy = Key::from_bytes(&mut bytes);
        if self.is_locked_in_memory() {
            copy.into_locked()
        } else {
            copy
        }
    }
}

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(Key);

        impl $name {
            pub fn from_key(key: Key) -> Self {
                Self(key)
            }

            pub fn key(&self) -> &Key {
                &self.0
            }

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                self.0.as_bytes()
            }

            pub fn into_locked(self) -> Self {
                Self(self.0.into_locked())
            }

            pub fn duplicate(&self) -> Self {
                Self(self.0.duplicate())
            }
        }
    };
}

key_type!(
    /// The vault's Master Key (MK). Never stored unwrapped.
    MasterKey
);
key_type!(
    /// A key-encryption key derived from a password, keyfile or recovery phrase.
    Kek
);
key_type!(
    /// `K_hmac = KDF(MK, 1)`: authenticates the header.
    HeaderMacKey
);
key_type!(
    /// `K_root = KDF(MK, 2)`: encrypts the root pointers.
    RootKey
);
key_type!(
    /// `K_obj = KDF(MK, 3)`: parent of every object key.
    ObjectRootKey
);
key_type!(
    /// The key of one object: `H(K_obj, "TJRI obj v1" || kind || object_id)`.
    ObjectKey
);
