//! The vault header (spec §5.1): exactly 1120 bytes.

use std::fmt;

use super::keyslot::{Keyslot, SLOT_COUNT, SLOT_LEN};
use crate::crypto::{HASH_LEN, HeaderMacKey, blake2b, ct_eq};
use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 1120;
pub const MAC_OFFSET: usize = 1088;
pub const MAGIC: &[u8; 4] = b"TJRI";
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
/// `required_features` bits this version understands.
pub const KNOWN_REQUIRED_FEATURES: u32 = 0;

#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    pub format_major: u16,
    pub format_minor: u16,
    pub required_features: u32,
    pub optional_features: u32,
    pub vault_uuid: [u8; 16],
    pub slots: [Keyslot; SLOT_COUNT],
    pub reserved: [u8; 32],
    pub mac: [u8; HASH_LEN],
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("format", &(self.format_major, self.format_minor))
            .field("required_features", &self.required_features)
            .field("optional_features", &self.optional_features)
            .field("slots", &self.slots)
            .finish_non_exhaustive()
    }
}

impl Header {
    /// A v1.0 header with no keyslots and no MAC yet.
    pub fn new(vault_uuid: [u8; 16]) -> Self {
        Header {
            format_major: FORMAT_MAJOR,
            format_minor: FORMAT_MINOR,
            required_features: 0,
            optional_features: 0,
            vault_uuid,
            slots: std::array::from_fn(|_| Keyslot::empty()),
            reserved: [0; 32],
            mac: [0; HASH_LEN],
        }
    }

    /// Unlock steps 1-2: size, magic, version, feature bits and slot limits.
    /// Nothing expensive happens before these checks pass.
    pub fn parse(bytes: &[u8]) -> Result<Header> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::damaged(format!(
                "vault.header is {} bytes, expected {HEADER_LEN}",
                bytes.len()
            )));
        }
        if &bytes[0..4] != MAGIC {
            return Err(Error::damaged("vault.header does not start with TJRI"));
        }
        let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("4 bytes"));
        let format_major = u16_at(4);
        if format_major != FORMAT_MAJOR {
            return Err(Error::unsupported(format!("vault format {format_major}.x")));
        }
        let required_features = u32_at(8);
        let unknown = required_features & !KNOWN_REQUIRED_FEATURES;
        if unknown != 0 {
            return Err(Error::unsupported(format!(
                "required feature bits {unknown:#x}"
            )));
        }
        let slots: [Keyslot; SLOT_COUNT] = std::array::from_fn(|i| {
            let off = 32 + i * SLOT_LEN;
            Keyslot::from_bytes(bytes[off..off + SLOT_LEN].try_into().expect("128 bytes"))
        });
        for s in &slots {
            s.check_limits()?;
        }
        if slots.iter().all(Keyslot::is_empty) {
            return Err(Error::damaged("vault.header has no keyslots"));
        }
        Ok(Header {
            format_major,
            format_minor: u16_at(6),
            required_features,
            optional_features: u32_at(12),
            vault_uuid: bytes[16..32].try_into().expect("16 bytes"),
            slots,
            reserved: bytes[1056..1088].try_into().expect("32 bytes"),
            mac: bytes[MAC_OFFSET..].try_into().expect("32 bytes"),
        })
    }

    /// Bytes 0..1088, which the MAC covers.
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&self.format_major.to_le_bytes());
        b.extend_from_slice(&self.format_minor.to_le_bytes());
        b.extend_from_slice(&self.required_features.to_le_bytes());
        b.extend_from_slice(&self.optional_features.to_le_bytes());
        b.extend_from_slice(&self.vault_uuid);
        for s in &self.slots {
            b.extend_from_slice(s.as_bytes());
        }
        b.extend_from_slice(&self.reserved);
        debug_assert_eq!(b.len(), MAC_OFFSET);
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.mac);
        b
    }

    pub fn compute_mac(&self, key: &HeaderMacKey) -> [u8; HASH_LEN] {
        blake2b(Some(key.as_bytes()), &[&self.body()])
    }

    /// Sets `header_mac` for the current contents.
    pub fn seal(&mut self, key: &HeaderMacKey) {
        self.mac = self.compute_mac(key);
    }

    /// Constant-time MAC check (unlock step 5).
    pub fn verify_mac(&self, key: &HeaderMacKey) -> bool {
        ct_eq(&self.compute_mac(key), &self.mac)
    }

    /// Index of the first empty slot.
    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(Keyslot::is_empty)
    }
}
