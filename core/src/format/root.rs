//! Root pointer files `vault.root.a` / `vault.root.b` (spec §8.1).

use super::cbor::{self, Value, decode_map};
use crate::crypto::{AEAD_NONCE_LEN, HASH_LEN, RootKey, aead_decrypt, aead_encrypt};
use crate::error::{Error, Result};

pub const ROOT_VERSION: u8 = 1;
pub const ROOT_MIN_LEN: usize = 41;
pub const ROOT_MAX_LEN: usize = 4096;
pub const LABEL_MAX_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootSlot {
    A,
    B,
}

impl RootSlot {
    pub const BOTH: [RootSlot; 2] = [RootSlot::A, RootSlot::B];

    pub fn letter(self) -> u8 {
        match self {
            RootSlot::A => b'a',
            RootSlot::B => b'b',
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            RootSlot::A => "vault.root.a",
            RootSlot::B => "vault.root.b",
        }
    }

    pub fn other(self) -> RootSlot {
        match self {
            RootSlot::A => RootSlot::B,
            RootSlot::B => RootSlot::A,
        }
    }
}

/// Vault settings, stored encrypted in the root pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Padmé padding of new objects (on by default).
    pub padding: bool,
    /// Refuse to mount; use the vault only inside the app.
    pub private_only: bool,
    /// A display name, at most 64 bytes.
    pub label: String,
    pub unknown: Vec<(Value, Value)>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            padding: true,
            private_only: false,
            label: String::new(),
            unknown: Vec::new(),
        }
    }
}

impl Settings {
    pub fn check_label(label: &str) -> Result<()> {
        if label.len() > LABEL_MAX_LEN {
            return Err(Error::invalid(format!(
                "the label is longer than {LABEL_MAX_LEN} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootPointer {
    pub rev: u64,
    pub root_id: [u8; 32],
    pub root_hash: [u8; HASH_LEN],
    pub settings: Settings,
    /// Unix seconds.
    pub written_at: u64,
    pub writer_id: [u8; 16],
    pub unknown: Vec<(Value, Value)>,
}

fn ad(uuid: &[u8; 16], slot: RootSlot) -> Vec<u8> {
    let mut ad = Vec::with_capacity(12 + 16 + 1);
    ad.extend_from_slice(b"TJRI root v1");
    ad.extend_from_slice(uuid);
    ad.push(slot.letter());
    ad
}

impl RootPointer {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut settings = vec![
            (Value::Uint(1), Value::Bool(self.settings.padding)),
            (Value::Uint(2), Value::Bool(self.settings.private_only)),
            (Value::Uint(3), Value::Text(self.settings.label.clone())),
        ];
        settings.extend(self.settings.unknown.iter().cloned());
        let mut fields = vec![
            (Value::Uint(1), Value::Uint(self.rev)),
            (Value::Uint(2), Value::Bytes(self.root_id.to_vec())),
            (Value::Uint(3), Value::Bytes(self.root_hash.to_vec())),
            (Value::Uint(4), Value::Map(settings)),
            (Value::Uint(5), Value::Uint(self.written_at)),
            (Value::Uint(6), Value::Bytes(self.writer_id.to_vec())),
        ];
        fields.extend(self.unknown.iter().cloned());
        cbor::encode(&Value::Map(fields))
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let mut m = decode_map(data, "root pointer")?;
        let rev = m.uint(1, "rev")?;
        let root_id = m.bytes(2, "root_id")?;
        let root_hash = m.bytes(3, "root_hash")?;
        let mut s = m.map(4, "settings")?;
        let padding = s.bool(1, "padding")?;
        let private_only = s.bool(2, "private_only")?;
        let label = s.text(3, "label")?;
        if label.len() > LABEL_MAX_LEN {
            return Err(Error::damaged("label is longer than 64 bytes"));
        }
        let written_at = m.uint(5, "written_at")?;
        let writer_id = m.bytes(6, "writer_id")?;
        Ok(RootPointer {
            rev,
            root_id,
            root_hash,
            settings: Settings {
                padding,
                private_only,
                label,
                unknown: s.rest(),
            },
            written_at,
            writer_id,
            unknown: m.rest(),
        })
    }

    /// Encrypts into the bytes of a root pointer file.
    pub fn seal(
        &self,
        key: &RootKey,
        uuid: &[u8; 16],
        slot: RootSlot,
        nonce: &[u8; AEAD_NONCE_LEN],
    ) -> Vec<u8> {
        let ct = aead_encrypt(key.key(), nonce, &self.to_cbor(), &ad(uuid, slot));
        let mut out = Vec::with_capacity(1 + AEAD_NONCE_LEN + ct.len());
        out.push(ROOT_VERSION);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypts and parses a root pointer file.
    pub fn open(file: &[u8], key: &RootKey, uuid: &[u8; 16], slot: RootSlot) -> Result<Self> {
        if !(ROOT_MIN_LEN..=ROOT_MAX_LEN).contains(&file.len()) {
            return Err(Error::damaged(format!(
                "{} is {} bytes, outside {ROOT_MIN_LEN}..={ROOT_MAX_LEN}",
                slot.file_name(),
                file.len()
            )));
        }
        if file[0] != ROOT_VERSION {
            return Err(Error::unsupported(format!(
                "root pointer version {}",
                file[0]
            )));
        }
        let nonce: &[u8; AEAD_NONCE_LEN] = file[1..25].try_into().expect("24 bytes");
        let pt = aead_decrypt(key.key(), nonce, &file[25..], &ad(uuid, slot)).ok_or_else(|| {
            Error::tampered(format!("{} failed authentication", slot.file_name()))
        })?;
        RootPointer::from_cbor(&pt)
    }
}
