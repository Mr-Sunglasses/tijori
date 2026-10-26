//! Keyslots (spec §5.2): 128 bytes each, wrapping MK under a KEK.

use std::fmt;

use crate::crypto::{AEAD_NONCE_LEN, Kek, Key, MasterKey, SALT_LEN, aead_decrypt, aead_encrypt};
use crate::error::{Error, Result};

pub const SLOT_LEN: usize = 128;
pub const SLOT_COUNT: usize = 8;

/// Reader limits for Argon2id parameters (spec §12).
pub const ARGON_MEM_MIN_KIB: u32 = 65_536;
pub const ARGON_MEM_MAX_KIB: u32 = 1_048_576;
pub const ARGON_OPS_MIN: u32 = 2;
pub const ARGON_OPS_MAX: u32 = 64;
/// Writers should not create slots above this (spec §12).
pub const ARGON_MEM_WRITER_MAX_KIB: u32 = 262_144;

const KDF_ARGON2ID: u8 = 1;
const KDF_BLAKE2B: u8 = 2;

/// The slot types this version understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// Type 1.
    Password,
    /// Type 2.
    PasswordKeyfile,
    /// Type 3.
    Recovery,
}

impl SlotKind {
    pub fn slot_type(self) -> u8 {
        match self {
            SlotKind::Password => 1,
            SlotKind::PasswordKeyfile => 2,
            SlotKind::Recovery => 3,
        }
    }

    fn kdf_id(self) -> u8 {
        match self {
            SlotKind::Password | SlotKind::PasswordKeyfile => KDF_ARGON2ID,
            SlotKind::Recovery => KDF_BLAKE2B,
        }
    }

    /// `None` for empty slots and for type/KDF combinations from newer
    /// versions, which readers skip (spec §13).
    fn from_fields(slot_type: u8, kdf_id: u8) -> Option<Self> {
        match (slot_type, kdf_id) {
            (1, KDF_ARGON2ID) => Some(SlotKind::Password),
            (2, KDF_ARGON2ID) => Some(SlotKind::PasswordKeyfile),
            (3, KDF_BLAKE2B) => Some(SlotKind::Recovery),
            _ => None,
        }
    }

    pub fn uses_argon(self) -> bool {
        self.kdf_id() == KDF_ARGON2ID
    }
}

impl fmt::Display for SlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SlotKind::Password => "password",
            SlotKind::PasswordKeyfile => "password + keyfile",
            SlotKind::Recovery => "recovery phrase",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgonParams {
    pub mem_kib: u32,
    pub ops: u32,
}

impl ArgonParams {
    pub fn within_reader_limits(self) -> bool {
        (ARGON_MEM_MIN_KIB..=ARGON_MEM_MAX_KIB).contains(&self.mem_kib)
            && (ARGON_OPS_MIN..=ARGON_OPS_MAX).contains(&self.ops)
    }
}

/// One 128-byte keyslot, kept as raw bytes so it round-trips exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct Keyslot {
    raw: [u8; SLOT_LEN],
}

impl fmt::Debug for Keyslot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keyslot(type {}, kdf {})",
            self.slot_type(),
            self.kdf_id()
        )
    }
}

/// `ad = "TJRI ks v1" || vault_uuid || slot_index || keyslot bytes 0..32`.
fn slot_ad(uuid: &[u8; 16], index: u8, prefix: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(10 + 16 + 1 + 32);
    ad.extend_from_slice(b"TJRI ks v1");
    ad.extend_from_slice(uuid);
    ad.push(index);
    ad.extend_from_slice(&prefix[..32]);
    ad
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

impl Keyslot {
    pub fn empty() -> Self {
        Keyslot { raw: [0; SLOT_LEN] }
    }

    pub fn from_bytes(raw: [u8; SLOT_LEN]) -> Self {
        Keyslot { raw }
    }

    pub fn as_bytes(&self) -> &[u8; SLOT_LEN] {
        &self.raw
    }

    pub fn slot_type(&self) -> u8 {
        self.raw[0]
    }

    pub fn kdf_id(&self) -> u8 {
        self.raw[1]
    }

    pub fn is_empty(&self) -> bool {
        self.slot_type() == 0
    }

    pub fn kind(&self) -> Option<SlotKind> {
        SlotKind::from_fields(self.slot_type(), self.kdf_id())
    }

    pub fn argon_params(&self) -> ArgonParams {
        ArgonParams {
            mem_kib: u32_at(&self.raw, 4),
            ops: u32_at(&self.raw, 8),
        }
    }

    pub fn argon_lanes(&self) -> u32 {
        u32_at(&self.raw, 12)
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        self.raw[16..32].try_into().expect("16 bytes")
    }

    fn nonce(&self) -> &[u8; AEAD_NONCE_LEN] {
        self.raw[32..56].try_into().expect("24 bytes")
    }

    /// Spec §12 limits for slots this version understands. Unknown slot
    /// types are skipped, not checked.
    pub fn check_limits(&self) -> Result<()> {
        let Some(kind) = self.kind() else {
            return Ok(());
        };
        let p = self.argon_params();
        if kind.uses_argon() {
            if !p.within_reader_limits() || self.argon_lanes() != 1 {
                return Err(Error::damaged(format!(
                    "keyslot Argon2id parameters out of range (memory {} KiB, ops {}, lanes {})",
                    p.mem_kib,
                    p.ops,
                    self.argon_lanes()
                )));
            }
        } else if p.mem_kib != 0 || p.ops != 0 || self.argon_lanes() != 0 {
            return Err(Error::damaged(
                "recovery keyslot has Argon2id parameters set",
            ));
        }
        Ok(())
    }

    /// Builds a slot wrapping `mk` under `kek`. `params` is required for
    /// Argon2id slot kinds and ignored for recovery slots.
    #[allow(clippy::too_many_arguments)]
    pub fn wrap(
        kind: SlotKind,
        params: Option<ArgonParams>,
        salt: &[u8; SALT_LEN],
        nonce: &[u8; AEAD_NONCE_LEN],
        kek: &Kek,
        mk: &MasterKey,
        uuid: &[u8; 16],
        index: u8,
    ) -> Keyslot {
        let mut raw = [0u8; SLOT_LEN];
        raw[0] = kind.slot_type();
        raw[1] = kind.kdf_id();
        if kind.uses_argon() {
            let p = params.expect("Argon2id slots need parameters");
            raw[4..8].copy_from_slice(&p.mem_kib.to_le_bytes());
            raw[8..12].copy_from_slice(&p.ops.to_le_bytes());
            raw[12..16].copy_from_slice(&1u32.to_le_bytes());
        }
        raw[16..32].copy_from_slice(salt);
        raw[32..56].copy_from_slice(nonce);
        let wrapped = aead_encrypt(kek.key(), nonce, mk.as_bytes(), &slot_ad(uuid, index, &raw));
        raw[56..104].copy_from_slice(&wrapped);
        Keyslot { raw }
    }

    /// Opens the slot. `None` means the KEK, index or vault UUID is wrong, or
    /// a parameter was changed.
    pub fn unwrap(&self, kek: &Kek, uuid: &[u8; 16], index: u8) -> Option<MasterKey> {
        let ad = slot_ad(uuid, index, &self.raw);
        let pt = aead_decrypt(kek.key(), self.nonce(), &self.raw[56..104], &ad)?;
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&pt);
        Some(MasterKey::from_key(Key::from_bytes(&mut mk)))
    }
}
