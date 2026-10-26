//! The key hierarchy (spec §4): what the user enters, the KEK each slot type
//! derives from it, and the subkeys of MK.

use std::io::Read;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::{
    Blake2b, HeaderMacKey, Kek, Key, MasterKey, ObjectRootKey, RootKey, SALT_LEN, argon2id,
    blake2b_key, kdf,
};
use crate::error::{Error, Result};
use crate::format::{ArgonParams, Keyslot, SlotKind};
use crate::names::normalize_password;
use crate::recovery::RecoveryPhrase;

/// A password as typed. Normalized to NFC only when a KEK is derived.
pub struct Password(SecretString);

impl Password {
    pub fn new(password: impl Into<String>) -> Self {
        Password(SecretString::from(password.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        Password::new(s)
    }
}

/// A keyfile, kept only as `KF = H(none, "TJRI keyfile v1" || keyfile_bytes)`.
pub struct Keyfile(Key);

impl Keyfile {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Keyfile(blake2b_key(None, &[b"TJRI keyfile v1", bytes]))
    }

    /// Hashes a keyfile of any size without holding it in memory.
    pub fn from_reader(mut r: impl Read) -> std::io::Result<Self> {
        let mut h = Blake2b::new(None);
        h.update(b"TJRI keyfile v1");
        let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let mut out = h.finalize();
        Ok(Keyfile(Key::from_bytes(&mut out)))
    }
}

/// What the user offers to unlock a vault.
pub enum UnlockSecret {
    Password {
        password: Password,
        keyfile: Option<Keyfile>,
    },
    Recovery(RecoveryPhrase),
}

impl UnlockSecret {
    pub fn password(password: impl Into<String>) -> Self {
        UnlockSecret::Password {
            password: Password::new(password),
            keyfile: None,
        }
    }

    /// Slot kinds worth trying for this secret (unlock step 3).
    pub fn candidate_kinds(&self) -> &'static [SlotKind] {
        match self {
            UnlockSecret::Password { keyfile: None, .. } => &[SlotKind::Password],
            UnlockSecret::Password {
                keyfile: Some(_), ..
            } => &[SlotKind::Password, SlotKind::PasswordKeyfile],
            UnlockSecret::Recovery(_) => &[SlotKind::Recovery],
        }
    }
}

/// Type 1: `KEK = ARGON2ID(NFC(password), salt, m, t)`.
pub fn kek_password(password: &Password, salt: &[u8; SALT_LEN], p: ArgonParams) -> Result<Kek> {
    let nfc = normalize_password(password.expose());
    Ok(Kek::from_key(argon2id(
        nfc.as_bytes(),
        salt,
        p.mem_kib,
        p.ops,
    )?))
}

/// Type 2: `KEK = H(KF, "TJRI kek v1" || ARGON2ID(NFC(password), salt, m, t))`.
pub fn kek_password_keyfile(
    password: &Password,
    keyfile: &Keyfile,
    salt: &[u8; SALT_LEN],
    p: ArgonParams,
) -> Result<Kek> {
    let a = kek_password(password, salt, p)?;
    Ok(Kek::from_key(blake2b_key(
        Some(keyfile.0.as_bytes()),
        &[b"TJRI kek v1", a.as_bytes()],
    )))
}

/// Type 3: `KEK = H(E, "TJRI recovery v1" || salt)`.
pub fn kek_recovery(phrase: &RecoveryPhrase, salt: &[u8; SALT_LEN]) -> Kek {
    Kek::from_key(blake2b_key(
        Some(phrase.entropy()),
        &[b"TJRI recovery v1", salt],
    ))
}

/// Derives the KEK for one slot from the secret, or `None` if the secret
/// does not apply to this slot kind.
pub fn derive_kek(slot: &Keyslot, secret: &UnlockSecret) -> Result<Option<Kek>> {
    let Some(kind) = slot.kind() else {
        return Ok(None);
    };
    if !secret.candidate_kinds().contains(&kind) {
        return Ok(None);
    }
    let salt = slot.salt();
    Ok(Some(match (kind, secret) {
        (SlotKind::Password, UnlockSecret::Password { password, .. }) => {
            kek_password(password, salt, slot.argon_params())?
        }
        (
            SlotKind::PasswordKeyfile,
            UnlockSecret::Password {
                password,
                keyfile: Some(kf),
            },
        ) => kek_password_keyfile(password, kf, salt, slot.argon_params())?,
        (SlotKind::Recovery, UnlockSecret::Recovery(phrase)) => kek_recovery(phrase, salt),
        _ => return Err(Error::Other("slot kind and secret do not match".into())),
    }))
}

/// A header whose MAC verified under the MK one of its slots opened.
pub struct OpenedHeader {
    pub header: crate::format::Header,
    pub mk: MasterKey,
    pub subkeys: Subkeys,
    /// The slot that opened.
    pub slot_index: usize,
}

/// Unlock steps 1-5 for one copy of the header: parse and check limits, try
/// each candidate slot in order, then verify the MAC.
///
/// Errors: `Damaged`/`Unsupported` from parsing, `WrongSecret` when no slot
/// opens, `Tampered` when a slot opens but the MAC fails.
pub fn open_header(bytes: &[u8], secret: &UnlockSecret) -> Result<OpenedHeader> {
    let header = crate::format::Header::parse(bytes)?;
    for (index, slot) in header.slots.iter().enumerate() {
        let Some(kek) = derive_kek(slot, secret)? else {
            continue;
        };
        let Some(mk) = slot.unwrap(&kek, &header.vault_uuid, index as u8) else {
            continue;
        };
        let mk = mk.into_locked();
        let subkeys = Subkeys::derive(&mk);
        if !header.verify_mac(&subkeys.hmac) {
            return Err(Error::tampered("header MAC does not verify"));
        }
        return Ok(OpenedHeader {
            header,
            mk,
            subkeys,
            slot_index: index,
        });
    }
    Err(Error::WrongSecret)
}

/// `K_hmac`, `K_root` and `K_obj`, kept in locked memory while unlocked.
pub struct Subkeys {
    pub hmac: HeaderMacKey,
    pub root: RootKey,
    pub obj: ObjectRootKey,
}

impl Subkeys {
    pub fn derive(mk: &MasterKey) -> Self {
        Subkeys {
            hmac: HeaderMacKey::from_key(kdf(mk.key(), 1)).into_locked(),
            root: RootKey::from_key(kdf(mk.key(), 2)).into_locked(),
            obj: ObjectRootKey::from_key(kdf(mk.key(), 3)).into_locked(),
        }
    }
}
