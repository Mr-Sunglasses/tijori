//! Device rollback records (spec §10): each device remembers the newest
//! revision of each vault it has seen, and warns when a drive goes backwards.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::crypto::{AEAD_NONCE_LEN, HASH_LEN, Key, aead_decrypt, aead_encrypt, random_array};
use crate::error::{Error, Result};
use crate::format::cbor::{self, Value, decode_map};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackRecord {
    pub max_rev: u64,
    /// Root hash at `max_rev`.
    pub root_hash: [u8; HASH_LEN],
    /// Unix seconds.
    pub last_seen: u64,
}

/// Result of comparing the drive with this device's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackStatus {
    /// No record on this device: first use here.
    FirstUse,
    Normal,
    /// Same revision as seen before, different contents.
    Fork {
        seen_rev: u64,
    },
    /// The drive is older than a revision this device has seen.
    Rollback {
        seen_rev: u64,
    },
    /// No rollback store was configured.
    NotChecked,
}

impl RollbackStatus {
    pub fn is_warning(self) -> bool {
        matches!(
            self,
            RollbackStatus::Fork { .. } | RollbackStatus::Rollback { .. }
        )
    }
}

pub fn compare(
    record: Option<&RollbackRecord>,
    rev: u64,
    root_hash: &[u8; HASH_LEN],
) -> RollbackStatus {
    match record {
        None => RollbackStatus::FirstUse,
        Some(r) if rev > r.max_rev => RollbackStatus::Normal,
        Some(r) if rev == r.max_rev && crate::crypto::ct_eq(root_hash, &r.root_hash) => {
            RollbackStatus::Normal
        }
        Some(r) if rev == r.max_rev => RollbackStatus::Fork {
            seen_rev: r.max_rev,
        },
        Some(r) => RollbackStatus::Rollback {
            seen_rev: r.max_rev,
        },
    }
}

/// Where records live. Implementations must keep them off the drive.
pub trait RollbackStore: Send + Sync {
    fn load(&self, vault_uuid: &[u8; 16]) -> Result<Option<RollbackRecord>>;
    fn save(&self, vault_uuid: &[u8; 16], record: &RollbackRecord) -> Result<()>;
}

/// Records in memory, for tests and sessions without a data folder.
#[derive(Default)]
pub struct MemRollbackStore(Mutex<HashMap<[u8; 16], RollbackRecord>>);

impl RollbackStore for MemRollbackStore {
    fn load(&self, vault_uuid: &[u8; 16]) -> Result<Option<RollbackRecord>> {
        Ok(self.0.lock().unwrap().get(vault_uuid).copied())
    }

    fn save(&self, vault_uuid: &[u8; 16], record: &RollbackRecord) -> Result<()> {
        self.0.lock().unwrap().insert(*vault_uuid, *record);
        Ok(())
    }
}

/// One encrypted file per vault in a private folder:
/// `nonce || AEAD(key, nonce, cbor{1: max_rev, 2: root_hash, 3: last_seen},
/// "TJRI rollback v1" || vault_uuid)`. The key comes from the OS keychain
/// (see `host`), or from a key file when no keychain is available.
pub struct FileRollbackStore {
    dir: PathBuf,
    key: Key,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl FileRollbackStore {
    pub fn new(dir: impl Into<PathBuf>, key: Key) -> Self {
        FileRollbackStore {
            dir: dir.into(),
            key: key.into_locked(),
        }
    }

    fn path(&self, uuid: &[u8; 16]) -> PathBuf {
        self.dir.join(format!("{}.rec", hex(uuid)))
    }

    fn ad(uuid: &[u8; 16]) -> Vec<u8> {
        [&b"TJRI rollback v1"[..], uuid].concat()
    }
}

impl RollbackStore for FileRollbackStore {
    fn load(&self, vault_uuid: &[u8; 16]) -> Result<Option<RollbackRecord>> {
        let data = match std::fs::read(self.path(vault_uuid)) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::from_io(e, "reading rollback record")),
        };
        if data.len() < AEAD_NONCE_LEN {
            return Err(Error::damaged("rollback record is truncated"));
        }
        let nonce: &[u8; AEAD_NONCE_LEN] = data[..AEAD_NONCE_LEN].try_into().expect("24 bytes");
        let pt = aead_decrypt(
            &self.key,
            nonce,
            &data[AEAD_NONCE_LEN..],
            &Self::ad(vault_uuid),
        )
        .ok_or_else(|| Error::tampered("this device's rollback record failed authentication"))?;
        let mut m = decode_map(&pt, "rollback record")?;
        Ok(Some(RollbackRecord {
            max_rev: m.uint(1, "max_rev")?,
            root_hash: m.bytes(2, "root_hash")?,
            last_seen: m.uint(3, "last_seen")?,
        }))
    }

    fn save(&self, vault_uuid: &[u8; 16], r: &RollbackRecord) -> Result<()> {
        let pt = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(r.max_rev)),
            (Value::Uint(2), Value::Bytes(r.root_hash.to_vec())),
            (Value::Uint(3), Value::Uint(r.last_seen)),
        ]));
        let nonce = random_array::<AEAD_NONCE_LEN>();
        let mut out = nonce.to_vec();
        out.extend(aead_encrypt(&self.key, &nonce, &pt, &Self::ad(vault_uuid)));
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| Error::from_io(e, "creating rollback folder"))?;
        let path = self.path(vault_uuid);
        let tmp = path.with_extension("rec.tmp");
        std::fs::write(&tmp, &out).map_err(|e| Error::from_io(e, "writing rollback record"))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::from_io(e, "writing rollback record"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_table() {
        let rec = RollbackRecord {
            max_rev: 5,
            root_hash: [1; 32],
            last_seen: 0,
        };
        assert_eq!(compare(None, 1, &[0; 32]), RollbackStatus::FirstUse);
        assert_eq!(compare(Some(&rec), 6, &[9; 32]), RollbackStatus::Normal);
        assert_eq!(compare(Some(&rec), 5, &[1; 32]), RollbackStatus::Normal);
        assert_eq!(
            compare(Some(&rec), 5, &[2; 32]),
            RollbackStatus::Fork { seen_rev: 5 }
        );
        assert_eq!(
            compare(Some(&rec), 4, &[1; 32]),
            RollbackStatus::Rollback { seen_rev: 5 }
        );
    }

    #[test]
    fn file_store_round_trip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileRollbackStore::new(dir.path(), Key::from_bytes(&mut [4; 32]));
        let uuid = [7u8; 16];
        assert_eq!(store.load(&uuid).unwrap(), None);
        let rec = RollbackRecord {
            max_rev: 3,
            root_hash: [8; 32],
            last_seen: 1_700_000_000,
        };
        store.save(&uuid, &rec).unwrap();
        assert_eq!(store.load(&uuid).unwrap(), Some(rec));
        let other = FileRollbackStore::new(dir.path(), Key::from_bytes(&mut [5; 32]));
        assert_eq!(
            other.load(&uuid).unwrap_err().class(),
            crate::ErrorClass::Tampered
        );
    }
}
