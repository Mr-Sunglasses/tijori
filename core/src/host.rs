//! Desktop integration (feature `host`): the app's private data folder, this
//! device's writer ID and the rollback-record store, whose key lives in the
//! OS keychain (macOS Keychain, Linux Secret Service).
//!
//! When no keychain is available the key falls back to a file in the data
//! folder, readable only by the user, and a warning is returned. Set
//! `TIJORI_DATA_DIR` to use another data folder and `TIJORI_NO_KEYRING=1` to
//! skip the keychain (headless systems and tests).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto::{KEY_LEN, Key, random_array};
use crate::error::{Error, Result};
use crate::rollback::{FileRollbackStore, RollbackStore};

const KEYRING_SERVICE: &str = "Tijori";
const KEYRING_USER: &str = "rollback-record-key";

pub struct Host {
    pub data_dir: PathBuf,
    pub writer_id: [u8; 16],
    pub rollback: Arc<dyn RollbackStore>,
    /// Things the user should know, such as a missing keychain.
    pub warnings: Vec<String>,
}

/// macOS: `~/Library/Application Support/Tijori`; Linux and other Unix:
/// `$XDG_DATA_HOME/tijori` or `~/.local/share/tijori`.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("TIJORI_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::Other("cannot find a home folder for Tijori's data".into()))?;
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library/Application Support/Tijori"));
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"));
    Ok(base.join("tijori"))
}

/// Creates a file only the current user can read.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn read_or_create(path: &Path, len: usize) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(d) if d.len() == len => return Ok(d),
        Ok(_) => {
            return Err(Error::damaged(format!(
                "{} has the wrong size",
                path.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::from_io(e, "reading Tijori data")),
    }
    let fresh = random_array::<32>()[..len].to_vec();
    write_private(path, &fresh).map_err(|e| Error::from_io(e, "writing Tijori data"))?;
    Ok(fresh)
}

fn key_from_keyring() -> std::result::Result<Key, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())?;
    let mut bytes = match entry.get_secret() {
        Ok(b) => b,
        Err(keyring::Error::NoEntry) => {
            let fresh = random_array::<KEY_LEN>().to_vec();
            entry.set_secret(&fresh).map_err(|e| e.to_string())?;
            fresh
        }
        Err(e) => return Err(e.to_string()),
    };
    let mut arr: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "the keychain entry has the wrong size".to_string())?;
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(Key::from_bytes(&mut arr))
}

impl Host {
    /// Uses the default data folder, and the keychain unless `TIJORI_NO_KEYRING` is set.
    pub fn init() -> Result<Host> {
        Self::init_at(data_dir()?, std::env::var_os("TIJORI_NO_KEYRING").is_none())
    }

    pub fn init_at(data_dir: PathBuf, use_keyring: bool) -> Result<Host> {
        fs::create_dir_all(&data_dir)
            .map_err(|e| Error::from_io(e, "creating Tijori's data folder"))?;
        let mut warnings = Vec::new();
        let writer_id: [u8; 16] = read_or_create(&data_dir.join("device-id"), 16)?
            .try_into()
            .expect("16 bytes");

        let key = match use_keyring.then(key_from_keyring) {
            Some(Ok(k)) => k,
            other => {
                if let Some(Err(e)) = other {
                    warnings.push(format!(
                        "The system keychain is not available ({e}); rollback records are protected by a key \
                         file in {} instead.",
                        data_dir.display()
                    ));
                }
                let mut arr: [u8; KEY_LEN] =
                    read_or_create(&data_dir.join("rollback.key"), KEY_LEN)?
                        .try_into()
                        .expect("32 bytes");
                Key::from_bytes(&mut arr)
            }
        };
        Ok(Host {
            rollback: Arc::new(FileRollbackStore::new(data_dir.join("rollback"), key)),
            data_dir,
            writer_id,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::RollbackRecord;

    #[test]
    fn file_fallback_is_stable_across_runs() {
        let dir = tempfile::tempdir().unwrap();
        let a = Host::init_at(dir.path().to_path_buf(), false).unwrap();
        let rec = RollbackRecord {
            max_rev: 9,
            root_hash: [1; 32],
            last_seen: 5,
        };
        a.rollback.save(&[3; 16], &rec).unwrap();
        let b = Host::init_at(dir.path().to_path_buf(), false).unwrap();
        assert_eq!(a.writer_id, b.writer_id);
        assert_eq!(b.rollback.load(&[3; 16]).unwrap(), Some(rec));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("rollback.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "key file is private");
        }
    }
}
