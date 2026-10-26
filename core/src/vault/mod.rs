//! The vault engine: create, unlock, read, write, commit, keyslots, re-key,
//! verify and garbage collection, over any [`Storage`](crate::storage::Storage).

mod lock;
mod maint;
mod open;
mod ops;
mod path;
mod tree;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use lock::{LockInfo, STALE_AFTER_SECS, break_lock, read_lock};
pub use maint::{GcReport, KeyslotInfo, NewSlot, VerifyProblem, VerifyReport};
pub use open::{ArgonChoice, CreateOptions, ReadOnlyReason, UnlockOptions, UnlockReport};
pub use ops::FileReader;
pub use path::{MAX_DEPTH, VaultPath};

use crate::crypto::MasterKey;
use crate::format::{Header, RootPointer, RootSlot, Settings};
use crate::keys::Subkeys;
use crate::rollback::{RollbackStatus, RollbackStore};
use crate::storage::Storage;
use lock::WriteLock;
use tree::DirNode;

pub const VAULT_DIR: &str = "TIJORI";
pub const HEADER_PATH: &str = "TIJORI/vault.header";
pub const HEADER_BACKUP_PATH: &str = "TIJORI/vault.header.bak";
pub const LOCK_PATH: &str = "TIJORI/.lock";
pub const OBJECTS_DIR: &str = "TIJORI/objects";
pub const README_PATH: &str = "README-TIJORI.txt";

pub const README_TEXT: &str = "This drive holds a Tijori vault (folder TIJORI).\n\
The files inside are encrypted. Open them with the Tijori app:\n\
install it, plug in this drive, and enter your password.\n\
Do not rename, edit or delete anything inside the TIJORI folder.\n";

/// What the app must tell the user after a password change (spec §14.2).
pub const PASSWORD_CHANGE_NOTE: &str = "Your password is changed. Someone who copied this drive before, and \
knows the old password, can still open that old copy. To lock them out of new changes too, re-key the vault.";

pub fn root_path(slot: RootSlot) -> String {
    format!("{VAULT_DIR}/{}", slot.file_name())
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Read-write needs the write lock; read-only never writes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

/// A file or folder as frontends see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    /// Content bytes for files, 0 for folders.
    pub size: u64,
    /// Unix milliseconds.
    pub mtime_ms: i64,
    pub executable: bool,
}

/// Metadata stored with an imported file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mtime_ms: i64,
    pub executable: bool,
}

impl FileMeta {
    pub fn now() -> Self {
        FileMeta {
            mtime_ms: now_ms(),
            executable: false,
        }
    }
}

/// Progress of a long operation. Callbacks return `false` to cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub phase: Phase,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Import,
    Verify,
    Rekey,
    Gc,
}

/// An unlocked vault. Keys live here, in locked memory where possible, and
/// are wiped when the vault is dropped.
pub struct Vault {
    storage: Arc<dyn Storage>,
    header: Header,
    mk: MasterKey,
    keys: Subkeys,
    /// The last committed root pointer and the slot that holds it.
    root: RootPointer,
    root_slot: RootSlot,
    tree: DirNode,
    settings: Settings,
    requested_mode: OpenMode,
    lock: Option<WriteLock>,
    read_only_reason: Option<ReadOnlyReason>,
    writer_id: [u8; 16],
    rollback: Option<Arc<dyn RollbackStore>>,
    rollback_status: RollbackStatus,
    /// Problems that happened after a commit point, such as failing to
    /// update the rollback record.
    warnings: Vec<String>,
}

impl Vault {
    pub fn vault_uuid(&self) -> [u8; 16] {
        self.header.vault_uuid
    }

    pub fn rev(&self) -> u64 {
        self.root.rev
    }

    /// `(format_major, format_minor)` from the header.
    pub fn format_version(&self) -> (u16, u16) {
        (self.header.format_major, self.header.format_minor)
    }

    /// Unix seconds of the last commit.
    pub fn last_written(&self) -> u64 {
        self.root.written_at
    }

    /// The device that made the last commit.
    pub fn last_writer_id(&self) -> [u8; 16] {
        self.root.writer_id
    }

    /// This session's device ID.
    pub fn writer_id(&self) -> [u8; 16] {
        self.writer_id
    }

    pub fn is_writable(&self) -> bool {
        self.lock.is_some()
    }

    pub fn read_only_reason(&self) -> Option<&ReadOnlyReason> {
        self.read_only_reason.as_ref()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Uncommitted changes, including folders already written whose root
    /// pointer write failed.
    pub fn has_pending_changes(&self) -> bool {
        let committed = self
            .tree
            .obj
            .is_some_and(|o| o.id == self.root.root_id && o.hash == self.root.root_hash);
        !committed || self.settings != self.root.settings
    }

    pub fn rollback_status(&self) -> RollbackStatus {
        self.rollback_status
    }

    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    /// Commits pending changes, releases the write lock and wipes all keys.
    pub fn lock(mut self) -> crate::Result<()> {
        let committed = if self.is_writable() {
            self.commit()
        } else {
            Ok(())
        };
        let released = match self.lock.take() {
            Some(l) => l.release(),
            None => Ok(()),
        };
        committed.and(released)
    }
}
