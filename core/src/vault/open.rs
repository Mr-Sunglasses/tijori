//! Creating and unlocking vaults (spec §6, Plan Milestone 2).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::lock::{Acquire, LockInfo, WriteLock};
use super::tree::{DirNode, ObjRef, Objects};
use super::{
    HEADER_BACKUP_PATH, HEADER_PATH, OBJECTS_DIR, OpenMode, README_PATH, README_TEXT, Vault,
    now_secs, root_path,
};
use crate::crypto::{Key, MasterKey, SALT_LEN, argon2id, random_array};
use crate::error::{Error, ErrorClass, Result};
use crate::format::keyslot::{ARGON_MEM_MIN_KIB, ARGON_MEM_WRITER_MAX_KIB, ARGON_OPS_MAX};
use crate::format::{
    ArgonParams, Directory, Header, Keyslot, RootPointer, RootSlot, Settings, SlotKind,
};
use crate::keys::{
    OpenedHeader, Subkeys, kek_password, kek_password_keyfile, kek_recovery, open_header,
};
use crate::recovery::RecoveryPhrase;
use crate::rollback::{RollbackRecord, RollbackStatus, RollbackStore, compare};
use crate::storage::Storage;
use crate::{Keyfile, Password, UnlockSecret, strength};

/// How to pick Argon2id parameters for a new password slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgonChoice {
    /// Fixed memory; raise `t` from `min_ops` until one hash takes about `target`.
    Calibrate {
        mem_kib: u32,
        min_ops: u32,
        target: Duration,
    },
    Fixed(ArgonParams),
}

impl ArgonChoice {
    /// Spec §5.4: 256 MiB, t >= 3, about 1 s.
    pub fn desktop() -> Self {
        ArgonChoice::Calibrate {
            mem_kib: 262_144,
            min_ops: 3,
            target: Duration::from_secs(1),
        }
    }

    /// Spec §5.4: 128 MiB, t >= 4, about 1 s.
    pub fn android() -> Self {
        ArgonChoice::Calibrate {
            mem_kib: 131_072,
            min_ops: 4,
            target: Duration::from_secs(1),
        }
    }

    /// The cheapest parameters readers accept. For tests only.
    pub fn minimum() -> Self {
        ArgonChoice::Fixed(ArgonParams {
            mem_kib: ARGON_MEM_MIN_KIB,
            ops: 2,
        })
    }

    pub fn resolve(&self) -> Result<ArgonParams> {
        match *self {
            ArgonChoice::Fixed(p) => {
                if !p.within_reader_limits() || p.mem_kib > ARGON_MEM_WRITER_MAX_KIB {
                    return Err(Error::invalid(
                        "Argon2id parameters are outside the allowed range",
                    ));
                }
                Ok(p)
            }
            ArgonChoice::Calibrate {
                mem_kib,
                min_ops,
                target,
            } => {
                let mem_kib = mem_kib.clamp(ARGON_MEM_MIN_KIB, ARGON_MEM_WRITER_MAX_KIB);
                let min_ops = min_ops.clamp(2, ARGON_OPS_MAX);
                let salt: [u8; SALT_LEN] = random_array();
                let start = Instant::now();
                argon2id(b"tijori calibration", &salt, mem_kib, min_ops)?;
                let per_run = start.elapsed().as_secs_f64().max(1e-3);
                // Argon2id time grows linearly with t.
                let ops = (f64::from(min_ops) * target.as_secs_f64() / per_run).floor() as u32;
                Ok(ArgonParams {
                    mem_kib,
                    ops: ops.clamp(min_ops, ARGON_OPS_MAX),
                })
            }
        }
    }
}

pub struct CreateOptions {
    pub password: Password,
    pub keyfile: Option<Keyfile>,
    pub argon: ArgonChoice,
    pub settings: Settings,
    pub writer_id: [u8; 16],
    pub rollback: Option<Arc<dyn RollbackStore>>,
}

impl CreateOptions {
    pub fn new(password: Password) -> Self {
        CreateOptions {
            password,
            keyfile: None,
            argon: ArgonChoice::desktop(),
            settings: Settings::default(),
            writer_id: random_array(),
            rollback: None,
        }
    }
}

pub struct UnlockOptions {
    pub mode: OpenMode,
    pub writer_id: [u8; 16],
    pub rollback: Option<Arc<dyn RollbackStore>>,
}

impl Default for UnlockOptions {
    fn default() -> Self {
        UnlockOptions {
            mode: OpenMode::ReadWrite,
            writer_id: random_array(),
            rollback: None,
        }
    }
}

/// Why a vault opened read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyReason {
    Requested,
    /// Another writer holds `.lock` (its contents, if readable).
    LockedBy(Option<LockInfo>),
    /// The drive is older than a state this device has seen.
    Rollback {
        seen_rev: u64,
    },
    /// The drive differs from a state this device saw at the same revision.
    Fork {
        seen_rev: u64,
    },
}

/// What happened during unlock, including warnings the user must see.
#[derive(Debug, Clone)]
pub struct UnlockReport {
    pub slot_index: usize,
    pub slot_kind: SlotKind,
    /// The primary header failed and the backup was used.
    pub used_backup_header: bool,
    /// The two header copies differed; repaired if the vault is writable.
    pub header_copies_differed: bool,
    pub root_slot: RootSlot,
    /// The other root slot exists but is unreadable (a torn or tampered write).
    pub other_root_slot_invalid: bool,
    pub rev: u64,
    pub rollback: RollbackStatus,
    pub read_only: Option<ReadOnlyReason>,
}

/// Spec §14.2: writers must refuse passwords scoring below 3 on zxcvbn.
pub(crate) fn require_strong(password: &Password, label: &str) -> Result<()> {
    let report = strength::check(password.expose(), &[label, "tijori"]);
    if report.acceptable {
        return Ok(());
    }
    let mut msg = String::from("this password is too easy to guess");
    if let Some(w) = &report.warning {
        msg.push_str(&format!(": {w}"));
    }
    if let Some(s) = report.suggestions.last() {
        msg.push_str(&format!(". {s}"));
    }
    Err(Error::InvalidInput(msg))
}

fn read_opt(storage: &dyn Storage, path: &str) -> Result<Option<Vec<u8>>> {
    match storage.read(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// How much an unlock failure tells the user, when both header copies fail.
fn severity(e: &Error) -> u8 {
    match e.class() {
        ErrorClass::Io => 5,
        ErrorClass::Tampered => 4,
        ErrorClass::WrongSecret => 3,
        ErrorClass::Unsupported => 2,
        _ => 1,
    }
}

struct HeaderOutcome {
    opened: OpenedHeader,
    used_backup: bool,
    differed: bool,
}

/// Unlock steps 1-5 with the backup fallback of spec §5.3.
fn open_headers(storage: &dyn Storage, secret: &UnlockSecret) -> Result<HeaderOutcome> {
    let primary = read_opt(storage, HEADER_PATH)?;
    let backup = read_opt(storage, HEADER_BACKUP_PATH)?;
    if primary.is_none() && backup.is_none() {
        return Err(Error::NotFound("no Tijori vault on this drive".into()));
    }
    let differed = primary != backup;
    let first_err = match &primary {
        Some(p) => match open_header(p, secret) {
            Ok(opened) => {
                return Ok(HeaderOutcome {
                    opened,
                    used_backup: false,
                    differed,
                });
            }
            Err(e) => e,
        },
        None => Error::damaged("vault.header is missing"),
    };
    // An identical backup cannot do better; skip the second Argon2id run.
    if !differed {
        return Err(first_err);
    }
    let second_err = match &backup {
        Some(b) => match open_header(b, secret) {
            Ok(opened) => {
                return Ok(HeaderOutcome {
                    opened,
                    used_backup: true,
                    differed,
                });
            }
            Err(e) => e,
        },
        None => Error::damaged("vault.header.bak is missing"),
    };
    Err(if severity(&second_err) > severity(&first_err) {
        second_err
    } else {
        first_err
    })
}

/// Unlock step 6: the valid root slot with the higher `rev`.
fn open_roots(
    storage: &dyn Storage,
    keys: &Subkeys,
    uuid: &[u8; 16],
) -> Result<(RootPointer, RootSlot, bool)> {
    let mut valid: Vec<(RootPointer, RootSlot)> = Vec::new();
    let mut invalid = 0;
    for slot in RootSlot::BOTH {
        let Some(data) = read_opt(storage, &root_path(slot))? else {
            continue;
        };
        match RootPointer::open(&data, &keys.root, uuid, slot) {
            Ok(r) => valid.push((r, slot)),
            Err(e) if e.class() == ErrorClass::Unsupported => return Err(e),
            Err(_) => invalid += 1,
        }
    }
    let best = valid
        .into_iter()
        .max_by_key(|(r, _)| (r.rev, r.written_at))
        .ok_or_else(|| Error::damaged("neither root pointer can be read"))?;
    Ok((best.0, best.1, invalid > 0))
}

impl Vault {
    /// Creates a vault in `TIJORI/` on an empty drive, returning the
    /// recovery phrase, which the app shows once.
    pub fn create(
        storage: Arc<dyn Storage>,
        opts: CreateOptions,
    ) -> Result<(Vault, RecoveryPhrase)> {
        if storage.exists(HEADER_PATH)? || storage.exists(HEADER_BACKUP_PATH)? {
            return Err(Error::AlreadyExists(
                "this drive already has a Tijori vault".into(),
            ));
        }
        require_strong(&opts.password, &opts.settings.label)?;
        Settings::check_label(&opts.settings.label)?;
        let params = opts.argon.resolve()?;

        storage.mkdir_all(OBJECTS_DIR)?;
        let lock = match WriteLock::acquire(storage.clone(), &opts.writer_id)? {
            Acquire::Acquired(l) => l,
            Acquire::HeldBy(_) => {
                return Err(Error::Locked(
                    "another Tijori writer is using this drive".into(),
                ));
            }
        };

        let mk = MasterKey::from_key(Key::random()).into_locked();
        let keys = Subkeys::derive(&mk);
        let uuid: [u8; 16] = random_array();
        let mut header = Header::new(uuid);

        let salt = random_array();
        let (kind, kek) = match &opts.keyfile {
            None => (
                SlotKind::Password,
                kek_password(&opts.password, &salt, params)?,
            ),
            Some(kf) => (
                SlotKind::PasswordKeyfile,
                kek_password_keyfile(&opts.password, kf, &salt, params)?,
            ),
        };
        header.slots[0] = Keyslot::wrap(
            kind,
            Some(params),
            &salt,
            &random_array(),
            &kek,
            &mk,
            &uuid,
            0,
        );
        let phrase = RecoveryPhrase::generate();
        let salt = random_array();
        let kek = kek_recovery(&phrase, &salt);
        header.slots[1] = Keyslot::wrap(
            SlotKind::Recovery,
            None,
            &salt,
            &random_array(),
            &kek,
            &mk,
            &uuid,
            1,
        );
        header.seal(&keys.hmac);

        let objects = Objects {
            storage: storage.as_ref(),
            k_obj: &keys.obj,
        };
        let root_ref = objects.write_dir(&Directory::default(), opts.settings.padding)?;
        let root = RootPointer {
            rev: 1,
            root_id: root_ref.id,
            root_hash: root_ref.hash,
            settings: opts.settings.clone(),
            written_at: now_secs(),
            writer_id: opts.writer_id,
            unknown: Vec::new(),
        };
        let path = root_path(RootSlot::A);
        storage.write_atomic(
            &path,
            &root.seal(&keys.root, &uuid, RootSlot::A, &random_array()),
        )?;
        let _ = storage.neutralize_times(&path);
        let bytes = header.to_bytes();
        for path in [HEADER_BACKUP_PATH, HEADER_PATH] {
            storage.write_atomic(path, &bytes)?;
            let _ = storage.neutralize_times(path);
        }
        storage.write_atomic(README_PATH, README_TEXT.as_bytes())?;
        let _ = storage.neutralize_times(README_PATH);

        let mut vault = Vault {
            storage,
            header,
            mk,
            keys,
            tree: DirNode::loaded(Directory::default(), root_ref),
            settings: opts.settings,
            root,
            root_slot: RootSlot::A,
            requested_mode: OpenMode::ReadWrite,
            lock: Some(lock),
            read_only_reason: None,
            writer_id: opts.writer_id,
            rollback: opts.rollback,
            rollback_status: RollbackStatus::FirstUse,
            warnings: Vec::new(),
        };
        vault.record_rollback();
        Ok((vault, phrase))
    }

    /// Unlocks a vault (spec §6).
    pub fn unlock(
        storage: Arc<dyn Storage>,
        secret: &UnlockSecret,
        opts: UnlockOptions,
    ) -> Result<(Vault, UnlockReport)> {
        let HeaderOutcome {
            opened,
            used_backup,
            differed,
        } = open_headers(storage.as_ref(), secret)?;
        let OpenedHeader {
            header,
            mk,
            subkeys: keys,
            slot_index,
        } = opened;
        let slot_kind = header.slots[slot_index]
            .kind()
            .expect("an opened slot has a known kind");

        let (root, root_slot, other_invalid) =
            open_roots(storage.as_ref(), &keys, &header.vault_uuid)?;
        let objects = Objects {
            storage: storage.as_ref(),
            k_obj: &keys.obj,
        };
        let root_ref = ObjRef {
            id: root.root_id,
            hash: root.root_hash,
        };
        let tree = DirNode::loaded(objects.load_dir(&root_ref)?, root_ref);

        let rollback_status = match &opts.rollback {
            None => RollbackStatus::NotChecked,
            Some(store) => compare(
                store.load(&header.vault_uuid)?.as_ref(),
                root.rev,
                &root.root_hash,
            ),
        };

        let mut vault = Vault {
            storage,
            settings: root.settings.clone(),
            header,
            mk,
            keys,
            root,
            root_slot,
            tree,
            requested_mode: opts.mode,
            lock: None,
            read_only_reason: None,
            writer_id: opts.writer_id,
            rollback: opts.rollback,
            rollback_status,
            warnings: Vec::new(),
        };
        vault.read_only_reason = match (opts.mode, rollback_status) {
            (OpenMode::ReadOnly, _) => Some(ReadOnlyReason::Requested),
            (_, RollbackStatus::Rollback { seen_rev }) => {
                Some(ReadOnlyReason::Rollback { seen_rev })
            }
            (_, RollbackStatus::Fork { seen_rev }) => Some(ReadOnlyReason::Fork { seen_rev }),
            _ => vault.try_take_lock()?,
        };
        if !rollback_status.is_warning() {
            vault.record_rollback();
        }
        if differed && vault.is_writable() {
            vault.write_header()?;
        }
        let report = UnlockReport {
            slot_index,
            slot_kind,
            used_backup_header: used_backup,
            header_copies_differed: differed,
            root_slot,
            other_root_slot_invalid: other_invalid,
            rev: vault.root.rev,
            rollback: rollback_status,
            read_only: vault.read_only_reason.clone(),
        };
        Ok((vault, report))
    }

    /// Tries to take the write lock; returns why not if it is held.
    fn try_take_lock(&mut self) -> Result<Option<ReadOnlyReason>> {
        match WriteLock::acquire(self.storage.clone(), &self.writer_id)? {
            Acquire::Acquired(l) => {
                self.lock = Some(l);
                Ok(None)
            }
            Acquire::HeldBy(info) => Ok(Some(ReadOnlyReason::LockedBy(info))),
        }
    }

    /// After a rollback or fork warning, the user chose to accept the
    /// drive's state: remember it as the newest and allow writing.
    pub fn accept_current_state(&mut self) -> Result<()> {
        if let Some(store) = &self.rollback {
            store.save(
                &self.header.vault_uuid,
                &RollbackRecord {
                    max_rev: self.root.rev,
                    root_hash: self.root.root_hash,
                    last_seen: now_secs(),
                },
            )?;
        }
        self.rollback_status = RollbackStatus::Normal;
        self.retry_write_access()
    }

    /// Tries again to get write access, for example after the user broke a
    /// stale lock. Does nothing if the vault was opened read-only on purpose.
    pub fn retry_write_access(&mut self) -> Result<()> {
        if self.requested_mode == OpenMode::ReadOnly
            || self.lock.is_some()
            || self.rollback_status.is_warning()
        {
            return Ok(());
        }
        self.read_only_reason = self.try_take_lock()?;
        if self.lock.is_some()
            && let Err(e) = self.reload_from_disk()
        {
            self.lock = None;
            return Err(e);
        }
        Ok(())
    }

    /// Another writer may have committed while this vault was read-only.
    /// Before writing, adopt the current header and root so their changes
    /// are built upon instead of overwritten.
    fn reload_from_disk(&mut self) -> Result<()> {
        let bytes = self.storage.read(HEADER_PATH)?;
        let header = Header::parse(&bytes)?;
        if !header.verify_mac(&self.keys.hmac) {
            return Err(Error::Other(
                "the vault was re-keyed or changed by another writer; lock it and unlock it again"
                    .into(),
            ));
        }
        self.header = header;
        let (root, slot, _) =
            open_roots(self.storage.as_ref(), &self.keys, &self.header.vault_uuid)?;
        if root != self.root || slot != self.root_slot {
            let objects = Objects {
                storage: self.storage.as_ref(),
                k_obj: &self.keys.obj,
            };
            let r = ObjRef {
                id: root.root_id,
                hash: root.root_hash,
            };
            self.tree = DirNode::loaded(objects.load_dir(&r)?, r);
            self.settings = root.settings.clone();
            self.root = root;
            self.root_slot = slot;
        }
        Ok(())
    }

    /// Updates this device's rollback record after a commit or unlock.
    pub(crate) fn record_rollback(&mut self) {
        let Some(store) = &self.rollback else { return };
        let uuid = self.header.vault_uuid;
        let result = store.load(&uuid).and_then(|old| {
            if old.is_some_and(|o| o.max_rev > self.root.rev) {
                return Ok(());
            }
            store.save(
                &uuid,
                &RollbackRecord {
                    max_rev: self.root.rev,
                    root_hash: self.root.root_hash,
                    last_seen: now_secs(),
                },
            )
        });
        if let Err(e) = result {
            self.warnings.push(format!(
                "could not update this device's rollback record: {e}"
            ));
        }
    }

    /// Writes the header to both copies: backup first, then primary (§5.3).
    pub(crate) fn write_header(&mut self) -> Result<()> {
        self.require_writable()?;
        self.header.seal(&self.keys.hmac);
        let bytes = self.header.to_bytes();
        for path in [HEADER_BACKUP_PATH, HEADER_PATH] {
            self.storage.write_atomic(path, &bytes)?;
            let _ = self.storage.neutralize_times(path);
        }
        Ok(())
    }

    pub(crate) fn require_writable(&self) -> Result<()> {
        if self.lock.is_some() {
            return Ok(());
        }
        let why = match &self.read_only_reason {
            Some(ReadOnlyReason::LockedBy(_)) => "another writer holds the lock",
            Some(ReadOnlyReason::Rollback { .. }) => {
                "the drive is older than one this device has seen"
            }
            Some(ReadOnlyReason::Fork { .. }) => "the drive differs from what this device has seen",
            _ => "it was opened read-only",
        };
        Err(Error::ReadOnly(why.into()))
    }
}
