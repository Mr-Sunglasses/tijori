//! Backups: an exact, encrypted copy of a vault in another folder or on
//! another drive. The copy is itself a vault that opens with the same
//! passwords, so restoring is a backup in the other direction.
//!
//! The copy is incremental (objects are immutable, so an object already at
//! the destination with the right size is kept) and safe to interrupt: new
//! objects go first, the root pointers and header after them, and objects
//! the copy no longer needs are deleted last. At every step the destination
//! opens at its old state or its new one.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use super::lock::{Acquire, WriteLock};
use super::maint::{mark_live, sweep};
use super::tree::{ObjRef, Objects, object_path};
use super::{
    HEADER_BACKUP_PATH, HEADER_PATH, OBJECTS_DIR, Phase, Progress, README_PATH, README_TEXT,
    VAULT_DIR, Vault, root_path,
};
use crate::crypto::{Blake2b, ct_eq};
use crate::error::{Error, Result};
use crate::format::{Header, RootPointer, RootSlot};
use crate::storage::Storage;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackupOptions {
    /// Overwrite a copy that has changes this vault does not have, or a
    /// `TIJORI` folder without a readable header.
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackupReport {
    /// The revision the copy now holds.
    pub rev: u64,
    /// Objects written to the destination.
    pub copied: u64,
    pub copied_bytes: u64,
    /// Objects the destination already had.
    pub unchanged: u64,
    /// Objects deleted from the destination because the vault no longer
    /// uses them.
    pub removed: u64,
    pub freed_bytes: u64,
}

/// A root slot as found on the source drive.
struct SlotSnapshot {
    slot: RootSlot,
    bytes: Vec<u8>,
    root: RootPointer,
}

fn read_opt(storage: &dyn Storage, path: &str) -> Result<Option<Vec<u8>>> {
    match storage.read(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn remove_opt(storage: &dyn Storage, path: &str) -> Result<()> {
    match storage.remove(path) {
        Err(e) if !e.is_not_found() => Err(e.into()),
        _ => Ok(()),
    }
}

impl Vault {
    /// Makes `dest` an exact copy of this vault's committed state. Commits
    /// pending changes first when the vault is writable; a read-only vault
    /// works too.
    pub fn backup_to(
        &mut self,
        dest: Arc<dyn Storage>,
        opts: BackupOptions,
        progress: &mut dyn FnMut(Progress) -> bool,
    ) -> Result<BackupReport> {
        if self.is_writable() {
            self.commit()?;
        }
        let uuid = self.header.vault_uuid;

        // Snapshot the root pointers first: everything copied below is
        // reachable from these, and objects never change once written.
        let mut slots = Vec::new();
        for slot in RootSlot::BOTH {
            let Some(bytes) = read_opt(self.storage.as_ref(), &root_path(slot))? else {
                continue;
            };
            if let Ok(root) = RootPointer::open(&bytes, &self.keys.root, &uuid, slot) {
                slots.push(SlotSnapshot { slot, bytes, root });
            }
        }
        let current = slots
            .iter()
            .max_by_key(|s| s.root.rev)
            .ok_or_else(|| Error::damaged("neither root pointer could be read"))?;
        let (current_slot, current_rev, current_hash) =
            (current.slot, current.root.rev, current.root.root_hash);

        dest.mkdir_all(VAULT_DIR)?;
        let lock = match WriteLock::acquire(dest.clone(), &self.writer_id)? {
            Acquire::Acquired(l) => l,
            Acquire::HeldBy(_) => {
                return Err(Error::Locked(
                    "the destination is in use by another Tijori".into(),
                ));
            }
        };
        self.check_destination(dest.as_ref(), current_rev, &current_hash, opts)?;

        let objects = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        let mut live = HashMap::new();
        for s in &slots {
            let r = ObjRef {
                id: s.root.root_id,
                hash: s.root.root_hash,
            };
            mark_live(&objects, &r, 1, &mut live)?;
        }

        let mut report = BackupReport {
            rev: current_rev,
            ..BackupReport::default()
        };
        let mut todo = Vec::new();
        let mut total = 0;
        for (id, hash) in &live {
            let path = object_path(id);
            let len = self.storage.len(&path).map_err(|e| {
                if e.is_not_found() {
                    Error::damaged("an object the vault needs is missing")
                } else {
                    e.into()
                }
            })?;
            match dest.len(&path) {
                Ok(l) if l == len => report.unchanged += 1,
                _ => {
                    todo.push((*id, *hash, path));
                    total += len;
                }
            }
        }
        let mut done = 0;
        for (id, hash, path) in &todo {
            dest.mkdir_all(&format!("{OBJECTS_DIR}/{:02x}", id[0]))?;
            let n = self.copy_object(dest.as_ref(), path, hash, &mut done, total, progress)?;
            report.copied += 1;
            report.copied_bytes += n;
        }

        // One root slot, then the header, then the other slot. The current
        // revision goes first unless that would overwrite the copy's own
        // newest slot, so an interruption leaves the copy at its old state
        // or the new one, or (after a re-key) at a previous revision.
        let order = match self.newest_slot(dest.as_ref())? {
            Some(theirs) if theirs == current_slot => [current_slot.other(), current_slot],
            _ => [current_slot, current_slot.other()],
        };
        let header = self.header.to_bytes();
        self.put_slot(dest.as_ref(), &slots, order[0])?;
        for path in [HEADER_BACKUP_PATH, HEADER_PATH] {
            if read_opt(dest.as_ref(), path)?.as_deref() != Some(&header[..]) {
                dest.write_atomic(path, &header)?;
            }
        }
        self.put_slot(dest.as_ref(), &slots, order[1])?;
        for slot in RootSlot::BOTH {
            let _ = dest.neutralize_times(&root_path(slot));
        }
        for path in [HEADER_BACKUP_PATH, HEADER_PATH] {
            let _ = dest.neutralize_times(path);
        }
        if !dest.exists(README_PATH)? {
            dest.write_atomic(README_PATH, README_TEXT.as_bytes())?;
            let _ = dest.neutralize_times(README_PATH);
        }

        let swept = sweep(dest.as_ref(), &|id| live.contains_key(id))?;
        report.removed = swept.removed;
        report.freed_bytes = swept.freed_bytes;
        lock.release()?;
        Ok(report)
    }

    /// The copy's newest root slot that opens under this vault's keys.
    fn newest_slot(&self, dest: &dyn Storage) -> Result<Option<RootSlot>> {
        let mut best: Option<(u64, RootSlot)> = None;
        for slot in RootSlot::BOTH {
            let Some(bytes) = read_opt(dest, &root_path(slot))? else {
                continue;
            };
            if let Ok(r) = RootPointer::open(&bytes, &self.keys.root, &self.header.vault_uuid, slot)
                && best.is_none_or(|(rev, _)| r.rev > rev)
            {
                best = Some((r.rev, slot));
            }
        }
        Ok(best.map(|(_, s)| s))
    }

    /// Writes one root slot as the source has it, or removes it when the
    /// source's is unreadable. Identical slots are not rewritten: a torn
    /// rewrite of good data would only destroy it.
    fn put_slot(&self, dest: &dyn Storage, slots: &[SlotSnapshot], slot: RootSlot) -> Result<()> {
        let path = root_path(slot);
        match slots.iter().find(|s| s.slot == slot) {
            Some(s) if read_opt(dest, &path)?.as_deref() != Some(&s.bytes[..]) => {
                Ok(dest.write_atomic(&path, &s.bytes)?)
            }
            Some(_) => Ok(()),
            None => remove_opt(dest, &path),
        }
    }

    /// Refuses to overwrite a different vault, a copy with changes this
    /// vault lacks, or a `TIJORI` folder whose vault cannot be identified.
    fn check_destination(
        &self,
        dest: &dyn Storage,
        rev: u64,
        root_hash: &[u8; 32],
        opts: BackupOptions,
    ) -> Result<()> {
        let mut header = None;
        for path in [HEADER_PATH, HEADER_BACKUP_PATH] {
            if let Some(h) = read_opt(dest, path)?.and_then(|b| Header::parse(&b).ok()) {
                header = Some(h);
                break;
            }
        }
        let Some(header) = header else {
            let has_data = !dest.list(OBJECTS_DIR)?.is_empty()
                || RootSlot::BOTH
                    .iter()
                    .any(|s| dest.exists(&root_path(*s)).unwrap_or(true));
            if has_data && !opts.force {
                return Err(Error::Diverged(
                    "the destination has a TIJORI folder without a readable vault header; \
                     it may hold another vault, so it was left alone"
                        .into(),
                ));
            }
            return Ok(());
        };
        if header.vault_uuid != self.header.vault_uuid {
            return Err(Error::AlreadyExists(
                "the destination holds a different Tijori vault".into(),
            ));
        }
        if opts.force {
            return Ok(());
        }
        for slot in RootSlot::BOTH {
            let Some(bytes) = read_opt(dest, &root_path(slot))? else {
                continue;
            };
            // A slot that does not open under this vault's keys is either
            // damaged or from before a re-key; neither holds newer changes
            // we could check.
            let Ok(theirs) =
                RootPointer::open(&bytes, &self.keys.root, &self.header.vault_uuid, slot)
            else {
                continue;
            };
            let newer =
                theirs.rev > rev || (theirs.rev == rev && !ct_eq(&theirs.root_hash, root_hash));
            if newer {
                return Err(Error::Diverged(format!(
                    "the destination has changes this vault does not have \
                     (revision {} there, {rev} here); copying would lose them",
                    theirs.rev
                )));
            }
        }
        Ok(())
    }

    /// Streams one object to `dest`, checking its hash before the copy
    /// becomes visible, so a damaged source never replaces a good copy.
    fn copy_object(
        &self,
        dest: &dyn Storage,
        path: &str,
        hash: &[u8; 32],
        done: &mut u64,
        total: u64,
        progress: &mut dyn FnMut(Progress) -> bool,
    ) -> Result<u64> {
        let mut input = self.storage.open_read(path)?;
        let mut out = dest.create_writer(path)?;
        let mut h = Blake2b::new(None);
        let mut buf = vec![0u8; 256 * 1024];
        let mut n = 0u64;
        loop {
            let got = input
                .read(&mut buf)
                .map_err(|e| Error::from_io(e, "reading an object"))?;
            if got == 0 {
                break;
            }
            h.update(&buf[..got]);
            out.write_all(&buf[..got])
                .map_err(|e| Error::from_io(e, "writing an object"))?;
            n += got as u64;
            *done += got as u64;
            let p = Progress {
                phase: Phase::Backup,
                done: *done,
                total,
            };
            if !progress(p) {
                return Err(Error::Cancelled);
            }
        }
        if !ct_eq(&h.finalize(), hash) {
            return Err(Error::tampered(
                "an object does not match its hash, so it was not copied",
            ));
        }
        out.commit()?;
        let _ = dest.neutralize_times(path);
        Ok(n)
    }
}
