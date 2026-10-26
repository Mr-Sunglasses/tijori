//! Keyslots, re-keying, verification and garbage collection.

use std::collections::HashSet;

use super::open::{ArgonChoice, require_strong};
use super::tree::{DirNode, ObjRef, Objects};
use super::{OBJECTS_DIR, Phase, Progress, VAULT_DIR, Vault, VaultPath, now_secs, root_path};
use crate::crypto::{Key, MasterKey, random_array};
use crate::error::{Error, ErrorClass, Result};
use crate::format::{ArgonParams, Header, Keyslot, RootPointer, RootSlot, SlotKind};
use crate::keys::{Subkeys, kek_password, kek_password_keyfile, kek_recovery};
use crate::recovery::RecoveryPhrase;
use crate::{Keyfile, Password};

/// Spec §12: at most 256 levels, counting the root folder.
const MAX_TREE_DEPTH: usize = 256;

/// A keyslot to create.
pub enum NewSlot {
    Password {
        password: Password,
        keyfile: Option<Keyfile>,
        argon: ArgonChoice,
    },
    /// A fresh recovery phrase, returned to the caller to show once.
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyslotInfo {
    pub index: usize,
    /// `None` for slot types from newer versions.
    pub kind: Option<SlotKind>,
    pub slot_type: u8,
    pub argon: Option<ArgonParams>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyProblem {
    pub path: String,
    pub class: ErrorClass,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub dirs: u64,
    pub files: u64,
    pub bytes: u64,
    pub problems: Vec<VerifyProblem>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    pub removed: u64,
    pub kept: u64,
    pub freed_bytes: u64,
}

fn build_slot(
    mk: &MasterKey,
    uuid: &[u8; 16],
    index: usize,
    new: &NewSlot,
    label: &str,
) -> Result<(Keyslot, Option<RecoveryPhrase>)> {
    let salt = random_array();
    let nonce = random_array();
    let index = index as u8;
    Ok(match new {
        NewSlot::Password {
            password,
            keyfile,
            argon,
        } => {
            require_strong(password, label)?;
            let params = argon.resolve()?;
            let (kind, kek) = match keyfile {
                None => (SlotKind::Password, kek_password(password, &salt, params)?),
                Some(kf) => (
                    SlotKind::PasswordKeyfile,
                    kek_password_keyfile(password, kf, &salt, params)?,
                ),
            };
            (
                Keyslot::wrap(kind, Some(params), &salt, &nonce, &kek, mk, uuid, index),
                None,
            )
        }
        NewSlot::Recovery => {
            let phrase = RecoveryPhrase::generate();
            let kek = kek_recovery(&phrase, &salt);
            let slot = Keyslot::wrap(
                SlotKind::Recovery,
                None,
                &salt,
                &nonce,
                &kek,
                mk,
                uuid,
                index,
            );
            (slot, Some(phrase))
        }
    })
}

/// Walks a committed tree, collecting every object ID.
fn mark_live(
    objects: &Objects,
    r: &ObjRef,
    depth: usize,
    live: &mut HashSet<[u8; 32]>,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::damaged("the folder tree is deeper than the limit"));
    }
    live.insert(r.id);
    let dir = objects.load_dir(r)?;
    for e in &dir.entries {
        let child = ObjRef {
            id: e.id,
            hash: e.hash,
        };
        if e.is_dir() {
            mark_live(objects, &child, depth + 1, live)?;
        } else {
            live.insert(e.id);
        }
    }
    Ok(())
}

/// Re-encrypts a tree under a new `K_obj`, giving every object a new ID.
struct Rekeyer<'a, 'p> {
    old: Objects<'a>,
    new: Objects<'a>,
    padding: bool,
    done: u64,
    total: u64,
    progress: &'p mut dyn FnMut(Progress) -> bool,
}

impl Rekeyer<'_, '_> {
    fn tick(&mut self) -> Result<()> {
        self.done += 1;
        let p = Progress {
            phase: Phase::Rekey,
            done: self.done,
            total: self.total,
        };
        if (self.progress)(p) {
            Ok(())
        } else {
            Err(Error::Cancelled)
        }
    }

    fn dir(&mut self, r: &ObjRef, depth: usize) -> Result<ObjRef> {
        if depth > MAX_TREE_DEPTH {
            return Err(Error::damaged("the folder tree is deeper than the limit"));
        }
        let mut dir = self.old.load_dir(r)?;
        for e in &mut dir.entries {
            let child = ObjRef {
                id: e.id,
                hash: e.hash,
            };
            let fresh = if e.is_dir() {
                self.dir(&child, depth + 1)?
            } else {
                let mut reader = self.old.open_file(&child)?;
                let len = reader.content_len();
                let r = self
                    .new
                    .write_file(&mut reader, len, self.padding, &mut |_| true)?;
                self.tick()?;
                r
            };
            e.id = fresh.id;
            e.hash = fresh.hash;
        }
        let r = self.new.write_dir(&dir, self.padding)?;
        self.tick()?;
        Ok(r)
    }
}

impl Vault {
    /// The non-empty keyslots.
    pub fn keyslots(&self) -> Vec<KeyslotInfo> {
        self.header
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_empty())
            .map(|(index, s)| KeyslotInfo {
                index,
                kind: s.kind(),
                slot_type: s.slot_type(),
                argon: s
                    .kind()
                    .filter(|k| k.uses_argon())
                    .map(|_| s.argon_params()),
            })
            .collect()
    }

    /// Adds a keyslot in the first free position.
    pub fn add_keyslot(&mut self, new: NewSlot) -> Result<(usize, Option<RecoveryPhrase>)> {
        self.require_writable()?;
        let index = self
            .header
            .free_slot()
            .ok_or_else(|| Error::invalid("all 8 keyslots are in use; remove one first"))?;
        let (slot, phrase) = build_slot(
            &self.mk,
            &self.header.vault_uuid,
            index,
            &new,
            &self.settings.label,
        )?;
        self.header.slots[index] = slot;
        self.write_header()?;
        Ok((index, phrase))
    }

    /// Replaces the slot at `index` (for example after a password change).
    pub fn replace_keyslot(
        &mut self,
        index: usize,
        new: NewSlot,
    ) -> Result<Option<RecoveryPhrase>> {
        self.require_writable()?;
        if index >= self.header.slots.len() || self.header.slots[index].is_empty() {
            return Err(Error::NotFound(format!("keyslot {index}")));
        }
        let (slot, phrase) = build_slot(
            &self.mk,
            &self.header.vault_uuid,
            index,
            &new,
            &self.settings.label,
        )?;
        self.header.slots[index] = slot;
        self.write_header()?;
        Ok(phrase)
    }

    /// Sets a new password on a password slot, keeping its Argon2id
    /// parameters. Show [`super::PASSWORD_CHANGE_NOTE`] afterwards.
    pub fn change_password(
        &mut self,
        index: usize,
        password: Password,
        keyfile: Option<Keyfile>,
    ) -> Result<()> {
        let slot = self
            .header
            .slots
            .get(index)
            .ok_or_else(|| Error::NotFound(format!("keyslot {index}")))?;
        if !slot.kind().is_some_and(SlotKind::uses_argon) {
            return Err(Error::invalid(format!(
                "keyslot {index} is not a password slot"
            )));
        }
        let argon = ArgonChoice::Fixed(slot.argon_params());
        self.replace_keyslot(
            index,
            NewSlot::Password {
                password,
                keyfile,
                argon,
            },
        )?;
        Ok(())
    }

    /// Removes a keyslot. The last usable slot can never be removed.
    pub fn remove_keyslot(&mut self, index: usize) -> Result<()> {
        self.require_writable()?;
        if index >= self.header.slots.len() || self.header.slots[index].is_empty() {
            return Err(Error::NotFound(format!("keyslot {index}")));
        }
        let usable_left = self
            .header
            .slots
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != index && s.kind().is_some())
            .count();
        if usable_left == 0 {
            return Err(Error::invalid(
                "cannot remove the last keyslot: the vault could never be opened again",
            ));
        }
        self.header.slots[index] = Keyslot::empty();
        self.write_header()
    }

    /// Re-keys the vault: a new MK, every object re-encrypted under new
    /// IDs, and a new header holding exactly `slots`. This is the only way
    /// to lock out someone holding an old copy of the header. Returns the
    /// new recovery phrase if `slots` asked for one.
    ///
    /// Crash safety: new objects are unreferenced until the root pointer
    /// under the new key lands in the older slot. Before the header changes,
    /// that slot is unreadable under the old MK, so the vault opens at the
    /// old state; after, the old slot is unreadable under the new MK, so it
    /// opens at the new one.
    pub fn rekey(
        &mut self,
        slots: Vec<NewSlot>,
        progress: &mut dyn FnMut(Progress) -> bool,
    ) -> Result<Option<RecoveryPhrase>> {
        self.require_writable()?;
        if slots.is_empty() || slots.len() > self.header.slots.len() {
            return Err(Error::invalid(
                "a re-keyed vault needs between 1 and 8 keyslots",
            ));
        }
        self.commit()?;
        let uuid = self.header.vault_uuid;
        let new_mk = MasterKey::from_key(Key::random()).into_locked();
        let new_keys = Subkeys::derive(&new_mk);

        let mut header = Header::new(uuid);
        let mut phrase = None;
        for (i, s) in slots.iter().enumerate() {
            let (slot, p) = build_slot(&new_mk, &uuid, i, s, &self.settings.label)?;
            header.slots[i] = slot;
            phrase = phrase.or(p);
        }
        header.seal(&new_keys.hmac);

        let old = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        let root_ref = ObjRef {
            id: self.root.root_id,
            hash: self.root.root_hash,
        };
        let mut live = HashSet::new();
        mark_live(&old, &root_ref, 1, &mut live)?;
        let mut rekeyer = Rekeyer {
            old,
            new: Objects {
                storage: self.storage.as_ref(),
                k_obj: &new_keys.obj,
            },
            padding: self.settings.padding,
            done: 0,
            total: live.len() as u64,
            progress,
        };
        let new_root = rekeyer.dir(&root_ref, 1)?;
        let new = rekeyer.new;

        let first = RootPointer {
            rev: self.root.rev + 1,
            root_id: new_root.id,
            root_hash: new_root.hash,
            settings: self.settings.clone(),
            written_at: now_secs(),
            writer_id: self.writer_id,
            unknown: self.root.unknown.clone(),
        };
        let slot = self.root_slot.other();
        let path = root_path(slot);
        self.storage.write_atomic(
            &path,
            &first.seal(&new_keys.root, &uuid, slot, &random_array()),
        )?;
        let _ = self.storage.neutralize_times(&path);

        let tree = DirNode::loaded(new.load_dir(&new_root)?, new_root);
        self.mk = new_mk;
        self.keys = new_keys;
        self.header = header;
        self.root = first.clone();
        self.root_slot = slot;
        self.tree = tree;
        self.write_header()?;
        self.write_root(RootPointer {
            rev: first.rev + 1,
            written_at: now_secs(),
            ..first
        })?;
        self.gc()?;
        Ok(phrase)
    }

    /// Checks every hash and decrypts every chunk of the committed tree.
    pub fn verify(&mut self, progress: &mut dyn FnMut(Progress) -> bool) -> Result<VerifyReport> {
        let objects = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        let mut report = VerifyReport::default();
        let mut files: Vec<(VaultPath, ObjRef, u64)> = Vec::new();
        let mut stack = vec![(
            VaultPath::root(),
            ObjRef {
                id: self.root.root_id,
                hash: self.root.root_hash,
            },
        )];
        while let Some((path, r)) = stack.pop() {
            if path.components().len() >= MAX_TREE_DEPTH {
                report.problems.push(VerifyProblem {
                    path: path.to_string(),
                    class: ErrorClass::Damaged,
                    message: "the folder tree is deeper than the limit".into(),
                });
                continue;
            }
            let dir = match objects.load_dir(&r) {
                Ok(d) => d,
                Err(e) => {
                    report.problems.push(VerifyProblem {
                        path: path.to_string(),
                        class: e.class(),
                        message: e.to_string(),
                    });
                    continue;
                }
            };
            report.dirs += 1;
            for e in dir.entries {
                let child_path = path.join(&e.name)?;
                let child = ObjRef {
                    id: e.id,
                    hash: e.hash,
                };
                if e.is_dir() {
                    stack.push((child_path, child));
                } else {
                    files.push((child_path, child, e.size.unwrap_or(0)));
                }
            }
        }
        let total: u64 = files.iter().map(|f| f.2).sum();
        let mut done = 0;
        for (path, r, size) in files {
            let result = objects.open_file(&r).and_then(|mut reader| {
                if reader.content_len() != size {
                    return Err(Error::damaged("size differs from its folder entry"));
                }
                std::io::copy(&mut reader, &mut std::io::sink())
                    .map_err(|e| Error::from_io(e, "verifying"))
            });
            match result {
                Ok(_) => report.files += 1,
                Err(e) => report.problems.push(VerifyProblem {
                    path: path.to_string(),
                    class: e.class(),
                    message: e.to_string(),
                }),
            }
            done += size;
            report.bytes += size;
            if !progress(Progress {
                phase: Phase::Verify,
                done,
                total,
            }) {
                return Err(Error::Cancelled);
            }
        }
        Ok(report)
    }

    /// Deletes objects reachable from neither root slot, and stray `.tmp`
    /// files (spec §9.3). Commits pending changes first.
    pub fn gc(&mut self) -> Result<GcReport> {
        self.require_writable()?;
        self.commit()?;
        let objects = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        let mut live = HashSet::new();
        for slot in RootSlot::BOTH {
            let Ok(data) = self.storage.read(&root_path(slot)) else {
                continue;
            };
            let Ok(root) = RootPointer::open(&data, &self.keys.root, &self.header.vault_uuid, slot)
            else {
                continue;
            };
            // If a valid tree cannot be walked completely, deleting anything
            // could destroy live data, so stop.
            mark_live(
                &objects,
                &ObjRef {
                    id: root.root_id,
                    hash: root.root_hash,
                },
                1,
                &mut live,
            )?;
        }
        let mut report = GcReport::default();
        for name in self.storage.list(VAULT_DIR)? {
            if name.ends_with(".tmp") {
                self.storage.remove(&format!("{VAULT_DIR}/{name}"))?;
            }
        }
        for fan in self.storage.list(OBJECTS_DIR)? {
            let dir = format!("{OBJECTS_DIR}/{fan}");
            for name in self.storage.list(&dir)? {
                let path = format!("{dir}/{name}");
                let dead = if name.ends_with(".tmp") {
                    true
                } else if let Some(id) = name.strip_suffix(".tjo").and_then(parse_id) {
                    !live.contains(&id)
                } else {
                    false
                };
                if dead {
                    report.freed_bytes += self.storage.len(&path).unwrap_or(0);
                    self.storage.remove(&path)?;
                    report.removed += 1;
                } else {
                    report.kept += 1;
                }
            }
        }
        Ok(report)
    }
}

fn parse_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(id)
}
