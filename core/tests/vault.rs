//! Vault engine acceptance tests (Plan Milestone 2): round trips, sample
//! vaults, crash injection, tampering, swaps, rollback, locking, keyslots,
//! re-keying and garbage collection.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use tijori_core::format::RootSlot;
use tijori_core::rollback::{MemRollbackStore, RollbackStatus, RollbackStore};
use tijori_core::storage::{Fault, MemStorage, StdFsStorage, Storage};
use tijori_core::vault::{
    ArgonChoice, CreateOptions, HEADER_BACKUP_PATH, HEADER_PATH, NewSlot, ReadOnlyReason,
    UnlockOptions, root_path,
};
use tijori_core::{
    Entry, EntryKind, Error, ErrorClass, FileMeta, Keyfile, OpenMode, Password, RecoveryPhrase,
    UnlockSecret, Vault, VaultPath,
};

/// Every path and its content (`None` for folders).
type Snap = BTreeMap<String, Option<Vec<u8>>>;

const PASSWORD: &str = "orbit lantern cactus velvet mango thunder";

fn p(s: &str) -> VaultPath {
    VaultPath::parse(s).unwrap()
}

fn meta() -> FileMeta {
    FileMeta {
        mtime_ms: 1_767_225_600_000,
        executable: false,
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn create(storage: &MemStorage) -> (Vault, String) {
    let mut opts = CreateOptions::new(Password::new(PASSWORD));
    opts.argon = ArgonChoice::minimum();
    let (v, phrase) = Vault::create(Arc::new(storage.clone()), opts).unwrap();
    (v, phrase.words().to_string())
}

fn unlock_with(
    storage: &MemStorage,
    secret: &UnlockSecret,
    mode: OpenMode,
) -> Result<Vault, Error> {
    let opts = UnlockOptions {
        mode,
        ..UnlockOptions::default()
    };
    Vault::unlock(Arc::new(storage.clone()), secret, opts).map(|(v, _)| v)
}

fn recovery(words: &str) -> UnlockSecret {
    UnlockSecret::Recovery(RecoveryPhrase::parse(words).unwrap())
}

/// Every path and its content (`None` for folders), read through the vault.
fn snapshot(v: &mut Vault) -> Result<Snap, Error> {
    let mut out = BTreeMap::new();
    let mut stack = vec![VaultPath::root()];
    while let Some(dir) = stack.pop() {
        for e in v.list(&dir)? {
            let path = dir.join(&e.name)?;
            if e.kind == EntryKind::Dir {
                out.insert(path.to_string(), None);
                stack.push(path);
            } else {
                out.insert(path.to_string(), Some(v.read_to_vec(&path, u64::MAX)?));
            }
        }
    }
    Ok(out)
}

/// A vault with two commits, so both root slots are in use.
fn populated() -> (MemStorage, String, Snap, Snap) {
    let s = MemStorage::new();
    let (mut v, words) = create(&s);
    v.write_bytes(&p("/a.txt"), b"first version", meta())
        .unwrap();
    v.mkdir(&p("/Docs")).unwrap();
    v.write_bytes(&p("/Docs/big.bin"), &pattern(70_000, 1), meta())
        .unwrap();
    v.commit().unwrap();
    let prev = snapshot(&mut v).unwrap();
    v.write_bytes(&p("/a.txt"), b"second version", meta())
        .unwrap();
    v.write_bytes(&p("/Docs/caf\u{e9}.txt"), b"nfc", meta())
        .unwrap();
    v.commit().unwrap();
    let cur = snapshot(&mut v).unwrap();
    v.lock().unwrap();
    (s, words, prev, cur)
}

#[test]
fn create_write_lock_unlock_round_trip() {
    let s = MemStorage::new();
    let (mut v, words) = create(&s);
    assert_eq!(words.split(' ').count(), 24);
    assert!(s.get("README-TIJORI.txt").is_some());
    v.mkdir_all(&p("/Photos/2024")).unwrap();
    v.write_bytes(&p("/Photos/2024/x.jpg"), &pattern(200_000, 9), meta())
        .unwrap();
    v.write_bytes(
        &p("/run.sh"),
        b"#!/bin/sh",
        FileMeta {
            executable: true,
            ..meta()
        },
    )
    .unwrap();
    assert_eq!(
        v.read_to_vec(&p("/run.sh"), 100).unwrap(),
        b"#!/bin/sh",
        "reads see uncommitted writes"
    );
    v.lock().unwrap();
    assert!(s.get("TIJORI/.lock").is_none(), "lock is released");

    for secret in [UnlockSecret::password(PASSWORD), recovery(&words)] {
        let mut v = unlock_with(&s, &secret, OpenMode::ReadWrite).unwrap();
        assert_eq!(v.rev(), 2);
        assert_eq!(
            v.read_to_vec(&p("/Photos/2024/x.jpg"), u64::MAX).unwrap(),
            pattern(200_000, 9)
        );
        let run = v.stat(&p("/run.sh")).unwrap();
        assert!(run.executable && run.size == 9);
        let names: Vec<String> = v
            .list(&VaultPath::root())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["Photos", "run.sh"]);
        v.lock().unwrap();
    }
    let err = unlock_with(
        &s,
        &UnlockSecret::password("orbit lantern cactus velvet mango thunderx"),
        OpenMode::ReadOnly,
    );
    assert_eq!(err.err().unwrap().class(), ErrorClass::WrongSecret);
}

#[test]
fn weak_passwords_are_refused() {
    let s = MemStorage::new();
    let mut opts = CreateOptions::new(Password::new("password123"));
    opts.argon = ArgonChoice::minimum();
    assert!(matches!(
        Vault::create(Arc::new(s.clone()), opts),
        Err(Error::InvalidInput(_))
    ));
    assert!(s.get(HEADER_PATH).is_none());
}

#[test]
fn second_create_is_refused() {
    let s = MemStorage::new();
    create(&s).0.lock().unwrap();
    let mut opts = CreateOptions::new(Password::new(PASSWORD));
    opts.argon = ArgonChoice::minimum();
    assert!(matches!(
        Vault::create(Arc::new(s), opts),
        Err(Error::AlreadyExists(_))
    ));
}

#[test]
fn folder_operations() {
    let s = MemStorage::new();
    let (mut v, _) = create(&s);
    v.mkdir(&p("/A")).unwrap();
    v.mkdir(&p("/A/B")).unwrap();
    v.write_bytes(&p("/A/B/f"), b"1", meta()).unwrap();
    assert!(matches!(v.mkdir(&p("/A")), Err(Error::AlreadyExists(_))));
    assert!(matches!(v.mkdir(&p("/missing/x")), Err(Error::NotFound(_))));
    assert!(matches!(
        v.write_bytes(&p("/A/B/f/g"), b"", meta()),
        Err(Error::NotADirectory(_))
    ));
    assert!(matches!(v.remove(&p("/A"), false), Err(Error::NotEmpty(_))));
    assert!(matches!(
        v.rename(&p("/A"), &p("/A/B/C")),
        Err(Error::InvalidInput(_))
    ));
    v.commit().unwrap();

    // Move a loaded folder with uncommitted changes, then an unloaded one.
    v.write_bytes(&p("/A/B/g"), b"2", meta()).unwrap();
    v.rename(&p("/A/B"), &p("/B2")).unwrap();
    v.commit().unwrap();
    v.lock().unwrap();
    let mut v = unlock_with(&s, &UnlockSecret::password(PASSWORD), OpenMode::ReadWrite).unwrap();
    v.rename(&p("/B2"), &p("/A/B3")).unwrap();
    v.write_bytes(&p("/x"), b"x", meta()).unwrap();
    v.write_bytes(&p("/y"), b"y", meta()).unwrap();
    v.rename(&p("/x"), &p("/y")).unwrap();
    assert!(matches!(
        v.rename(&p("/y"), &p("/A")),
        Err(Error::AlreadyExists(_))
    ));
    v.commit().unwrap();
    let snap = snapshot(&mut v).unwrap();
    let expected: Snap = [
        ("/A", None),
        ("/A/B3", None),
        ("/A/B3/f", Some(b"1".to_vec())),
        ("/A/B3/g", Some(b"2".to_vec())),
        ("/y", Some(b"x".to_vec())),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    assert_eq!(snap, expected);
    v.remove(&p("/A"), true).unwrap();
    v.commit().unwrap();
    assert_eq!(v.list(&VaultPath::root()).unwrap().len(), 1);
    assert!(v.verify(&mut |_| true).unwrap().is_ok());
}

// --- Sample vaults written by the Python generator ---------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec/vectors")
}

#[test]
fn sample_vaults_from_the_generator() {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("vault.json")).unwrap())
            .unwrap();
    for case in manifest["vaults"].as_array().unwrap() {
        let storage = Arc::new(StdFsStorage::new(
            vectors_dir().join(case["path"].as_str().unwrap()),
        ));
        for secret in [
            UnlockSecret::password(case["password"].as_str().unwrap()),
            UnlockSecret::Recovery(
                RecoveryPhrase::parse(case["recovery_phrase"].as_str().unwrap()).unwrap(),
            ),
        ] {
            let opts = UnlockOptions {
                mode: OpenMode::ReadOnly,
                ..UnlockOptions::default()
            };
            let (mut v, report) = Vault::unlock(storage.clone(), &secret, opts).unwrap();
            assert_eq!(
                v.rev(),
                case["expected_rev"].as_u64().unwrap(),
                "{}",
                case["name"]
            );
            assert_eq!(
                v.settings().label,
                case["settings"]["label"].as_str().unwrap()
            );
            assert_eq!(report.other_root_slot_invalid, case["expected_rev"] == 1);
            let snap = snapshot(&mut v).unwrap();
            let mut expected = BTreeMap::new();
            for item in case["tree"].as_array().unwrap() {
                let content = match item["kind"].as_str().unwrap() {
                    "dir" => None,
                    _ => Some(match item["content"].get("hex") {
                        Some(h) => hex::decode(h.as_str().unwrap()).unwrap(),
                        None => (0..item["content"]["len"].as_u64().unwrap())
                            .map(|i| (i % 251) as u8)
                            .collect(),
                    }),
                };
                expected.insert(item["path"].as_str().unwrap().to_string(), content);
            }
            assert_eq!(snap, expected, "{}", case["name"]);
            assert!(v.verify(&mut |_| true).unwrap().is_ok());
        }
    }
}

// --- Crash safety --------------------------------------------------------------

fn change_set(v: &mut Vault) -> Result<(), Error> {
    v.write_bytes(&p("/new.txt"), b"brand new", meta())?;
    v.write_bytes(&p("/a.txt"), b"third version", meta())?;
    v.mkdir(&p("/F"))?;
    v.write_bytes(&p("/F/g.bin"), &pattern(140_000, 3), meta())?;
    v.remove(&p("/Docs/big.bin"), false)?;
    v.commit()?;
    v.gc()?;
    Ok(())
}

#[test]
fn crash_at_every_write_leaves_old_or_new_state() {
    let (base, words, _, old) = populated();
    // Dry run to learn the expected new state and the number of writes.
    let dry = base.reboot();
    let mut v = unlock_with(&dry, &recovery(&words), OpenMode::ReadWrite).unwrap();
    dry.crash_at(usize::MAX, Fault::Fail);
    change_set(&mut v).unwrap();
    let total = dry.ops();
    let new = snapshot(&mut v).unwrap();
    drop(v);
    assert!(total > 10, "{total} writes");

    for fault in [Fault::Fail, Fault::Tear, Fault::Delete] {
        for n in 0..total {
            let s = base.reboot();
            let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadWrite).unwrap();
            s.crash_at(n, fault);
            assert!(
                change_set(&mut v).is_err(),
                "{fault:?} at {n} should interrupt"
            );
            drop(v);
            let after = s.reboot();
            let mut v = unlock_with(&after, &recovery(&words), OpenMode::ReadOnly)
                .unwrap_or_else(|e| panic!("{fault:?} at write {n}: vault does not open: {e}"));
            let snap: Snap = snapshot(&mut v).unwrap_or_else(|e| panic!("{fault:?} at {n}: {e}"));
            assert!(
                snap == old || snap == new,
                "{fault:?} at write {n}: neither old nor new state"
            );
            assert!(v.verify(&mut |_| true).unwrap().is_ok(), "{fault:?} at {n}");
        }
    }
}

// --- Tampering -----------------------------------------------------------------

fn positions(len: usize) -> Vec<usize> {
    if len <= 3000 {
        (0..len).collect()
    } else {
        // Every byte of the first and last chunk boundaries, then a stride.
        let mut v: Vec<usize> = (0..200).chain(len - 200..len).collect();
        v.extend((200..len - 200).step_by(97));
        v
    }
}

#[test]
fn flipping_any_byte_never_yields_wrong_plaintext() {
    let (base, words, prev, cur) = populated();
    let secret = recovery(&words);
    for path in base.files() {
        if path == "TIJORI/.lock" || path == "README-TIJORI.txt" {
            continue;
        }
        let data = base.get(&path).unwrap();
        for pos in positions(data.len()) {
            let s = base.reboot();
            let mut bad = data.clone();
            bad[pos] ^= 0x01;
            s.put(&path, bad);
            match unlock_with(&s, &secret, OpenMode::ReadOnly) {
                Err(e) => assert!(
                    matches!(e.class(), ErrorClass::Tampered | ErrorClass::WrongSecret),
                    "{path}[{pos}]: {e}"
                ),
                Ok(mut v) => match snapshot(&mut v) {
                    // Backup header or the older root slot took over.
                    Ok(snap) => {
                        assert!(snap == cur || snap == prev, "{path}[{pos}]: wrong contents")
                    }
                    Err(e) => assert_eq!(e.class(), ErrorClass::Tampered, "{path}[{pos}]: {e}"),
                },
            }
        }
    }
}

#[test]
fn flipping_both_header_copies_is_detected() {
    let (base, words, _, _) = populated();
    let secret = recovery(&words);
    let header = base.get(HEADER_PATH).unwrap();
    for pos in 0..header.len() {
        let s = base.reboot();
        let mut bad = header.clone();
        bad[pos] ^= 0x01;
        s.put(HEADER_PATH, bad.clone());
        s.put(HEADER_BACKUP_PATH, bad);
        let class = unlock_with(&s, &secret, OpenMode::ReadOnly)
            .err()
            .map(|e| e.class());
        assert!(
            matches!(
                class,
                Some(
                    ErrorClass::Tampered
                        | ErrorClass::WrongSecret
                        | ErrorClass::Damaged
                        | ErrorClass::Unsupported
                )
            ),
            "byte {pos}: {class:?}"
        );
    }
}

#[test]
fn primary_header_damage_is_repaired_from_backup() {
    let (s, words, _, cur) = populated();
    let good = s.get(HEADER_PATH).unwrap();
    s.put(HEADER_PATH, good[..100].to_vec());
    let (mut v, report) = Vault::unlock(
        Arc::new(s.clone()),
        &recovery(&words),
        UnlockOptions::default(),
    )
    .unwrap();
    assert!(report.used_backup_header && report.header_copies_differed);
    assert_eq!(snapshot(&mut v).unwrap(), cur);
    assert_eq!(
        s.get(HEADER_PATH).unwrap(),
        good,
        "writable unlock repairs the primary"
    );
}

// --- Swaps and replays ---------------------------------------------------------

#[test]
fn swapped_objects_are_tampered() {
    let (base, words, _, _) = populated();
    let objects: Vec<String> = base
        .files()
        .into_iter()
        .filter(|f| f.ends_with(".tjo"))
        .collect();
    for (i, a) in objects.iter().enumerate() {
        for b in &objects[i + 1..] {
            let s = base.reboot();
            let (da, db) = (s.get(a).unwrap(), s.get(b).unwrap());
            s.put(a, db);
            s.put(b, da);
            let result = unlock_with(&s, &recovery(&words), OpenMode::ReadOnly)
                .and_then(|mut v| snapshot(&mut v));
            if let Err(e) = result {
                assert_eq!(e.class(), ErrorClass::Tampered, "{a} <-> {b}: {e}");
            }
            // Swapping two objects that are both garbage changes nothing visible.
        }
    }
}

#[test]
fn swapped_root_slots_are_damaged() {
    let (s, words, _, _) = populated();
    let (a, b) = (
        s.get(&root_path(RootSlot::A)).unwrap(),
        s.get(&root_path(RootSlot::B)).unwrap(),
    );
    s.put(&root_path(RootSlot::A), b);
    s.put(&root_path(RootSlot::B), a);
    let err = unlock_with(&s, &recovery(&words), OpenMode::ReadOnly)
        .err()
        .unwrap();
    assert_eq!(err.class(), ErrorClass::Damaged, "{err}");
}

#[test]
fn newer_root_version_refuses_instead_of_falling_back() {
    let (s, words, _, _) = populated();
    // Whichever slot is newer: mark it as written by a future version.
    for slot in [RootSlot::A, RootSlot::B] {
        let t = s.reboot();
        let mut data = t.get(&root_path(slot)).unwrap();
        data[0] = 2;
        t.put(&root_path(slot), data);
        let err = unlock_with(&t, &recovery(&words), OpenMode::ReadOnly)
            .err()
            .unwrap();
        assert_eq!(err.class(), ErrorClass::Unsupported, "{slot:?}");
    }
}

#[test]
fn replayed_root_slot_and_restored_drive_warn_of_rollback() {
    let s = MemStorage::new();
    let store: Arc<dyn RollbackStore> = Arc::new(MemRollbackStore::default());
    let mut opts = CreateOptions::new(Password::new(PASSWORD));
    opts.argon = ArgonChoice::minimum();
    opts.rollback = Some(store.clone());
    let (mut v, phrase) = Vault::create(Arc::new(s.clone()), opts).unwrap();
    let words = phrase.words().to_string();
    let slot_a_rev1 = s.get(&root_path(RootSlot::A)).unwrap();
    let drive_rev1 = s.reboot();
    v.write_bytes(&p("/f"), b"2", meta()).unwrap();
    v.commit().unwrap(); // rev 2 in B
    v.write_bytes(&p("/f"), b"3", meta()).unwrap();
    v.commit().unwrap(); // rev 3 in A
    v.lock().unwrap();

    let unlock = |storage: &MemStorage| {
        let opts = UnlockOptions {
            rollback: Some(store.clone()),
            ..UnlockOptions::default()
        };
        Vault::unlock(Arc::new(storage.clone()), &recovery(&words), opts).unwrap()
    };

    // Replay the rev-1 copy of slot A: the vault opens at rev 2, which this
    // device knows is old.
    let replay = s.reboot();
    replay.put(&root_path(RootSlot::A), slot_a_rev1);
    let (mut v, report) = unlock(&replay);
    assert_eq!(report.rev, 2);
    assert_eq!(report.rollback, RollbackStatus::Rollback { seen_rev: 3 });
    assert_eq!(
        report.read_only,
        Some(ReadOnlyReason::Rollback { seen_rev: 3 })
    );
    assert!(matches!(
        v.write_bytes(&p("/g"), b"", meta()),
        Err(Error::ReadOnly(_))
    ));
    drop(v);

    // Restore the whole drive from a backup taken at rev 1 (while that
    // session held the lock, so drop the stale lock file too).
    let restored = drive_rev1.reboot();
    restored.delete("TIJORI/.lock");
    let (mut v, report) = unlock(&restored);
    assert_eq!(report.rollback, RollbackStatus::Rollback { seen_rev: 3 });
    v.accept_current_state().unwrap();
    assert!(v.is_writable());
    v.write_bytes(&p("/g"), b"", meta()).unwrap();
    v.commit().unwrap();
}

#[test]
fn fork_is_detected() {
    let s = MemStorage::new();
    let store: Arc<dyn RollbackStore> = Arc::new(MemRollbackStore::default());
    let (v, words) = create(&s);
    v.lock().unwrap();
    let copy = s.reboot();
    let with_store = || UnlockOptions {
        rollback: Some(store.clone()),
        ..UnlockOptions::default()
    };
    // This device sees rev 2 with "one" ...
    let (mut v, _) = Vault::unlock(Arc::new(s.clone()), &recovery(&words), with_store()).unwrap();
    v.write_bytes(&p("/f"), b"one", meta()).unwrap();
    v.lock().unwrap();
    // ... while a copy of the drive gets a different rev 2 elsewhere.
    let (mut v, _) = Vault::unlock(
        Arc::new(copy.clone()),
        &recovery(&words),
        UnlockOptions::default(),
    )
    .unwrap();
    v.write_bytes(&p("/f"), b"two", meta()).unwrap();
    v.lock().unwrap();
    let (_, report) = Vault::unlock(Arc::new(copy), &recovery(&words), with_store()).unwrap();
    assert_eq!(report.rollback, RollbackStatus::Fork { seen_rev: 2 });
    assert_eq!(report.read_only, Some(ReadOnlyReason::Fork { seen_rev: 2 }));
}

// --- Locking -------------------------------------------------------------------

#[test]
fn second_writer_opens_read_only() {
    let (s, words, _, _) = populated();
    let mut first = unlock_with(&s, &recovery(&words), OpenMode::ReadWrite).unwrap();
    let (mut second, report) = Vault::unlock(
        Arc::new(s.clone()),
        &recovery(&words),
        UnlockOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        report.read_only,
        Some(ReadOnlyReason::LockedBy(Some(_)))
    ));
    assert!(!second.is_writable());
    assert!(matches!(second.mkdir(&p("/x")), Err(Error::ReadOnly(_))));
    first.write_bytes(&p("/by-first"), b"1", meta()).unwrap();
    first.lock().unwrap();
    second.retry_write_access().unwrap();
    assert!(second.is_writable());
    // The second writer builds on the first one's commit instead of losing it.
    second.write_bytes(&p("/by-second"), b"2", meta()).unwrap();
    second.lock().unwrap();
    let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadOnly).unwrap();
    assert!(v.exists(&p("/by-first")).unwrap() && v.exists(&p("/by-second")).unwrap());
}

// --- Keyslots and re-keying ----------------------------------------------------

const OTHER: &str = "quartz pelican harbor midnight saffron tundra";

#[test]
fn keyslot_management() {
    let (s, words, _, cur) = populated();
    let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadWrite).unwrap();
    assert_eq!(v.keyslots().len(), 2);
    let keyfile = b"keyfile contents".to_vec();
    let (idx, _) = v
        .add_keyslot(NewSlot::Password {
            password: Password::new(OTHER),
            keyfile: Some(Keyfile::from_bytes(&keyfile)),
            argon: ArgonChoice::minimum(),
        })
        .unwrap();
    v.change_password(0, Password::new(OTHER), None).unwrap();
    assert!(
        v.change_password(1, Password::new(OTHER), None).is_err(),
        "recovery slot"
    );
    assert!(
        v.change_password(0, Password::new("letmein"), None)
            .is_err_and(|e| matches!(e, Error::InvalidInput(_)))
    );
    v.lock().unwrap();

    let old = unlock_with(&s, &UnlockSecret::password(PASSWORD), OpenMode::ReadOnly);
    assert_eq!(old.err().unwrap().class(), ErrorClass::WrongSecret);
    let mut v = unlock_with(&s, &UnlockSecret::password(OTHER), OpenMode::ReadWrite).unwrap();
    assert_eq!(snapshot(&mut v).unwrap(), cur);
    v.remove_keyslot(0).unwrap();
    v.remove_keyslot(1).unwrap();
    assert!(v.remove_keyslot(idx).is_err(), "never the last one");
    v.lock().unwrap();
    let with_keyfile = UnlockSecret::Password {
        password: Password::new(OTHER),
        keyfile: Some(Keyfile::from_bytes(&keyfile)),
    };
    let (_, report) =
        Vault::unlock(Arc::new(s.clone()), &with_keyfile, UnlockOptions::default()).unwrap();
    assert_eq!(report.slot_index, idx);
    assert_eq!(
        unlock_with(&s, &UnlockSecret::password(OTHER), OpenMode::ReadOnly)
            .err()
            .unwrap()
            .class(),
        ErrorClass::WrongSecret,
        "keyfile slot needs the keyfile"
    );
}

#[test]
fn rekey_revokes_old_headers() {
    let (s, words, _, cur) = populated();
    let old_header = s.get(HEADER_PATH).unwrap();
    let old_objects: Vec<String> = s
        .files()
        .into_iter()
        .filter(|f| f.ends_with(".tjo"))
        .collect();
    let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadWrite).unwrap();
    let rev = v.rev();
    let phrase = v
        .rekey(
            vec![
                NewSlot::Password {
                    password: Password::new(OTHER),
                    keyfile: None,
                    argon: ArgonChoice::minimum(),
                },
                NewSlot::Recovery,
            ],
            &mut |_| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(v.rev(), rev + 2);
    v.lock().unwrap();
    for o in &old_objects {
        assert!(s.get(o).is_none(), "old object {o} was collected");
    }
    let mut v = unlock_with(&s, &recovery(&phrase.words()), OpenMode::ReadOnly).unwrap();
    assert_eq!(snapshot(&mut v).unwrap(), cur);
    assert!(v.verify(&mut |_| true).unwrap().is_ok());
    assert_eq!(
        unlock_with(&s, &recovery(&words), OpenMode::ReadOnly)
            .err()
            .unwrap()
            .class(),
        ErrorClass::WrongSecret
    );
    // Someone kept the old header and knows the old recovery phrase.
    let stolen = s.reboot();
    stolen.put(HEADER_PATH, old_header.clone());
    stolen.put(HEADER_BACKUP_PATH, old_header);
    let err = unlock_with(&stolen, &recovery(&words), OpenMode::ReadOnly)
        .err()
        .unwrap();
    assert_eq!(
        err.class(),
        ErrorClass::Damaged,
        "old MK opens nothing: {err}"
    );
}

#[test]
fn crash_during_rekey_opens_old_or_new_state() {
    let (base, words, _, cur) = populated();
    let new_slots = || {
        vec![NewSlot::Password {
            password: Password::new(OTHER),
            keyfile: None,
            argon: ArgonChoice::minimum(),
        }]
    };
    let dry = base.reboot();
    let mut v = unlock_with(&dry, &recovery(&words), OpenMode::ReadWrite).unwrap();
    dry.crash_at(usize::MAX, Fault::Fail);
    v.rekey(new_slots(), &mut |_| true).unwrap();
    let total = dry.ops();
    drop(v);
    for fault in [Fault::Fail, Fault::Tear, Fault::Delete] {
        for n in 0..total {
            let s = base.reboot();
            let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadWrite).unwrap();
            s.crash_at(n, fault);
            assert!(v.rekey(new_slots(), &mut |_| true).is_err());
            drop(v);
            let after = s.reboot();
            // Either secret may be the right one, depending on where it stopped.
            let opened = unlock_with(&after, &recovery(&words), OpenMode::ReadOnly).or_else(|_| {
                unlock_with(&after, &UnlockSecret::password(OTHER), OpenMode::ReadOnly)
            });
            let mut v = opened.unwrap_or_else(|e| panic!("{fault:?} at {n}: {e}"));
            assert_eq!(snapshot(&mut v).unwrap(), cur, "{fault:?} at {n}");
        }
    }
}

// --- Garbage collection and verification ----------------------------------------

#[test]
fn gc_removes_only_unreachable_objects() {
    let s = MemStorage::new();
    let (mut v, _) = create(&s);
    for i in 0..5 {
        v.write_bytes(&p("/f"), &pattern(1000, i), meta()).unwrap();
        v.commit().unwrap();
    }
    s.put("TIJORI/objects/00/stray.tjo.tmp", vec![1, 2, 3]);
    s.put("TIJORI/vault.root.a.tmp", vec![1]);
    let report = v.gc().unwrap();
    // Root folders and files from revs 1-4 go, except those rev 5's
    // predecessor (in the other root slot) still uses.
    assert!(report.removed >= 6, "{report:?}");
    assert_eq!(report.kept, 4, "two trees of one folder and one file each");
    assert!(s.get("TIJORI/objects/00/stray.tjo.tmp").is_none());
    assert!(s.get("TIJORI/vault.root.a.tmp").is_none());
    assert!(v.verify(&mut |_| true).unwrap().is_ok());
    assert_eq!(v.read_to_vec(&p("/f"), 10_000).unwrap(), pattern(1000, 4));
}

#[test]
fn verify_reports_damage_by_path() {
    let (s, words, _, _) = populated();
    let mut v = unlock_with(&s, &recovery(&words), OpenMode::ReadOnly).unwrap();
    let entries: Vec<Entry> = v.list(&p("/Docs")).unwrap();
    assert_eq!(entries.len(), 2);
    drop(v);
    // Corrupt every object once; verify must name what broke.
    let mut found = 0;
    for path in s.files().into_iter().filter(|f| f.ends_with(".tjo")) {
        let t = s.reboot();
        let mut data = t.get(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 1;
        t.put(&path, data);
        if let Ok(mut v) = unlock_with(&t, &recovery(&words), OpenMode::ReadOnly) {
            let report = v.verify(&mut |_| true).unwrap();
            if !report.is_ok() {
                found += 1;
                assert!(
                    report
                        .problems
                        .iter()
                        .all(|p| p.class == ErrorClass::Tampered)
                );
            }
        }
    }
    assert!(found >= 2, "file objects in the current tree are reported");
}

// --- Large files -----------------------------------------------------------------

/// Plan Milestone 2: a 2 GiB file imports and exports with flat memory use.
/// Run with: cargo test --release -p tijori-core --test vault -- --ignored huge
#[test]
#[ignore]
fn huge_file_streams() {
    const LEN: u64 = 2 * 1024 * 1024 * 1024;
    struct Gen(u64);
    impl Read for Gen {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min((LEN - self.0) as usize);
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = ((self.0 + i as u64) % 251) as u8;
            }
            self.0 += n as u64;
            Ok(n)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(StdFsStorage::new(dir.path()));
    let mut opts = CreateOptions::new(Password::new(PASSWORD));
    opts.argon = ArgonChoice::minimum();
    let (mut v, _) = Vault::create(storage, opts).unwrap();
    v.import(&mut Gen(0), &p("/huge.bin"), LEN, meta()).unwrap();
    v.commit().unwrap();
    let mut r = v.read_file(&p("/huge.bin")).unwrap();
    let mut expected = Gen(0);
    let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    let mut total = 0u64;
    loop {
        let n = r.read(&mut a).unwrap();
        if n == 0 {
            break;
        }
        expected.read_exact(&mut b[..n]).unwrap();
        assert!(a[..n] == b[..n], "mismatch at {total}");
        total += n as u64;
    }
    assert_eq!(total, LEN);
}

#[test]
fn storage_trait_is_object_safe() {
    let s: Arc<dyn Storage> = Arc::new(MemStorage::new());
    assert!(s.list("TIJORI").unwrap().is_empty());
}
