//! Runs every vector file in spec/vectors (produced by spec/generator with
//! libsodium) against the Rust implementation, including every negative
//! case with its exact error class.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use serde_json::Value as J;
use tijori_core::crypto::{Kek, Key, MasterKey, ObjectRootKey, RootKey, argon2id, hash, kdf};
use tijori_core::format::object::{ObjectReader, object_key};
use tijori_core::format::{ArgonParams, Directory, Keyslot, ObjectKind, RootPointer, RootSlot};
use tijori_core::keys::{
    derive_kek, kek_password, kek_password_keyfile, kek_recovery, open_header,
};
use tijori_core::padding::padme;
use tijori_core::{Error, Keyfile, Password, RecoveryPhrase, UnlockSecret};

fn vectors(name: &str) -> J {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../spec/vectors")
        .join(name);
    serde_json::from_str(
        &fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap()
}

fn bytes(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).unwrap()
}

fn arr<const N: usize>(v: &J) -> [u8; N] {
    bytes(v).try_into().unwrap()
}

fn key(v: &J) -> Key {
    Key::from_bytes(&mut arr(v))
}

fn cases<'a>(v: &'a J, field: &str) -> &'a Vec<J> {
    v[field]
        .as_array()
        .unwrap_or_else(|| panic!("missing {field}"))
}

fn name(c: &J) -> &str {
    c["name"].as_str().unwrap()
}

fn expect_class(result: Result<impl Sized, Error>, c: &J) {
    let expected = c["error"].as_str().unwrap();
    match result {
        Ok(_) => panic!("{}: expected {expected}, got success", name(c)),
        Err(e) => assert_eq!(e.class().vector_name(), expected, "{}: {e}", name(c)),
    }
}

fn content(c: &J) -> Vec<u8> {
    if let Some(h) = c.get("hex") {
        bytes(h)
    } else {
        assert_eq!(c["pattern"], "mod251");
        (0..c["len"].as_u64().unwrap())
            .map(|i| (i % 251) as u8)
            .collect()
    }
}

fn secret(c: &J) -> UnlockSecret {
    if let Some(p) = c.get("recovery_phrase") {
        return UnlockSecret::Recovery(RecoveryPhrase::parse(p.as_str().unwrap()).unwrap());
    }
    UnlockSecret::Password {
        password: Password::new(c["password"].as_str().unwrap()),
        keyfile: c.get("keyfile_hex").map(|k| Keyfile::from_bytes(&bytes(k))),
    }
}

fn params(c: &J) -> ArgonParams {
    ArgonParams {
        mem_kib: c["mem_kib"].as_u64().unwrap() as u32,
        ops: c["ops"].as_u64().unwrap() as u32,
    }
}

#[test]
fn subkeys() {
    for c in cases(&vectors("subkeys.json"), "cases") {
        let mk = key(&c["mk"]);
        assert_eq!(kdf(&mk, 1).as_bytes(), &arr(&c["k_hmac"]));
        assert_eq!(kdf(&mk, 2).as_bytes(), &arr(&c["k_root"]));
        assert_eq!(kdf(&mk, 3).as_bytes(), &arr(&c["k_obj"]));
        let k_obj = ObjectRootKey::from_key(kdf(&mk, 3));
        for ok in cases(c, "object_keys") {
            let kind = if ok["kind"] == 1 {
                ObjectKind::File
            } else {
                ObjectKind::Dir
            };
            let derived = object_key(&k_obj, kind, &arr(&ok["object_id"]));
            assert_eq!(derived.as_bytes(), &arr(&ok["object_key"]));
        }
    }
}

#[test]
fn padme_vectors() {
    let v = vectors("padme.json");
    for c in cases(&v, "cases") {
        assert_eq!(
            padme(c["l"].as_u64().unwrap()),
            c["padme"].as_u64().unwrap(),
            "{c}"
        );
    }
    for c in cases(&v, "content_examples") {
        let total = tijori_core::padding::stream_total(c["content_length"].as_u64().unwrap(), true);
        assert_eq!(total, c["stored_plaintext"].as_u64().unwrap());
        assert_eq!(
            tijori_core::format::object::disk_size(total),
            c["disk_size"].as_u64().unwrap()
        );
    }
}

#[test]
fn kek() {
    let v = vectors("kek.json");
    for c in cases(&v, "cases") {
        let salt = arr(&c["salt"]);
        let kek: Kek = match c["slot_type"].as_u64().unwrap() {
            1 => kek_password(
                &Password::new(c["password"].as_str().unwrap()),
                &salt,
                params(c),
            )
            .unwrap(),
            2 => {
                let p = Password::new(c["password"].as_str().unwrap());
                let a = kek_password(&p, &salt, params(c)).unwrap();
                assert_eq!(a.as_bytes(), &arr(&c["argon_output"]), "{}", name(c));
                kek_password_keyfile(
                    &p,
                    &Keyfile::from_bytes(&bytes(&c["keyfile_hex"])),
                    &salt,
                    params(c),
                )
                .unwrap()
            }
            3 => {
                let phrase = RecoveryPhrase::parse(c["recovery_phrase"].as_str().unwrap()).unwrap();
                let from_entropy = RecoveryPhrase::from_entropy(arr(&c["entropy"]));
                assert_eq!(*phrase.words(), *from_entropy.words());
                kek_recovery(&phrase, &salt)
            }
            t => panic!("slot type {t}"),
        };
        assert_eq!(kek.as_bytes(), &arr(&c["kek"]), "{}", name(c));
    }
    for c in cases(&v, "negative") {
        let salt = arr(&c["salt"]);
        let got: [u8; 32] = if let Some(raw) = c.get("argon_input_utf8_hex") {
            let out = argon2id(&bytes(raw), &salt, params(c).mem_kib, params(c).ops).unwrap();
            assert_eq!(out.as_bytes(), &arr(&c["argon_output"]));
            *out.as_bytes()
        } else {
            let p = Password::new(c["password"].as_str().unwrap());
            let kf = Keyfile::from_bytes(&bytes(&c["keyfile_hex"]));
            *kek_password_keyfile(&p, &kf, &salt, params(c))
                .unwrap()
                .as_bytes()
        };
        assert_ne!(got, arr::<32>(&c["must_not_equal"]), "{}", name(c));
    }
}

fn unwrap_slot(c: &J) -> Result<MasterKey, Error> {
    let slot = Keyslot::from_bytes(arr(&c["slot"]));
    let kek = derive_kek(&slot, &secret(c))?.ok_or(Error::WrongSecret)?;
    slot.unwrap(
        &kek,
        &arr(&c["vault_uuid"]),
        c["slot_index"].as_u64().unwrap() as u8,
    )
    .ok_or(Error::WrongSecret)
}

#[test]
fn keyslot() {
    let v = vectors("keyslot.json");
    for c in cases(&v, "cases") {
        let mk = unwrap_slot(c).unwrap_or_else(|e| panic!("{}: {e}", name(c)));
        assert_eq!(mk.as_bytes(), &arr(&c["mk"]), "{}", name(c));
    }
    for c in cases(&v, "negative") {
        expect_class(unwrap_slot(c), c);
    }
}

#[test]
fn header() {
    let v = vectors("header.json");
    for c in cases(&v, "cases") {
        let opened = open_header(&bytes(&c["header"]), &secret(c))
            .unwrap_or_else(|e| panic!("{}: {e}", name(c)));
        assert_eq!(opened.mk.as_bytes(), &arr(&c["mk"]), "{}", name(c));
        assert_eq!(
            opened.slot_index as u64,
            c["opened_slot"].as_u64().unwrap(),
            "{}",
            name(c)
        );
        assert_eq!(
            opened.header.to_bytes(),
            bytes(&c["header"]),
            "{}: round trip",
            name(c)
        );
        if let Some(mac) = c.get("header_mac") {
            assert_eq!(opened.header.mac, arr(mac));
            assert_eq!(opened.header.vault_uuid, arr(&c["vault_uuid"]));
        }
    }
    for c in cases(&v, "negative") {
        expect_class(open_header(&bytes(&c["header"]), &secret(c)), c);
    }
}

fn read_object(
    data: &[u8],
    k: &tijori_core::crypto::ObjectKey,
    kind: ObjectKind,
    id: &[u8; 32],
    h: Option<[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    let mut r = ObjectReader::new(data, k, kind, id, h)?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)
        .map_err(|e| Error::from_io(e, "test"))?;
    Ok(out)
}

fn kind_of(v: &J) -> ObjectKind {
    if *v == 1 {
        ObjectKind::File
    } else {
        ObjectKind::Dir
    }
}

#[test]
fn object() {
    let v = vectors("object.json");
    let k_obj = ObjectRootKey::from_key(key(&v["k_obj"]));
    let positives = cases(&v, "cases");
    for c in positives {
        let (kind, id) = (kind_of(&c["kind"]), arr(&c["object_id"]));
        let k = object_key(&k_obj, kind, &id);
        assert_eq!(k.as_bytes(), &arr(&c["object_key"]));
        let data = bytes(&c["object"]);
        assert_eq!(hash(&data), arr(&c["hash"]));
        let got = read_object(&data, &k, kind, &id, Some(arr(&c["hash"])))
            .unwrap_or_else(|e| panic!("{}: {e}", name(c)));
        assert_eq!(got, content(&c["content"]), "{}", name(c));
    }
    for c in cases(&v, "negative") {
        let (kind, id) = (kind_of(&c["kind"]), arr(&c["object_id"]));
        let data = if let Some(base) = c.get("base") {
            let b = positives.iter().find(|p| p["name"] == *base).unwrap();
            let mut data = bytes(&b["object"]);
            let m = &c["mutation"];
            if let Some(n) = m.get("truncate_to") {
                data.truncate(n.as_u64().unwrap() as usize);
            }
            if let Some(h) = m.get("append_hex") {
                data.extend(bytes(h));
            }
            if let Some(s) = m.get("swap") {
                let s: Vec<usize> = s
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as usize)
                    .collect();
                let (a, b) = (data[s[0]..s[1]].to_vec(), data[s[2]..s[3]].to_vec());
                assert_eq!(s[1], s[2]);
                data.splice(s[0]..s[3], b.into_iter().chain(a));
            }
            if let Some(sb) = m.get("set_byte") {
                data[sb[0].as_u64().unwrap() as usize] = sb[1].as_u64().unwrap() as u8;
            }
            data
        } else {
            bytes(&c["object"])
        };
        let k = object_key(&k_obj, kind, &id);
        expect_class(read_object(&data, &k, kind, &id, None), c);
    }
}

#[test]
fn root() {
    let v = vectors("root.json");
    let uuid = arr(&v["vault_uuid"]);
    let mk = key(&v["mk"]);
    assert_eq!(kdf(&mk, 2).as_bytes(), &arr(&v["k_root"]));
    let k_root = RootKey::from_key(kdf(&mk, 2));
    let slot = |c: &J| {
        if c["slot"] == "a" {
            RootSlot::A
        } else {
            RootSlot::B
        }
    };
    for c in cases(&v, "cases") {
        let r = RootPointer::open(&bytes(&c["file"]), &k_root, &uuid, slot(c)).unwrap();
        let f = &c["fields"];
        assert_eq!(r.rev, f["rev"].as_u64().unwrap());
        assert_eq!(r.root_id, arr(&f["root_id"]));
        assert_eq!(r.root_hash, arr(&f["root_hash"]));
        assert_eq!(r.written_at, f["written_at"].as_u64().unwrap());
        assert_eq!(r.writer_id, arr(&f["writer_id"]));
        assert_eq!(
            r.settings.padding,
            f["settings"]["padding"].as_bool().unwrap()
        );
        assert_eq!(
            r.settings.private_only,
            f["settings"]["private_only"].as_bool().unwrap()
        );
        assert_eq!(r.settings.label, f["settings"]["label"].as_str().unwrap());
        assert_eq!(r.to_cbor(), bytes(&c["cbor"]), "deterministic encoding");
    }
    for c in cases(&v, "negative") {
        expect_class(
            RootPointer::open(&bytes(&c["file"]), &k_root, &arr(&c["vault_uuid"]), slot(c)),
            c,
        );
    }
}

#[test]
fn dir() {
    let v = vectors("dir.json");
    for c in cases(&v, "cases") {
        let cbor = bytes(&c["cbor"]);
        let d = Directory::decode(&cbor).unwrap();
        let expected = cases(c, "entries");
        assert_eq!(d.entries.len(), expected.len());
        for (e, x) in d.entries.iter().zip(expected) {
            assert_eq!(e.name, x["name"].as_str().unwrap());
            assert_eq!(e.kind as u64, x["kind"].as_u64().unwrap());
            assert_eq!(e.id, arr(&x["id"]));
            assert_eq!(e.hash, arr(&x["hash"]));
            assert_eq!(e.mtime, x["mtime"].as_i64().unwrap());
            assert_eq!(e.size, x.get("size").map(|s| s.as_u64().unwrap()));
            assert_eq!(e.mode, x.get("mode").map(|s| s.as_u64().unwrap()));
            let unknown = x
                .get("unknown_cbor")
                .map(|u| u.as_object().unwrap().len())
                .unwrap_or(0);
            assert_eq!(e.unknown.len(), unknown, "unknown fields are kept");
        }
        assert_eq!(
            d.encode(),
            cbor,
            "{}: deterministic re-encoding keeps unknown fields",
            name(c)
        );
    }
    for c in cases(&v, "negative") {
        expect_class(Directory::decode(&bytes(&c["cbor"])), c);
    }
}
