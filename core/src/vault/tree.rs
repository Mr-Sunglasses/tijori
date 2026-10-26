//! Object I/O and the in-memory, copy-on-write directory tree.
//!
//! Folders are loaded lazily and cached. A change marks every folder from
//! the change up to the root dirty; `flush` writes dirty folders deepest
//! first as new objects, so the root pointer is the only thing that commits.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::crypto::{Blake2b, HASH_LEN, ObjectRootKey, ct_eq, random_array};
use crate::error::{Error, Result, StorageError};
use crate::format::Directory;
use crate::format::dir::MAX_DIR_PLAINTEXT;
use crate::format::object::{
    ObjectKind, ObjectReader, ObjectWriter, WrittenObject, decrypt_object, disk_size,
    encrypt_object, object_key,
};
use crate::padding::stream_total;
use crate::storage::Storage;

use super::{OBJECTS_DIR, hex};

/// The ID and file hash of a stored object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjRef {
    pub id: [u8; 32],
    pub hash: [u8; HASH_LEN],
}

pub(crate) fn object_path(id: &[u8; 32]) -> String {
    let h = hex(id);
    format!("{OBJECTS_DIR}/{}/{h}.tjo", &h[..2])
}

fn object_dir(id: &[u8; 32]) -> String {
    format!("{OBJECTS_DIR}/{:02x}", id[0])
}

fn missing_or(e: StorageError, what: &str) -> Error {
    if e.is_not_found() {
        Error::damaged(format!("{what} is missing"))
    } else {
        e.into()
    }
}

/// Reads and writes objects under one `K_obj`.
pub(crate) struct Objects<'a> {
    pub storage: &'a dyn Storage,
    pub k_obj: &'a ObjectRootKey,
}

impl Objects<'_> {
    /// Loads a folder: size limit, hash check, then decryption (spec §8.2:
    /// verify the hash before decrypting).
    pub fn load_dir(&self, r: &ObjRef) -> Result<Directory> {
        let path = object_path(&r.id);
        let max_disk = disk_size(stream_total(MAX_DIR_PLAINTEXT, true));
        let len = self
            .storage
            .len(&path)
            .map_err(|e| missing_or(e, "a folder object"))?;
        if len > max_disk {
            return Err(Error::damaged("a folder object is larger than the limit"));
        }
        let data = self
            .storage
            .read(&path)
            .map_err(|e| missing_or(e, "a folder object"))?;
        if !ct_eq(&crate::crypto::hash(&data), &r.hash) {
            return Err(Error::tampered("a folder object does not match its hash"));
        }
        let key = object_key(self.k_obj, ObjectKind::Dir, &r.id);
        let content = decrypt_object(&data, &key, ObjectKind::Dir, &r.id, MAX_DIR_PLAINTEXT - 8)?;
        Directory::decode(&content)
    }

    /// Checks a file object's hash in a first pass, then opens it for
    /// streaming decryption (which re-checks the hash at the end).
    pub fn open_file(&self, r: &ObjRef) -> Result<ObjectReader<Box<dyn Read + Send>>> {
        let path = object_path(&r.id);
        let mut input = self
            .storage
            .open_read(&path)
            .map_err(|e| missing_or(e, "a file object"))?;
        let mut h = Blake2b::new(None);
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = input
                .read(&mut buf)
                .map_err(|e| Error::from_io(e, "reading a file object"))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        if !ct_eq(&h.finalize(), &r.hash) {
            return Err(Error::tampered("a file object does not match its hash"));
        }
        let input = self
            .storage
            .open_read(&path)
            .map_err(|e| missing_or(e, "a file object"))?;
        let key = object_key(self.k_obj, ObjectKind::File, &r.id);
        ObjectReader::new(input, &key, ObjectKind::File, &r.id, Some(r.hash))
    }

    /// Writes a folder as a new object.
    pub fn write_dir(&self, dir: &Directory, padding: bool) -> Result<ObjRef> {
        let content = dir.encode();
        if content.len() as u64 > MAX_DIR_PLAINTEXT - 8 {
            return Err(Error::invalid("this folder has too many entries to store"));
        }
        let id = random_array::<32>();
        let key = object_key(self.k_obj, ObjectKind::Dir, &id);
        let (bytes, info) = encrypt_object(&key, ObjectKind::Dir, &id, &content, padding);
        self.storage.mkdir_all(&object_dir(&id))?;
        let path = object_path(&id);
        self.storage.write_atomic(&path, &bytes)?;
        let _ = self.storage.neutralize_times(&path);
        Ok(ObjRef {
            id,
            hash: info.hash,
        })
    }

    /// Streams `len` bytes from `src` into a new file object.
    pub fn write_file(
        &self,
        src: &mut dyn Read,
        len: u64,
        padding: bool,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<ObjRef> {
        let id = random_array::<32>();
        let key = object_key(self.k_obj, ObjectKind::File, &id);
        self.storage.mkdir_all(&object_dir(&id))?;
        let path = object_path(&id);
        let out = self.storage.create_writer(&path)?;
        let mut w = ObjectWriter::new(out, &key, ObjectKind::File, &id, len, padding)?;
        let mut buf = zeroize::Zeroizing::new(vec![0u8; 256 * 1024]);
        let mut done = 0u64;
        while done < len {
            let want = (len - done).min(buf.len() as u64) as usize;
            let n = match src.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from_io(e, "reading the source file")),
            };
            w.write_all(&buf[..n])
                .map_err(|e| Error::from_io(e, "writing a file object"))?;
            done += n as u64;
            if !progress(done) {
                return Err(Error::Cancelled);
            }
        }
        let (out, WrittenObject { hash, .. }) = w.finish()?;
        out.commit()?;
        let _ = self.storage.neutralize_times(&path);
        Ok(ObjRef { id, hash })
    }
}

/// A loaded folder. `obj` is `None` while it has unwritten changes.
#[derive(Debug, Clone)]
pub(crate) struct DirNode {
    pub dir: Directory,
    pub obj: Option<ObjRef>,
    /// Loaded subfolders, by entry name.
    pub children: BTreeMap<String, DirNode>,
}

impl DirNode {
    pub fn loaded(dir: Directory, obj: ObjRef) -> Self {
        DirNode {
            dir,
            obj: Some(obj),
            children: BTreeMap::new(),
        }
    }

    pub fn new_empty() -> Self {
        DirNode {
            dir: Directory::default(),
            obj: None,
            children: BTreeMap::new(),
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.obj.is_none()
    }

    /// Walks to the folder at `comps`, loading folders as needed. With
    /// `dirty`, every folder on the way is marked changed.
    pub fn walk<'n>(
        &'n mut self,
        objects: &Objects,
        comps: &[String],
        dirty: bool,
    ) -> Result<&'n mut DirNode> {
        if dirty {
            self.obj = None;
        }
        let Some((name, rest)) = comps.split_first() else {
            return Ok(self);
        };
        if !self.children.contains_key(name) {
            let entry = self
                .dir
                .get(name)
                .ok_or_else(|| Error::NotFound(name.clone()))?;
            if !entry.is_dir() {
                return Err(Error::NotADirectory(name.clone()));
            }
            let r = ObjRef {
                id: entry.id,
                hash: entry.hash,
            };
            let child = DirNode::loaded(objects.load_dir(&r)?, r);
            self.children.insert(name.clone(), child);
        }
        let child = self.children.get_mut(name).expect("inserted above");
        child.walk(objects, rest, dirty)
    }

    /// Writes every dirty folder below and including this one, deepest
    /// first, updating parent entries with the new IDs and hashes.
    pub fn flush(&mut self, objects: &Objects, padding: bool, now_ms: i64) -> Result<ObjRef> {
        if let Some(r) = self.obj {
            return Ok(r);
        }
        let names: Vec<String> = self
            .children
            .iter()
            .filter(|(_, c)| c.is_dirty())
            .map(|(n, _)| n.clone())
            .collect();
        for name in names {
            let child = self.children.get_mut(&name).expect("listed above");
            let r = child.flush(objects, padding, now_ms)?;
            if let Some(e) = self.dir.entries.iter_mut().find(|e| e.name == name) {
                e.id = r.id;
                e.hash = r.hash;
                e.mtime = now_ms;
            }
        }
        let r = objects.write_dir(&self.dir, padding)?;
        self.obj = Some(r);
        Ok(r)
    }
}
