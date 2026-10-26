//! Directory objects (spec §8.2): the content of a kind-2 object.

use super::cbor::{self, Value, decode_map};
use super::object::ObjectKind;
use crate::crypto::HASH_LEN;
use crate::error::{Error, Result};
use crate::names;

pub const DIR_VERSION: u64 = 1;
pub const MAX_ENTRIES: usize = 200_000;
/// Directory plaintext limit (spec §12).
pub const MAX_DIR_PLAINTEXT: u64 = 64 * 1024 * 1024;

/// Bit 0 of `mode`.
pub const MODE_EXECUTABLE: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// NFC, valid per spec §11.
    pub name: String,
    pub kind: ObjectKind,
    pub id: [u8; 32],
    /// `H(none, child object file bytes)`.
    pub hash: [u8; HASH_LEN],
    /// Content bytes; files only.
    pub size: Option<u64>,
    /// Unix milliseconds.
    pub mtime: i64,
    pub mode: Option<u64>,
    /// Fields from newer versions, kept when the entry is copied unchanged.
    pub unknown: Vec<(Value, Value)>,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.kind == ObjectKind::Dir
    }

    pub fn is_executable(&self) -> bool {
        self.mode.is_some_and(|m| m & MODE_EXECUTABLE != 0)
    }

    fn to_value(&self) -> Value {
        let mut f = vec![
            (Value::Uint(1), Value::Text(self.name.clone())),
            (Value::Uint(2), Value::Uint(self.kind as u64)),
            (Value::Uint(3), Value::Bytes(self.id.to_vec())),
            (Value::Uint(4), Value::Bytes(self.hash.to_vec())),
            (Value::Uint(6), Value::int(self.mtime)),
        ];
        if let Some(size) = self.size {
            f.push((Value::Uint(5), Value::Uint(size)));
        }
        if let Some(mode) = self.mode {
            f.push((Value::Uint(7), Value::Uint(mode)));
        }
        f.extend(self.unknown.iter().cloned());
        Value::Map(f)
    }

    fn from_value(v: Value) -> Result<Self> {
        let mut m = cbor::MapFields::from_value(v)
            .ok_or_else(|| Error::damaged("directory entry is not a map"))?;
        let name = m.text(1, "name")?;
        names::check_stored(&name).map_err(|p| Error::damaged(format!("stored {p}")))?;
        let kind = match m.uint(2, "kind")? {
            1 => ObjectKind::File,
            2 => ObjectKind::Dir,
            k => return Err(Error::damaged(format!("unknown entry kind {k}"))),
        };
        let id = m.bytes(3, "id")?;
        let hash = m.bytes(4, "hash")?;
        let size = m.opt_uint(5, "size")?;
        match (kind, size) {
            (ObjectKind::File, None) => return Err(Error::damaged("file entry without size")),
            (ObjectKind::Dir, Some(_)) => return Err(Error::damaged("folder entry with size")),
            _ => {}
        }
        let mtime = m.int(6, "mtime")?;
        let mode = m.opt_uint(7, "mode")?;
        Ok(DirEntry {
            name,
            kind,
            id,
            hash,
            size,
            mtime,
            mode,
            unknown: m.rest(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    /// Sorted by name bytes, names unique.
    pub entries: Vec<DirEntry>,
    pub unknown: Vec<(Value, Value)>,
}

impl Directory {
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut m = decode_map(data, "directory")?;
        let version = m.uint(1, "dir_version")?;
        if version != DIR_VERSION {
            return Err(Error::unsupported(format!("directory version {version}")));
        }
        let items = m.array(2, "entries")?;
        if items.len() > MAX_ENTRIES {
            return Err(Error::damaged(format!(
                "directory has more than {MAX_ENTRIES} entries"
            )));
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            let e = DirEntry::from_value(item)?;
            if let Some(prev) = entries.last().map(|p: &DirEntry| p.name.as_bytes())
                && prev >= e.name.as_bytes()
            {
                return Err(Error::damaged(
                    "directory entries are unsorted or duplicated",
                ));
            }
            entries.push(e);
        }
        Ok(Directory {
            entries,
            unknown: m.rest(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.entries
                .windows(2)
                .all(|w| w[0].name.as_bytes() < w[1].name.as_bytes())
        );
        let mut f = vec![
            (Value::Uint(1), Value::Uint(DIR_VERSION)),
            (
                Value::Uint(2),
                Value::Array(self.entries.iter().map(DirEntry::to_value).collect()),
            ),
        ];
        f.extend(self.unknown.iter().cloned());
        cbor::encode(&Value::Map(f))
    }

    fn position(&self, name: &str) -> std::result::Result<usize, usize> {
        self.entries
            .binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes()))
    }

    pub fn get(&self, name: &str) -> Option<&DirEntry> {
        self.position(name).ok().map(|i| &self.entries[i])
    }

    /// Inserts or replaces the entry with the same name, keeping order.
    pub fn upsert(&mut self, entry: DirEntry) -> Result<()> {
        match self.position(&entry.name) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => {
                if self.entries.len() >= MAX_ENTRIES {
                    return Err(Error::invalid(format!(
                        "a folder can hold at most {MAX_ENTRIES} entries"
                    )));
                }
                self.entries.insert(i, entry)
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Option<DirEntry> {
        self.position(name).ok().map(|i| self.entries.remove(i))
    }
}
