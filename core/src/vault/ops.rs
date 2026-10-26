//! Everyday operations: list, read, import, folders, rename, remove and
//! commit (spec §9.1).

use std::io::{self, Read};

use super::tree::{DirNode, ObjRef, Objects};
use super::{
    Entry, EntryKind, FileMeta, Phase, Progress, Vault, VaultPath, now_ms, now_secs, root_path,
};
use crate::crypto::random_array;
use crate::error::{Error, Result};
use crate::format::dir::{DirEntry, MODE_EXECUTABLE};
use crate::format::{ObjectKind, ObjectReader, RootPointer, Settings};

/// Streams a file's verified content. Read errors carry the vault error
/// class (use [`Error::from_io`]); an error at any point, including the end,
/// means the whole file must be discarded.
pub struct FileReader {
    inner: ObjectReader<Box<dyn Read + Send>>,
}

impl FileReader {
    pub fn len(&self) -> u64 {
        self.inner.content_len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

fn to_entry(e: &DirEntry) -> Entry {
    Entry {
        name: e.name.clone(),
        kind: if e.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        },
        size: e.size.unwrap_or(0),
        mtime_ms: e.mtime,
        executable: e.is_executable(),
    }
}

impl Vault {
    fn objects(&self) -> Objects<'_> {
        Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        }
    }

    /// The folder node at `path`, loading it if needed.
    fn node(&mut self, path: &VaultPath, dirty: bool) -> Result<&mut DirNode> {
        let objects = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        self.tree
            .walk(&objects, path.components(), dirty)
            .map_err(|e| match e {
                Error::NotFound(_) => Error::NotFound(path.to_string()),
                Error::NotADirectory(_) => Error::NotADirectory(path.to_string()),
                other => other,
            })
    }

    /// The parent folder and the entry name of a non-root path.
    fn split(path: &VaultPath) -> Result<(VaultPath, &str)> {
        match (path.parent(), path.name()) {
            (Some(p), Some(n)) => Ok((p, n)),
            _ => Err(Error::invalid(
                "this operation does not apply to the vault's top folder",
            )),
        }
    }

    pub fn list(&mut self, path: &VaultPath) -> Result<Vec<Entry>> {
        Ok(self
            .node(path, false)?
            .dir
            .entries
            .iter()
            .map(to_entry)
            .collect())
    }

    pub fn stat(&mut self, path: &VaultPath) -> Result<Entry> {
        if path.is_root() {
            return Ok(Entry {
                name: String::new(),
                kind: EntryKind::Dir,
                size: 0,
                mtime_ms: self.root.written_at as i64 * 1000,
                executable: false,
            });
        }
        let (parent, name) = Self::split(path)?;
        let node = self.node(&parent, false)?;
        node.dir
            .get(name)
            .map(to_entry)
            .ok_or_else(|| Error::NotFound(path.to_string()))
    }

    pub fn exists(&mut self, path: &VaultPath) -> Result<bool> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(Error::NotFound(_) | Error::NotADirectory(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Opens a file for streaming. Its hash is verified before decryption.
    pub fn read_file(&mut self, path: &VaultPath) -> Result<FileReader> {
        let (parent, name) = Self::split(path)?;
        let entry = self
            .node(&parent, false)?
            .dir
            .get(name)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        if entry.is_dir() {
            return Err(Error::IsADirectory(path.to_string()));
        }
        let inner = self.objects().open_file(&ObjRef {
            id: entry.id,
            hash: entry.hash,
        })?;
        if Some(inner.content_len()) != entry.size {
            return Err(Error::damaged(format!(
                "{path} has a different size than its folder entry"
            )));
        }
        Ok(FileReader { inner })
    }

    /// Reads a whole file into memory, refusing files larger than `max_len`.
    pub fn read_to_vec(&mut self, path: &VaultPath, max_len: u64) -> Result<Vec<u8>> {
        let mut r = self.read_file(path)?;
        if r.len() > max_len {
            return Err(Error::invalid(format!(
                "{path} is larger than {max_len} bytes"
            )));
        }
        let mut out = Vec::with_capacity(r.len() as usize);
        r.read_to_end(&mut out)
            .map_err(|e| Error::from_io(e, "reading from the vault"))?;
        Ok(out)
    }

    /// Adds or replaces a file with `len` bytes from `src`. The content is
    /// encrypted while it streams; the change becomes visible to other
    /// devices at the next [`Vault::commit`].
    pub fn import(
        &mut self,
        src: &mut dyn Read,
        dest: &VaultPath,
        len: u64,
        meta: FileMeta,
    ) -> Result<()> {
        self.import_with_progress(src, dest, len, meta, &mut |_| true)
    }

    pub fn import_with_progress(
        &mut self,
        src: &mut dyn Read,
        dest: &VaultPath,
        len: u64,
        meta: FileMeta,
        progress: &mut dyn FnMut(Progress) -> bool,
    ) -> Result<()> {
        self.require_writable()?;
        let (parent, name) = Self::split(dest)?;
        let name = name.to_string();
        if self
            .node(&parent, false)?
            .dir
            .get(&name)
            .is_some_and(DirEntry::is_dir)
        {
            return Err(Error::IsADirectory(dest.to_string()));
        }
        let padding = self.settings.padding;
        let r = self.objects().write_file(src, len, padding, &mut |done| {
            progress(Progress {
                phase: Phase::Import,
                done,
                total: len,
            })
        })?;
        let node = self.node(&parent, true)?;
        node.dir.upsert(DirEntry {
            name,
            kind: ObjectKind::File,
            id: r.id,
            hash: r.hash,
            size: Some(len),
            mtime: meta.mtime_ms,
            mode: meta.executable.then_some(MODE_EXECUTABLE),
            unknown: Vec::new(),
        })
    }

    pub fn write_bytes(&mut self, dest: &VaultPath, data: &[u8], meta: FileMeta) -> Result<()> {
        self.import(&mut &data[..], dest, data.len() as u64, meta)
    }

    pub fn mkdir(&mut self, path: &VaultPath) -> Result<()> {
        self.require_writable()?;
        let (parent, name) = Self::split(path)?;
        let name = name.to_string();
        if self.node(&parent, false)?.dir.get(&name).is_some() {
            return Err(Error::AlreadyExists(path.to_string()));
        }
        let node = self.node(&parent, true)?;
        node.dir.upsert(DirEntry {
            name: name.clone(),
            kind: ObjectKind::Dir,
            // Filled in by `flush` when the new folder is written.
            id: [0; 32],
            hash: [0; 32],
            size: None,
            mtime: now_ms(),
            mode: None,
            unknown: Vec::new(),
        })?;
        node.children.insert(name, DirNode::new_empty());
        Ok(())
    }

    /// Creates `path` and any missing parents; existing folders are fine.
    pub fn mkdir_all(&mut self, path: &VaultPath) -> Result<()> {
        let mut cur = VaultPath::root();
        for c in path.components() {
            cur = cur.join(c)?;
            match self.stat(&cur) {
                Ok(e) if e.kind == EntryKind::Dir => {}
                Ok(_) => return Err(Error::NotADirectory(cur.to_string())),
                Err(Error::NotFound(_)) => self.mkdir(&cur)?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Moves or renames a file or folder. An existing file at `to` is
    /// replaced by a file; anything else at `to` is an error.
    pub fn rename(&mut self, from: &VaultPath, to: &VaultPath) -> Result<()> {
        self.require_writable()?;
        let (from_parent, from_name) = Self::split(from)?;
        let (to_parent, to_name) = Self::split(to)?;
        let (from_name, to_name) = (from_name.to_string(), to_name.to_string());
        if from == to {
            return Ok(());
        }
        if to.starts_with(from) {
            return Err(Error::invalid("cannot move a folder into itself"));
        }
        let entry = self
            .node(&from_parent, false)?
            .dir
            .get(&from_name)
            .cloned()
            .ok_or_else(|| Error::NotFound(from.to_string()))?;
        match self.node(&to_parent, false)?.dir.get(&to_name) {
            Some(existing) if existing.is_dir() || entry.is_dir() => {
                return Err(Error::AlreadyExists(to.to_string()));
            }
            _ => {}
        }
        // A loaded folder node travels with its entry; an unloaded one needs
        // nothing, as its entry still names the right object.
        let src = self.node(&from_parent, true)?;
        let mut entry = src.dir.remove(&from_name).expect("checked above");
        let child = src.children.remove(&from_name);
        let dst = self.node(&to_parent, true)?;
        entry.name = to_name.clone();
        dst.dir.upsert(entry)?;
        match child {
            Some(c) => {
                dst.children.insert(to_name, c);
            }
            None => {
                dst.children.remove(&to_name);
            }
        }
        Ok(())
    }

    /// Removes a file, an empty folder, or with `recursive` any folder.
    pub fn remove(&mut self, path: &VaultPath, recursive: bool) -> Result<()> {
        self.require_writable()?;
        let (parent, name) = Self::split(path)?;
        let name = name.to_string();
        let entry = self
            .node(&parent, false)?
            .dir
            .get(&name)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        if entry.is_dir() && !recursive && !self.node(path, false)?.dir.entries.is_empty() {
            return Err(Error::NotEmpty(path.to_string()));
        }
        let node = self.node(&parent, true)?;
        node.dir.remove(&name);
        node.children.remove(&name);
        Ok(())
    }

    /// Changes a file's or folder's modification time and, for files, the
    /// executable bit. Stored at the next commit.
    pub fn set_meta(
        &mut self,
        path: &VaultPath,
        mtime_ms: Option<i64>,
        executable: Option<bool>,
    ) -> Result<()> {
        self.require_writable()?;
        let (parent, name) = Self::split(path)?;
        let name = name.to_string();
        let mut entry = self
            .node(&parent, false)?
            .dir
            .get(&name)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        let before = entry.clone();
        if let Some(m) = mtime_ms {
            entry.mtime = m;
        }
        if let Some(x) = executable
            && !entry.is_dir()
        {
            entry.mode = x.then_some(MODE_EXECUTABLE);
        }
        if entry != before {
            self.node(&parent, true)?.dir.upsert(entry)?;
        }
        Ok(())
    }

    /// Changes settings; they are stored at the next commit.
    pub fn set_settings(&mut self, settings: Settings) -> Result<()> {
        self.require_writable()?;
        Settings::check_label(&settings.label)?;
        self.settings = settings;
        Ok(())
    }

    /// Writes all pending changes and makes them visible with one root
    /// pointer write into the older slot (spec §9.1).
    pub fn commit(&mut self) -> Result<()> {
        if !self.has_pending_changes() {
            return Ok(());
        }
        self.require_writable()?;
        if let Some(l) = &mut self.lock {
            l.refresh()?;
        }
        let objects = Objects {
            storage: self.storage.as_ref(),
            k_obj: &self.keys.obj,
        };
        let r = self.tree.flush(&objects, self.settings.padding, now_ms())?;
        let new_root = RootPointer {
            rev: self.root.rev + 1,
            root_id: r.id,
            root_hash: r.hash,
            settings: self.settings.clone(),
            written_at: now_secs(),
            writer_id: self.writer_id,
            unknown: self.root.unknown.clone(),
        };
        self.write_root(new_root)
    }

    /// Writes `root` into the slot not holding the current root: the commit point.
    pub(crate) fn write_root(&mut self, root: RootPointer) -> Result<()> {
        let slot = self.root_slot.other();
        let bytes = root.seal(
            &self.keys.root,
            &self.header.vault_uuid,
            slot,
            &random_array(),
        );
        let path = root_path(slot);
        self.storage.write_atomic(&path, &bytes)?;
        let _ = self.storage.neutralize_times(&path);
        self.root = root;
        self.root_slot = slot;
        self.record_rollback();
        Ok(())
    }
}
