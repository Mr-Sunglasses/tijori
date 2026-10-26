//! Encrypted objects (spec §7): `object_version || stream_header || chunks`,
//! over the plaintext `content_length (u64) || content || zero padding`.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::crypto::{
    Blake2b, HASH_LEN, ObjectKey, ObjectRootKey, STREAM_ABYTES, STREAM_HEADER_LEN, StreamPull,
    StreamPush, StreamTag, blake2b_key, ct_eq,
};
use crate::error::{Error, Result};
use crate::padding::stream_total;

pub const OBJECT_VERSION: u8 = 1;
pub const CHUNK_LEN: usize = 65_536;
pub const CHUNK_CT_LEN: usize = CHUNK_LEN + STREAM_ABYTES;
/// `object_version` plus the stream header.
pub const PREFIX_LEN: usize = 1 + STREAM_HEADER_LEN;
/// Object plaintext limit (spec §12).
pub const MAX_PLAINTEXT: u64 = 1 << 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectKind {
    File = 1,
    Dir = 2,
}

/// Associated data of every chunk: `kind || object_id`.
fn chunk_ad(kind: ObjectKind, id: &[u8; 32]) -> [u8; 33] {
    let mut ad = [0u8; 33];
    ad[0] = kind as u8;
    ad[1..].copy_from_slice(id);
    ad
}

/// `object_key = H(K_obj, "TJRI obj v1" || kind || object_id)`.
pub fn object_key(k_obj: &ObjectRootKey, kind: ObjectKind, id: &[u8; 32]) -> ObjectKey {
    ObjectKey::from_key(blake2b_key(
        Some(k_obj.as_bytes()),
        &[b"TJRI obj v1", &[kind as u8], id],
    ))
}

/// Size of an object on disk for a plaintext stream of `total` bytes (§7.4).
pub fn disk_size(total: u64) -> u64 {
    PREFIX_LEN as u64 + total + STREAM_ABYTES as u64 * total.div_ceil(CHUNK_LEN as u64)
}

/// Where an object went and what it hashes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenObject {
    /// `H(none, object file bytes)`, for the parent directory entry.
    pub hash: [u8; HASH_LEN],
    pub disk_len: u64,
}

struct HashingWriter<W> {
    inner: W,
    hasher: Blake2b,
    len: u64,
}

impl<W: Write> HashingWriter<W> {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data)?;
        self.hasher.update(data);
        self.len += data.len() as u64;
        Ok(())
    }
}

/// Streams content into an encrypted object. The content length must be
/// known up front because it is the first thing in the plaintext.
pub struct ObjectWriter<W: Write> {
    out: HashingWriter<W>,
    push: StreamPush,
    ad: [u8; 33],
    buf: Zeroizing<Vec<u8>>,
    ct: Vec<u8>,
    total: u64,
    fed: u64,
    content_len: u64,
    content_written: u64,
}

impl<W: Write> ObjectWriter<W> {
    pub fn new(
        out: W,
        key: &ObjectKey,
        kind: ObjectKind,
        id: &[u8; 32],
        content_len: u64,
        padding: bool,
    ) -> Result<Self> {
        if content_len > MAX_PLAINTEXT - 8 {
            return Err(Error::invalid("file is too large for a Tijori vault"));
        }
        let (push, header) = StreamPush::new(key.key());
        let mut out = HashingWriter {
            inner: out,
            hasher: Blake2b::new(None),
            len: 0,
        };
        let io_err = |e| Error::from_io(e, "writing object");
        out.write_all(&[OBJECT_VERSION]).map_err(io_err)?;
        out.write_all(&header).map_err(io_err)?;
        let mut w = ObjectWriter {
            out,
            push,
            ad: chunk_ad(kind, id),
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
            ct: Vec::with_capacity(CHUNK_CT_LEN),
            total: stream_total(content_len, padding).min(MAX_PLAINTEXT),
            fed: 0,
            content_len,
            content_written: 0,
        };
        w.feed(&content_len.to_le_bytes()).map_err(io_err)?;
        Ok(w)
    }

    fn emit(&mut self, tag: StreamTag) -> io::Result<()> {
        self.ct.clear();
        self.push.push(&self.buf, &self.ad, tag, &mut self.ct);
        self.buf.clear();
        let ct = std::mem::take(&mut self.ct);
        let r = self.out.write_all(&ct);
        self.ct = ct;
        r
    }

    /// Adds plaintext; full chunks are emitted as MESSAGE while more follows.
    /// The last chunk is held back for `finish`, which tags it FINAL.
    fn feed(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            if self.buf.len() == CHUNK_LEN {
                self.emit(StreamTag::Message)?;
            }
            let n = (CHUNK_LEN - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..n]);
            self.fed += n as u64;
            data = &data[n..];
        }
        if self.buf.len() == CHUNK_LEN && self.fed < self.total {
            self.emit(StreamTag::Message)?;
        }
        Ok(())
    }

    /// Writes the padding and the FINAL chunk. Fails if fewer content bytes
    /// were written than announced.
    pub fn finish(mut self) -> Result<(W, WrittenObject)> {
        if self.content_written != self.content_len {
            return Err(Error::invalid(format!(
                "source ended after {} of {} bytes; it changed while it was being added",
                self.content_written, self.content_len
            )));
        }
        let io_err = |e| Error::from_io(e, "writing object");
        static ZEROS: [u8; CHUNK_LEN] = [0; CHUNK_LEN];
        while self.fed < self.total {
            let n = (self.total - self.fed).min(CHUNK_LEN as u64) as usize;
            self.feed(&ZEROS[..n]).map_err(io_err)?;
        }
        self.emit(StreamTag::Final).map_err(io_err)?;
        self.out.inner.flush().map_err(io_err)?;
        let info = WrittenObject {
            hash: self.out.hasher.finalize(),
            disk_len: self.out.len,
        };
        debug_assert_eq!(info.disk_len, disk_size(self.total));
        Ok((self.out.inner, info))
    }
}

impl<W: Write> Write for ObjectWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let left = self.content_len - self.content_written;
        if data.len() as u64 > left {
            return Err(Error::invalid("source grew while it was being added").into_io());
        }
        self.feed(data)?;
        self.content_written += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encrypts a whole in-memory content (used for directories).
pub fn encrypt_object(
    key: &ObjectKey,
    kind: ObjectKind,
    id: &[u8; 32],
    content: &[u8],
    padding: bool,
) -> (Vec<u8>, WrittenObject) {
    let cap = disk_size(stream_total(content.len() as u64, padding)) as usize;
    let mut w = ObjectWriter::new(
        Vec::with_capacity(cap),
        key,
        kind,
        id,
        content.len() as u64,
        padding,
    )
    .expect("in-memory writes cannot fail");
    w.write_all(content).expect("in-memory writes cannot fail");
    w.finish().expect("content length matches")
}

/// Streams and verifies an object, yielding its content.
///
/// Every chunk is authenticated before its bytes are returned. Truncation,
/// extension, bad padding and (if given) a wrong file hash are detected when
/// the stream ends, so callers must treat any error, including one after
/// some bytes were returned, as a failure of the whole object.
pub struct ObjectReader<R: Read> {
    input: R,
    hasher: Option<(Blake2b, [u8; HASH_LEN])>,
    pull: StreamPull,
    ad: [u8; 33],
    ct: Vec<u8>,
    pt: Zeroizing<Vec<u8>>,
    pt_pos: usize,
    pt_end: usize,
    content_len: u64,
    content_assigned: u64,
    total: u64,
    first_chunk: bool,
    final_seen: bool,
    done: bool,
}

/// Reads until `buf` is full or the input ends; returns the bytes read.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

impl<R: Read> ObjectReader<R> {
    /// Opens an object. With `expected_hash`, the whole file's hash is also
    /// checked when the stream ends.
    pub fn new(
        mut input: R,
        key: &ObjectKey,
        kind: ObjectKind,
        id: &[u8; 32],
        expected_hash: Option<[u8; HASH_LEN]>,
    ) -> Result<Self> {
        let mut prefix = [0u8; PREFIX_LEN];
        let n = fill(&mut input, &mut prefix).map_err(|e| Error::from_io(e, "reading object"))?;
        // A higher version comes from a newer Tijori; 0 was never written.
        if n >= 1 && prefix[0] > OBJECT_VERSION {
            return Err(Error::unsupported(format!("object version {}", prefix[0])));
        }
        if n >= 1 && prefix[0] < OBJECT_VERSION {
            return Err(Error::damaged("object version 0"));
        }
        if n < PREFIX_LEN {
            return Err(Error::tampered("object is truncated"));
        }
        let mut hasher = expected_hash.map(|h| (Blake2b::new(None), h));
        if let Some((h, _)) = &mut hasher {
            h.update(&prefix);
        }
        let header: &[u8; STREAM_HEADER_LEN] = prefix[1..].try_into().expect("24 bytes");
        let mut r = ObjectReader {
            input,
            hasher,
            pull: StreamPull::new(key.key(), header),
            ad: chunk_ad(kind, id),
            ct: vec![0u8; CHUNK_CT_LEN],
            pt: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
            pt_pos: 0,
            pt_end: 0,
            content_len: 0,
            content_assigned: 0,
            total: 0,
            first_chunk: true,
            final_seen: false,
            done: false,
        };
        r.next_chunk()?;
        Ok(r)
    }

    pub fn content_len(&self) -> u64 {
        self.content_len
    }

    fn read_input(&mut self, buf_len: usize) -> Result<usize> {
        let n = fill(&mut self.input, &mut self.ct[..buf_len])
            .map_err(|e| Error::from_io(e, "reading object"))?;
        if let Some((h, _)) = &mut self.hasher {
            h.update(&self.ct[..n]);
        }
        Ok(n)
    }

    fn next_chunk(&mut self) -> Result<()> {
        let n = self.read_input(CHUNK_CT_LEN)?;
        if n == 0 {
            return Err(Error::tampered("object is truncated (no FINAL chunk)"));
        }
        let ct = std::mem::take(&mut self.ct);
        let tag = self.pull.pull(&ct[..n], &self.ad, &mut self.pt);
        self.ct = ct;
        let tag = tag.ok_or_else(|| Error::tampered("object chunk failed authentication"))?;
        match tag {
            StreamTag::Final => self.final_seen = true,
            StreamTag::Message if self.pt.len() == CHUNK_LEN => {}
            StreamTag::Message => {
                return Err(Error::tampered("object is truncated (no FINAL chunk)"));
            }
            other => {
                return Err(Error::damaged(format!(
                    "object chunk has unexpected tag {other:?}"
                )));
            }
        }
        self.total += self.pt.len() as u64;
        if self.total > MAX_PLAINTEXT {
            return Err(Error::damaged("object plaintext exceeds the limit"));
        }
        let mut start = 0;
        if self.first_chunk {
            self.first_chunk = false;
            if self.pt.len() < 8 {
                return Err(Error::damaged("object plaintext is shorter than 8 bytes"));
            }
            self.content_len = u64::from_le_bytes(self.pt[..8].try_into().expect("8 bytes"));
            if self.content_len > MAX_PLAINTEXT - 8 {
                return Err(Error::damaged("object content_length exceeds the limit"));
            }
            start = 8;
        }
        let avail = (self.pt.len() - start) as u64;
        let content_here = (self.content_len - self.content_assigned).min(avail) as usize;
        self.content_assigned += content_here as u64;
        if self.pt[start + content_here..].iter().any(|&b| b != 0) {
            return Err(Error::damaged("object padding is not zero"));
        }
        self.pt_pos = start;
        self.pt_end = start + content_here;
        if self.final_seen {
            self.finish_stream()?;
        }
        Ok(())
    }

    fn finish_stream(&mut self) -> Result<()> {
        if self.read_input(1)? != 0 {
            return Err(Error::tampered("object has data after its FINAL chunk"));
        }
        if self.content_assigned != self.content_len {
            return Err(Error::damaged(
                "object content_length is larger than its plaintext",
            ));
        }
        if let Some((h, expected)) = self.hasher.take()
            && !ct_eq(&h.finalize(), &expected)
        {
            return Err(Error::tampered(
                "object hash does not match its folder entry",
            ));
        }
        self.done = true;
        Ok(())
    }

    /// Reads content; `Ok(0)` only after the whole object has verified.
    pub fn read_content(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if self.pt_pos < self.pt_end {
                let n = (self.pt_end - self.pt_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.pt[self.pt_pos..self.pt_pos + n]);
                self.pt_pos += n;
                return Ok(n);
            }
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            self.next_chunk()?;
        }
    }

    /// Reads and verifies the whole content into memory, refusing objects
    /// whose content is larger than `max_len` before allocating.
    pub fn read_all(mut self, max_len: u64) -> Result<Zeroizing<Vec<u8>>> {
        if self.content_len > max_len {
            return Err(Error::damaged(format!(
                "object content is larger than {max_len} bytes"
            )));
        }
        let mut out = Zeroizing::new(vec![0u8; self.content_len as usize]);
        let mut pos = 0;
        while pos < out.len() {
            let n = self.read_content(&mut out[pos..])?;
            if n == 0 {
                break;
            }
            pos += n;
        }
        let mut probe = [0u8; 1];
        if self.read_content(&mut probe)? != 0 || pos != out.len() {
            return Err(Error::damaged("object content length mismatch"));
        }
        Ok(out)
    }
}

impl<R: Read> Read for ObjectReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_content(buf).map_err(Error::into_io)
    }
}

/// Decrypts a whole object held in memory.
pub fn decrypt_object(
    data: &[u8],
    key: &ObjectKey,
    kind: ObjectKind,
    id: &[u8; 32],
    max_len: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    ObjectReader::new(data, key, kind, id, None)?.read_all(max_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;
    use proptest::prelude::*;

    fn key() -> ObjectKey {
        ObjectKey::from_key(Key::random())
    }

    fn content(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn round_trip(n: usize, padding: bool) {
        let k = key();
        let id = [3u8; 32];
        let data = content(n);
        let (obj, info) = encrypt_object(&k, ObjectKind::File, &id, &data, padding);
        assert_eq!(obj.len() as u64, info.disk_len);
        assert_eq!(info.disk_len, disk_size(stream_total(n as u64, padding)));
        assert_eq!(info.hash, crate::crypto::hash(&obj));
        let mut r =
            ObjectReader::new(&obj[..], &k, ObjectKind::File, &id, Some(info.hash)).unwrap();
        assert_eq!(r.content_len(), n as u64);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data, "size {n} padding {padding}");
    }

    #[test]
    fn chunk_boundaries() {
        for n in [
            0, 1, 7, 8, 65_527, 65_528, 65_529, 65_535, 65_536, 65_537, 131_064, 131_072, 131_073,
            200_000,
        ] {
            round_trip(n, false);
            round_trip(n, true);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn random_sizes_round_trip(n in 0usize..=(1 << 20), padding: bool) {
            round_trip(n, padding);
        }
    }

    #[test]
    fn streaming_writer_matches_sizes() {
        let k = key();
        let id = [1u8; 32];
        let data = content(150_000);
        let mut w = ObjectWriter::new(
            Vec::new(),
            &k,
            ObjectKind::File,
            &id,
            data.len() as u64,
            true,
        )
        .unwrap();
        for piece in data.chunks(777) {
            w.write_all(piece).unwrap();
        }
        let (obj, _) = w.finish().unwrap();
        let back = decrypt_object(&obj, &k, ObjectKind::File, &id, u64::MAX).unwrap();
        assert_eq!(&back[..], &data[..]);
    }

    #[test]
    fn short_or_long_sources_are_rejected() {
        let k = key();
        let mut w =
            ObjectWriter::new(Vec::new(), &k, ObjectKind::File, &[0; 32], 10, false).unwrap();
        w.write_all(b"12345").unwrap();
        assert!(w.finish().is_err());
        let mut w =
            ObjectWriter::new(Vec::new(), &k, ObjectKind::File, &[0; 32], 3, false).unwrap();
        assert!(w.write_all(b"12345").is_err());
    }

    #[test]
    fn wrong_hash_is_tampered() {
        let k = key();
        for n in [3, 200_000] {
            let data = content(n);
            let (obj, _) = encrypt_object(&k, ObjectKind::Dir, &[5; 32], &data, true);
            // A one-chunk object finishes (and checks its hash) while opening.
            let err =
                match ObjectReader::new(&obj[..], &k, ObjectKind::Dir, &[5; 32], Some([0; 32])) {
                    Err(e) => e,
                    Ok(mut r) => Error::from_io(r.read_to_end(&mut Vec::new()).unwrap_err(), ""),
                };
            assert_eq!(err.class(), crate::ErrorClass::Tampered, "size {n}");
        }
    }

    #[test]
    fn read_all_respects_limit() {
        let k = key();
        let (obj, _) = encrypt_object(&k, ObjectKind::Dir, &[5; 32], &[1; 100], true);
        assert!(decrypt_object(&obj, &k, ObjectKind::Dir, &[5; 32], 99).is_err());
        assert_eq!(
            decrypt_object(&obj, &k, ObjectKind::Dir, &[5; 32], 100)
                .unwrap()
                .len(),
            100
        );
    }
}
