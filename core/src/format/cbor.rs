//! Strict deterministic CBOR (RFC 8949 §4.2.1) for the subset Tijori uses.
//!
//! The decoder rejects everything spec §12 forbids: indefinite lengths, tags,
//! floats, `undefined` and other simple values, non-shortest integers,
//! duplicate or unsorted map keys, invalid UTF-8 and trailing bytes. Lengths
//! are checked against the remaining input before anything is allocated.

use std::fmt;

/// Nesting deeper than this is rejected (directory entries need depth 3).
const MAX_DEPTH: usize = 16;

#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// A negative integer `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in canonical order (sorted by encoded key bytes).
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

// Values can hold names and settings; keep them out of logs anyway.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Uint(n) => write!(f, "Uint({n})"),
            Value::Nint(n) => write!(f, "Nint({n})"),
            Value::Bytes(b) => write!(f, "Bytes(len {})", b.len()),
            Value::Text(t) => write!(f, "Text(len {})", t.len()),
            Value::Array(a) => write!(f, "Array(len {})", a.len()),
            Value::Map(m) => write!(f, "Map(len {})", m.len()),
            Value::Bool(b) => write!(f, "Bool({b})"),
            Value::Null => f.write_str("Null"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    Truncated,
    TrailingBytes,
    IndefiniteLength,
    NonShortestInteger,
    Tag,
    Float,
    ForbiddenSimpleValue,
    ReservedAdditionalInfo,
    InvalidUtf8,
    UnsortedOrDuplicateKey,
    TooDeep,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CborError::Truncated => "CBOR data is truncated",
            CborError::TrailingBytes => "CBOR data has trailing bytes",
            CborError::IndefiniteLength => "CBOR uses an indefinite length",
            CborError::NonShortestInteger => "CBOR integer is not in shortest form",
            CborError::Tag => "CBOR uses a tag",
            CborError::Float => "CBOR uses a float",
            CborError::ForbiddenSimpleValue => "CBOR uses a forbidden simple value",
            CborError::ReservedAdditionalInfo => "CBOR uses reserved additional information",
            CborError::InvalidUtf8 => "CBOR text is not valid UTF-8",
            CborError::UnsortedOrDuplicateKey => "CBOR map keys are unsorted or duplicated",
            CborError::TooDeep => "CBOR nesting is too deep",
        })
    }
}

/// Decodes exactly one item that spans all of `data`.
pub fn decode(data: &[u8]) -> Result<Value, CborError> {
    let mut d = Decoder { data, pos: 0 };
    let v = d.item(0)?;
    if d.pos != data.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        if n > self.remaining() {
            return Err(CborError::Truncated);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads the argument of a head with additional info `ai`, enforcing the
    /// shortest form.
    fn argument(&mut self, ai: u8) -> Result<u64, CborError> {
        let (n, min) = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("2 bytes"),
                )),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().expect("4 bytes"),
                )),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
                0x1_0000_0000,
            ),
            31 => return Err(CborError::IndefiniteLength),
            _ => return Err(CborError::ReservedAdditionalInfo),
        };
        if n < min {
            return Err(CborError::NonShortestInteger);
        }
        Ok(n)
    }

    /// A length that must fit in the remaining input (each element takes at
    /// least `min_item_size` bytes), so hostile lengths never allocate.
    fn length(&mut self, ai: u8, min_item_size: usize) -> Result<usize, CborError> {
        let n = self.argument(ai)?;
        let n = usize::try_from(n).map_err(|_| CborError::Truncated)?;
        if n.checked_mul(min_item_size)
            .is_none_or(|need| need > self.remaining())
        {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        Ok(match major {
            0 => Value::Uint(self.argument(ai)?),
            1 => Value::Nint(self.argument(ai)?),
            2 => {
                let n = self.length(ai, 1)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(ai, 1)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| CborError::InvalidUtf8)?;
                Value::Text(s.to_owned())
            }
            4 => {
                let n = self.length(ai, 1)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.length(ai, 2)?;
                let mut pairs = Vec::with_capacity(n);
                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(depth + 1)?;
                    let key_bytes = &self.data[start..self.pos];
                    if prev_key.is_some_and(|p| p >= key_bytes) {
                        return Err(CborError::UnsortedOrDuplicateKey);
                    }
                    prev_key = Some(key_bytes);
                    let v = self.item(depth + 1)?;
                    pairs.push((k, v));
                }
                Value::Map(pairs)
            }
            6 => return Err(CborError::Tag),
            _ => match ai {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                25..=27 => return Err(CborError::Float),
                31 => return Err(CborError::IndefiniteLength),
                28..=30 => return Err(CborError::ReservedAdditionalInfo),
                _ => return Err(CborError::ForbiddenSimpleValue),
            },
        })
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Encodes deterministically: shortest integers, map keys sorted by their
/// encoded bytes.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => head(out, 0, *n),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out);
            }
        }
        Value::Map(pairs) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> =
                pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

impl Value {
    pub fn int(n: i64) -> Value {
        if n >= 0 {
            Value::Uint(n as u64)
        } else {
            Value::Nint((-1 - n) as u64)
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Uint(n) => i64::try_from(n).ok(),
            Value::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

/// Typed access to a map with unsigned-integer keys. Keys not taken by the
/// schema are kept (in order) so writers can preserve them (spec §8.2).
pub struct MapFields {
    pairs: Vec<(Value, Value)>,
}

impl MapFields {
    pub fn from_value(v: Value) -> Option<Self> {
        match v {
            Value::Map(pairs) => Some(MapFields { pairs }),
            _ => None,
        }
    }

    pub fn take(&mut self, key: u64) -> Option<Value> {
        let i = self
            .pairs
            .iter()
            .position(|(k, _)| *k == Value::Uint(key))?;
        Some(self.pairs.remove(i).1)
    }

    /// Everything not taken, for round-tripping unknown fields.
    pub fn rest(self) -> Vec<(Value, Value)> {
        self.pairs
    }

    fn required(&mut self, key: u64, name: &str) -> crate::Result<Value> {
        self.take(key)
            .ok_or_else(|| crate::Error::damaged(format!("missing field {name}")))
    }

    pub fn uint(&mut self, key: u64, name: &str) -> crate::Result<u64> {
        match self.required(key, name)? {
            Value::Uint(n) => Ok(n),
            _ => Err(type_error(name)),
        }
    }

    pub fn opt_uint(&mut self, key: u64, name: &str) -> crate::Result<Option<u64>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Uint(n)) => Ok(Some(n)),
            Some(_) => Err(type_error(name)),
        }
    }

    pub fn int(&mut self, key: u64, name: &str) -> crate::Result<i64> {
        self.required(key, name)?
            .as_i64()
            .ok_or_else(|| type_error(name))
    }

    pub fn bool(&mut self, key: u64, name: &str) -> crate::Result<bool> {
        match self.required(key, name)? {
            Value::Bool(b) => Ok(b),
            _ => Err(type_error(name)),
        }
    }

    pub fn opt_text(&mut self, key: u64, name: &str) -> crate::Result<Option<String>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Text(t)) => Ok(Some(t)),
            Some(_) => Err(type_error(name)),
        }
    }

    pub fn text(&mut self, key: u64, name: &str) -> crate::Result<String> {
        match self.required(key, name)? {
            Value::Text(t) => Ok(t),
            _ => Err(type_error(name)),
        }
    }

    pub fn bytes<const N: usize>(&mut self, key: u64, name: &str) -> crate::Result<[u8; N]> {
        match self.required(key, name)? {
            Value::Bytes(b) => b.try_into().map_err(|_| type_error(name)),
            _ => Err(type_error(name)),
        }
    }

    pub fn map(&mut self, key: u64, name: &str) -> crate::Result<MapFields> {
        MapFields::from_value(self.required(key, name)?).ok_or_else(|| type_error(name))
    }

    pub fn array(&mut self, key: u64, name: &str) -> crate::Result<Vec<Value>> {
        match self.required(key, name)? {
            Value::Array(a) => Ok(a),
            _ => Err(type_error(name)),
        }
    }
}

fn type_error(name: &str) -> crate::Error {
    crate::Error::damaged(format!("field {name} has the wrong type or size"))
}

/// Decodes `data` as a CBOR map, reporting failures as damage.
pub fn decode_map(data: &[u8], what: &str) -> crate::Result<MapFields> {
    let v = decode(data).map_err(|e| crate::Error::damaged(format!("{what}: {e}")))?;
    MapFields::from_value(v)
        .ok_or_else(|| crate::Error::damaged(format!("{what} is not a CBOR map")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn rejects_forbidden_encodings() {
        let cases = [
            ("1801", CborError::NonShortestInteger),
            ("190001", CborError::NonShortestInteger),
            ("9fff", CborError::IndefiniteLength),
            ("c000", CborError::Tag),
            ("f93c00", CborError::Float),
            ("fb3ff8000000000000", CborError::Float),
            ("f7", CborError::ForbiddenSimpleValue),
            ("f820", CborError::ForbiddenSimpleValue),
            ("a201010101", CborError::UnsortedOrDuplicateKey),
            ("a202010101", CborError::UnsortedOrDuplicateKey),
            ("62ff00", CborError::InvalidUtf8),
            ("0000", CborError::TrailingBytes),
            ("5affffffff", CborError::Truncated),
            ("1c", CborError::ReservedAdditionalInfo),
        ];
        for (input, err) in cases {
            assert_eq!(decode(&h(input)), Err(err), "{input}");
        }
    }

    #[test]
    fn huge_lengths_do_not_allocate() {
        // Array claiming 2^64-1 items: rejected before allocating.
        assert_eq!(decode(&h("9bffffffffffffffff")), Err(CborError::Truncated));
        assert_eq!(decode(&h("bbffffffffffffffff")), Err(CborError::Truncated));
    }

    #[test]
    fn nesting_limit() {
        let mut deep = vec![0x81u8; 40];
        deep.push(0x00);
        assert_eq!(decode(&deep), Err(CborError::TooDeep));
    }

    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Uint),
            any::<u64>().prop_map(Value::Nint),
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
            ".{0,20}".prop_map(Value::Text),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                proptest::collection::btree_map(any::<u32>(), inner, 0..8).prop_map(|m| {
                    Value::Map(
                        m.into_iter()
                            .map(|(k, v)| (Value::Uint(k.into()), v))
                            .collect(),
                    )
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn encode_decode_round_trip(v in value()) {
            let bytes = encode(&v);
            let back = decode(&bytes).unwrap();
            prop_assert_eq!(encode(&back), bytes);
        }

        #[test]
        fn decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&data);
        }
    }
}
