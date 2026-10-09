//! Strict CBOR (RFC 8949) subset used by every binary structure (protocol §1).
//!
//! Supported: unsigned integers, byte strings, text strings, arrays, maps with
//! unsigned-integer keys, and the simple values `false`/`true`. Everything else
//! (negative integers, tags, floats, `null`, `undefined`, other simple values) is
//! rejected.
//!
//! The decoder rejects indefinite lengths, non-shortest integers and lengths,
//! duplicate or unsorted map keys, invalid UTF-8, nesting deeper than
//! [`Limits::max_depth`], and trailing bytes. Every declared length or count is
//! checked against the remaining input and the limits **before** allocating.
//! Byte and text strings are borrowed from the input.

use std::fmt;

/// Decoding limits. Callers pass the limit from protocol §10 for the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth; the top-level item has depth 1 (protocol: 8).
    pub max_depth: usize,
    /// Maximum total input size in bytes.
    pub max_input: usize,
    /// Maximum element count of any single array or map.
    pub max_items: usize,
}

impl Limits {
    /// Protocol defaults: depth 8, the given input cap, at most 1024 items.
    pub const fn new(max_input: usize) -> Self {
        Self {
            max_depth: 8,
            max_input,
            max_items: 1024,
        }
    }
}

/// A decoded item. Strings borrow from the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    /// Entries in strictly ascending key order (enforced by the decoder).
    Map(Vec<(u64, Value<'a>)>),
    Bool(bool),
}

/// Why an input was rejected. Each variant is covered by a negative test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input ended inside an item.
    Truncated,
    /// Input larger than `Limits::max_input`.
    InputTooLarge,
    /// An integer or length not in shortest form.
    NonShortest,
    /// Indefinite-length string, array or map (or a stray "break").
    Indefinite,
    /// Additional-information values 28–30 are reserved.
    Reserved,
    /// Negative integer, tag, float, null, undefined or other simple value.
    Unsupported,
    /// Map key that is not an unsigned integer.
    NonUintKey,
    /// The same map key twice.
    DuplicateKey,
    /// Map keys not in ascending order.
    UnsortedKeys,
    /// Text string that is not valid UTF-8.
    InvalidUtf8,
    /// Nesting deeper than `Limits::max_depth`.
    TooDeep,
    /// Array or map with more than `Limits::max_items` entries.
    TooManyItems,
    /// Bytes left after the top-level item.
    TrailingBytes,
    /// Encoder: map keys given out of order or duplicated.
    EncodeUnsortedKeys,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

/// Decodes exactly one item that spans the whole input.
pub fn decode<'a>(input: &'a [u8], limits: &Limits) -> Result<Value<'a>, Error> {
    if input.len() > limits.max_input {
        return Err(Error::InputTooLarge);
    }
    let mut d = Decoder {
        buf: input,
        pos: 0,
        limits,
    };
    let v = d.item(1)?;
    if d.pos != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

struct Decoder<'a, 'l> {
    buf: &'a [u8],
    pos: usize,
    limits: &'l Limits,
}

impl<'a> Decoder<'a, '_> {
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(Error::Truncated)?;
        Ok(b)
    }

    /// Reads the argument for additional info `ai`, enforcing shortest form.
    fn argument(&mut self, ai: u8) -> Result<u64, Error> {
        let v = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(Error::NonShortest);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(arr(self.take(2)?)?));
                if v <= 0xff {
                    return Err(Error::NonShortest);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(arr(self.take(4)?)?));
                if v <= 0xffff {
                    return Err(Error::NonShortest);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(arr(self.take(8)?)?);
                if v <= 0xffff_ffff {
                    return Err(Error::NonShortest);
                }
                v
            }
            28..=30 => return Err(Error::Reserved),
            _ => return Err(Error::Indefinite),
        };
        Ok(v)
    }

    /// A length that must fit in the remaining input (each unit ≥ `unit` bytes).
    fn length(&mut self, ai: u8, unit: usize) -> Result<usize, Error> {
        let n = self.argument(ai)?;
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        if n.checked_mul(unit)
            .is_none_or(|need| need > self.remaining())
        {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::TooDeep);
        }
        let ib = self.byte()?;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        match major {
            0 => Ok(Value::Uint(self.argument(ai)?)),
            2 => {
                let n = self.length(ai, 1)?;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.length(ai, 1)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(s))
            }
            4 => {
                let n = self.length(ai, 1)?;
                if n > self.limits.max_items {
                    return Err(Error::TooManyItems);
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.item(depth.saturating_add(1))?);
                }
                Ok(Value::Array(v))
            }
            5 => {
                let n = self.length(ai, 2)?;
                if n > self.limits.max_items {
                    return Err(Error::TooManyItems);
                }
                let mut v: Vec<(u64, Value<'a>)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let kb = self.byte()?;
                    if kb >> 5 != 0 {
                        // Distinguish malformed headers from well-formed non-uint keys.
                        if kb & 0x1f == 31 {
                            return Err(Error::Indefinite);
                        }
                        return Err(Error::NonUintKey);
                    }
                    let k = self.argument(kb & 0x1f)?;
                    if let Some((last, _)) = v.last() {
                        if k == *last {
                            return Err(Error::DuplicateKey);
                        }
                        if k < *last {
                            return Err(Error::UnsortedKeys);
                        }
                    }
                    let val = self.item(depth.saturating_add(1))?;
                    v.push((k, val));
                }
                Ok(Value::Map(v))
            }
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                28..=30 => Err(Error::Reserved),
                31 => Err(Error::Indefinite),
                _ => Err(Error::Unsupported),
            },
            // 1: negative integers, 6: tags.
            _ => {
                if ai == 31 {
                    return Err(Error::Indefinite);
                }
                Err(Error::Unsupported)
            }
        }
    }
}

fn arr<const N: usize>(s: &[u8]) -> Result<[u8; N], Error> {
    s.try_into().map_err(|_| Error::Truncated)
}

/// Shortest-form encoder for the same subset.
#[derive(Debug, Default)]
pub struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn head(&mut self, major: u8, v: u64) {
        let m = major << 5;
        if v < 24 {
            self.out.push(m | v as u8);
        } else if v <= 0xff {
            self.out.extend_from_slice(&[m | 24, v as u8]);
        } else if v <= 0xffff {
            self.out.push(m | 25);
            self.out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.out.push(m | 26);
            self.out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.out.push(m | 27);
            self.out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.head(0, v);
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(2, b.len() as u64);
        self.out.extend_from_slice(b);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.head(3, s.len() as u64);
        self.out.extend_from_slice(s.as_bytes());
        self
    }

    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.out.push(if b { 0xf5 } else { 0xf4 });
        self
    }

    /// Array header; the caller then writes `len` items.
    pub fn array(&mut self, len: usize) -> &mut Self {
        self.head(4, len as u64);
        self
    }

    /// Map header; the caller then writes `len` key/value pairs in ascending key order.
    pub fn map(&mut self, len: usize) -> &mut Self {
        self.head(5, len as u64);
        self
    }

    /// Encodes a full value tree, checking map key order.
    pub fn value(&mut self, v: &Value<'_>) -> Result<&mut Self, Error> {
        match v {
            Value::Uint(n) => {
                self.uint(*n);
            }
            Value::Bytes(b) => {
                self.bytes(b);
            }
            Value::Text(s) => {
                self.text(s);
            }
            Value::Bool(b) => {
                self.bool(*b);
            }
            Value::Array(items) => {
                self.array(items.len());
                for i in items {
                    self.value(i)?;
                }
            }
            Value::Map(entries) => {
                if entries
                    .windows(2)
                    .any(|w| matches!(w, [(a, _), (b, _)] if a >= b))
                {
                    return Err(Error::EncodeUnsortedKeys);
                }
                self.map(entries.len());
                for (k, val) in entries {
                    self.uint(*k);
                    self.value(val)?;
                }
            }
        }
        Ok(self)
    }
}

/// Encodes a value tree to bytes.
pub fn encode(v: &Value<'_>) -> Result<Vec<u8>, Error> {
    let mut e = Encoder::new();
    e.value(v)?;
    Ok(e.into_bytes())
}

/// Schema errors when reading a decoded map (beyond CBOR well-formedness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldError {
    Missing(u64),
    WrongType(u64),
    WrongSize(u64),
    OutOfRange(u64),
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for FieldError {}

/// Typed access to a decoded map. Unknown keys are ignored (protocol §1).
#[derive(Debug, Clone, Copy)]
pub struct MapRef<'v, 'a>(&'v [(u64, Value<'a>)]);

impl<'v, 'a> MapRef<'v, 'a> {
    pub fn new(v: &'v Value<'a>) -> Option<Self> {
        match v {
            Value::Map(m) => Some(Self(m)),
            _ => None,
        }
    }

    pub fn get(&self, key: u64) -> Option<&'v Value<'a>> {
        self.0
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .and_then(|i| self.0.get(i))
            .map(|(_, v)| v)
    }

    pub fn has(&self, key: u64) -> bool {
        self.get(key).is_some()
    }

    pub fn uint(&self, key: u64) -> Result<u64, FieldError> {
        self.opt_uint(key)?.ok_or(FieldError::Missing(key))
    }

    pub fn opt_uint(&self, key: u64) -> Result<Option<u64>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Uint(n)) => Ok(Some(*n)),
            Some(_) => Err(FieldError::WrongType(key)),
        }
    }

    pub fn bytes(&self, key: u64) -> Result<&'a [u8], FieldError> {
        self.opt_bytes(key)?.ok_or(FieldError::Missing(key))
    }

    pub fn opt_bytes(&self, key: u64) -> Result<Option<&'a [u8]>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(_) => Err(FieldError::WrongType(key)),
        }
    }

    pub fn fixed<const N: usize>(&self, key: u64) -> Result<[u8; N], FieldError> {
        self.bytes(key)?
            .try_into()
            .map_err(|_| FieldError::WrongSize(key))
    }

    pub fn opt_fixed<const N: usize>(&self, key: u64) -> Result<Option<[u8; N]>, FieldError> {
        self.opt_bytes(key)?
            .map(|b| b.try_into().map_err(|_| FieldError::WrongSize(key)))
            .transpose()
    }

    pub fn text(&self, key: u64) -> Result<&'a str, FieldError> {
        self.opt_text(key)?.ok_or(FieldError::Missing(key))
    }

    pub fn opt_text(&self, key: u64) -> Result<Option<&'a str>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Text(s)) => Ok(Some(s)),
            Some(_) => Err(FieldError::WrongType(key)),
        }
    }

    pub fn opt_bool(&self, key: u64) -> Result<Option<bool>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(FieldError::WrongType(key)),
        }
    }

    pub fn opt_map(&self, key: u64) -> Result<Option<MapRef<'v, 'a>>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => MapRef::new(v).map(Some).ok_or(FieldError::WrongType(key)),
        }
    }

    pub fn opt_array(&self, key: u64) -> Result<Option<&'v [Value<'a>]>, FieldError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a)),
            Some(_) => Err(FieldError::WrongType(key)),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    const L: Limits = Limits::new(1 << 20);

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rej(h: &str) -> Error {
        decode(&hex(h), &L).unwrap_err()
    }

    #[test]
    fn rfc8949_appendix_a_valid_subset() {
        let cases: &[(&str, Value)] = &[
            ("00", Value::Uint(0)),
            ("17", Value::Uint(23)),
            ("1818", Value::Uint(24)),
            ("1903e8", Value::Uint(1000)),
            ("1a000f4240", Value::Uint(1_000_000)),
            ("1b000000e8d4a51000", Value::Uint(1_000_000_000_000)),
            ("1bffffffffffffffff", Value::Uint(u64::MAX)),
            ("40", Value::Bytes(&[])),
            ("4401020304", Value::Bytes(&[1, 2, 3, 4])),
            ("60", Value::Text("")),
            ("6449455446", Value::Text("IETF")),
            ("62c3bc", Value::Text("ü")),
            ("80", Value::Array(vec![])),
            (
                "83010203",
                Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]),
            ),
            ("a0", Value::Map(vec![])),
            (
                "a201020304",
                Value::Map(vec![(1, Value::Uint(2)), (3, Value::Uint(4))]),
            ),
            ("f4", Value::Bool(false)),
            ("f5", Value::Bool(true)),
        ];
        for (h, v) in cases {
            let b = hex(h);
            assert_eq!(&decode(&b, &L).unwrap(), v, "{h}");
            assert_eq!(encode(v).unwrap(), b, "re-encode {h}");
        }
    }

    #[test]
    fn rejects_non_shortest() {
        assert_eq!(rej("1817"), Error::NonShortest);
        assert_eq!(rej("190017"), Error::NonShortest);
        assert_eq!(rej("1900ff"), Error::NonShortest);
        assert_eq!(rej("1a0000ffff"), Error::NonShortest);
        assert_eq!(rej("1b00000000ffffffff"), Error::NonShortest);
        assert_eq!(rej("580100"), Error::NonShortest); // bstr length 1 in 1-byte form
        assert_eq!(rej("98020102"), Error::NonShortest); // array length 2 in 1-byte form
        assert_eq!(rej("a1180101"), Error::NonShortest); // map key 1 in 1-byte form
    }

    #[test]
    fn rejects_indefinite_and_break() {
        assert_eq!(rej("5f4101ff"), Error::Indefinite);
        assert_eq!(rej("7f6161ff"), Error::Indefinite);
        assert_eq!(rej("9f01ff"), Error::Indefinite);
        assert_eq!(rej("bf0101ff"), Error::Indefinite);
        assert_eq!(rej("ff"), Error::Indefinite);
        assert_eq!(rej("1f"), Error::Indefinite);
    }

    #[test]
    fn rejects_reserved_ai() {
        assert_eq!(rej("1c"), Error::Reserved);
        assert_eq!(rej("5d"), Error::Reserved);
        assert_eq!(rej("fe"), Error::Reserved);
    }

    #[test]
    fn rejects_unsupported_types() {
        assert_eq!(rej("20"), Error::Unsupported); // -1
        assert_eq!(
            rej("c074323031332d30332d32315432303a30343a30305a"),
            Error::Unsupported
        ); // tag 0
        assert_eq!(rej("f6"), Error::Unsupported); // null
        assert_eq!(rej("f7"), Error::Unsupported); // undefined
        assert_eq!(rej("f90000"), Error::Unsupported); // half float
        assert_eq!(rej("fa47c35000"), Error::Unsupported); // float
        assert_eq!(rej("fb3ff199999999999a"), Error::Unsupported); // double
        assert_eq!(rej("f0"), Error::Unsupported); // simple(16)
    }

    #[test]
    fn rejects_bad_maps() {
        assert_eq!(rej("a201020103"), Error::DuplicateKey);
        assert_eq!(rej("a203040102"), Error::UnsortedKeys);
        assert_eq!(rej("a1616101"), Error::NonUintKey); // text key
        assert_eq!(rej("a12001"), Error::NonUintKey); // negative key
        assert_eq!(rej("a1f501"), Error::NonUintKey); // bool key
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(rej("62c328"), Error::InvalidUtf8);
        assert_eq!(rej("61ff"), Error::InvalidUtf8);
        assert_eq!(rej("63eda080"), Error::InvalidUtf8); // surrogate
    }

    #[test]
    fn rejects_truncation_and_trailing() {
        assert_eq!(rej(""), Error::Truncated);
        assert_eq!(rej("18"), Error::Truncated);
        assert_eq!(rej("1a0001"), Error::Truncated);
        assert_eq!(rej("4401"), Error::Truncated);
        assert_eq!(rej("830102"), Error::Truncated);
        assert_eq!(rej("a10102a0"), Error::TrailingBytes);
        assert_eq!(rej("0000"), Error::TrailingBytes);
    }

    #[test]
    fn length_checked_before_allocation() {
        // Claims 2^32 elements / bytes with a tiny input: must fail without allocating.
        assert_eq!(rej("9b0000000100000000"), Error::Truncated);
        assert_eq!(rej("5b0000000100000000"), Error::Truncated);
        assert_eq!(rej("bb0000000100000000"), Error::Truncated);
        assert_eq!(rej("9bffffffffffffffff"), Error::Truncated);
    }

    #[test]
    fn enforces_depth_items_and_input_limits() {
        // depth 8 ok, 9 rejected
        let ok = format!("{}00", "81".repeat(7));
        assert!(decode(&hex(&ok), &L).is_ok());
        let deep = format!("{}00", "81".repeat(8));
        assert_eq!(decode(&hex(&deep), &L).unwrap_err(), Error::TooDeep);
        let small = Limits { max_items: 2, ..L };
        assert_eq!(
            decode(&hex("83010203"), &small).unwrap_err(),
            Error::TooManyItems
        );
        let tiny = Limits { max_input: 2, ..L };
        assert_eq!(
            decode(&hex("1903e8"), &tiny).unwrap_err(),
            Error::InputTooLarge
        );
    }

    #[test]
    fn encoder_rejects_unsorted_maps() {
        let v = Value::Map(vec![(2, Value::Uint(0)), (1, Value::Uint(0))]);
        assert_eq!(encode(&v).unwrap_err(), Error::EncodeUnsortedKeys);
        let v = Value::Map(vec![(1, Value::Uint(0)), (1, Value::Uint(0))]);
        assert_eq!(encode(&v).unwrap_err(), Error::EncodeUnsortedKeys);
    }

    #[test]
    fn map_ref_typed_access() {
        let b = hex("a4010203424142056161074101");
        let v = decode(&b, &L).unwrap();
        let m = MapRef::new(&v).unwrap();
        assert_eq!(m.uint(1), Ok(2));
        assert_eq!(m.bytes(3), Ok(&b"AB"[..]));
        assert_eq!(m.fixed::<2>(3), Ok(*b"AB"));
        assert_eq!(m.fixed::<3>(3), Err(FieldError::WrongSize(3)));
        assert_eq!(m.text(5), Ok("a"));
        assert_eq!(m.uint(5), Err(FieldError::WrongType(5)));
        assert_eq!(m.uint(9), Err(FieldError::Missing(9)));
        assert_eq!(m.opt_uint(9), Ok(None));
    }

    /// xorshift64* — deterministic, dependency-free input generator.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// Accepted input ⇒ re-encoding reproduces it exactly (canonical form is unique);
    /// no input panics. Mixes random bytes with mutations of valid encodings.
    fn fuzz_iterations(n: u64, seed: u64) {
        let seeds: Vec<Vec<u8>> = [
            "a4010203424142056161074101",
            "83010203",
            "a201820102038144deadbeef",
            "1bffffffffffffffff",
            "f5",
        ]
        .iter()
        .map(|h| hex(h))
        .collect();
        let mut r = Rng(seed);
        let lim = Limits::new(4096);
        for _ in 0..n {
            let mut b = if r.next().is_multiple_of(2) {
                let len = (r.next() % 48) as usize;
                (0..len).map(|_| r.next() as u8).collect::<Vec<u8>>()
            } else {
                let mut b = seeds[(r.next() % seeds.len() as u64) as usize].clone();
                for _ in 0..=(r.next() % 3) {
                    match r.next() % 4 {
                        0 if !b.is_empty() => {
                            let i = (r.next() % b.len() as u64) as usize;
                            b[i] = r.next() as u8;
                        }
                        1 if !b.is_empty() => {
                            let i = (r.next() % b.len() as u64) as usize;
                            b.remove(i);
                        }
                        2 => {
                            let i = (r.next() % (b.len() as u64 + 1)) as usize;
                            b.insert(i, r.next() as u8);
                        }
                        _ => b.truncate((r.next() % (b.len() as u64 + 1)) as usize),
                    }
                }
                b
            };
            if let Ok(v) = decode(&b, &lim) {
                assert_eq!(
                    encode(&v).unwrap(),
                    b,
                    "non-canonical input accepted: {b:02x?}"
                );
            }
            b.clear();
        }
    }

    #[test]
    fn fuzz_short() {
        fuzz_iterations(200_000, 0x9e37_79b9_7f4a_7c15);
    }

    /// Long run: `WARPSHOT_FUZZ_SECS=600 cargo test -p warpshot-core --release fuzz_long -- --ignored`
    #[test]
    #[ignore]
    fn fuzz_long() {
        let secs: u64 = std::env::var("WARPSHOT_FUZZ_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let start = std::time::Instant::now();
        let mut seed = 1u64;
        while start.elapsed().as_secs() < secs {
            fuzz_iterations(100_000, seed);
            seed += 1;
        }
    }
}
