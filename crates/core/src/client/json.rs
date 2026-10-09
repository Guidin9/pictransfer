//! Minimal strict JSON (RFC 8259) for the server API (protocol §6).
//!
//! The server's messages are small objects of strings, unsigned integers,
//! booleans, `null` and arrays. The parser accepts exactly that subset:
//! numbers must be non-negative integers that fit a `u64` (no fraction, no
//! exponent, no sign, no leading zeros). It rejects duplicate keys, nesting
//! deeper than [`MAX_DEPTH`], invalid escapes and unpaired surrogates, and
//! trailing bytes. The input size is bounded by the caller (HTTP / WebSocket
//! caps), so every allocation is bounded by it.

use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Uint(u64),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// Why a document was rejected. Carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    Syntax,
    Depth,
    DuplicateKey,
    Number,
    Escape,
    Utf8,
    Trailing,
}

pub fn parse(input: &[u8]) -> Result<Value, JsonError> {
    let mut p = Parser { b: input, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != input.len() {
        return Err(JsonError::Trailing);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i = self.i.saturating_add(1);
        Some(c)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i = self.i.saturating_add(1);
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.bump() == Some(c) {
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn literal(&mut self, lit: &[u8], v: Value) -> Result<Value, JsonError> {
        let end = self.i.checked_add(lit.len()).ok_or(JsonError::Syntax)?;
        if self.b.get(self.i..end) == Some(lit) {
            self.i = end;
            Ok(v)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        match self.peek().ok_or(JsonError::Syntax)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'0'..=b'9' => self.number(),
            b'-' => Err(JsonError::Number),
            _ => Err(JsonError::Syntax),
        }
    }

    fn enter(depth: usize) -> Result<usize, JsonError> {
        let d = depth.saturating_add(1);
        if d > MAX_DEPTH {
            Err(JsonError::Depth)
        } else {
            Ok(d)
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        let depth = Self::enter(depth)?;
        self.eat(b'{')?;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i = self.i.saturating_add(1);
            return Ok(Value::Object(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(depth)?;
            if m.insert(k, v).is_some() {
                return Err(JsonError::DuplicateKey);
            }
            self.ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(Value::Object(m)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        let depth = Self::enter(depth)?;
        self.eat(b'[')?;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i = self.i.saturating_add(1);
            return Ok(Value::Array(a));
        }
        loop {
            self.ws();
            a.push(self.value(depth)?);
            self.ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::Array(a)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i = self.i.saturating_add(1);
        }
        let digits = self.b.get(start..self.i).ok_or(JsonError::Number)?;
        if matches!(self.peek(), Some(b'.' | b'e' | b'E'))
            || (digits.len() > 1 && digits.first() == Some(&b'0'))
        {
            return Err(JsonError::Number);
        }
        let mut n: u64 = 0;
        for d in digits {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(d.saturating_sub(b'0'))))
                .ok_or(JsonError::Number)?;
        }
        Ok(Value::Uint(n))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut n = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or(JsonError::Escape)?;
            let d = char::from(c).to_digit(16).ok_or(JsonError::Escape)?;
            n = (n << 4) | d;
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.bump().ok_or(JsonError::Syntax)?;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.bump().ok_or(JsonError::Escape)?;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(JsonError::Escape);
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JsonError::Escape);
                                }
                                0x10000u32
                                    .saturating_add((hi.saturating_sub(0xD800)) << 10)
                                    .saturating_add(lo.saturating_sub(0xDC00))
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or(JsonError::Escape)?
                        }
                        _ => return Err(JsonError::Escape),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return Err(JsonError::Syntax),
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| JsonError::Utf8)
    }
}

/// Appends `s` as a JSON string literal.
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON object built from `(key, value)` pairs, in the given order.
/// Values are pre-encoded fragments made with [`str_lit`] or [`uint`].
pub fn object(fields: &[(&str, String)]) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_str(&mut out, k);
        out.push(':');
        out.push_str(v);
    }
    out.push('}');
    out
}

pub fn str_lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    push_str(&mut out, s);
    out
}

pub fn uint(n: u64) -> String {
    n.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_shapes() {
        let v = parse(
            br#" {"records": ["AA", "AQ"], "head": {"seq": 3, "id": "x"}, "n": null, "b": true} "#,
        )
        .unwrap();
        assert_eq!(v.get("head").unwrap().get("seq").unwrap().as_u64(), Some(3));
        assert_eq!(v.get("records").unwrap().as_array().unwrap().len(), 2);
        assert!(v.get("n").unwrap().is_null());
        assert_eq!(v.get("b").unwrap().as_bool(), Some(true));
        assert_eq!(
            parse(b"18446744073709551615").unwrap(),
            Value::Uint(u64::MAX)
        );
        assert_eq!(
            parse(br#""a\"\\\/\n\u00e9\ud83d\ude00""#).unwrap(),
            Value::Str("a\"\\/\n\u{e9}\u{1F600}".into())
        );
    }

    #[test]
    fn rejects_invalid() {
        for bad in [
            &b""[..],
            b"{",
            b"{\"a\":1,}",
            b"[1,]",
            b"{\"a\":1,\"a\":2}",
            b"-1",
            b"1.5",
            b"1e3",
            b"01",
            b"18446744073709551616",
            b"\"\\x\"",
            b"\"\\ud800\"",
            b"\"\\udc00\"",
            b"\"\\ud800\\u0041\"",
            b"\"a\nb\"",
            b"\"\xff\"",
            b"{} x",
            b"{}{}",
            b"tru",
            b"nul",
            b"{1:2}",
            b"'a'",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn depth_limit() {
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(parse(deep.as_bytes()), Err(JsonError::Depth));
        let deep = "[".repeat(100_000);
        assert_eq!(parse(deep.as_bytes()), Err(JsonError::Depth));
    }

    #[test]
    fn encodes_and_roundtrips() {
        let s = object(&[
            ("t", str_lit("wake")),
            ("id", uint(7)),
            ("x", str_lit("q\"\\\u{1}\n")),
        ]);
        assert_eq!(s, r#"{"t":"wake","id":7,"x":"q\"\\\u0001\n"}"#);
        let v = parse(s.as_bytes()).unwrap();
        assert_eq!(v.get("x").unwrap().as_str(), Some("q\"\\\u{1}\n"));
    }
}
