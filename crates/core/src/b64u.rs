//! Base64url without padding (RFC 4648 §5), as used in all JSON (protocol §1).
//! The decoder is strict: no padding, no whitespace, no non-zero trailing bits.

// Shift amounts and alphabet offsets are bounded by construction (i < 4,
// c within its matched range); input lengths only flow into checked or saturating ops.
#![allow(clippy::arithmetic_side_effects)]

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len().saturating_add(1);
        for i in 0..chars {
            let idx = (n >> (18 - 6 * i as u32)) & 63;
            out.push(char::from(
                ALPHABET.get(idx as usize).copied().unwrap_or(b'A'),
            ));
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    }))
}

/// Strict decode; `None` on any deviation from the canonical encoding.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3) / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i as u32);
        }
        let produced = chunk.len().saturating_sub(1);
        let full = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Canonical form: bits below the last full byte must be zero.
        let unused_mask = match produced {
            1 => 0xffff,
            2 => 0xff,
            _ => 0,
        };
        if n & unused_mask != 0 {
            return None;
        }
        out.extend_from_slice(full.get(..produced)?);
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_without_padding() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn rejects_non_canonical() {
        assert!(decode("Zg==").is_none()); // padding
        assert!(decode("Zh").is_none()); // non-zero trailing bits
        assert!(decode("Z").is_none()); // impossible length
        assert!(decode("Zm9v+/").is_none()); // standard alphabet
        assert!(decode("Zm 9v").is_none()); // whitespace
    }

    #[test]
    fn roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            assert_eq!(decode(&encode(&data[..n])).unwrap(), &data[..n]);
        }
    }
}
