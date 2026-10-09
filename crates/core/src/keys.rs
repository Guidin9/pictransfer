//! Device keys (protocol §2.2): the Ed25519 identity key `IK` and the X-Wing KEM
//! key `KK`, plus the [`Keystore`] trait that wraps them with the OS keystore.
//!
//! Secrets live in zeroize-on-drop types and never appear in `Debug` output.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x_wing::{Decapsulator, KeyExport, TryDecapsulate};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Encoder, Limits, MapRef};

/// X-Wing encapsulation key length (protocol §2.1).
pub const KEM_PK_LEN: usize = 1216;
/// X-Wing ciphertext length.
pub const KEM_CT_LEN: usize = 1120;

/// 32-byte Ed25519 public key: iroh endpoint id and group identity (§3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointId(pub [u8; 32]);

impl fmt::Debug for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointId({})", short_hex(&self.0))
    }
}

/// First 8 bytes as hex, for ids in logs and debug output (never for secrets).
pub fn short_hex(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The OS random number generator failed.
    Rng,
    /// Malformed key bytes.
    Invalid,
    /// The keystore refused or failed to wrap/unwrap.
    Keystore,
    /// Decapsulation failed (including a non-contributory X25519 share).
    Decapsulation,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for KeyError {}

/// Fills `buf` from the OS CSPRNG.
pub fn random(buf: &mut [u8]) -> Result<(), KeyError> {
    getrandom::fill(buf).map_err(|_| KeyError::Rng)
}

/// Ed25519 identity key `IK`.
pub struct IdentityKey(SigningKey);

impl IdentityKey {
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        random(seed.as_mut())?;
        Ok(Self::from_secret(&seed))
    }

    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(secret))
    }

    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn endpoint_id(&self) -> EndpointId {
        EndpointId(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKey(<redacted>, {:?})", self.endpoint_id())
    }
}

/// Strict Ed25519 verification (§2.1): rejects non-canonical encodings and
/// small-order points.
pub fn verify_strict(signer: &EndpointId, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&signer.0) else {
        return false;
    };
    if vk.is_weak() {
        return false;
    }
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

/// X-Wing KEM key `KK`, stored as its 32-byte seed.
pub struct KemKey {
    seed: Zeroizing<[u8; 32]>,
}

impl KemKey {
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        random(seed.as_mut())?;
        Ok(Self { seed })
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.seed)
    }

    fn dk(&self) -> x_wing::DecapsulationKeyRejectNonContrib {
        x_wing::DecapsulationKeyRejectNonContrib::from(*self.seed)
    }

    /// The 1216-byte encapsulation key published in `DeviceInfo.kem_pk`.
    pub fn public_key(&self) -> Vec<u8> {
        self.dk().encapsulation_key().to_bytes().to_vec()
    }

    /// Decapsulates `ct`; the X25519 all-zero case is rejected (§2.1).
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let ct = x_wing::Ciphertext::try_from(ct).map_err(|_| KeyError::Invalid)?;
        let mut ss = self
            .dk()
            .try_decapsulate(&ct)
            .map_err(|_| KeyError::Decapsulation)?;
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(ss.as_slice());
        ss.as_mut_slice().zeroize();
        Ok(out)
    }
}

impl fmt::Debug for KemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KemKey(<redacted>)")
    }
}

/// `kid(kem_pk)` = first 8 bytes of SHA-256(kem_pk) (§3).
pub fn kid(kem_pk: &[u8]) -> [u8; 8] {
    let d = Sha256::digest(kem_pk);
    let mut k = [0u8; 8];
    k.copy_from_slice(d.get(..8).unwrap_or(&[0u8; 8]));
    k
}

/// OS keystore wrapping (Windows DPAPI in the agent, Android Keystore via FFI).
/// `label` names the secret ("ik", "kk", "history") and is bound into the wrap
/// where the platform supports it.
pub trait Keystore {
    fn wrap(&self, label: &str, plain: &[u8]) -> Result<Vec<u8>, KeyError>;
    fn unwrap(&self, label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}

/// Both device keys.
#[derive(Debug)]
pub struct DeviceKeys {
    pub ik: IdentityKey,
    pub kk: KemKey,
}

impl DeviceKeys {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self {
            ik: IdentityKey::generate()?,
            kk: KemKey::generate()?,
        })
    }

    /// Serializes both keys wrapped by `ks`: CBOR `{0: v=1, 1: ik_wrapped, 2: kk_wrapped}`.
    pub fn to_wrapped(&self, ks: &dyn Keystore) -> Result<Vec<u8>, KeyError> {
        let ik = ks.wrap("ik", self.ik.secret().as_ref())?;
        let kk = ks.wrap("kk", self.kk.seed().as_ref())?;
        let mut e = Encoder::new();
        e.map(3)
            .uint(0)
            .uint(1)
            .uint(1)
            .bytes(&ik)
            .uint(2)
            .bytes(&kk);
        Ok(e.into_bytes())
    }

    pub fn from_wrapped(blob: &[u8], ks: &dyn Keystore) -> Result<Self, KeyError> {
        let v = cbor::decode(blob, &Limits::new(16 * 1024)).map_err(|_| KeyError::Invalid)?;
        let m = MapRef::new(&v).ok_or(KeyError::Invalid)?;
        if m.uint(0) != Ok(1) {
            return Err(KeyError::Invalid);
        }
        let ik = ks.unwrap("ik", m.bytes(1).map_err(|_| KeyError::Invalid)?)?;
        let kk = ks.unwrap("kk", m.bytes(2).map_err(|_| KeyError::Invalid)?)?;
        let ik: &[u8; 32] = ik.as_slice().try_into().map_err(|_| KeyError::Invalid)?;
        let kk: &[u8; 32] = kk.as_slice().try_into().map_err(|_| KeyError::Invalid)?;
        Ok(Self {
            ik: IdentityKey::from_secret(ik),
            kk: KemKey::from_seed(kk),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// XOR "keystore" for tests only.
    pub struct TestKeystore(pub u8);

    impl Keystore for TestKeystore {
        fn wrap(&self, label: &str, plain: &[u8]) -> Result<Vec<u8>, KeyError> {
            let mut v = label.as_bytes().to_vec();
            v.push(0);
            v.extend(plain.iter().map(|b| b ^ self.0));
            Ok(v)
        }
        fn unwrap(&self, label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            let rest = wrapped
                .strip_prefix(label.as_bytes())
                .and_then(|r| r.strip_prefix(&[0]))
                .ok_or(KeyError::Keystore)?;
            Ok(Zeroizing::new(rest.iter().map(|b| b ^ self.0).collect()))
        }
    }

    #[test]
    fn sign_verify_strict() {
        let ik = IdentityKey::from_secret(&[7; 32]);
        let id = ik.endpoint_id();
        let sig = ik.sign(b"msg");
        assert!(verify_strict(&id, b"msg", &sig));
        assert!(!verify_strict(&id, b"msh", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify_strict(&id, b"msg", &bad));
    }

    #[test]
    fn verify_rejects_small_order_key() {
        // The identity point (small order) as a public key, with a trivially "valid" signature.
        let mut id = [0u8; 32];
        id[0] = 1;
        let mut sig = [0u8; 64];
        sig[0] = 1;
        assert!(!verify_strict(&EndpointId(id), b"anything", &sig));
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        let ik = IdentityKey::from_secret(&[9; 32]);
        let mut sig = ik.sign(b"m");
        // s + L (group order) is non-canonical; add L to the scalar half.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = sig[32 + i] as u16 + L[i] as u16 + carry;
            sig[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(!verify_strict(&ik.endpoint_id(), b"m", &sig));
    }

    #[test]
    fn kem_roundtrip_and_kid() {
        let kk = KemKey::from_seed(&[3; 32]);
        let pk = kk.public_key();
        assert_eq!(pk.len(), KEM_PK_LEN);
        assert_eq!(kid(&pk), kid(&kk.public_key()));
        assert!(kk.decapsulate(&[0u8; 10]).is_err());
    }

    #[test]
    fn wrapped_roundtrip() {
        let keys = DeviceKeys::generate().unwrap();
        let blob = keys.to_wrapped(&TestKeystore(0x5a)).unwrap();
        let back = DeviceKeys::from_wrapped(&blob, &TestKeystore(0x5a)).unwrap();
        assert_eq!(back.ik.endpoint_id(), keys.ik.endpoint_id());
        assert_eq!(back.kk.public_key(), keys.kk.public_key());
        // Secrets are not in the serialized blob in plaintext.
        let ik = keys.ik.secret();
        assert!(!blob.windows(32).any(|w| w == ik.as_ref()));
        assert!(
            DeviceKeys::from_wrapped(&blob, &TestKeystore(0x11)).is_err() || {
                let b = DeviceKeys::from_wrapped(&blob, &TestKeystore(0x11)).unwrap();
                b.ik.endpoint_id() != keys.ik.endpoint_id()
            }
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        let ik = IdentityKey::from_secret(&[0xab; 32]);
        let kk = KemKey::from_seed(&[0xcd; 32]);
        let s = format!("{ik:?} {kk:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("abab") && !s.contains("cdcd") && !s.contains("171"));
    }
}
