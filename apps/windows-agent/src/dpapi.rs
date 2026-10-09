//! DPAPI keystore (CurrentUser scope): device keys at rest are wrapped with
//! `CryptProtectData`, bound to the Windows user account. The label is passed
//! as optional entropy so a blob cannot be swapped for another key's.

use warpshot_core::keys::{KeyError, Keystore};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroizing;

#[derive(Debug, Default, Clone, Copy)]
pub struct Dpapi;

fn blob(b: &[u8]) -> Result<CRYPT_INTEGER_BLOB, KeyError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(b.len()).map_err(|_| KeyError::Keystore)?,
        pbData: b.as_ptr().cast_mut(),
    })
}

/// Copies and frees a LocalAlloc'd output blob.
fn take(out: &CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    let len = usize::try_from(out.cbData).unwrap_or(0);
    let v = if out.pbData.is_null() || len == 0 {
        Vec::new()
    } else {
        // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`.
        unsafe { std::slice::from_raw_parts(out.pbData, len) }.to_vec()
    };
    if !out.pbData.is_null() {
        // SAFETY: the buffer is LocalAlloc'd by DPAPI and owned by us; wipe, then free.
        unsafe {
            std::ptr::write_bytes(out.pbData, 0, len);
            LocalFree(out.pbData.cast());
        }
    }
    Zeroizing::new(v)
}

impl Keystore for Dpapi {
    fn wrap(&self, label: &str, plain: &[u8]) -> Result<Vec<u8>, KeyError> {
        let input = blob(plain)?;
        let entropy = blob(label.as_bytes())?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: input blobs point to live slices for the duration of the call.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(KeyError::Keystore);
        }
        Ok(take(&out).to_vec())
    }

    fn unwrap(&self, label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let input = blob(wrapped)?;
        let entropy = blob(label.as_bytes())?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `wrap`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(KeyError::Keystore);
        }
        Ok(take(&out))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_label_binding() {
        let w = Dpapi.wrap("ik", b"secret key bytes").unwrap();
        assert_ne!(&w[..], b"secret key bytes");
        assert_eq!(&Dpapi.unwrap("ik", &w).unwrap()[..], b"secret key bytes");
        assert!(Dpapi.unwrap("kk", &w).is_err(), "wrong label is refused");
        let mut bad = w.clone();
        if let Some(b) = bad.last_mut() {
            *b ^= 1;
        }
        assert!(
            Dpapi.unwrap("ik", &bad).is_err(),
            "tampered blob is refused"
        );
    }
}
