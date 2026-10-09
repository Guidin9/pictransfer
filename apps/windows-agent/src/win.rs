//! Small Win32 helpers shared by the modules: UTF-16 strings, the current user's
//! SID, an owned `HANDLE`, and a hidden window for tests and tools.

use std::io;

use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, HWND, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// NUL-terminated UTF-16 copy of `s`.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The calling thread's last Win32 error as an `io::Error`.
pub fn last_error() -> io::Error {
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
}

/// A kernel handle that is closed on drop.
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own this handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Memory returned by an API that must be released with `LocalFree`.
#[derive(Debug)]
pub struct LocalBox(pub *mut core::ffi::c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate with LocalAlloc.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// Length of a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must point to a readable NUL-terminated UTF-16 string.
unsafe fn wcslen(p: *const u16) -> usize {
    let mut n = 0usize;
    // SAFETY: the caller guarantees a terminator; we stop at it.
    while unsafe { *p.add(n) } != 0 {
        n = n.saturating_add(1);
    }
    n
}

/// The current process user's SID in string form (`S-1-5-21-…`).
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out-pointer; the handle is wrapped right away.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let token = OwnedHandle(token);
    // TOKEN_USER plus the SID fits easily; u64 storage keeps the buffer aligned.
    let mut buf = [0u64; 64];
    let mut len = 0u32;
    let size = u32::try_from(std::mem::size_of_val(&buf)).unwrap_or(0);
    // SAFETY: buffer and size match; GetTokenInformation writes at most `size` bytes.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), size, &mut len) }
        == 0
    {
        return Err(last_error());
    }
    // SAFETY: on success the buffer starts with an aligned TOKEN_USER.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` points into `buf`, which is alive for the call.
    unsafe { sid_to_string(sid) }
}

/// String form of a binary SID.
///
/// # Safety
/// `sid` must point to a valid SID for the duration of the call.
pub unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut s: *mut u16 = std::ptr::null_mut();
    // SAFETY: valid SID per the caller; `s` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return Err(last_error());
    }
    let owned = LocalBox(s.cast());
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string.
    let out = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(s, wcslen(s))) };
    drop(owned);
    Ok(out)
}

/// Converts an `HWND` to an integer so it can cross threads (`HWND` is a raw
/// pointer and not `Send`). Window handles are global within the session.
pub fn hwnd_to_bits(hwnd: HWND) -> usize {
    hwnd as usize
}

/// Inverse of [`hwnd_to_bits`].
pub fn hwnd_from_bits(bits: usize) -> HWND {
    bits as HWND
}

#[cfg(test)]
pub mod test_window {
    //! A message-only window for tests (hotkeys, clipboard ownership).
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, HWND_MESSAGE, RegisterClassW, WNDCLASSW,
        },
    };

    unsafe extern "system" fn proc_(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        // SAFETY: default handling for every message.
        unsafe { DefWindowProcW(h, m, w, l) }
    }

    #[derive(Debug)]
    pub struct TestWindow(pub HWND);

    impl Default for TestWindow {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestWindow {
        pub fn new() -> Self {
            let class = super::wide("WarpshotAgentTestWindow");
            // SAFETY: plain class registration (repeat registration fails harmlessly)
            // and creation of a message-only window owned by this thread.
            let hwnd = unsafe {
                let hinst = GetModuleHandleW(std::ptr::null());
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(proc_),
                    hInstance: hinst,
                    lpszClassName: class.as_ptr(),
                    ..std::mem::zeroed()
                };
                RegisterClassW(&wc);
                CreateWindowExW(
                    0,
                    class.as_ptr(),
                    class.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    std::ptr::null_mut(),
                    hinst,
                    std::ptr::null(),
                )
            };
            assert!(!hwnd.is_null(), "CreateWindowExW failed");
            TestWindow(hwnd)
        }
    }

    impl Drop for TestWindow {
        fn drop(&mut self) {
            // SAFETY: the window was created on this thread and is destroyed once.
            unsafe { DestroyWindow(self.0) };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn sid_looks_like_a_user_sid() {
        let sid = super::current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert!(sid.len() > 8);
    }

    #[test]
    fn wide_is_nul_terminated() {
        assert_eq!(super::wide("ab"), vec![97, 98, 0]);
    }
}
