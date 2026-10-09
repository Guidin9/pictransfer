//! The only Win32 FFI in the UI: current user SID, pipe server owner check,
//! and the single-instance mutex.
#![allow(unsafe_code)]

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, IsIconic, SW_RESTORE, SetForegroundWindow, ShowWindow,
};

/// A kernel handle closed on drop.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own this handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Runs `f` with the user SID of the process behind `process`.
fn with_token_user<R>(process: HANDLE, f: impl FnOnce(PSID) -> Option<R>) -> Option<R> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid process handle and out pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle(token);
    let mut len: u32 = 0;
    // SAFETY: size query with a null buffer; failure with the needed size is expected.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 || len > 64 * 1024 {
        return None;
    }
    // u64 storage keeps TOKEN_USER (pointer-aligned) correctly aligned.
    let words = (len as usize).div_ceil(8);
    let mut buf = vec![0u64; words];
    // SAFETY: the buffer holds at least `len` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            len,
            &mut len,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points
    // into the same buffer, which outlives `f`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` comes from the kernel.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    f(sid)
}

fn sid_bytes(sid: PSID) -> Option<Vec<u8>> {
    // SAFETY: `sid` is a valid SID (checked by the caller via IsValidSid).
    let n = unsafe { GetLengthSid(sid) } as usize;
    if n == 0 || n > 68 {
        return None;
    }
    // SAFETY: a valid SID is `n` readable bytes.
    Some(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), n) }.to_vec())
}

/// The current user's SID as a string (`S-1-5-21-...`).
pub fn current_user_sid() -> Option<String> {
    // SAFETY: pseudo-handle, never needs closing.
    let me = unsafe { GetCurrentProcess() };
    with_token_user(me, |sid| {
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: valid SID, out pointer receives a LocalAlloc'd string.
        if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 || out.is_null() {
            return None;
        }
        let mut n = 0usize;
        // SAFETY: NUL-terminated string from the OS, bounded scan.
        while n < 256 && unsafe { *out.add(n) } != 0 {
            n += 1;
        }
        // SAFETY: `n` u16s were just scanned.
        let s = String::from_utf16(unsafe { std::slice::from_raw_parts(out, n) }).ok();
        // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
        unsafe { LocalFree(out as HLOCAL) };
        s
    })
}

/// True if the process serving the named pipe `pipe` runs as the current user.
/// Guards against pipe-name squatting by another account (threat model T9).
pub fn pipe_server_is_current_user(pipe: HANDLE) -> bool {
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is an open client pipe handle.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return false;
    }
    // SAFETY: plain open; null on failure.
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc_handle.is_null() {
        return false;
    }
    let proc_handle = OwnedHandle(proc_handle);
    let theirs = with_token_user(proc_handle.0, sid_bytes);
    // SAFETY: pseudo-handle.
    let mine = with_token_user(unsafe { GetCurrentProcess() }, sid_bytes);
    matches!((theirs, mine), (Some(a), Some(b)) if a == b)
}

/// Outcome of the single-instance check.
#[derive(Debug)]
pub enum Instance {
    /// We are the only instance; keep the mutex alive for the process lifetime.
    First(OwnedHandle),
    /// Another UI instance is running.
    AlreadyRunning,
}

pub fn single_instance(sid: &str) -> Instance {
    let name = wide(&format!("Local\\warpshot-ui-{sid}"));
    // SAFETY: NUL-terminated name, default security.
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    // SAFETY: read right after the call.
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let h = OwnedHandle(h);
    if already {
        Instance::AlreadyRunning
    } else {
        Instance::First(h)
    }
}

/// Brings the existing UI window (by title) to the foreground.
pub fn focus_window(title: &str) {
    let t = wide(title);
    // SAFETY: NUL-terminated title; null class matches any.
    let hwnd = unsafe { FindWindowW(std::ptr::null(), t.as_ptr()) };
    if hwnd.is_null() {
        return;
    }
    // SAFETY: valid top-level window handle.
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        SetForegroundWindow(hwnd);
    }
}
