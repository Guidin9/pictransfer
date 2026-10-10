//! Single instance per user session: named mutex `Local\warpshot-agent-<SID>`.
//!
//! `Local\` is per session, so other users' sessions cannot squat the name.

use std::io;

use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError},
    System::Threading::CreateMutexW,
};

use crate::win::{OwnedHandle, current_user_sid, last_error, wide};

/// Holds the instance mutex; dropping it releases the slot.
#[derive(Debug)]
pub struct InstanceGuard {
    _handle: OwnedHandle,
}

/// Result of [`acquire`].
#[derive(Debug)]
pub enum Instance {
    /// We are the only instance; keep the guard alive for the process lifetime.
    First(InstanceGuard),
    /// Another instance already holds the mutex.
    AlreadyRunning,
}

/// The agent's mutex name for the current user.
pub fn mutex_name() -> io::Result<String> {
    Ok(format!(
        r"Local\warpshot-agent-{}{}",
        current_user_sid()?,
        crate::instance_suffix()
    ))
}

/// Acquires the agent's single-instance mutex.
pub fn acquire() -> io::Result<Instance> {
    acquire_named(&mutex_name()?)
}

/// Acquires a named single-instance mutex (tests use their own names).
pub fn acquire_named(name: &str) -> io::Result<Instance> {
    let w = wide(name);
    // SAFETY: valid NUL-terminated name; default security; the handle is owned below.
    let (h, err) = unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, w.as_ptr());
        (h, GetLastError())
    };
    if h.is_null() {
        return Err(last_error());
    }
    let handle = OwnedHandle(h);
    if err == ERROR_ALREADY_EXISTS {
        return Ok(Instance::AlreadyRunning);
    }
    Ok(Instance::First(InstanceGuard { _handle: handle }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_is_refused_until_released() {
        let name = format!(r"Local\warpshot-agent-test-{}", std::process::id());
        let first = acquire_named(&name).unwrap();
        assert!(matches!(first, Instance::First(_)));
        assert!(matches!(
            acquire_named(&name).unwrap(),
            Instance::AlreadyRunning
        ));
        drop(first);
        assert!(matches!(acquire_named(&name).unwrap(), Instance::First(_)));
    }

    #[test]
    fn name_contains_sid() {
        assert!(
            mutex_name()
                .unwrap()
                .starts_with(r"Local\warpshot-agent-S-1-5-")
        );
    }
}
