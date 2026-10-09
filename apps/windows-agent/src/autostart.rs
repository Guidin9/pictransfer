//! Autostart via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (no admin rights).
//!
//! Task Manager's "Startup apps" toggle writes `…\Explorer\StartupApproved\Run`;
//! an entry disabled there counts as disabled. Enabling from our settings is an
//! explicit user choice, so it clears that marker.

use std::io;

use windows_registry::CURRENT_USER;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// The agent's value name.
pub const VALUE_NAME: &str = "Warpshot";
/// Argument the agent receives when started by Windows at logon.
pub const AUTOSTART_ARG: &str = "--autostart";
/// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).
const NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

fn io_err(e: windows_registry::Result<()>) -> io::Result<()> {
    e.map_err(io::Error::other)
}

/// The command line registered for the current executable.
pub fn command_for_current_exe() -> io::Result<String> {
    let exe = std::env::current_exe()?;
    Ok(format!("\"{}\" {AUTOSTART_ARG}", exe.display()))
}

/// Enables autostart for the current executable.
pub fn enable() -> io::Result<()> {
    enable_named(VALUE_NAME, &command_for_current_exe()?)
}

/// Disables autostart (no error if it was not enabled).
pub fn disable() -> io::Result<()> {
    disable_named(VALUE_NAME)
}

/// `true` if the Run entry points at the current executable and Task Manager
/// has not disabled it.
pub fn is_enabled() -> io::Result<bool> {
    is_enabled_named(VALUE_NAME, &command_for_current_exe()?)
}

pub fn enable_named(name: &str, command: &str) -> io::Result<()> {
    let key = CURRENT_USER.create(RUN).map_err(io::Error::other)?;
    io_err(key.set_string(name, command))?;
    if let Ok(approved) = CURRENT_USER.options().read().write().open(APPROVED) {
        ignore_not_found(approved.remove_value(name))?;
    }
    Ok(())
}

pub fn disable_named(name: &str) -> io::Result<()> {
    let key = match CURRENT_USER.options().read().write().open(RUN) {
        Ok(k) => k,
        Err(e) if e.code().0 == NOT_FOUND => return Ok(()),
        Err(e) => return Err(io::Error::other(e)),
    };
    ignore_not_found(key.remove_value(name))?;
    if let Ok(approved) = CURRENT_USER.options().read().write().open(APPROVED) {
        ignore_not_found(approved.remove_value(name))?;
    }
    Ok(())
}

pub fn is_enabled_named(name: &str, command: &str) -> io::Result<bool> {
    let Ok(key) = CURRENT_USER.open(RUN) else {
        return Ok(false);
    };
    let value = match key.get_string(name) {
        Ok(v) => v,
        Err(e) if e.code().0 == NOT_FOUND => return Ok(false),
        Err(e) => return Err(io::Error::other(e)),
    };
    if !value.eq_ignore_ascii_case(command) {
        return Ok(false);
    }
    // StartupApproved: first byte even (0x02/0x06) = enabled, odd (0x03/0x07) = disabled.
    let disabled = CURRENT_USER
        .open(APPROVED)
        .and_then(|k| k.get_value(name))
        .ok()
        .and_then(|v| v.first().copied())
        .is_some_and(|b| b & 1 == 1);
    Ok(!disabled)
}

fn ignore_not_found(r: windows_registry::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.code().0 == NOT_FOUND => Ok(()),
        other => io_err(other),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn enable_disable_round_trip_with_test_value() {
        let name = format!("WarpshotTest{}", std::process::id());
        let cmd = r#""C:\nowhere\warpshot-agent.exe" --autostart"#;
        disable_named(&name).unwrap();
        assert!(!is_enabled_named(&name, cmd).unwrap());
        enable_named(&name, cmd).unwrap();
        let result = (|| -> io::Result<()> {
            assert!(is_enabled_named(&name, cmd)?);
            assert!(!is_enabled_named(&name, r#""C:\other.exe""#)?);
            // Task Manager "disabled" marker.
            let approved = CURRENT_USER.create(APPROVED).map_err(io::Error::other)?;
            io_err(approved.set_bytes(
                &name,
                windows_registry::Type::Bytes,
                &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ))?;
            assert!(!is_enabled_named(&name, cmd)?);
            enable_named(&name, cmd)?; // explicit enable clears the marker
            assert!(is_enabled_named(&name, cmd)?);
            Ok(())
        })();
        disable_named(&name).unwrap();
        result.unwrap();
        assert!(!is_enabled_named(&name, cmd).unwrap());
        disable_named(&name).unwrap(); // idempotent
    }

    #[test]
    fn command_quotes_exe() {
        let c = command_for_current_exe().unwrap();
        assert!(c.starts_with('"') && c.ends_with("\" --autostart"), "{c}");
    }
}
