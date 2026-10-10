//! Embeds the Warpshot icon (resource id 1) so Explorer, the startup list and
//! the tray show the logo. Compiles `res/agent.rc` with the Windows SDK's
//! `rc.exe` and links the `.res`; no build dependencies.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=res/agent.rc");
    println!("cargo:rerun-if-changed=../windows-ui/src-tauri/icons/icon.ico");
    println!("cargo:rerun-if-env-changed=RC");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let Some(rc) = find_rc() else {
        // Build still works; the tray then falls back to the system icon.
        println!("cargo:warning=rc.exe not found (set RC); building without the icon");
        return;
    };
    let out = PathBuf::from(env::var("OUT_DIR").unwrap_or_default()).join("agent.res");
    let status = Command::new(&rc)
        .args(["/nologo", "/fo"])
        .arg(&out)
        .arg("agent.rc")
        // Paths in the script are relative to its own directory.
        .current_dir("res")
        .status();
    match status {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg-bins={}", out.display()),
        _ => println!("cargo:warning=rc.exe failed; building without the icon"),
    }
}

/// `RC` if set, else the newest Windows 10/11 SDK `rc.exe` for the host.
fn find_rc() -> Option<PathBuf> {
    if let Some(rc) = env::var_os("RC") {
        return Some(PathBuf::from(rc));
    }
    let base = PathBuf::from(env::var_os("ProgramFiles(x86)")?).join("Windows Kits\\10\\bin");
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let mut versions: Vec<PathBuf> = std::fs::read_dir(&base)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join(arch).join("rc.exe").is_file())
        .collect();
    versions.sort();
    versions.pop().map(|v| v.join(arch).join("rc.exe"))
}
