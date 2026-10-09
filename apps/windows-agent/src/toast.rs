//! WinRT toasts (`Windows.UI.Notifications`) for an unpackaged app.
//!
//! Every toast builds its XML, notifier and notification on demand and drops
//! them right after `Show` (resource-budget.md §2.5: no long-lived ToastNotifier).
//! Unpackaged apps need a Start Menu shortcut carrying the AUMID, otherwise
//! Windows drops the toast: [`install_start_menu_shortcut`] creates it and is
//! only run by the installer / an explicit CLI flag, never by tests.
//!
//! Activation: buttons and the body carry `arguments` such as
//! `action=open&id=<history id>`. There is deliberately **no URL protocol
//! handler** (threat model T9).
//!
//! TODO(W4): COM activator. Register `HKCU\Software\Classes\CLSID\{ACTIVATOR}\LocalServer32
//! = "<exe>" -ToastActivated`, set `PKEY_AppUserModel_ToastActivatorCLSID` on the
//! shortcut, and implement `INotificationActivationCallback` in a short-lived
//! process started by COM that forwards `invokedArgs` to the running agent over
//! the named pipe and exits. Keeping the class object registered inside the
//! agent would require COM/RPC worker threads at idle, which the budget forbids.

use std::{fmt, path::Path};

use windows::{
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
    Win32::{
        Storage::EnhancedStorage::PKEY_AppUserModel_ID,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoTaskMemFree, IPersistFile,
                StructuredStorage::{
                    PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
                },
            },
            Variant::VT_LPWSTR,
        },
        UI::Shell::{
            FOLDERID_Programs, IShellLinkW, KF_FLAG_DEFAULT, PropertiesSystem::IPropertyStore,
            SHGetKnownFolderPath, ShellLink,
        },
    },
    core::{HSTRING, Interface, PCWSTR, PWSTR},
};

/// The agent's AppUserModelID (also on the Start Menu shortcut).
pub const AUMID: &str = "Warpshot.Agent";
/// Start Menu shortcut file name (under `%APPDATA%\Microsoft\Windows\Start Menu\Programs`).
pub const SHORTCUT_NAME: &str = "Warpshot.lnk";

/// One toast. `id` identifies the history item the actions refer to.
#[derive(Debug, Clone, Default)]
pub struct Toast<'a> {
    pub title: &'a str,
    pub body: &'a str,
    /// Local image shown as the hero preview (a received screenshot).
    pub image: Option<&'a Path>,
    /// History item id; adds "Open" / "Show in folder" actions when set.
    pub id: Option<&'a str>,
}

#[derive(Debug)]
pub struct ToastError(pub windows::core::Error);

impl fmt::Display for ToastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "toast failed: {:#010x}", self.0.code().0)
    }
}

impl std::error::Error for ToastError {}

impl From<windows::core::Error> for ToastError {
    fn from(e: windows::core::Error) -> Self {
        ToastError(e)
    }
}

/// XML-escapes text and attribute values.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            // XML 1.0 forbids most control characters; drop them.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => o.push(c),
        }
    }
    o
}

/// `file:///C:/…` URI for a local path, percent-encoding what a URI cannot hold.
fn file_uri(p: &Path) -> String {
    let mut o = String::from("file:///");
    for b in p.to_string_lossy().replace('\\', "/").bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b':' | b'-' | b'_' | b'.' | b'~' => {
                o.push(char::from(b))
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Activation arguments for an action on a history item (`&`-separated, ids are
/// percent-safe base64url in practice; escaped anyway).
fn action_args(action: &str, id: &str) -> String {
    format!("action={action}&id={id}")
}

/// Builds the toast XML (ToastGeneric).
pub fn build_xml(t: &Toast<'_>) -> String {
    let launch =
        t.id.map(|id| format!(" launch=\"{}\"", esc(&action_args("open", id))))
            .unwrap_or_default();
    let mut x = format!("<toast{launch}><visual><binding template=\"ToastGeneric\">");
    x.push_str(&format!("<text>{}</text>", esc(t.title)));
    if !t.body.is_empty() {
        x.push_str(&format!("<text>{}</text>", esc(t.body)));
    }
    if let Some(img) = t.image {
        x.push_str(&format!(
            "<image placement=\"hero\" src=\"{}\"/>",
            esc(&file_uri(img))
        ));
    }
    x.push_str("</binding></visual>");
    if let Some(id) = t.id {
        x.push_str("<actions>");
        for (label, action) in [("Open", "open"), ("Show in folder", "folder")] {
            x.push_str(&format!(
                "<action content=\"{label}\" arguments=\"{}\" activationType=\"foreground\"/>",
                esc(&action_args(action, id))
            ));
        }
        x.push_str("</actions>");
    }
    x.push_str("</toast>");
    x
}

/// Creates the WinRT notification object (no UI). Separate from [`show`] so it
/// can be tested without popping a toast.
fn create(t: &Toast<'_>) -> Result<ToastNotification, ToastError> {
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(build_xml(t)))?;
    Ok(ToastNotification::CreateToastNotification(&doc)?)
}

/// Builds the XML and the WinRT notification object without showing it.
pub fn validate(t: &Toast<'_>) -> Result<(), ToastError> {
    create(t).map(drop)
}

/// Ensures COM is initialized on this thread (STA, the UI thread). Kept for the
/// thread's lifetime: WinRT caches agile factories, so we never uninitialize.
fn ensure_com() {
    // SAFETY: plain call; S_FALSE (already initialized) and RPC_E_CHANGED_MODE
    // (an MTA thread) are both fine for the calls that follow.
    let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
}

/// Shows a toast. Call on the UI thread. All WinRT objects are released on return.
pub fn show(t: &Toast<'_>) -> Result<(), ToastError> {
    ensure_com();
    let toast = create(t)?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?;
    notifier.Show(&toast)?;
    Ok(())
}

/// Path of the Start Menu shortcut.
pub fn shortcut_path() -> Result<std::path::PathBuf, ToastError> {
    ensure_com();
    // SAFETY: SHGetKnownFolderPath returns a CoTaskMemAlloc'd string we free.
    unsafe {
        let p: PWSTR = SHGetKnownFolderPath(&FOLDERID_Programs, KF_FLAG_DEFAULT, None)?;
        let s = p.to_string();
        CoTaskMemFree(Some(p.0 as *const _));
        let s = s.map_err(|_| {
            ToastError(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        })?;
        Ok(std::path::PathBuf::from(s).join(SHORTCUT_NAME))
    }
}

/// Creates (or overwrites) the Start Menu shortcut to the current exe with the
/// AUMID. Installer step; never run by tests.
pub fn install_start_menu_shortcut() -> Result<std::path::PathBuf, ToastError> {
    let exe = std::env::current_exe().map_err(|_| {
        ToastError(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_FAIL,
        ))
    })?;
    let lnk = shortcut_path()?;
    let exe_w = HSTRING::from(exe.as_os_str());
    let lnk_w = HSTRING::from(lnk.as_os_str());
    let mut aumid: Vec<u16> = AUMID.encode_utf16().chain([0]).collect();
    // SAFETY: COM is initialized on this thread (`shortcut_path`); all interface
    // pointers are owned smart pointers. The PROPVARIANT borrows `aumid` (alive
    // across SetValue) and is wrapped in ManuallyDrop so PropVariantClear never
    // frees memory it does not own.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&exe_w)?;
        link.SetArguments(PCWSTR::null())?;
        let store: IPropertyStore = link.cast()?;
        let pv = std::mem::ManuallyDrop::new(PROPVARIANT {
            Anonymous: PROPVARIANT_0 {
                Anonymous: std::mem::ManuallyDrop::new(PROPVARIANT_0_0 {
                    vt: VT_LPWSTR,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: PROPVARIANT_0_0_0 {
                        pwszVal: PWSTR(aumid.as_mut_ptr()),
                    },
                }),
            },
        });
        store.SetValue(&PKEY_AppUserModel_ID, &*pv)?;
        store.Commit()?;
        let file: IPersistFile = link.cast()?;
        file.Save(&lnk_w, true)?;
    }
    Ok(lnk)
}

/// Removes the Start Menu shortcut (uninstall). No error if it does not exist.
pub fn remove_start_menu_shortcut() -> Result<(), ToastError> {
    let lnk = shortcut_path()?;
    match std::fs::remove_file(lnk) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(ToastError(
            windows::core::Error::from_hresult(windows::Win32::Foundation::E_FAIL),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn xml_escapes_and_has_actions() {
        let t = Toast {
            title: "Sent <ok> & \"done\"",
            body: "a'b\u{1}c",
            image: Some(Path::new(r"C:\Users\x\Pictures\shot 1.png")),
            id: Some("abc_-1"),
        };
        let x = build_xml(&t);
        assert!(
            x.contains("<text>Sent &lt;ok&gt; &amp; &quot;done&quot;</text>"),
            "{x}"
        );
        assert!(x.contains("<text>a&apos;bc</text>"), "{x}");
        assert!(
            x.contains("src=\"file:///C:/Users/x/Pictures/shot%201.png\""),
            "{x}"
        );
        assert!(x.contains("launch=\"action=open&amp;id=abc_-1\""), "{x}");
        assert!(
            x.contains("content=\"Open\" arguments=\"action=open&amp;id=abc_-1\""),
            "{x}"
        );
        assert!(
            x.contains("content=\"Show in folder\" arguments=\"action=folder&amp;id=abc_-1\""),
            "{x}"
        );
        assert!(!x.contains("protocol"), "no URL protocol activation");
    }

    #[test]
    fn minimal_toast_has_no_actions() {
        let x = build_xml(&Toast {
            title: "Hi",
            ..Default::default()
        });
        assert_eq!(
            x,
            "<toast><visual><binding template=\"ToastGeneric\"><text>Hi</text></binding></visual></toast>"
        );
    }

    /// Exercises WinRT (XmlDocument + ToastNotification) without showing anything.
    #[test]
    fn winrt_accepts_the_xml() {
        let t = Toast {
            title: "T",
            body: "B & <b>",
            image: Some(Path::new(r"C:\x y\ğ.png")),
            id: Some("id1"),
        };
        create(&t).unwrap();
    }
}
