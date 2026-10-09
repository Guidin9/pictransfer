//! Global hotkey: parse/format (`Ctrl+Alt+Shift+S`), register on a window
//! (`WM_HOTKEY` arrives on that window's thread), and the AltGr conflict check.
//!
//! AltGr is Ctrl+Alt on Windows. A hotkey with Ctrl+Alt (and no Win) on a key
//! that produces a character with AltGr in the user's layout would steal that
//! character (e.g. Turkish Q: AltGr+Q = `@`). The check asks the layout itself
//! via `ToUnicodeEx` with flag 4 (keyboard state unchanged).

use std::{fmt, io};

use windows_sys::Win32::{
    Foundation::{ERROR_HOTKEY_ALREADY_REGISTERED, HWND},
    UI::{
        Input::KeyboardAndMouse::{
            GetKeyboardLayout, GetKeyboardLayoutList, HKL, HOT_KEY_MODIFIERS, KLF_NOTELLSHELL,
            LoadKeyboardLayoutW, MAPVK_VK_TO_VSC, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT,
            MOD_WIN, MapVirtualKeyExW, RegisterHotKey, ToUnicodeEx, UnloadKeyboardLayout,
            UnregisterHotKey, VK_CONTROL, VK_MENU, VK_SHIFT,
        },
        WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
    },
};

use crate::win::{last_error, wide};

/// The default send hotkey (architecture.md §8).
pub const DEFAULT_HOTKEY: &str = "Ctrl+Alt+Shift+S";

/// A modifier set plus one virtual key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hotkey {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub win: bool,
    /// Win32 virtual-key code.
    pub vk: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    UnknownKey(String),
    DuplicateModifier,
    MissingKey,
    MultipleKeys,
    /// Needs Ctrl, Alt or Win; Shift alone (or nothing) would hijack typing.
    NeedsModifier,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => f.write_str("empty hotkey"),
            ParseError::UnknownKey(k) => write!(f, "unknown key {k:?}"),
            ParseError::DuplicateModifier => f.write_str("duplicate modifier"),
            ParseError::MissingKey => f.write_str("missing key"),
            ParseError::MultipleKeys => f.write_str("more than one non-modifier key"),
            ParseError::NeedsModifier => f.write_str("needs Ctrl, Alt or Win"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Named keys (canonical spelling first, aliases after).
const NAMED: &[(&str, u16)] = &[
    ("Space", 0x20),
    ("Enter", 0x0D),
    ("Tab", 0x09),
    ("Esc", 0x1B),
    ("Escape", 0x1B),
    ("Backspace", 0x08),
    ("Insert", 0x2D),
    ("Delete", 0x2E),
    ("Del", 0x2E),
    ("Home", 0x24),
    ("End", 0x23),
    ("PageUp", 0x21),
    ("PageDown", 0x22),
    ("Left", 0x25),
    ("Up", 0x26),
    ("Right", 0x27),
    ("Down", 0x28),
    ("PrintScreen", 0x2C),
    ("Pause", 0x13),
];

fn key_from_name(name: &str) -> Option<u16> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.clone().next()) {
        let c = c.to_ascii_uppercase();
        if c.is_ascii_uppercase() || c.is_ascii_digit() {
            return Some(u16::from(c as u8));
        }
    }
    let upper = name.to_ascii_uppercase();
    if let Some(n) = upper.strip_prefix('F').and_then(|n| n.parse::<u16>().ok())
        && (1..=24).contains(&n)
    {
        // VK_F1 = 0x70 … VK_F24 = 0x87.
        return 0x6Fu16.checked_add(n);
    }
    NAMED
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, vk)| *vk)
}

fn key_name(vk: u16) -> String {
    match vk {
        0x30..=0x39 | 0x41..=0x5A => char::from(u8::try_from(vk).unwrap_or(b'?')).to_string(),
        0x70..=0x87 => format!("F{}", vk.saturating_sub(0x6F)),
        _ => NAMED
            .iter()
            .find(|(_, v)| *v == vk)
            .map_or_else(|| format!("VK{vk:#04X}"), |(n, _)| (*n).to_string()),
    }
}

impl Hotkey {
    /// Parses `Ctrl+Alt+Shift+S` style strings (case-insensitive; `Control`,
    /// `Win`/`Super`/`Meta` accepted).
    pub fn parse(s: &str) -> Result<Hotkey, ParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }
        let (mut ctrl, mut alt, mut shift, mut win) = (false, false, false, false);
        let mut vk = None;
        for part in s.split('+').map(str::trim) {
            let flag = match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => &mut ctrl,
                "alt" => &mut alt,
                "shift" => &mut shift,
                "win" | "super" | "meta" => &mut win,
                "" => return Err(ParseError::MissingKey),
                _ => {
                    if vk.is_some() {
                        return Err(ParseError::MultipleKeys);
                    }
                    vk = Some(
                        key_from_name(part)
                            .ok_or_else(|| ParseError::UnknownKey(part.to_string()))?,
                    );
                    continue;
                }
            };
            if *flag {
                return Err(ParseError::DuplicateModifier);
            }
            *flag = true;
        }
        let vk = vk.ok_or(ParseError::MissingKey)?;
        if !(ctrl || alt || win) {
            return Err(ParseError::NeedsModifier);
        }
        Ok(Hotkey {
            ctrl,
            alt,
            shift,
            win,
            vk,
        })
    }

    /// `RegisterHotKey` modifier flags (with `MOD_NOREPEAT`).
    pub fn modifiers(&self) -> HOT_KEY_MODIFIERS {
        let mut m = MOD_NOREPEAT;
        if self.ctrl {
            m |= MOD_CONTROL;
        }
        if self.alt {
            m |= MOD_ALT;
        }
        if self.shift {
            m |= MOD_SHIFT;
        }
        if self.win {
            m |= MOD_WIN;
        }
        m
    }

    /// Ctrl+Alt without Win is what AltGr sends.
    pub fn is_altgr_combo(&self) -> bool {
        self.ctrl && self.alt && !self.win
    }
}

impl fmt::Display for Hotkey {
    /// Canonical form: `Ctrl+Alt+Shift+Win+Key`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (on, name) in [
            (self.ctrl, "Ctrl+"),
            (self.alt, "Alt+"),
            (self.shift, "Shift+"),
            (self.win, "Win+"),
        ] {
            if on {
                f.write_str(name)?;
            }
        }
        f.write_str(&key_name(self.vk))
    }
}

#[derive(Debug)]
pub enum RegisterError {
    /// Another application owns this combination (show a toast, open the recorder).
    Taken,
    Os(io::Error),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterError::Taken => f.write_str("hotkey already registered by another application"),
            RegisterError::Os(e) => write!(f, "RegisterHotKey failed: {e}"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// Registers `hk` as hotkey `id` on `hwnd`. Must be called on the window's thread.
pub fn register(hwnd: HWND, id: i32, hk: &Hotkey) -> Result<(), RegisterError> {
    // SAFETY: plain Win32 call with a window handle owned by this thread.
    if unsafe { RegisterHotKey(hwnd, id, hk.modifiers(), u32::from(hk.vk)) } != 0 {
        return Ok(());
    }
    let e = last_error();
    if e.raw_os_error() == i32::try_from(ERROR_HOTKEY_ALREADY_REGISTERED).ok() {
        Err(RegisterError::Taken)
    } else {
        Err(RegisterError::Os(e))
    }
}

/// Unregisters hotkey `id` on `hwnd`. Returns `false` if it was not registered.
pub fn unregister(hwnd: HWND, id: i32) -> bool {
    // SAFETY: plain Win32 call.
    unsafe { UnregisterHotKey(hwnd, id) != 0 }
}

/// What AltGr+key yields on a layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltGrOutput {
    Char(String),
    DeadKey,
}

impl fmt::Display for AltGrOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AltGrOutput::Char(s) => f.write_str(s),
            AltGrOutput::DeadKey => f.write_str("<dead key>"),
        }
    }
}

/// AltGr conflict of `hk` on the layout `hkl`; `None` = no conflict.
pub fn altgr_conflict(hk: &Hotkey, hkl: HKL) -> Option<AltGrOutput> {
    if !hk.is_altgr_combo() {
        return None;
    }
    let mut ks = [0u8; 256];
    for vk in [
        Some(VK_CONTROL),
        Some(VK_MENU),
        hk.shift.then_some(VK_SHIFT),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(slot) = ks.get_mut(usize::from(vk)) {
            *slot = 0x80;
        }
    }
    let mut buf = [0u16; 8];
    // SAFETY: 256-byte key-state array and an 8-unit output buffer whose length we
    // pass; flag 4 leaves the kernel keyboard state (incl. dead keys) unchanged.
    let n = unsafe {
        let sc = MapVirtualKeyExW(u32::from(hk.vk), MAPVK_VK_TO_VSC, hkl);
        ToUnicodeEx(
            u32::from(hk.vk),
            sc,
            ks.as_ptr(),
            buf.as_mut_ptr(),
            8,
            4,
            hkl,
        )
    };
    match n {
        0 => None,
        n if n < 0 => Some(AltGrOutput::DeadKey),
        n => {
            let len = usize::try_from(n).unwrap_or(0).min(buf.len());
            let s = String::from_utf16_lossy(buf.get(..len).unwrap_or(&[]));
            // Control characters are not "typed" characters.
            if s.chars().all(char::is_control) {
                None
            } else {
                Some(AltGrOutput::Char(s))
            }
        }
    }
}

/// The layout the user is typing with: the foreground thread's, else ours.
pub fn current_layout() -> HKL {
    // SAFETY: plain queries; a null foreground window maps to thread 0 = this thread.
    unsafe {
        let fg = GetForegroundWindow();
        let tid = if fg.is_null() {
            0
        } else {
            GetWindowThreadProcessId(fg, std::ptr::null_mut())
        };
        GetKeyboardLayout(tid)
    }
}

/// AltGr conflict on the current layout.
pub fn altgr_conflict_current(hk: &Hotkey) -> Option<AltGrOutput> {
    altgr_conflict(hk, current_layout())
}

/// Installed keyboard layouts of this session.
pub fn installed_layouts() -> Vec<HKL> {
    let mut list = [std::ptr::null_mut(); 64];
    // SAFETY: buffer length passed matches the array.
    let n = unsafe { GetKeyboardLayoutList(64, list.as_mut_ptr()) };
    let n = usize::try_from(n).unwrap_or(0).min(list.len());
    list.get(..n).map(<[HKL]>::to_vec).unwrap_or_default()
}

/// AltGr conflicts on all installed layouts, as (layout id = low 32 bits of the HKL, output).
pub fn altgr_conflicts_installed(hk: &Hotkey) -> Vec<(u32, AltGrOutput)> {
    installed_layouts()
        .into_iter()
        .filter_map(|h| altgr_conflict(hk, h).map(|o| ((h as usize & 0xffff_ffff) as u32, o)))
        .collect()
}

/// AltGr conflict on a layout given by KLID (e.g. `"0000041F"` = Turkish Q).
/// A layout that is not installed is loaded with `KLF_NOTELLSHELL` and unloaded again.
pub fn altgr_conflict_for_klid(hk: &Hotkey, klid: &str) -> io::Result<Option<AltGrOutput>> {
    let before = installed_layouts();
    let w = wide(klid);
    // SAFETY: valid NUL-terminated KLID; KLF_NOTELLSHELL keeps the shell's list unchanged.
    let hkl = unsafe { LoadKeyboardLayoutW(w.as_ptr(), KLF_NOTELLSHELL) };
    if hkl.is_null() {
        return Err(last_error());
    }
    let out = altgr_conflict(hk, hkl);
    if !before.contains(&hkl) {
        // SAFETY: we loaded this layout ourselves above and it was not installed before.
        unsafe { UnloadKeyboardLayout(hkl) };
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::win::test_window::TestWindow;

    #[test]
    fn parse_and_format_round_trip() {
        let hk = Hotkey::parse("ctrl + alt+shift+s").unwrap();
        assert_eq!(
            hk,
            Hotkey {
                ctrl: true,
                alt: true,
                shift: true,
                win: false,
                vk: 0x53
            }
        );
        assert_eq!(hk.to_string(), "Ctrl+Alt+Shift+S");
        for s in [
            "Ctrl+Alt+Shift+S",
            "Win+F12",
            "Alt+PageDown",
            "Ctrl+Shift+5",
            "Ctrl+Win+Space",
            "Ctrl+F24",
        ] {
            assert_eq!(Hotkey::parse(s).unwrap().to_string(), s);
        }
        assert_eq!(
            Hotkey::parse("Shift+Control+Super+x").unwrap().to_string(),
            "Ctrl+Shift+Win+X"
        );
        assert_eq!(
            Hotkey::parse(DEFAULT_HOTKEY).unwrap().modifiers(),
            MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT
        );
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(Hotkey::parse(" "), Err(ParseError::Empty));
        assert_eq!(Hotkey::parse("Ctrl+Alt"), Err(ParseError::MissingKey));
        assert_eq!(Hotkey::parse("Ctrl++S"), Err(ParseError::MissingKey));
        assert_eq!(
            Hotkey::parse("Ctrl+Ctrl+S"),
            Err(ParseError::DuplicateModifier)
        );
        assert_eq!(Hotkey::parse("Ctrl+S+T"), Err(ParseError::MultipleKeys));
        assert_eq!(
            Hotkey::parse("Ctrl+Foo"),
            Err(ParseError::UnknownKey("Foo".into()))
        );
        assert_eq!(
            Hotkey::parse("Ctrl+F25"),
            Err(ParseError::UnknownKey("F25".into()))
        );
        assert_eq!(Hotkey::parse("Shift+S"), Err(ParseError::NeedsModifier));
        assert_eq!(Hotkey::parse("S"), Err(ParseError::NeedsModifier));
    }

    #[test]
    fn turkish_q_altgr_conflicts() {
        let q = Hotkey::parse("Ctrl+Alt+Q").unwrap();
        assert_eq!(
            altgr_conflict_for_klid(&q, "0000041F").unwrap(),
            Some(AltGrOutput::Char("@".into()))
        );
        let s = Hotkey::parse(DEFAULT_HOTKEY).unwrap();
        assert_eq!(altgr_conflict_for_klid(&s, "0000041F").unwrap(), None);
        // Not an AltGr combination at all.
        let w = Hotkey::parse("Ctrl+Alt+Win+Q").unwrap();
        assert_eq!(altgr_conflict_for_klid(&w, "0000041F").unwrap(), None);
    }

    #[test]
    fn us_layout_has_no_altgr_on_q() {
        let q = Hotkey::parse("Ctrl+Alt+Q").unwrap();
        assert_eq!(altgr_conflict_for_klid(&q, "00000409").unwrap(), None);
    }

    #[test]
    fn register_detects_taken_and_unregisters() {
        let w = TestWindow::new();
        let hk = Hotkey::parse("Ctrl+Alt+Shift+F23").unwrap();
        register(w.0, 1, &hk).unwrap();
        assert!(matches!(register(w.0, 2, &hk), Err(RegisterError::Taken)));
        assert!(unregister(w.0, 1));
        assert!(!unregister(w.0, 1));
        register(w.0, 3, &hk).unwrap();
        assert!(unregister(w.0, 3));
    }
}
