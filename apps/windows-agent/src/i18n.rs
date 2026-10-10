//! User-facing text in the Windows display language: Turkish when the user's
//! UI language is Turkish, English otherwise (the settings window follows the
//! same rule). `WARPSHOT_LANG=en|tr` overrides it (tests, screenshots).
//!
//! Strings live next to their use as `(en, tr)` pairs: [`pick`] for plain
//! text, [`l10n!`] for formatted text.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
}

/// `LANG_TURKISH`, the primary language id in a `LANGID`.
const LANG_TURKISH: u16 = 0x1f;

pub fn lang() -> Lang {
    static LANG: OnceLock<Lang> = OnceLock::new();
    *LANG.get_or_init(|| match std::env::var("WARPSHOT_LANG").as_deref() {
        Ok("tr") => Lang::Tr,
        Ok("en") => Lang::En,
        _ => system(),
    })
}

fn system() -> Lang {
    // SAFETY: no arguments; returns the calling user's UI language id.
    let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
    if id & 0x3ff == LANG_TURKISH {
        Lang::Tr
    } else {
        Lang::En
    }
}

pub fn is_tr() -> bool {
    lang() == Lang::Tr
}

/// The text for the current language.
pub fn pick(en: &'static str, tr: &'static str) -> &'static str {
    if is_tr() { tr } else { en }
}

/// `format!` with an English and a Turkish template (same arguments).
#[macro_export]
macro_rules! l10n {
    ($en:literal, $tr:literal $(, $arg:expr)* $(,)?) => {
        if $crate::i18n::is_tr() {
            format!($tr $(, $arg)*)
        } else {
            format!($en $(, $arg)*)
        }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn picks_one_of_the_pair() {
        let s = super::pick("Sent", "Gönderildi");
        assert!(s == "Sent" || s == "Gönderildi");
        let n = 3;
        let f = l10n!("{} items", "{} öğe", n);
        assert!(f == "3 items" || f == "3 öğe");
    }
}
