//! Received file names (protocol §8.6 step 3, threat model): the sender's name is
//! untrusted. The result is a single safe path component on Windows and Android.

/// Longest result in characters, leaving room for a " (999)" de-dup suffix
/// inside NTFS's 255-unit component limit.
pub const MAX_CHARS: usize = 200;

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn is_dropped(c: char) -> bool {
    c.is_control()
        || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        // Bidi formatting and zero-width characters can disguise an extension.
        || matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

fn is_reserved(stem: &str) -> bool {
    let upper = stem.trim_end_matches([' ', '.']).to_ascii_uppercase();
    // COM¹ etc. are also reserved on Windows.
    let upper = upper.replace(['¹', '²', '³'], "1");
    RESERVED.contains(&upper.as_str())
}

/// Sanitizes an untrusted name into one safe file-name component.
pub fn sanitize(name: &str, fallback: &str) -> String {
    // Keep only the last path component, whatever separator the sender used.
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = last.chars().filter(|c| !is_dropped(*c)).collect();
    // Windows strips trailing dots and spaces; leading/trailing whitespace is never intended.
    s = s.trim().trim_end_matches(['.', ' ']).to_string();
    if s.chars().all(|c| c == '.') {
        s.clear();
    }
    if s.chars().count() > MAX_CHARS {
        // Keep the extension when shortening.
        let (stem, ext) = split_ext(&s);
        let ext: String = ext.chars().take(16).collect();
        let keep = MAX_CHARS.saturating_sub(ext.chars().count());
        s = stem.chars().take(keep).collect::<String>() + &ext;
    }
    if s.is_empty() {
        s = fallback.to_string();
    }
    // Windows matches device names against the part before the FIRST dot.
    let first = s.split('.').next().unwrap_or("");
    if is_reserved(first) {
        s = format!("_{s}");
    }
    s
}

/// ("photo", ".png") — the extension includes the dot; dotfiles have no extension.
pub fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    }
}

/// First free name among `name`, `stem (1).ext`, `stem (2).ext`, …
pub fn dedupe(name: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    if !exists(name) {
        return Some(name.to_string());
    }
    let (stem, ext) = split_ext(name);
    (1..1000)
        .map(|i| format!("{stem} ({i}){ext}"))
        .find(|n| !exists(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_and_separators() {
        assert_eq!(
            sanitize("../../Windows/System32/evil.dll", "file"),
            "evil.dll"
        );
        assert_eq!(sanitize("..\\..\\boot.ini", "file"), "boot.ini");
        assert_eq!(sanitize("C:\\Users\\x\\a.txt", "file"), "a.txt");
        assert_eq!(sanitize("..", "file"), "file");
        assert_eq!(sanitize(".", "file"), "file");
        assert_eq!(sanitize("dir/", "file"), "file");
        assert_eq!(sanitize("", "file"), "file");
    }

    #[test]
    fn windows_reserved_and_streams() {
        assert_eq!(sanitize("CON", "f"), "_CON");
        assert_eq!(sanitize("con.txt", "f"), "_con.txt");
        assert_eq!(sanitize("LPT9.tar.gz", "f"), "_LPT9.tar.gz");
        assert_eq!(sanitize("CONSOLE.log", "f"), "CONSOLE.log");
        assert_eq!(sanitize("nul .png", "f"), "_nul .png");
        assert_eq!(sanitize("COM¹", "f"), "_COM¹");
        assert_eq!(
            sanitize("a.txt:Zone.Identifier", "f"),
            "a.txtZone.Identifier"
        );
        assert_eq!(sanitize("report.pdf. . .", "f"), "report.pdf");
        assert_eq!(sanitize("a<b>c|d?e*f\"g", "f"), "abcdefg");
    }

    #[test]
    fn control_and_spoofing_characters() {
        assert_eq!(sanitize("photo\u{202E}gpj.exe", "f"), "photogpj.exe");
        assert_eq!(sanitize("a\u{0}b\nc\u{7f}.txt", "f"), "abc.txt");
        assert_eq!(sanitize("in\u{200B}voice.pdf", "f"), "invoice.pdf");
        assert_eq!(
            sanitize("ekran görüntüsü 2026.png", "f"),
            "ekran görüntüsü 2026.png"
        );
    }

    #[test]
    fn length_keeps_extension() {
        let long = format!("{}.jpeg", "x".repeat(500));
        let s = sanitize(&long, "f");
        assert_eq!(s.chars().count(), MAX_CHARS);
        assert!(s.ends_with(".jpeg"));
    }

    #[test]
    fn dedupe_suffixes() {
        let taken = ["a.png", "a (1).png"];
        assert_eq!(
            dedupe("a.png", |n| taken.contains(&n)).as_deref(),
            Some("a (2).png")
        );
        assert_eq!(
            dedupe("b.png", |n| taken.contains(&n)).as_deref(),
            Some("b.png")
        );
        assert_eq!(dedupe(".env", |n| n == ".env").as_deref(), Some(".env (1)"));
        assert_eq!(dedupe("x", |_| true), None);
    }
}
