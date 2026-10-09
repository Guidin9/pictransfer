//! Clipboard read and write.
//!
//! Read priority: registered `PNG` format → `CF_DIBV5` / `CF_DIB` (converted to
//! PNG) → `CF_HDROP` (files) → `CF_UNICODETEXT`. Files rank above text because
//! a file copy in Explorer is the user's intent, while text next to an `HDROP`
//! would only be a path listing.
//!
//! Write: an image goes out as `PNG` **and** `CF_DIBV5` (Windows synthesizes
//! `CF_DIB`/`CF_BITMAP` from it, so Paint, Word and browsers paste it); files go
//! out as `CF_HDROP` plus `Preferred DropEffect = COPY` (Explorer pastes a copy).
//!
//! Every size is capped, and nothing here logs or formats clipboard content.
//! All functions must run on a thread that owns `hwnd` (the UI thread).

use std::{
    ffi::OsString,
    fmt, io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND},
    System::{
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
            OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
        },
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
        Ole::{CF_DIB, CF_DIBV5, CF_HDROP, CF_UNICODETEXT},
    },
    UI::Shell::DragQueryFileW,
};

use crate::{
    image::{self, ImageError},
    win::{last_error, wide},
};

/// Largest text we read or write (UTF-16 bytes).
pub const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
/// Largest number of files in one `CF_HDROP`.
pub const MAX_FILES: usize = 10_000;
/// Longest path (UTF-16 units) we accept, the Win32 long-path limit.
const MAX_PATH_UNITS: usize = 32_767;
/// Largest raw clipboard image we copy out (a 40 M-pixel 32 bpp DIB plus headers).
const MAX_RAW_IMAGE_BYTES: usize = image::MAX_IMAGE_PIXELS * 4 + 4096;
const DROPEFFECT_COPY: u32 = 1;

/// What the clipboard holds, in the agent's terms.
#[derive(Clone, PartialEq, Eq)]
pub enum ClipContent {
    Png(Vec<u8>),
    Text(String),
    Files(Vec<PathBuf>),
}

impl fmt::Debug for ClipContent {
    /// Kind and size only: clipboard content is never formatted (logging invariant).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipContent::Png(b) => write!(f, "Png({} bytes)", b.len()),
            ClipContent::Text(s) => write!(f, "Text({} bytes)", s.len()),
            ClipContent::Files(v) => write!(f, "Files({} items)", v.len()),
        }
    }
}

/// Kind of content available, checked without opening the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipKind {
    Png,
    Dib,
    Files,
    Text,
}

impl ClipKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClipKind::Png => "png",
            ClipKind::Dib => "dib",
            ClipKind::Files => "files",
            ClipKind::Text => "text",
        }
    }
}

#[derive(Debug)]
pub enum ClipError {
    /// Another application keeps the clipboard open.
    Busy,
    TooLarge,
    Image(ImageError),
    /// A path that is empty, relative, too long or contains NUL.
    InvalidPath,
    Os(io::Error),
}

impl fmt::Display for ClipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipError::Busy => f.write_str("clipboard busy"),
            ClipError::TooLarge => f.write_str("clipboard content too large"),
            ClipError::Image(e) => write!(f, "clipboard image: {e}"),
            ClipError::InvalidPath => f.write_str("invalid file path"),
            ClipError::Os(e) => write!(f, "clipboard: {e}"),
        }
    }
}

impl std::error::Error for ClipError {}

impl From<ImageError> for ClipError {
    fn from(e: ImageError) -> Self {
        ClipError::Image(e)
    }
}

fn png_format() -> u32 {
    let name = wide("PNG");
    // SAFETY: NUL-terminated name; registering an existing format returns its id.
    unsafe { RegisterClipboardFormatW(name.as_ptr()) }
}

fn drop_effect_format() -> u32 {
    let name = wide("Preferred DropEffect");
    // SAFETY: as above.
    unsafe { RegisterClipboardFormatW(name.as_ptr()) }
}

fn available(fmt: u32) -> bool {
    // SAFETY: no preconditions; works without opening the clipboard.
    fmt != 0 && unsafe { IsClipboardFormatAvailable(fmt) } != 0
}

/// The best available kind, without opening the clipboard or reading content.
pub fn available_kind() -> Option<ClipKind> {
    if available(png_format()) {
        Some(ClipKind::Png)
    } else if available(u32::from(CF_DIBV5)) || available(u32::from(CF_DIB)) {
        Some(ClipKind::Dib)
    } else if available(u32::from(CF_HDROP)) {
        Some(ClipKind::Files)
    } else if available(u32::from(CF_UNICODETEXT)) {
        Some(ClipKind::Text)
    } else {
        None
    }
}

/// An open clipboard; closed on drop.
struct Opened;

impl Opened {
    /// Opens the clipboard, retrying briefly if another app holds it (only on
    /// contention, a few ms — not idle polling).
    fn open(hwnd: HWND) -> Result<Opened, ClipError> {
        for attempt in 0..10u32 {
            // SAFETY: plain call; on success we own the open clipboard until drop.
            if unsafe { OpenClipboard(hwnd) } != 0 {
                return Ok(Opened);
            }
            if attempt < 9 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(ClipError::Busy)
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the clipboard was opened by this thread in `open`.
        unsafe { CloseClipboard() };
    }
}

/// Copies the bytes of a clipboard global (at most `cap`).
fn global_bytes(h: HANDLE, cap: usize) -> Result<Vec<u8>, ClipError> {
    // SAFETY: `h` is a clipboard-owned global handle valid while the clipboard is
    // open; it is locked only for the copy and its size comes from GlobalSize.
    unsafe {
        let size = GlobalSize(h);
        if size > cap {
            return Err(ClipError::TooLarge);
        }
        let p = GlobalLock(h) as *const u8;
        if p.is_null() {
            return Err(ClipError::Os(last_error()));
        }
        let v = std::slice::from_raw_parts(p, size).to_vec();
        GlobalUnlock(h);
        Ok(v)
    }
}

fn data(fmt: u32) -> Option<HANDLE> {
    if !available(fmt) {
        return None;
    }
    // SAFETY: the clipboard is open (callers hold `Opened`).
    let h = unsafe { GetClipboardData(fmt) };
    (!h.is_null()).then_some(h)
}

/// Reads the clipboard. `Ok(None)` when it holds nothing we handle.
pub fn read(hwnd: HWND) -> Result<Option<ClipContent>, ClipError> {
    let _open = Opened::open(hwnd)?;
    if let Some(h) = data(png_format()) {
        let bytes = global_bytes(h, image::MAX_PNG_BYTES)?;
        if image::is_png(&bytes) {
            return Ok(Some(ClipContent::Png(bytes)));
        }
        // A broken "PNG" entry: fall through to the DIB the app also offered.
    }
    for fmt in [CF_DIBV5, CF_DIB] {
        if let Some(h) = data(u32::from(fmt)) {
            let dib = global_bytes(h, MAX_RAW_IMAGE_BYTES)?;
            return Ok(Some(ClipContent::Png(image::dib_to_png(&dib)?)));
        }
    }
    if let Some(h) = data(u32::from(CF_HDROP)) {
        return Ok(Some(ClipContent::Files(hdrop_paths(h)?)));
    }
    if let Some(h) = data(u32::from(CF_UNICODETEXT)) {
        let bytes = global_bytes(h, MAX_TEXT_BYTES.saturating_add(2))?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        if end.saturating_mul(2) > MAX_TEXT_BYTES {
            return Err(ClipError::TooLarge);
        }
        return Ok(Some(ClipContent::Text(String::from_utf16_lossy(
            units.get(..end).unwrap_or(&[]),
        ))));
    }
    Ok(None)
}

/// Paths of an `HDROP` (wide or ANSI; the shell decodes both).
fn hdrop_paths(h: HANDLE) -> Result<Vec<PathBuf>, ClipError> {
    // SAFETY: `h` is an HDROP global; index 0xFFFFFFFF returns the count.
    let count = unsafe { DragQueryFileW(h, u32::MAX, std::ptr::null_mut(), 0) };
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    if count > MAX_FILES {
        return Err(ClipError::TooLarge);
    }
    let mut out = Vec::with_capacity(count);
    let mut buf: Vec<u16> = Vec::new();
    for i in 0..u32::try_from(count).unwrap_or(0) {
        // SAFETY: a null buffer asks for the length (without terminator).
        let len = usize::try_from(unsafe { DragQueryFileW(h, i, std::ptr::null_mut(), 0) })
            .unwrap_or(usize::MAX);
        if len == 0 || len > MAX_PATH_UNITS {
            return Err(ClipError::InvalidPath);
        }
        buf.clear();
        buf.resize(len.saturating_add(1), 0);
        let cap = u32::try_from(buf.len()).unwrap_or(0);
        // SAFETY: `buf` has room for `len` units plus the terminator; we pass its size.
        let got =
            usize::try_from(unsafe { DragQueryFileW(h, i, buf.as_mut_ptr(), cap) }).unwrap_or(0);
        let path = buf.get(..got.min(len)).ok_or(ClipError::InvalidPath)?;
        out.push(PathBuf::from(OsString::from_wide(path)));
    }
    Ok(out)
}

/// Builds a packed `DROPFILES` (wide) for `paths`. Paths must be absolute.
pub fn build_dropfiles(paths: &[PathBuf]) -> Result<Vec<u8>, ClipError> {
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err(if paths.is_empty() {
            ClipError::InvalidPath
        } else {
            ClipError::TooLarge
        });
    }
    // DROPFILES { pFiles: u32 = 20, pt: POINT = (0, 0), fNC: BOOL = 0, fWide: BOOL = 1 }
    let mut out = Vec::new();
    for v in [20u32, 0, 0, 0, 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for p in paths {
        let units: Vec<u16> = p.as_os_str().encode_wide().collect();
        if units.is_empty()
            || units.len() > MAX_PATH_UNITS
            || units.contains(&0)
            || !p.is_absolute()
        {
            return Err(ClipError::InvalidPath);
        }
        for u in units.into_iter().chain([0]) {
            out.extend_from_slice(&u.to_le_bytes());
        }
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

/// Allocates a movable global holding `bytes`.
fn alloc_global(bytes: &[u8]) -> Result<HGLOBAL, ClipError> {
    // SAFETY: allocation of `len` bytes (at least 1); we copy exactly `len` bytes
    // into the locked block and unlock it again.
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
        if h.is_null() {
            return Err(ClipError::Os(last_error()));
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            let e = last_error();
            GlobalFree(h);
            return Err(ClipError::Os(e));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(h);
        Ok(h)
    }
}

/// Puts `bytes` on the (open, emptied) clipboard as `fmt`.
fn set(fmt: u32, bytes: &[u8]) -> Result<(), ClipError> {
    let h = alloc_global(bytes)?;
    // SAFETY: the clipboard is open and owned by us; on success the system owns `h`,
    // on failure we still own it and free it.
    unsafe {
        if SetClipboardData(fmt, h).is_null() {
            let e = last_error();
            GlobalFree(h);
            return Err(ClipError::Os(e));
        }
    }
    Ok(())
}

/// Replaces the clipboard with `items`, prepared before the clipboard is opened.
fn replace(hwnd: HWND, items: &[(u32, &[u8])]) -> Result<(), ClipError> {
    let _open = Opened::open(hwnd)?;
    // SAFETY: the clipboard is open; EmptyClipboard makes `hwnd` its owner.
    if unsafe { EmptyClipboard() } == 0 {
        return Err(ClipError::Os(last_error()));
    }
    for (fmt, bytes) in items {
        set(*fmt, bytes)?;
    }
    Ok(())
}

/// Writes a PNG as `PNG` + `CF_DIBV5`.
pub fn write_png(hwnd: HWND, png: &[u8]) -> Result<(), ClipError> {
    let dib = image::png_to_dibv5(png)?;
    replace(hwnd, &[(png_format(), png), (u32::from(CF_DIBV5), &dib)])
}

/// Writes text as `CF_UNICODETEXT`.
pub fn write_text(hwnd: HWND, text: &str) -> Result<(), ClipError> {
    let mut bytes = Vec::with_capacity(text.len().saturating_mul(2).saturating_add(2));
    for u in text.encode_utf16().chain([0]) {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    if bytes.len() > MAX_TEXT_BYTES.saturating_add(2) {
        return Err(ClipError::TooLarge);
    }
    replace(hwnd, &[(u32::from(CF_UNICODETEXT), &bytes)])
}

/// Writes files as `CF_HDROP` with `Preferred DropEffect = COPY`.
pub fn write_files(hwnd: HWND, paths: &[PathBuf]) -> Result<(), ClipError> {
    let drop = build_dropfiles(paths)?;
    let effect = DROPEFFECT_COPY.to_le_bytes();
    replace(
        hwnd,
        &[
            (u32::from(CF_HDROP), &drop),
            (drop_effect_format(), &effect),
        ],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::win::test_window::TestWindow;

    /// Round-trips a DROPFILES block through the shell's own parser, in memory.
    #[test]
    fn dropfiles_round_trip_via_dragqueryfile() {
        let paths = vec![
            PathBuf::from(r"C:\Users\x\a b.png"),
            PathBuf::from(r"D:\ğüşİ\çö.txt"),
        ];
        let block = build_dropfiles(&paths).unwrap();
        let h = alloc_global(&block).unwrap();
        let got = hdrop_paths(h).unwrap();
        // SAFETY: we allocated `h` and nobody else owns it.
        unsafe { GlobalFree(h) };
        assert_eq!(got, paths);
    }

    #[test]
    fn dropfiles_rejects_bad_paths() {
        assert!(matches!(build_dropfiles(&[]), Err(ClipError::InvalidPath)));
        assert!(matches!(
            build_dropfiles(&[PathBuf::from("relative.txt")]),
            Err(ClipError::InvalidPath)
        ));
        assert!(matches!(
            build_dropfiles(&[PathBuf::from("C:\\a\0b")]),
            Err(ClipError::InvalidPath)
        ));
        let long = PathBuf::from(format!("C:\\{}", "a".repeat(MAX_PATH_UNITS)));
        assert!(matches!(
            build_dropfiles(&[long]),
            Err(ClipError::InvalidPath)
        ));
        let many = vec![PathBuf::from("C:\\a"); MAX_FILES + 1];
        assert!(matches!(build_dropfiles(&many), Err(ClipError::TooLarge)));
    }

    #[test]
    fn debug_never_shows_content() {
        let s = format!("{:?}", ClipContent::Text("secret".into()));
        assert!(!s.contains("secret"), "{s}");
        let s = format!(
            "{:?}",
            ClipContent::Files(vec![PathBuf::from("C:\\secret")])
        );
        assert!(!s.contains("secret"), "{s}");
    }

    /// Writes the real clipboard: only with WARPSHOT_CLIPBOARD_TESTS=1.
    /// One test function so the steps cannot race each other.
    #[test]
    fn real_clipboard_write_read() {
        if std::env::var("WARPSHOT_CLIPBOARD_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: set WARPSHOT_CLIPBOARD_TESTS=1 (overwrites the clipboard)");
            return;
        }
        let w = TestWindow::new();
        let png =
            image::encode_png(2, 1, png::ColorType::Rgba, &[1, 2, 3, 255, 4, 5, 6, 128]).unwrap();
        write_png(w.0, &png).unwrap();
        assert_eq!(available_kind(), Some(ClipKind::Png));
        assert_eq!(read(w.0).unwrap(), Some(ClipContent::Png(png.clone())));
        assert!(
            available(u32::from(CF_DIB)),
            "Windows synthesizes CF_DIB from CF_DIBV5"
        );

        write_text(w.0, "merhaba dünya ✓").unwrap();
        assert_eq!(available_kind(), Some(ClipKind::Text));
        assert_eq!(
            read(w.0).unwrap(),
            Some(ClipContent::Text("merhaba dünya ✓".into()))
        );

        let files = vec![std::env::current_exe().unwrap()];
        write_files(w.0, &files).unwrap();
        assert_eq!(available_kind(), Some(ClipKind::Files));
        assert_eq!(read(w.0).unwrap(), Some(ClipContent::Files(files)));
    }
}
