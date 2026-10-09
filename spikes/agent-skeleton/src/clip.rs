//! Clipboard image read (registered "PNG" format, else CF_DIBV5/CF_DIB → PNG).
//! Read-only: the spike never writes the user's clipboard.

use std::time::Instant;

use windows_sys::Win32::{
    Foundation::HWND,
    System::{
        DataExchange::{CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW},
        Memory::{GlobalLock, GlobalSize, GlobalUnlock},
        Ole::{CF_DIB, CF_DIBV5},
    },
};

pub enum Source {
    Png,
    Dib,
}

/// Returns PNG bytes for the image on the clipboard, if any.
pub fn read_png(hwnd: HWND) -> Option<(Source, Vec<u8>)> {
    let png_fmt: Vec<u16> = "PNG\0".encode_utf16().collect();
    // SAFETY: clipboard is opened/closed in this scope; the global handle is locked
    // only while copying and its size comes from GlobalSize.
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return None;
        }
        let png_id = RegisterClipboardFormatW(png_fmt.as_ptr());
        let mut out = None;
        for (fmt, src) in [(png_id, 0u8), (CF_DIBV5 as u32, 1), (CF_DIB as u32, 1)] {
            if IsClipboardFormatAvailable(fmt) == 0 {
                continue;
            }
            let h = GetClipboardData(fmt);
            if h.is_null() {
                continue;
            }
            let p = GlobalLock(h) as *const u8;
            if p.is_null() {
                continue;
            }
            let bytes = std::slice::from_raw_parts(p, GlobalSize(h)).to_vec();
            GlobalUnlock(h);
            out = if src == 0 { Some((Source::Png, bytes)) } else { dib_to_png(&bytes).map(|b| (Source::Dib, b)) };
            break;
        }
        CloseClipboard();
        out
    }
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Converts a packed DIB (BITMAPINFOHEADER or BITMAPV5HEADER, 24/32 bpp, BI_RGB or
/// BI_BITFIELDS) to PNG. 32 bpp is treated as BGRX (screenshot alpha is unreliable).
pub fn dib_to_png(dib: &[u8]) -> Option<Vec<u8>> {
    let hsize = u32le(dib, 0)? as usize;
    let width = u32le(dib, 4)? as i32;
    let height = u32le(dib, 8)? as i32;
    let bpp = u16::from_le_bytes(dib.get(14..16)?.try_into().ok()?);
    let compression = u32le(dib, 16)?;
    if width <= 0 || height == 0 || !(bpp == 24 || bpp == 32) || !(compression == 0 || compression == 3) {
        return None;
    }
    let masks = if compression == 3 && hsize == 40 { 12 } else { 0 };
    let offset = hsize + masks;
    let (w, h) = (width as usize, height.unsigned_abs() as usize);
    let stride = (w * bpp as usize / 8).div_ceil(4) * 4;
    let px = dib.get(offset..offset.checked_add(stride.checked_mul(h)?)?)?;
    let bytes_pp = bpp as usize / 8;
    let mut rgb = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        let row = if height > 0 { h - 1 - y } else { y };
        let r = &px[row * stride..row * stride + w * bytes_pp];
        for p in r.chunks_exact(bytes_pp) {
            rgb.extend_from_slice(&[p[2], p[1], p[0]]);
        }
    }
    encode_rgb(w as u32, h as u32, &rgb)
}

pub fn encode_rgb(w: u32, h: u32, rgb: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(rgb.len() / 8);
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(png::ColorType::Rgb);
    e.set_depth(png::BitDepth::Eight);
    e.set_compression(match std::env::var("SPIKE_PNG").as_deref() {
        Ok("fastest") => png::Compression::Fastest,
        Ok("balanced") => png::Compression::Balanced,
        _ => png::Compression::Fast,
    });
    match std::env::var("SPIKE_FILTER").as_deref() {
        Ok("none") => e.set_filter(png::Filter::NoFilter),
        Ok("adaptive") => e.set_filter(png::Filter::Adaptive),
        Ok("up") => e.set_filter(png::Filter::Up),
        Ok("paeth") => e.set_filter(png::Filter::Paeth),
        // Spike B result: Sub is ~2.3x faster than Adaptive at +7 % size.
        _ => e.set_filter(png::Filter::Sub),
    }
    let mut wr = e.write_header().ok()?;
    wr.write_image_data(rgb).ok()?;
    wr.finish().ok()?;
    Some(out)
}

/// B3 benchmark on a synthetic 3840×2160 screenshot-like image (UI blocks,
/// gradients, text-like noise) held in memory as a bottom-up 32 bpp DIB.
pub fn bench() -> String {
    let (w, h) = (3840usize, 2160usize);
    let mut dib = Vec::with_capacity(40 + w * h * 4);
    for v in [40u32, w as u32, h as u32] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&32u16.to_le_bytes());
    dib.extend_from_slice(&[0u8; 24]);
    let mut seed = 0x2545F491u32;
    for y in 0..h {
        for x in 0..w {
            let (b, g, r) = if y < 48 {
                (40, 40, 48) // title bar
            } else if x < 300 {
                (250, 245, 240) // sidebar
            } else if (y / 22) % 3 == 0 && (x / 7) % 9 < 7 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let t = if seed & 3 == 0 { 30 } else { 255 }; // glyph-like pixels
                (t, t, t)
            } else {
                (255, (200 + x * 55 / w) as u8, (230 + y * 25 / h) as u8) // gradient
            };
            dib.extend_from_slice(&[b as u8, g as u8, r as u8, 0]);
        }
    }
    let t = Instant::now();
    let png = dib_to_png(&dib);
    let dib_ms = t.elapsed().as_secs_f64() * 1e3;
    let png = png.unwrap_or_default();
    let t = Instant::now();
    let copied = png.to_vec(); // PNG already on the clipboard: cost is one copy
    let png_ms = t.elapsed().as_secs_f64() * 1e3;
    format!(
        "{{\"b3_dib_encode_ms\":{dib_ms:.1},\"b3_png_present_ms\":{png_ms:.2},\"png_bytes\":{},\"dib_bytes\":{}}}",
        copied.len(),
        dib.len()
    )
}
