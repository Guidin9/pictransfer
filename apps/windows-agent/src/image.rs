//! In-memory image conversions for the clipboard: packed DIB (`CF_DIB` /
//! `CF_DIBV5`) → PNG, and PNG → `CF_DIBV5`. Pure functions over untrusted
//! bytes: all offsets are checked, sizes are capped.
//!
//! PNG encoding uses `Filter::Sub` + `Compression::Fast` (Spike B: 84 ms for a
//! 4K screenshot vs 190 ms with the adaptive filter, +7 % size).

use std::{fmt, io::Cursor};

/// Largest image we convert (≈ 8K × 5K). Bounds the BGRA buffer to 160 MB.
pub const MAX_IMAGE_PIXELS: usize = 40_000_000;
/// Largest PNG we accept for decoding.
pub const MAX_PNG_BYTES: usize = 128 * 1024 * 1024;

const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;
const V5_HEADER: usize = 124;
const LCS_SRGB: u32 = 0x7352_4742; // 'sRGB'
const LCS_GM_IMAGES: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    /// Header or pixel data is shorter than the header claims.
    Truncated,
    /// Format we do not convert (bit depth, compression, header kind).
    Unsupported,
    /// Dimensions are zero, negative or above [`MAX_IMAGE_PIXELS`].
    BadDimensions,
    TooLarge,
    Encode,
    Decode,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ImageError::Truncated => "truncated image data",
            ImageError::Unsupported => "unsupported image format",
            ImageError::BadDimensions => "bad image dimensions",
            ImageError::TooLarge => "image too large",
            ImageError::Encode => "png encode failed",
            ImageError::Decode => "png decode failed",
        })
    }
}

impl std::error::Error for ImageError {}

fn u32_at(b: &[u8], at: usize) -> Result<u32, ImageError> {
    let end = at.checked_add(4).ok_or(ImageError::Truncated)?;
    let s: [u8; 4] = b
        .get(at..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(ImageError::Truncated)?;
    Ok(u32::from_le_bytes(s))
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, ImageError> {
    let end = at.checked_add(2).ok_or(ImageError::Truncated)?;
    let s: [u8; 2] = b
        .get(at..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(ImageError::Truncated)?;
    Ok(u16::from_le_bytes(s))
}

/// One channel of a BI_BITFIELDS pixel, scaled to 8 bits.
#[derive(Clone, Copy)]
struct Field {
    mask: u32,
    shift: u32,
    bits: u32,
}

impl Field {
    fn new(mask: u32) -> Field {
        Field {
            mask,
            shift: mask.trailing_zeros().min(31),
            bits: mask.count_ones(),
        }
    }

    fn get(self, px: u32) -> u8 {
        if self.bits == 0 {
            return 0;
        }
        let v = (px & self.mask) >> self.shift;
        let v = match self.bits {
            8 => v,
            b if b > 8 => v >> (b.saturating_sub(8)),
            // Scale up: v * 255 / (2^b - 1); v < 2^b ≤ 128 so nothing overflows.
            b => v
                .saturating_mul(255)
                .checked_div((1u32 << b).saturating_sub(1))
                .unwrap_or(0),
        };
        u8::try_from(v).unwrap_or(u8::MAX)
    }
}

/// Converts a packed DIB (BITMAPINFOHEADER / V4 / V5; 24 or 32 bpp; BI_RGB or
/// BI_BITFIELDS; bottom-up or top-down) to PNG.
///
/// 32 bpp BI_RGB is BGRX (alpha ignored, as Windows defines it). With a V4/V5
/// header and a non-zero alpha mask the alpha is kept, unless every pixel has
/// alpha 0 (screenshots often do), in which case the image is opaque.
pub fn dib_to_png(dib: &[u8]) -> Result<Vec<u8>, ImageError> {
    let hsize = usize::try_from(u32_at(dib, 0)?).map_err(|_| ImageError::Unsupported)?;
    if !matches!(hsize, 40 | 52 | 56 | 108 | 124) {
        return Err(ImageError::Unsupported);
    }
    let width = u32_at(dib, 4)? as i32;
    let height = u32_at(dib, 8)? as i32;
    let bpp = u16_at(dib, 14)?;
    let compression = u32_at(dib, 16)?;
    let clr_used = usize::try_from(u32_at(dib, 32)?).map_err(|_| ImageError::Unsupported)?;
    if width <= 0 || height == 0 || height == i32::MIN {
        return Err(ImageError::BadDimensions);
    }
    let w = usize::try_from(width).map_err(|_| ImageError::BadDimensions)?;
    let h = usize::try_from(height.unsigned_abs()).map_err(|_| ImageError::BadDimensions)?;
    if w.checked_mul(h).is_none_or(|p| p > MAX_IMAGE_PIXELS) {
        return Err(ImageError::BadDimensions);
    }
    let bytes_pp: usize = match (bpp, compression) {
        (24, BI_RGB) => 3,
        (32, BI_RGB | BI_BITFIELDS) => 4,
        _ => return Err(ImageError::Unsupported),
    };
    // Masks live at bytes 40..52 for every header kind (after a 40-byte header,
    // inside V2+ headers); the alpha mask at 52..56 exists from V3 (56 bytes) up.
    let (r, g, b, a) = if compression == BI_BITFIELDS {
        let a = if hsize >= 56 { u32_at(dib, 52)? } else { 0 };
        (
            Field::new(u32_at(dib, 40)?),
            Field::new(u32_at(dib, 44)?),
            Field::new(u32_at(dib, 48)?),
            Field::new(a),
        )
    } else {
        (
            Field::new(0x00ff_0000),
            Field::new(0x0000_ff00),
            Field::new(0x0000_00ff),
            Field::new(0),
        )
    };
    let masks_after_header = if compression == BI_BITFIELDS && hsize == 40 {
        12
    } else {
        0
    };
    let table = clr_used.checked_mul(4).ok_or(ImageError::Truncated)?;
    let offset = hsize
        .checked_add(masks_after_header)
        .and_then(|o| o.checked_add(table))
        .ok_or(ImageError::Truncated)?;
    let row_bytes = w.checked_mul(bytes_pp).ok_or(ImageError::TooLarge)?;
    let stride = row_bytes
        .div_ceil(4)
        .checked_mul(4)
        .ok_or(ImageError::TooLarge)?;
    let end = stride
        .checked_mul(h)
        .and_then(|n| n.checked_add(offset))
        .ok_or(ImageError::TooLarge)?;
    let px = dib.get(offset..end).ok_or(ImageError::Truncated)?;

    let has_alpha = a.bits > 0
        && px.chunks_exact(stride).any(|row| {
            row.get(..row_bytes).is_some_and(|r| {
                r.as_chunks::<4>()
                    .0
                    .iter()
                    .any(|p| a.get(u32::from_le_bytes(*p)) != 0)
            })
        });
    let channels = if has_alpha { 4 } else { 3 };
    let mut out = Vec::with_capacity(w.saturating_mul(h).saturating_mul(channels));
    let mut push_row = |row: &[u8]| -> Result<(), ImageError> {
        let row = row.get(..row_bytes).ok_or(ImageError::Truncated)?;
        for p in row.chunks_exact(bytes_pp) {
            match *p {
                [bb, gg, rr] => out.extend_from_slice(&[rr, gg, bb]),
                [p0, p1, p2, p3] => {
                    let v = u32::from_le_bytes([p0, p1, p2, p3]);
                    out.extend_from_slice(&[r.get(v), g.get(v), b.get(v)]);
                    if has_alpha {
                        out.push(a.get(v));
                    }
                }
                _ => return Err(ImageError::Truncated),
            }
        }
        Ok(())
    };
    if height > 0 {
        for row in px.chunks_exact(stride).rev() {
            push_row(row)?;
        }
    } else {
        for row in px.chunks_exact(stride) {
            push_row(row)?;
        }
    }
    let color = if has_alpha {
        png::ColorType::Rgba
    } else {
        png::ColorType::Rgb
    };
    encode_png(
        u32::try_from(w).unwrap_or(0),
        u32::try_from(h).unwrap_or(0),
        color,
        &out,
    )
}

/// Encodes 8-bit RGB or RGBA pixels as PNG (Sub filter, fast compression).
pub fn encode_png(
    w: u32,
    h: u32,
    color: png::ColorType,
    pixels: &[u8],
) -> Result<Vec<u8>, ImageError> {
    let mut out = Vec::with_capacity(pixels.len() / 8);
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(color);
    e.set_depth(png::BitDepth::Eight);
    e.set_compression(png::Compression::Fast);
    e.set_filter(png::Filter::Sub);
    let mut wr = e.write_header().map_err(|_| ImageError::Encode)?;
    wr.write_image_data(pixels)
        .map_err(|_| ImageError::Encode)?;
    wr.finish().map_err(|_| ImageError::Encode)?;
    Ok(out)
}

/// `true` if `b` starts with the PNG signature.
pub fn is_png(b: &[u8]) -> bool {
    b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
}

/// Decodes a PNG into a packed `CF_DIBV5`: BITMAPV5HEADER, 32 bpp BI_BITFIELDS
/// (BGRA masks inside the header), bottom-up, sRGB, straight alpha.
pub fn png_to_dibv5(png_bytes: &[u8]) -> Result<Vec<u8>, ImageError> {
    if png_bytes.len() > MAX_PNG_BYTES {
        return Err(ImageError::TooLarge);
    }
    if !is_png(png_bytes) {
        return Err(ImageError::Decode);
    }
    let limits = png::Limits {
        bytes: MAX_IMAGE_PIXELS.saturating_mul(4),
    };
    let mut dec = png::Decoder::new_with_limits(Cursor::new(png_bytes), limits);
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = dec.read_info().map_err(|_| ImageError::Decode)?;
    let (w, h) = {
        let info = reader.info();
        (info.width, info.height)
    };
    let (wu, hu) = (
        usize::try_from(w).map_err(|_| ImageError::BadDimensions)?,
        usize::try_from(h).map_err(|_| ImageError::BadDimensions)?,
    );
    if wu == 0 || hu == 0 || wu.checked_mul(hu).is_none_or(|p| p > MAX_IMAGE_PIXELS) {
        return Err(ImageError::BadDimensions);
    }
    let size = reader.output_buffer_size().ok_or(ImageError::TooLarge)?;
    let mut buf = vec![0u8; size];
    let frame = reader
        .next_frame(&mut buf)
        .map_err(|_| ImageError::Decode)?;
    let channels: usize = match frame.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err(ImageError::Unsupported),
    };
    if frame.bit_depth != png::BitDepth::Eight {
        return Err(ImageError::Unsupported);
    }
    let line = frame.line_size;
    let img_bytes = wu
        .checked_mul(hu)
        .and_then(|p| p.checked_mul(4))
        .ok_or(ImageError::TooLarge)?;
    let mut dib = Vec::with_capacity(V5_HEADER.saturating_add(img_bytes));
    let header: [u32; 30] = [
        V5_HEADER as u32,                                            // bV5Size
        w,                                                           // bV5Width
        h,              // bV5Height (positive: bottom-up)
        1 | (32 << 16), // bV5Planes = 1, bV5BitCount = 32
        BI_BITFIELDS,   // bV5Compression
        u32::try_from(img_bytes).map_err(|_| ImageError::TooLarge)?, // bV5SizeImage
        2835,           // bV5XPelsPerMeter (72 dpi)
        2835,           // bV5YPelsPerMeter
        0,              // bV5ClrUsed
        0,              // bV5ClrImportant
        0x00ff_0000,    // bV5RedMask
        0x0000_ff00,    // bV5GreenMask
        0x0000_00ff,    // bV5BlueMask
        0xff00_0000,    // bV5AlphaMask
        LCS_SRGB,       // bV5CSType
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0, // bV5Endpoints
        0,
        0,
        0,             // bV5GammaRed/Green/Blue
        LCS_GM_IMAGES, // bV5Intent
        0,             // bV5ProfileData
        0,             // bV5ProfileSize
    ];
    for v in header {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&0u32.to_le_bytes()); // bV5Reserved → 124 bytes total
    let rows = buf
        .get(..line.checked_mul(hu).ok_or(ImageError::TooLarge)?)
        .ok_or(ImageError::Truncated)?;
    for row in rows.chunks_exact(line).rev() {
        let row = row
            .get(..wu.saturating_mul(channels))
            .ok_or(ImageError::Truncated)?;
        for p in row.chunks_exact(channels) {
            let [r, g, b, a] = match *p {
                [y] => [y, y, y, 255],
                [y, a] => [y, y, y, a],
                [r, g, b] => [r, g, b, 255],
                [r, g, b, a] => [r, g, b, a],
                _ => return Err(ImageError::Truncated),
            };
            dib.extend_from_slice(&[b, g, r, a]);
        }
    }
    Ok(dib)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
pub(crate) mod tests {
    use super::*;

    /// Decodes a PNG to (w, h, color, pixels) for assertions.
    pub fn decode(png_bytes: &[u8]) -> (u32, u32, png::ColorType, Vec<u8>) {
        let mut r = png::Decoder::new(Cursor::new(png_bytes))
            .read_info()
            .unwrap();
        let mut buf = vec![0; r.output_buffer_size().unwrap()];
        let f = r.next_frame(&mut buf).unwrap();
        buf.truncate(f.buffer_size());
        (f.width, f.height, f.color_type, buf)
    }

    /// A 40-byte-header DIB with the given rows (top row first), `bpp` 24/32.
    fn info_dib(
        w: u32,
        rows: &[Vec<[u8; 4]>],
        bpp: u16,
        top_down: bool,
        bitfields: Option<[u32; 3]>,
    ) -> Vec<u8> {
        let h = rows.len() as i32;
        let mut d = Vec::new();
        d.extend_from_slice(&40u32.to_le_bytes());
        d.extend_from_slice(&w.to_le_bytes());
        d.extend_from_slice(&(if top_down { -h } else { h }).to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&bpp.to_le_bytes());
        d.extend_from_slice(
            &(if bitfields.is_some() {
                BI_BITFIELDS
            } else {
                BI_RGB
            })
            .to_le_bytes(),
        );
        d.extend_from_slice(&[0u8; 20]);
        if let Some(m) = bitfields {
            for v in m {
                d.extend_from_slice(&v.to_le_bytes());
            }
        }
        let order: Vec<&Vec<[u8; 4]>> = if top_down {
            rows.iter().collect()
        } else {
            rows.iter().rev().collect()
        };
        for row in order {
            let start = d.len();
            for p in row {
                d.extend_from_slice(&p[..usize::from(bpp / 8)]);
            }
            while (d.len() - start) % 4 != 0 {
                d.push(0);
            }
        }
        d
    }

    #[test]
    fn dib24_bottom_up_with_row_padding() {
        // 3×2, 24 bpp: rows need 1 byte of padding each.
        let rows = vec![
            vec![[0, 0, 255, 0], [0, 255, 0, 0], [255, 0, 0, 0]], // top: red, green, blue (BGR order)
            vec![[1, 2, 3, 0], [4, 5, 6, 0], [7, 8, 9, 0]],
        ];
        let png_bytes = dib_to_png(&info_dib(3, &rows, 24, false, None)).unwrap();
        let (w, h, c, px) = decode(&png_bytes);
        assert_eq!((w, h, c), (3, 2, png::ColorType::Rgb));
        assert_eq!(
            px,
            vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 3, 2, 1, 6, 5, 4, 9, 8, 7]
        );
    }

    #[test]
    fn dib32_top_down_bgrx_ignores_alpha_byte() {
        let rows = vec![vec![[10, 20, 30, 0], [40, 50, 60, 99]]];
        let png_bytes = dib_to_png(&info_dib(2, &rows, 32, true, None)).unwrap();
        let (_, _, c, px) = decode(&png_bytes);
        assert_eq!(c, png::ColorType::Rgb);
        assert_eq!(px, vec![30, 20, 10, 60, 50, 40]);
    }

    #[test]
    fn dib32_bitfields_after_info_header() {
        // Masks swapped to RGBX byte order: R in the low byte.
        let rows = vec![vec![[1, 2, 3, 0]]];
        let dib = info_dib(
            1,
            &rows,
            32,
            false,
            Some([0x0000_00ff, 0x0000_ff00, 0x00ff_0000]),
        );
        let (_, _, _, px) = decode(&dib_to_png(&dib).unwrap());
        assert_eq!(px, vec![1, 2, 3]);
    }

    #[test]
    fn dibv5_round_trip_keeps_alpha() {
        // RGBA 2×2 → PNG → DIBV5 → PNG.
        let rgba = vec![255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 9, 8, 7, 255];
        let png1 = encode_png(2, 2, png::ColorType::Rgba, &rgba).unwrap();
        let dib = png_to_dibv5(&png1).unwrap();
        assert_eq!(dib.len(), 124 + 16);
        assert_eq!(u32_at(&dib, 0).unwrap(), 124);
        assert_eq!(u32_at(&dib, 16).unwrap(), BI_BITFIELDS);
        // Bottom-up: first stored row is the bottom row (blue a=0, then 9,8,7).
        assert_eq!(&dib[124..132], &[255, 0, 0, 0, 7, 8, 9, 255]);
        let (w, h, c, px) = decode(&dib_to_png(&dib).unwrap());
        assert_eq!((w, h, c), (2, 2, png::ColorType::Rgba));
        assert_eq!(px, rgba);
    }

    #[test]
    fn dibv5_all_zero_alpha_is_opaque() {
        let rgb_as_rgba = vec![1, 2, 3, 0, 4, 5, 6, 0];
        let png1 = encode_png(2, 1, png::ColorType::Rgba, &rgb_as_rgba).unwrap();
        let dib = png_to_dibv5(&png1).unwrap();
        let (_, _, c, px) = decode(&dib_to_png(&dib).unwrap());
        assert_eq!(c, png::ColorType::Rgb);
        assert_eq!(px, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn gray_png_to_dibv5() {
        let png1 = encode_png(1, 1, png::ColorType::Rgb, &[7, 7, 7]).unwrap();
        let dib = png_to_dibv5(&png1).unwrap();
        assert_eq!(&dib[124..], &[7, 7, 7, 255]);
    }

    #[test]
    fn rejects_malformed_dibs() {
        let good = info_dib(2, &[vec![[1, 2, 3, 0], [4, 5, 6, 0]]], 32, false, None);
        // Truncated pixel data and header.
        assert_eq!(
            dib_to_png(&good[..good.len() - 1]),
            Err(ImageError::Truncated)
        );
        assert_eq!(dib_to_png(&good[..20]), Err(ImageError::Truncated));
        assert_eq!(dib_to_png(&[]), Err(ImageError::Truncated));
        // Unknown header size, unsupported bpp/compression.
        let mut bad = good.clone();
        bad[0] = 12;
        assert_eq!(dib_to_png(&bad), Err(ImageError::Unsupported));
        let mut bad = good.clone();
        bad[14] = 8;
        assert_eq!(dib_to_png(&bad), Err(ImageError::Unsupported));
        let mut bad = good.clone();
        bad[16] = 1; // BI_RLE8
        assert_eq!(dib_to_png(&bad), Err(ImageError::Unsupported));
        // Zero / negative width, zero height, huge dimensions.
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(dib_to_png(&bad), Err(ImageError::BadDimensions));
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&(-2i32).to_le_bytes());
        assert_eq!(dib_to_png(&bad), Err(ImageError::BadDimensions));
        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(dib_to_png(&bad), Err(ImageError::BadDimensions));
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&100_000u32.to_le_bytes());
        bad[8..12].copy_from_slice(&100_000u32.to_le_bytes());
        assert_eq!(dib_to_png(&bad), Err(ImageError::BadDimensions));
        // A colour table that runs past the data.
        let mut bad = good.clone();
        bad[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(dib_to_png(&bad).is_err());
    }

    #[test]
    fn rejects_bad_pngs() {
        assert_eq!(png_to_dibv5(b"not a png"), Err(ImageError::Decode));
        let png1 = encode_png(4, 4, png::ColorType::Rgb, &[0; 48]).unwrap();
        assert_eq!(
            png_to_dibv5(&png1[..png1.len() / 2]),
            Err(ImageError::Decode)
        );
    }

    #[test]
    fn bitfield_scaling() {
        assert_eq!(Field::new(0x1f).get(0x1f), 255); // 5-bit full scale
        assert_eq!(Field::new(0x1f).get(0), 0);
        assert_eq!(Field::new(0xffff_0000).get(0xabcd_0000), 0xab); // 16-bit → top 8
        assert_eq!(Field::new(0).get(0xffff_ffff), 0);
    }
}
