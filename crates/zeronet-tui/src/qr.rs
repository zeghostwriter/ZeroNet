//! QR codes: generating them for sharing, and reading them back from images.
//!
//! ## Rendering in a terminal
//!
//! A QR module must be square to scan reliably, and a terminal cell is about
//! twice as tall as it is wide. Two encodings handle that:
//!
//! * **Half-blocks** (`▀`, `▄`, `█`) pack two module rows into one cell,
//!   giving a square-ish code at one cell per module horizontally. This is
//!   the compact form and what most phone cameras handle happily.
//! * **Double-width** (`██`, two spaces) uses two cells per module. Wider,
//!   but it survives terminals whose block glyphs render with gaps.
//!
//! Both are drawn light-on-dark with a quiet zone, because scanners need the
//! four-module margin and the inverted-contrast convention that dark
//! terminals require.
//!
//! ## Reading
//!
//! `rqrr` locates and decodes codes in a decoded image, so a user can point
//! the app at a screenshot of a config and have it imported.

use image::GenericImageView;
use qrcode::{EcLevel, QrCode};

/// Quiet-zone width, in modules. The QR spec requires four.
const QUIET_ZONE: usize = 4;

/// How a code should be drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrStyle {
    /// One cell per module horizontally, two module-rows per cell.
    HalfBlock,
    /// Two cells per module. Wider but more robust.
    DoubleWidth,
}

/// A rendered QR code, ready to draw as lines of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedQr {
    pub lines: Vec<String>,
    /// Side length of the underlying code in modules, quiet zone included.
    pub modules: usize,
    pub width_cells: usize,
    pub height_cells: usize,
}

/// Encode `data` and render it for the terminal.
///
/// Error correction is chosen for the payload size: share links are long, and
/// forcing a high correction level on a long link pushes the code into a
/// version so dense it stops scanning from a screen.
pub fn render(data: &str, style: QrStyle) -> Result<RenderedQr, String> {
    if data.is_empty() {
        return Err("nothing to encode".into());
    }

    let code = QrCode::with_error_correction_level(data.as_bytes(), ec_level_for(data.len()))
        .map_err(|e| format!("cannot encode as a QR code: {e}"))?;

    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();

    let padded = width + QUIET_ZONE * 2;
    // `true` means dark; the quiet zone is light.
    let dark = |x: usize, y: usize| -> bool {
        if x < QUIET_ZONE || y < QUIET_ZONE || x >= QUIET_ZONE + width || y >= QUIET_ZONE + width {
            return false;
        }
        modules[(y - QUIET_ZONE) * width + (x - QUIET_ZONE)]
    };

    let lines = match style {
        QrStyle::HalfBlock => render_half_blocks(padded, &dark),
        QrStyle::DoubleWidth => render_double_width(padded, &dark),
    };

    let height_cells = lines.len();
    let width_cells = match style {
        QrStyle::HalfBlock => padded,
        QrStyle::DoubleWidth => padded * 2,
    };

    Ok(RenderedQr {
        lines,
        modules: padded,
        width_cells,
        height_cells,
    })
}

/// Pick the error-correction level a payload of this size can afford.
fn ec_level_for(len: usize) -> EcLevel {
    match len {
        0..=120 => EcLevel::Q,
        121..=350 => EcLevel::M,
        _ => EcLevel::L,
    }
}

/// Two module rows per text row, using upper/lower half blocks.
///
/// Drawn light-on-dark: a *dark* module becomes background and a *light*
/// module becomes a foreground block. On a dark terminal that produces the
/// contrast a scanner expects without the app having to paint a white card
/// behind the code.
fn render_half_blocks(size: usize, dark: &dyn Fn(usize, usize) -> bool) -> Vec<String> {
    let mut lines = Vec::with_capacity(size.div_ceil(2));
    for row in (0..size).step_by(2) {
        let mut line = String::with_capacity(size);
        for x in 0..size {
            let top_light = !dark(x, row);
            // An odd-height code has no lower row on the last line; treat the
            // missing row as quiet zone so the code stays valid.
            let bottom_light = if row + 1 < size {
                !dark(x, row + 1)
            } else {
                true
            };
            line.push(match (top_light, bottom_light) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
    }
    lines
}

/// One module per text row, two cells wide, so modules stay square.
fn render_double_width(size: usize, dark: &dyn Fn(usize, usize) -> bool) -> Vec<String> {
    (0..size)
        .map(|y| {
            let mut line = String::with_capacity(size * 2);
            for x in 0..size {
                line.push_str(if dark(x, y) { "  " } else { "██" });
            }
            line
        })
        .collect()
}

/// Everything decoded from one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Decoded payloads, in the order they were found.
    pub payloads: Vec<String>,
}

/// Decode every QR code in an image file.
///
/// Accepts any format the `image` crate can read — a screenshot, a photo of a
/// screen, a saved QR from another client.
pub fn scan_file(path: &std::path::Path) -> Result<ScanResult, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    scan_bytes(&bytes)
}

/// Decode every QR code in an encoded image.
pub fn scan_bytes(bytes: &[u8]) -> Result<ScanResult, String> {
    if bytes.is_empty() {
        return Err("image file is empty".into());
    }
    let image = image::load_from_memory(bytes).map_err(|e| format!("not a readable image: {e}"))?;
    scan_image(&image)
}

/// Decode every QR code in an already-decoded image.
pub fn scan_image(image: &image::DynamicImage) -> Result<ScanResult, String> {
    let (w, h) = image.dimensions();
    if w == 0 || h == 0 {
        return Err("image has no pixels".into());
    }

    let luma = image.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);

    let mut payloads = Vec::new();
    for grid in prepared.detect_grids() {
        // A grid that fails to decode is a damaged or partial code, not a
        // reason to abandon the others in the image.
        if let Ok((_meta, content)) = grid.decode() {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                payloads.push(trimmed);
            }
        }
    }

    if payloads.is_empty() {
        return Err("no readable QR code found in that image".into());
    }
    Ok(ScanResult { payloads })
}

/// Keep only the payloads that look like proxy share links.
///
/// A QR in the wild may hold a URL, a Wi-Fi credential, or anything else;
/// this is what separates "found a code" from "found a config".
pub fn config_payloads(result: &ScanResult) -> Vec<String> {
    result
        .payloads
        .iter()
        .filter(|p| looks_like_config(p))
        .cloned()
        .collect()
}

/// Whether a string is plausibly a proxy config.
pub fn looks_like_config(text: &str) -> bool {
    const SCHEMES: [&str; 8] = [
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "ssr://",
        "hysteria2://",
        "tuic://",
        "anytls://",
    ];
    let t = text.trim();
    SCHEMES.iter().any(|s| t.starts_with(s))
        // A subscription body, or a raw Xray config pasted as a QR.
        || t.starts_with('{') && t.contains("outbounds")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&type=tcp#AmneziaVPN";

    /// Re-render a QR as a black-and-white image so the decoder can read it.
    ///
    /// This is what makes the round-trip test meaningful: it proves the
    /// generated code is actually scannable, not merely that it was produced.
    fn qr_to_image(data: &str, scale: u32) -> image::DynamicImage {
        let code =
            QrCode::with_error_correction_level(data.as_bytes(), ec_level_for(data.len())).unwrap();
        let width = code.width();
        let colors = code.to_colors();
        let padded = width + QUIET_ZONE * 2;
        let size = padded as u32 * scale;

        let mut img = image::GrayImage::from_pixel(size, size, image::Luma([255u8]));
        for y in 0..width {
            for x in 0..width {
                if colors[y * width + x] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (x + QUIET_ZONE) as u32 * scale + dx;
                            let py = (y + QUIET_ZONE) as u32 * scale + dy;
                            img.put_pixel(px, py, image::Luma([0u8]));
                        }
                    }
                }
            }
        }
        image::DynamicImage::ImageLuma8(img)
    }

    #[test]
    fn a_generated_code_scans_back_to_the_original_link() {
        let image = qr_to_image(LINK, 4);
        let result = scan_image(&image).expect("generated QR should be readable");
        assert_eq!(result.payloads, vec![LINK.to_string()]);
    }

    #[test]
    fn a_scanned_link_parses_as_a_real_config() {
        // End to end: encode a share link, decode it, and feed it to the
        // parser the import path uses.
        let image = qr_to_image(LINK, 4);
        let result = scan_image(&image).unwrap();
        let configs = config_payloads(&result);
        assert_eq!(configs.len(), 1);

        let parsed = zero_config::parse_link(&configs[0]).expect("scanned link parses");
        assert_eq!(parsed.remark, "AmneziaVPN");
    }

    #[test]
    fn half_block_rendering_has_the_expected_shape() {
        let qr = render(LINK, QrStyle::HalfBlock).unwrap();
        // Two module rows per line, so height is half the module count.
        assert_eq!(qr.height_cells, qr.modules.div_ceil(2));
        assert_eq!(qr.width_cells, qr.modules);
        assert!(qr.lines.iter().all(|l| l.chars().count() == qr.modules));
    }

    #[test]
    fn double_width_rendering_keeps_modules_square() {
        let qr = render(LINK, QrStyle::DoubleWidth).unwrap();
        assert_eq!(qr.height_cells, qr.modules);
        assert_eq!(qr.width_cells, qr.modules * 2);
        assert!(qr.lines.iter().all(|l| l.chars().count() == qr.modules * 2));
    }

    #[test]
    fn the_quiet_zone_is_present_on_every_side() {
        // Scanners need four clear modules around the code. In the
        // light-on-dark rendering that means solid blocks, not blanks.
        let qr = render("hello", QrStyle::DoubleWidth).unwrap();
        let blocks_only = |line: &str| line.chars().all(|c| c == '█');

        for line in qr.lines.iter().take(QUIET_ZONE) {
            assert!(blocks_only(line), "top quiet zone broken: {line:?}");
        }
        for line in qr.lines.iter().rev().take(QUIET_ZONE) {
            assert!(blocks_only(line), "bottom quiet zone broken: {line:?}");
        }
        for line in &qr.lines {
            let chars: Vec<char> = line.chars().collect();
            assert!(chars[..QUIET_ZONE * 2].iter().all(|c| *c == '█'));
            assert!(chars[chars.len() - QUIET_ZONE * 2..]
                .iter()
                .all(|c| *c == '█'));
        }
    }

    #[test]
    fn error_correction_steps_down_as_payloads_grow() {
        // A long link at high correction would need a denser version than a
        // phone can read off a terminal.
        assert_eq!(ec_level_for(50), EcLevel::Q);
        assert_eq!(ec_level_for(200), EcLevel::M);
        assert_eq!(ec_level_for(900), EcLevel::L);
    }

    #[test]
    fn a_long_subscription_link_still_encodes() {
        let long: String =
            std::iter::repeat_n("vless://node-with-a-long-name@host:443#n\n", 20).collect();
        let qr = render(&long, QrStyle::HalfBlock).expect("long payload should encode");
        assert!(
            qr.modules > 40,
            "expected a higher QR version, got {}",
            qr.modules
        );
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(render("", QrStyle::HalfBlock).is_err());
    }

    #[test]
    fn scanning_a_non_image_explains_itself() {
        let err = scan_bytes(b"this is not an image").unwrap_err();
        assert!(err.contains("readable image"), "{err}");
        assert!(scan_bytes(&[]).unwrap_err().contains("empty"));
    }

    #[test]
    fn an_image_with_no_code_reports_that() {
        let blank = image::DynamicImage::ImageLuma8(image::GrayImage::from_pixel(
            120,
            120,
            image::Luma([255u8]),
        ));
        let err = scan_image(&blank).unwrap_err();
        assert!(err.contains("no readable QR"), "{err}");
    }

    #[test]
    fn scanning_reads_a_real_png_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "zeronet_qr_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("code.png");

        qr_to_image(LINK, 4).save(&path).expect("write png");
        let result = scan_file(&path).expect("read the png back");
        assert_eq!(result.payloads, vec![LINK.to_string()]);

        let missing = dir.join("nope.png");
        assert!(scan_file(&missing).unwrap_err().contains("cannot read"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_detection_accepts_every_supported_scheme() {
        for scheme in [
            "vless://x",
            "vmess://x",
            "trojan://x",
            "ss://x",
            "ssr://x",
            "hysteria2://x",
            "tuic://x",
            "anytls://x",
        ] {
            assert!(looks_like_config(scheme), "{scheme} rejected");
        }
        assert!(looks_like_config(r#"{"outbounds": []}"#));

        assert!(!looks_like_config("https://example.com"));
        assert!(!looks_like_config("WIFI:S:home;T:WPA;P:hunter2;;"));
        assert!(!looks_like_config(""));
    }

    #[test]
    fn config_payloads_filters_out_unrelated_codes() {
        let result = ScanResult {
            payloads: vec![
                "https://example.com".into(),
                LINK.into(),
                "plain text".into(),
            ],
        };
        assert_eq!(config_payloads(&result), vec![LINK.to_string()]);
    }
}
