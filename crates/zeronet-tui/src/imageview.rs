//! Showing images inside the terminal.
//!
//! Used when a user points the app at a QR image: rather than reporting a
//! bare "scanned / not scanned", the picture itself is shown so they can see
//! whether they opened the file they meant, and whether the code is legible
//! at all.
//!
//! Terminals vary enormously in what they can draw: kitty, iTerm2 and sixel
//! each have their own graphics protocol, and everything else falls back to
//! Unicode half-blocks, which work anywhere with 256 colours.
//!
//! ## Why the protocol is not auto-detected by default
//!
//! `ratatui_image`'s `Picker::from_query_stdio` identifies the protocol by
//! writing a query escape sequence and reading the terminal's reply. That
//! handshake takes over stdin — it enables raw mode itself, reads, and
//! restores — and in practice it leaves the terminal in a state where the
//! application's own reader stops seeing `Ctrl`+letter control bytes.
//! The symptom is brutal and hard to trace: `Esc` and `F1` keep working while
//! every `Ctrl` shortcut silently does nothing.
//!
//! So the default is half-blocks with a fixed cell size, which needs no
//! handshake and renders a QR code perfectly legibly. Setting
//! `ZERONET_IMAGE_PROTOCOL=detect` opts into the query for users who want
//! sixel or kitty graphics and can live with the risk.

use image::DynamicImage;
use ratatui::layout::Rect;
use ratatui::Frame;
use ratatui_image::picker::{Picker, ProtocolType};
use ratatui_image::protocol::StatefulProtocol;
use ratatui_image::{Resize, StatefulImage};

/// Assumed terminal cell size in pixels, used when the protocol is not
/// queried. 8x16 is the classic console cell and gives half-blocks a correct
/// 1:2 aspect on essentially every terminal.
const DEFAULT_CELL_SIZE: (u16, u16) = (8, 16);

/// A decoded image plus whatever the terminal needs to draw it.
pub struct TerminalImage {
    /// Where the image came from, shown alongside it.
    pub label: String,
    pub width: u32,
    pub height: u32,
    protocol: StatefulProtocol,
}

impl std::fmt::Debug for TerminalImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `StatefulProtocol` is not Debug, and a dialog holding one has to be.
        f.debug_struct("TerminalImage")
            .field("label", &self.label)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// Terminal graphics capability, probed once.
pub struct ImageSupport {
    picker: Option<Picker>,
}

impl ImageSupport {
    /// Choose how images will be drawn.
    ///
    /// Defaults to half-blocks, which need no terminal handshake. Call this
    /// **before** entering raw mode: the opt-in detection path writes to
    /// stdout and reads the reply, and must not run alongside the frame loop.
    pub fn detect() -> Self {
        let wants_query = matches!(
            std::env::var("ZERONET_IMAGE_PROTOCOL").as_deref(),
            Ok("detect") | Ok("auto") | Ok("query")
        );

        let picker = if wants_query {
            // See the module docs: this can cost the application its Ctrl
            // key bindings, so it is never the default.
            Picker::from_query_stdio().ok().or_else(halfblocks_picker)
        } else {
            halfblocks_picker()
        };
        Self { picker }
    }

    /// A no-graphics stand-in, for tests and headless runs.
    pub fn unavailable() -> Self {
        Self { picker: None }
    }

    pub fn is_available(&self) -> bool {
        self.picker.is_some()
    }

    /// Describe what the terminal will use, for the settings screen.
    pub fn describe(&self) -> String {
        match &self.picker {
            Some(p) => format!("{:?}", p.protocol_type()).to_lowercase(),
            None => "unavailable".to_string(),
        }
    }

    /// Prepare an image for display.
    pub fn prepare(&self, image: DynamicImage, label: impl Into<String>) -> Option<TerminalImage> {
        let picker = self.picker.as_ref()?;
        let (width, height) = (image.width(), image.height());
        Some(TerminalImage {
            label: label.into(),
            width,
            height,
            protocol: picker.new_resize_protocol(image),
        })
    }

    /// Load and prepare an image file.
    pub fn load(&self, path: &std::path::Path) -> Result<TerminalImage, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let image =
            image::load_from_memory(&bytes).map_err(|e| format!("not a readable image: {e}"))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        self.prepare(image, name)
            .ok_or_else(|| "this terminal cannot display images".to_string())
    }
}

/// Half-blocks with a fixed cell size. `from_fontsize` alone still picks
/// iTerm2 when `TERM_PROGRAM` is set, which paints nothing in a test backend.
fn halfblocks_picker() -> Option<Picker> {
    let mut p = Picker::from_fontsize(DEFAULT_CELL_SIZE);
    p.set_protocol_type(ProtocolType::Halfblocks);
    Some(p)
}

/// Draw a prepared image, fitted to `area` without distorting it.
pub fn render(frame: &mut Frame, area: Rect, image: &mut TerminalImage) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    // `Fit` preserves the aspect ratio; a stretched QR code is a QR code that
    // no longer scans.
    let widget = StatefulImage::default().resize(Resize::Fit(None));
    frame.render_stateful_widget(widget, area, &mut image.protocol);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_image() -> DynamicImage {
        DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            64,
            32,
            image::Rgb([120, 40, 200]),
        ))
    }

    #[test]
    fn detection_defaults_to_half_blocks_without_touching_stdin() {
        // The default must never run the stdio query: that handshake breaks
        // the application's own key reading.
        std::env::remove_var("ZERONET_IMAGE_PROTOCOL");
        let support = ImageSupport::detect();
        assert!(support.is_available());
        assert_eq!(support.describe(), "halfblocks");
    }

    #[test]
    fn an_unavailable_terminal_prepares_nothing() {
        let support = ImageSupport::unavailable();
        assert!(!support.is_available());
        assert!(support.prepare(test_image(), "x").is_none());
        assert_eq!(support.describe(), "unavailable");
    }

    #[test]
    fn a_fontsize_picker_can_prepare_an_image() {
        // The fallback path, which is what a test or a pipe gets.
        let support = ImageSupport {
            picker: halfblocks_picker(),
        };
        assert!(support.is_available());

        let prepared = support.prepare(test_image(), "swatch.png").unwrap();
        assert_eq!(prepared.label, "swatch.png");
        assert_eq!((prepared.width, prepared.height), (64, 32));
    }

    #[test]
    fn loading_a_missing_or_invalid_file_explains_itself() {
        let support = ImageSupport {
            picker: halfblocks_picker(),
        };

        let missing = std::path::Path::new("/nonexistent/zeronet/nope.png");
        assert!(support.load(missing).unwrap_err().contains("cannot read"));

        let dir = std::env::temp_dir().join(format!(
            "zeronet_img_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bogus = dir.join("not-an-image.png");
        std::fs::write(&bogus, b"definitely not a png").unwrap();
        assert!(support.load(&bogus).unwrap_err().contains("readable image"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_png_round_trips_from_disk() {
        let support = ImageSupport {
            picker: halfblocks_picker(),
        };
        let dir = std::env::temp_dir().join(format!(
            "zeronet_img2_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("swatch.png");
        test_image().save(&path).unwrap();

        let loaded = support.load(&path).expect("loads");
        assert_eq!(loaded.label, "swatch.png");
        assert_eq!((loaded.width, loaded.height), (64, 32));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rendering_into_a_zero_sized_area_is_a_no_op() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let support = ImageSupport {
            picker: halfblocks_picker(),
        };
        let mut prepared = support.prepare(test_image(), "x").unwrap();
        let mut terminal = Terminal::new(TestBackend::new(20, 10)).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    Rect {
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                    },
                    &mut prepared,
                );
            })
            .unwrap();
    }

    #[test]
    fn an_image_renders_into_a_real_area() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let support = ImageSupport {
            picker: halfblocks_picker(),
        };
        let mut prepared = support.prepare(test_image(), "x").unwrap();
        let mut terminal = Terminal::new(TestBackend::new(40, 20)).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    Rect {
                        x: 2,
                        y: 1,
                        width: 20,
                        height: 10,
                    },
                    &mut prepared,
                );
            })
            .unwrap();

        // Half-blocks encode a pixel pair per cell as foreground and
        // background colour. A solid image therefore paints *spaces* with
        // matching colours — so the check is for colour, not glyphs.
        let buffer = terminal.backend().buffer();
        let painted: Vec<_> = (1..11)
            .flat_map(|y| (2..22).map(move |x| (x, y)))
            .filter(|(x, y)| buffer[(*x, *y)].bg == ratatui::style::Color::Rgb(120, 40, 200))
            .collect();
        assert!(!painted.is_empty(), "the image drew nothing into its area");
        // 64x32 px at an 8x16 cell is 8 cells across and 2 down.
        assert_eq!(painted.len(), 16, "unexpected footprint: {painted:?}");
    }
}
