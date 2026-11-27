//! A small picture that stands for a WARP account's fingerprint.
//!
//! The fingerprint (`warp::fingerprint`) is a string nobody compares by eye;
//! this turns it into six-by-four mirrored blocks and a colour, so two
//! accounts in a list look different at a glance and the same account always
//! looks the same. The Android app draws the identical picture from the same
//! fingerprint (`ui/effects/Glyph.kt`), and the tests on both sides share
//! their vectors.

/// Columns and rows of the picture.
pub const COLUMNS: usize = 6;
pub const ROWS: usize = 4;

/// The picture: `rows[r]` has bit `c` set when the block in column `c` of row
/// `r` is filled, and it is mirrored, so column `c` and `5 - c` always agree.
/// `hue` is the colour, in degrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Glyph {
    pub rows: [u8; ROWS],
    pub hue: u16,
}

impl Glyph {
    /// The picture for a fingerprint, or `None` when it is not one (fewer
    /// than four hex digits).
    pub fn of(fingerprint: &str) -> Option<Self> {
        let digits: Vec<u8> = fingerprint
            .chars()
            .filter_map(|c| c.to_digit(16).map(|d| d as u8))
            .collect();
        if digits.len() < 8 {
            return None;
        }
        let word = |at: usize| -> u32 {
            digits[at..at + 4]
                .iter()
                .fold(0u32, |acc, d| acc << 4 | *d as u32)
        };
        let mut cells = word(0) & 0xFFF;
        if cells == 0 {
            // Every fingerprint gets a mark: a blank picture reads as missing.
            cells = 1 << 5 | 1 << 8;
        }
        let mut rows = [0u8; ROWS];
        for (r, row) in rows.iter_mut().enumerate() {
            for c in 0..COLUMNS / 2 {
                if cells >> (r * 3 + c) & 1 == 1 {
                    *row |= 1 << c | 1 << (COLUMNS - 1 - c);
                }
            }
        }
        Some(Self {
            rows,
            hue: (word(4) % 360) as u16,
        })
    }

    /// Whether the block at `column`, `row` is filled.
    pub fn filled(&self, column: usize, row: usize) -> bool {
        column < COLUMNS && row < ROWS && self.rows[row] >> column & 1 == 1
    }

    /// The picture as Braille, one character per two columns: three
    /// characters wide, one tall. Each block is a 2×1 patch of dots, so the
    /// rows of the picture are the four dot rows of the character.
    pub fn braille(&self) -> String {
        (0..COLUMNS / 2)
            .map(|pair| {
                let mut bits = 0u32;
                for row in 0..ROWS {
                    for side in 0..2 {
                        if self.filled(pair * 2 + side, row) {
                            bits |= braille_dot(side, row);
                        }
                    }
                }
                char::from_u32(0x2800 + bits).unwrap_or(' ')
            })
            .collect()
    }
}

/// The bit of a Braille character for the dot in `column` (0 or 1) and `row`
/// (0..4).
fn braille_dot(column: usize, row: usize) -> u32 {
    match (column, row) {
        (0, 0) => 0x01,
        (0, 1) => 0x02,
        (0, 2) => 0x04,
        (1, 0) => 0x08,
        (1, 1) => 0x10,
        (1, 2) => 0x20,
        (0, 3) => 0x40,
        _ => 0x80,
    }
}

/// An RGB colour for a hue, at a fixed lightness and saturation that read on
/// both dark and light backgrounds.
pub fn rgb_of_hue(hue: u16) -> (u8, u8, u8) {
    // HSL with s = 0.62, l = 0.58.
    let (s, l) = (0.62f32, 0.58f32);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let h = f32::from(hue % 360) / 60.0;
    let x = c * (1.0 - (h % 2.0 - 1.0).abs());
    let (r, g, b) = match h as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    let byte = |v: f32| ((v + m).clamp(0.0, 1.0) * 255.0).round() as u8;
    (byte(r), byte(g), byte(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "3FA9 C0D1 7B42 E8A5 0F1E 2D3C 4B5A 6978";

    #[test]
    fn a_fingerprint_always_gives_the_same_picture_and_others_give_others() {
        let a = Glyph::of(FINGERPRINT).unwrap();
        assert_eq!(a, Glyph::of(FINGERPRINT).unwrap());
        assert_eq!(a, Glyph::of(&FINGERPRINT.replace(' ', "")).unwrap());
        assert_eq!(a, Glyph::of(&FINGERPRINT.to_lowercase()).unwrap());
        assert_ne!(a, Glyph::of("3FA8 C0D1 7B42 E8A5").unwrap());
        assert_ne!(a, Glyph::of("3FA9 C0D2 7B42 E8A5").unwrap());
    }

    #[test]
    fn the_picture_is_mirrored_left_to_right() {
        for seed in 0..200u32 {
            let fingerprint = format!(
                "{:04X} {:04X}",
                seed.wrapping_mul(2654435761) >> 16,
                seed * 977
            );
            let glyph = Glyph::of(&fingerprint).unwrap();
            for row in 0..ROWS {
                for column in 0..COLUMNS {
                    assert_eq!(
                        glyph.filled(column, row),
                        glyph.filled(COLUMNS - 1 - column, row),
                        "{fingerprint}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_fingerprint_gives_an_empty_picture() {
        let glyph = Glyph::of("0000 0000").unwrap();
        assert!(glyph.rows.iter().any(|row| *row != 0));
        assert!(Glyph::of("").is_none());
        assert!(Glyph::of("zz").is_none());
        assert!(Glyph::of("3FA").is_none());
    }

    #[test]
    fn hue_is_a_valid_angle_and_the_colour_is_never_dull_or_extreme() {
        for hue in 0..360u16 {
            let (r, g, b) = rgb_of_hue(hue);
            let high = r.max(g).max(b) as i32;
            let low = r.min(g).min(b) as i32;
            assert!(high - low > 40, "hue {hue} is grey");
            assert!(high > 120 && low < 200, "hue {hue}: ({r}, {g}, {b})");
        }
    }

    #[test]
    fn braille_puts_each_block_on_its_own_dots() {
        let glyph = Glyph {
            rows: [0b100001, 0, 0, 0b100001],
            hue: 0,
        };
        // Columns 0 and 5, rows 0 and 3: the first and the last character.
        let first = char::from_u32(0x2800 + 0x01 + 0x40).unwrap();
        let last = char::from_u32(0x2800 + 0x08 + 0x80).unwrap();
        assert_eq!(glyph.braille(), format!("{first}\u{2800}{last}"));
    }

    /// Fixed outputs, the same ones the Android app's tests check.
    #[test]
    fn the_shared_test_vectors() {
        let glyph = Glyph::of(FINGERPRINT).unwrap();
        assert_eq!(glyph.rows, [0b100001, 0b101101, 0b011110, 0b111111]);
        assert_eq!(glyph.hue, 41);
        assert_eq!(rgb_of_hue(41), (214, 172, 81));
    }
}
