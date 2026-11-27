//! The key-decryption effect.
//!
//! A row of glyphs that churns like cipher text and then settles, left to
//! right, into the real characters. While the account is still being made the
//! row only churns; when the key is known, a bright front sweeps across it
//! and leaves the fingerprint behind it.
//!
//! Everything here is a pure function of `(template, tick, locked, seed)`, so
//! a frame can be tested, and so the Android app can draw the identical
//! sequence: `docs/` of the mobile app hold the same test vectors.
//!
//! Most of what churns is hex digits and marks from a few Unicode blocks;
//! about one in twenty-five is a Chinese character. Those are two columns
//! wide, so one takes the place of two cells and the row keeps its width.

/// Share, in percent, of churning cells that are Chinese characters.
pub const WIDE_PERCENT: u64 = 4;

/// Characters about keys, locks and codes; the ones the churn draws from.
const WIDE: &[char] = &[
    '密', '钥', '解', '码', '安', '全', '加', '锁', '数', '据', '匙', '令', '牌', '破', '译', '密',
];

/// Hex digits, most of the churn.
const HEX: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

/// Marks from Greek, mathematical operators, geometric shapes and blocks.
const MARKS: &[char] = &[
    'α', 'β', 'γ', 'δ', 'λ', 'μ', 'π', 'σ', 'φ', 'ψ', 'ω', '∑', '∏', '∂', '∇', '≈', '≠', '∞', '⊕',
    '⊗', '◆', '◇', '▲', '▽', '●', '○', '■', '□', '░', '▒', '▓', '¤', '§', '¶',
];

/// What a cell is doing this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A gap between groups; never churns.
    Gap,
    /// Settled on its real character.
    Locked,
    /// The one the decryption has reached: churning, and lit.
    Front,
    /// Churning, not yet reached.
    Churn,
    /// A Chinese character, two columns wide, churning.
    Wide,
}

/// One drawn cell. A [`Kind::Wide`] cell takes two columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub kind: Kind,
}

impl Cell {
    /// Columns this cell takes.
    pub fn width(&self) -> usize {
        if self.kind == Kind::Wide {
            2
        } else {
            1
        }
    }
}

/// A small, fixed mixing function (splitmix64 finaliser), so the same inputs
/// give the same glyph on every platform.
pub fn mix(seed: u64, index: u64, step: u64) -> u64 {
    let mut z =
        seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ step.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// How many ticks a churning cell keeps its glyph.
pub const STEP_TICKS: u64 = 2;

/// The glyph a churning cell shows at `tick`: hex about three times in five,
/// a mark about one in three, and a Chinese character [`WIDE_PERCENT`] percent
/// of the time when `allow_wide` (there is room for two columns).
fn churn(seed: u64, index: usize, tick: u64, allow_wide: bool) -> (char, bool) {
    let h = mix(seed, index as u64, tick / STEP_TICKS);
    if allow_wide && (h >> 40) % 100 < WIDE_PERCENT {
        return (WIDE[((h >> 8) as usize) % WIDE.len()], true);
    }
    let pick = ((h >> 8) as usize, (h >> 48) % 100);
    if pick.1 < 62 {
        (HEX[pick.0 % HEX.len()], false)
    } else {
        (MARKS[pick.0 % MARKS.len()], false)
    }
}

/// The row at `tick`.
///
/// `template` is the row as it will end up: a space is a gap that never
/// churns, anything else is a cell that settles on that character once the
/// front has passed it. `locked` is how many cells have settled, or `None`
/// while nothing is known yet; the cell at `locked` is the front.
pub fn frame(template: &[char], tick: u64, locked: Option<usize>, seed: u64) -> Vec<Cell> {
    // The front is the first real cell from `locked` on: a gap is stepped over.
    // With nothing known yet there is no front and nothing settles.
    let front = locked.and_then(|from| (from..template.len()).find(|i| template[*i] != ' '));
    let locked = locked.unwrap_or(0);
    let mut cells = Vec::with_capacity(template.len());
    let mut index = 0;
    while index < template.len() {
        let real = template[index];
        if real == ' ' {
            cells.push(Cell {
                ch: ' ',
                kind: Kind::Gap,
            });
            index += 1;
            continue;
        }
        if index < locked {
            cells.push(Cell {
                ch: real,
                kind: Kind::Locked,
            });
            index += 1;
            continue;
        }
        if Some(index) == front {
            let (ch, _) = churn(seed, index, tick, false);
            cells.push(Cell {
                ch,
                kind: Kind::Front,
            });
            index += 1;
            continue;
        }
        // Room for a two-column character: the next cell churns too.
        let room = template.get(index + 1).is_some_and(|next| *next != ' ');
        let (ch, wide) = churn(seed, index, tick, room);
        cells.push(Cell {
            ch,
            kind: if wide { Kind::Wide } else { Kind::Churn },
        });
        index += if wide { 2 } else { 1 };
    }
    cells
}

/// Ticks the front takes per cell when the key is revealed.
pub const REVEAL_TICKS_PER_CELL: u64 = 1;

/// How many cells have settled `elapsed` ticks after the reveal began, out of
/// `count` real cells.
pub fn settled(elapsed: u64, count: usize) -> usize {
    ((elapsed / REVEAL_TICKS_PER_CELL) as usize).min(count)
}

/// Ticks a reveal of `count` cells takes, plus a beat for the last one.
pub fn reveal_duration(count: usize) -> u64 {
    count as u64 * REVEAL_TICKS_PER_CELL + 6
}

/// A row as text, one character per cell, for tests and logs.
pub fn to_text(cells: &[Cell]) -> String {
    cells.iter().map(|cell| cell.ch).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Vec<char> {
        "3FA9 C0D1 7B42 E8A5".chars().collect()
    }

    /// Display columns of a row.
    fn columns(cells: &[Cell]) -> usize {
        cells.iter().map(Cell::width).sum()
    }

    #[test]
    fn a_row_keeps_its_width_however_many_wide_characters_it_draws() {
        let template = template();
        for tick in 0..400 {
            let cells = frame(&template, tick, None, 7);
            assert_eq!(columns(&cells), template.len(), "tick {tick}");
        }
    }

    #[test]
    fn gaps_never_churn_and_settled_cells_show_the_real_characters() {
        let template = template();
        let cells = frame(&template, 40, Some(9), 7);
        // Position 4 and 9 are the gaps; the first nine columns are settled.
        let text = to_text(&cells);
        assert!(text.starts_with("3FA9 C0D1"), "{text}");
        assert_eq!(cells[4].kind, Kind::Gap);
        // The front is the next real cell, lit, and everything after churns.
        assert_eq!(cells[10].kind, Kind::Front);
        assert!(cells[11..]
            .iter()
            .all(|cell| matches!(cell.kind, Kind::Churn | Kind::Wide | Kind::Gap)));
        // Fully settled once the front is past the end.
        let done = frame(&template, 99, Some(template.len()), 7);
        assert_eq!(to_text(&done), "3FA9 C0D1 7B42 E8A5");
        assert!(done
            .iter()
            .all(|c| matches!(c.kind, Kind::Locked | Kind::Gap)));
    }

    #[test]
    fn churn_is_deterministic_and_moves_with_time() {
        let template = template();
        let a = to_text(&frame(&template, 10, None, 1));
        assert_eq!(a, to_text(&frame(&template, 10, None, 1)));
        // The same glyph for a step, another the next one.
        assert_eq!(a, to_text(&frame(&template, 11, None, 1)));
        assert_ne!(a, to_text(&frame(&template, 12, None, 1)));
        // Another seed, another row.
        assert_ne!(a, to_text(&frame(&template, 10, None, 2)));
    }

    #[test]
    fn about_four_percent_of_the_churn_is_chinese() {
        let template: Vec<char> = "A".repeat(60).chars().collect();
        let (mut wide, mut all) = (0u64, 0u64);
        for tick in (0..6000).step_by(STEP_TICKS as usize) {
            for cell in frame(&template, tick, None, 99) {
                all += 1;
                if cell.kind == Kind::Wide {
                    wide += 1;
                    assert!(WIDE.contains(&cell.ch), "{}", cell.ch);
                }
            }
        }
        // A wide cell replaces two, so the rate of cells is a little under
        // the rate of rolls; it stays close to four in a hundred.
        let share = wide as f64 * 100.0 / all as f64;
        assert!((3.0..=5.0).contains(&share), "{share:.2}%");
    }

    #[test]
    fn the_glyphs_are_hex_and_marks_and_the_odd_chinese_character() {
        let template: Vec<char> = "A".repeat(40).chars().collect();
        let mut seen_mark = false;
        for tick in (0..400).step_by(2) {
            for cell in frame(&template, tick, None, 5) {
                match cell.kind {
                    Kind::Churn | Kind::Front => {
                        assert!(HEX.contains(&cell.ch) || MARKS.contains(&cell.ch));
                        seen_mark |= MARKS.contains(&cell.ch);
                    }
                    Kind::Wide => assert!(WIDE.contains(&cell.ch)),
                    _ => {}
                }
            }
        }
        assert!(seen_mark);
    }

    #[test]
    fn the_reveal_takes_a_known_time_and_settles_every_cell() {
        assert_eq!(settled(0, 32), 0);
        assert_eq!(settled(10, 32), 10);
        assert_eq!(settled(1000, 32), 32);
        assert!(reveal_duration(32) > 32);
    }

    /// Fixed outputs, the same ones the Android app's tests check, so the two
    /// draw the same sequence.
    #[test]
    fn the_shared_test_vectors() {
        assert_eq!(mix(1, 2, 3), 0x1915_f685_d2b0_e282);
        assert_eq!(
            to_text(&frame(&template(), 6, None, 42)),
            "1░π9 6C4C ▓05B 2F○B"
        );
        assert_eq!(
            to_text(&frame(&template(), 31, Some(7), 42)),
            "3FA9 C0∂F 3ψ76 αφπC"
        );
    }
}
