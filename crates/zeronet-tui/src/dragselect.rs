//! Rubber-band selection: hold the left button and drag over rows.
//!
//! Ticking rows one at a time is fine for two of them and tedious for twenty.
//! Dragging a box over a list is the gesture every file manager uses, and it
//! maps cleanly onto a TUI because a row is a full-width band: only the
//! *vertical* extent of the drag matters, so the box selects every row whose
//! line the drag passed through.
//!
//! A drag has to be distinguished from a click. The button going down does
//! not start a selection — moving [`DRAG_THRESHOLD`] rows away from the
//! origin does. Below that it is still a click, and releasing performs the
//! click as usual.

use ratatui::layout::Rect;

/// Rows the pointer must move before a press becomes a drag.
///
/// One row: enough that a click with a shaky hand is not reinterpreted, small
/// enough that the gesture feels immediate.
pub const DRAG_THRESHOLD: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DragSelect {
    /// Where the button went down.
    origin: (u16, u16),
    /// Where the pointer is now.
    current: (u16, u16),
    /// Whether the threshold has been crossed.
    active: bool,
    /// Whether the selection adds to what was already ticked.
    additive: bool,
}

impl DragSelect {
    /// Record a button press. Not yet a drag.
    pub fn press(x: u16, y: u16, additive: bool) -> Self {
        Self {
            origin: (x, y),
            current: (x, y),
            active: false,
            additive,
        }
    }

    /// Update for pointer movement, returning whether this is now a drag.
    pub fn moved(&mut self, x: u16, y: u16) -> bool {
        self.current = (x, y);
        if !self.active && self.origin.1.abs_diff(y) >= DRAG_THRESHOLD {
            self.active = true;
        }
        self.active
    }

    /// Whether the gesture has become a drag rather than a click.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether a modifier was held, meaning "add to the selection".
    pub fn is_additive(&self) -> bool {
        self.additive
    }

    pub fn origin(&self) -> (u16, u16) {
        self.origin
    }

    /// The rectangle the band covers, normalised so it is valid whichever
    /// direction the drag went.
    pub fn rect(&self) -> Rect {
        let (x0, y0) = self.origin;
        let (x1, y1) = self.current;
        let (left, right) = (x0.min(x1), x0.max(x1));
        let (top, bottom) = (y0.min(y1), y0.max(y1));
        Rect {
            x: left,
            y: top,
            width: right - left + 1,
            height: bottom - top + 1,
        }
    }

    /// The inclusive range of screen rows the drag covers.
    pub fn row_span(&self) -> (u16, u16) {
        let (_, y0) = self.origin;
        let (_, y1) = self.current;
        (y0.min(y1), y0.max(y1))
    }

    /// Whether a row at screen row `y` falls inside the band.
    pub fn covers_row(&self, y: u16) -> bool {
        let (top, bottom) = self.row_span();
        (top..=bottom).contains(&y)
    }
}

/// Which list rows a drag has swept over.
///
/// `first_row` is the screen row of list item zero, and rows are one line
/// tall. Returns indices into the *visible* list, clamped to `len`.
pub fn swept_indices(drag: &DragSelect, first_row: u16, len: usize) -> Vec<usize> {
    if !drag.is_active() || len == 0 {
        return Vec::new();
    }
    let (top, bottom) = drag.row_span();

    // Rows above the list contribute nothing; the band simply starts at the
    // first item.
    let start = top.saturating_sub(first_row) as usize;
    let end = bottom.saturating_sub(first_row) as usize;

    if bottom < first_row {
        return Vec::new();
    }
    (start..=end).filter(|i| *i < len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_press_alone_is_not_a_drag() {
        // Otherwise every click would clear and re-make the selection.
        let d = DragSelect::press(10, 5, false);
        assert!(!d.is_active());
        assert!(swept_indices(&d, 3, 20).is_empty());
    }

    #[test]
    fn moving_within_the_threshold_stays_a_click() {
        let mut d = DragSelect::press(10, 5, false);
        assert!(!d.moved(14, 5), "horizontal movement alone started a drag");
        assert!(!d.is_active());
    }

    #[test]
    fn moving_a_row_away_starts_the_drag() {
        let mut d = DragSelect::press(10, 5, false);
        assert!(d.moved(10, 6));
        assert!(d.is_active());
    }

    #[test]
    fn the_band_is_normalised_whichever_way_it_is_dragged() {
        let mut down = DragSelect::press(10, 5, false);
        down.moved(20, 9);

        let mut up = DragSelect::press(20, 9, false);
        up.moved(10, 5);

        assert_eq!(down.rect(), up.rect());
        assert_eq!(down.row_span(), up.row_span());

        let r = down.rect();
        assert_eq!((r.x, r.y), (10, 5));
        assert_eq!((r.width, r.height), (11, 5));
    }

    #[test]
    fn sweeping_selects_every_row_the_band_crossed() {
        // The list starts at screen row 3.
        let mut d = DragSelect::press(10, 4, false);
        d.moved(10, 7);
        assert_eq!(swept_indices(&d, 3, 20), vec![1, 2, 3, 4]);
    }

    #[test]
    fn sweeping_upwards_selects_the_same_rows() {
        let mut d = DragSelect::press(10, 7, false);
        d.moved(10, 4);
        assert_eq!(swept_indices(&d, 3, 20), vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_band_past_the_end_of_the_list_is_clamped() {
        let mut d = DragSelect::press(10, 4, false);
        d.moved(10, 40);
        let swept = swept_indices(&d, 3, 6);
        assert_eq!(swept, vec![1, 2, 3, 4, 5]);
        assert!(swept.iter().all(|i| *i < 6));
    }

    #[test]
    fn a_band_entirely_above_the_list_selects_nothing() {
        let mut d = DragSelect::press(10, 0, false);
        d.moved(10, 1);
        assert!(swept_indices(&d, 10, 20).is_empty());
    }

    #[test]
    fn a_band_starting_above_the_list_begins_at_the_first_row() {
        let mut d = DragSelect::press(10, 0, false);
        d.moved(10, 5);
        assert_eq!(swept_indices(&d, 3, 20), vec![0, 1, 2]);
    }

    #[test]
    fn covers_row_matches_the_span() {
        let mut d = DragSelect::press(10, 4, false);
        d.moved(10, 8);
        for y in 4..=8 {
            assert!(d.covers_row(y), "row {y} should be inside the band");
        }
        assert!(!d.covers_row(3));
        assert!(!d.covers_row(9));
    }

    #[test]
    fn the_additive_flag_is_carried_through() {
        // Ctrl-drag adds to a selection rather than replacing it.
        let plain = DragSelect::press(1, 1, false);
        let additive = DragSelect::press(1, 1, true);
        assert!(!plain.is_additive());
        assert!(additive.is_additive());
    }

    #[test]
    fn an_empty_list_sweeps_nothing() {
        let mut d = DragSelect::press(10, 4, false);
        d.moved(10, 20);
        assert!(swept_indices(&d, 3, 0).is_empty());
    }
}
