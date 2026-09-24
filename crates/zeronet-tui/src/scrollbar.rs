//! A scrollbar the pointer can actually move.
//!
//! The painted bar and the hit targets are the same rectangle. `layout`
//! splits that column into the thumb and the track above and below it, so a
//! drag on the thumb never falls through to the rows behind it.
//!
//! Thumb height is `viewport / content`, never shorter than one row. Its top
//! maps linearly onto the scroll offset, which is what makes a grab at the
//! bottom of the bar land on the last line.

use ratatui::layout::Rect;

/// Which list a bar belongs to. The mouse handler uses this to pick the
/// offset it should change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollTarget {
    Profiles,
    Settings,
    Help,
}

/// Which part of the bar the pointer is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollPart {
    /// Empty track above the thumb. A click pages up.
    TrackUp,
    /// The thumb itself. A drag scrubs the offset.
    Thumb,
    /// Empty track below the thumb. A click pages down.
    TrackDown,
}

/// One hit region of a scrollbar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollHit {
    pub target: ScrollTarget,
    pub part: ScrollPart,
    pub rect: Rect,
}

/// Geometry shared by the paint and the gesture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollLayout {
    pub track: Rect,
    pub thumb: Rect,
    pub offset: usize,
    pub max_offset: usize,
    pub content: usize,
    pub viewport: usize,
}

/// Split `track` into a thumb and the gaps around it.
///
/// `offset` is the first visible line, `max_offset` the largest legal one,
/// `content` the full length and `viewport` how many lines are on screen.
/// Returns nothing when the content already fits, which is when no bar
/// should be drawn or clickable.
pub fn layout(
    track: Rect,
    offset: usize,
    max_offset: usize,
    content: usize,
    viewport: usize,
) -> Option<ScrollLayout> {
    if track.width == 0 || track.height < 2 || content <= viewport || max_offset == 0 {
        return None;
    }
    let span = track.height as usize;
    let thumb_h = ((span * viewport) / content).clamp(1, span.saturating_sub(1)) as u16;
    let travel = span - thumb_h as usize;
    let thumb_top = if travel == 0 {
        0
    } else {
        ((offset.min(max_offset) * travel) / max_offset).min(travel)
    };
    let thumb = Rect {
        x: track.x,
        y: track.y + thumb_top as u16,
        width: track.width,
        height: thumb_h,
    };
    Some(ScrollLayout {
        track,
        thumb,
        offset,
        max_offset,
        content,
        viewport,
    })
}

/// The clickable pieces of a laid-out bar.
pub fn hits(target: ScrollTarget, layout: ScrollLayout) -> Vec<ScrollHit> {
    let mut out = Vec::with_capacity(3);
    let above = layout.thumb.y.saturating_sub(layout.track.y);
    if above > 0 {
        out.push(ScrollHit {
            target,
            part: ScrollPart::TrackUp,
            rect: Rect {
                x: layout.track.x,
                y: layout.track.y,
                width: layout.track.width,
                height: above,
            },
        });
    }
    out.push(ScrollHit {
        target,
        part: ScrollPart::Thumb,
        rect: layout.thumb,
    });
    let below_y = layout.thumb.y + layout.thumb.height;
    let track_bottom = layout.track.y + layout.track.height;
    if below_y < track_bottom {
        out.push(ScrollHit {
            target,
            part: ScrollPart::TrackDown,
            rect: Rect {
                x: layout.track.x,
                y: below_y,
                width: layout.track.width,
                height: track_bottom - below_y,
            },
        });
    }
    out
}

/// Map a pointer row to a scroll offset while a thumb is being dragged.
///
/// `grab` is how many rows into the thumb the press landed, so the thumb does
/// not jump to put its top under the cursor.
pub fn offset_for_drag(
    pointer_y: u16,
    track: Rect,
    thumb_height: u16,
    grab: u16,
    max_offset: usize,
) -> usize {
    if max_offset == 0 || track.height <= thumb_height {
        return 0;
    }
    let travel = (track.height - thumb_height) as usize;
    let top = pointer_y
        .saturating_sub(grab)
        .saturating_sub(track.y)
        .min(travel as u16) as usize;
    (top * max_offset) / travel
}

/// A thumb drag in progress. Held by the app until the button is released,
/// so the rows underneath are never selected by the same gesture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThumbDrag {
    pub target: ScrollTarget,
    pub track: Rect,
    pub thumb_height: u16,
    /// Rows from the top of the thumb to where it was grabbed.
    pub grab: u16,
    pub max_offset: usize,
}

impl ThumbDrag {
    pub fn offset_at(&self, pointer_y: u16) -> usize {
        offset_for_drag(
            pointer_y,
            self.track,
            self.thumb_height,
            self.grab,
            self.max_offset,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track() -> Rect {
        Rect {
            x: 10,
            y: 2,
            width: 1,
            height: 10,
        }
    }

    #[test]
    fn nothing_is_drawn_when_the_content_fits() {
        assert!(layout(track(), 0, 0, 5, 10).is_none());
    }

    #[test]
    fn the_thumb_starts_at_the_top_and_ends_at_the_bottom() {
        let top = layout(track(), 0, 90, 100, 10).unwrap();
        assert_eq!(top.thumb.y, 2);
        let bottom = layout(track(), 90, 90, 100, 10).unwrap();
        assert_eq!(bottom.thumb.y + bottom.thumb.height, 12);
    }

    #[test]
    fn the_thumb_is_at_least_one_row_and_leaves_room_to_travel() {
        let laid = layout(track(), 50, 990, 1000, 10).unwrap();
        assert!(laid.thumb.height >= 1);
        assert!(laid.thumb.height < track().height);
    }

    #[test]
    fn hits_cover_the_track_without_overlapping() {
        let laid = layout(track(), 40, 90, 100, 10).unwrap();
        let parts = hits(ScrollTarget::Profiles, laid);
        assert!(parts.iter().any(|h| h.part == ScrollPart::Thumb));
        let mut covered = 0u16;
        for hit in &parts {
            covered += hit.rect.height;
            assert_eq!(hit.rect.x, 10);
        }
        assert_eq!(covered, track().height);
    }

    #[test]
    fn dragging_keeps_the_grab_point_under_the_pointer() {
        let laid = layout(track(), 0, 90, 100, 10).unwrap();
        let drag = ThumbDrag {
            target: ScrollTarget::Settings,
            track: laid.track,
            thumb_height: laid.thumb.height,
            grab: 0,
            max_offset: 90,
        };
        assert_eq!(drag.offset_at(laid.track.y), 0);
        assert_eq!(
            drag.offset_at(laid.track.y + laid.track.height - laid.thumb.height),
            90
        );
    }
}
