//! Text editing for the "My server" page: a cursor and a selection over a
//! `String`, driven by the keys a desktop text box answers to.
//!
//! How this works: the text lives where it always did (a `String` in the
//! form); [`Caret`] is only the position inside it. `cursor` is a byte offset
//! that always sits on a character boundary, and `anchor` is the other end of
//! the selection when one exists (the selection is the bytes between the two,
//! in either order). [`apply`] takes one key and edits the text and the caret
//! together, so the two cannot disagree.
//!
//! The keys, as in any GUI text box:
//!
//! | keys | does |
//! |---|---|
//! | `←` `→` `Home` `End` | move; with `Shift`, extend the selection |
//! | `Ctrl+←` `Ctrl+→` | move by word (add `Shift` to select) |
//! | `Ctrl+A` | select everything |
//! | `Ctrl+C` `Ctrl+X` | hand the selection back to be copied (and cut) |
//! | `Backspace` `Delete` | delete the selection, else one character |
//! | `Ctrl+W` `Ctrl+Backspace` | delete the word before the cursor |
//! | `Ctrl+K` | delete to the end of the line |
//! | `Ctrl+U` | clear the line |
//!
//! Typing or pasting over a selection replaces it. Nothing here allocates a
//! second copy of the text beyond the one edit being made, and nothing is
//! logged: the text may be a password.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Where the cursor is, and the far end of the selection if there is one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caret {
    /// Byte offset of the cursor; always on a character boundary.
    pub cursor: usize,
    /// The other end of the selection, when something is selected.
    pub anchor: Option<usize>,
}

/// What a key did, so the caller can redraw, copy, or let the key go on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// The key means nothing to a text box.
    Ignored,
    /// Only the cursor or the selection moved.
    Moved,
    /// The text changed.
    Changed,
    /// The person asked to copy this text (the selection).
    Copy(String),
    /// The person asked to cut: copy this, and it has been removed.
    Cut(String),
}

impl Caret {
    /// A cursor at the end of `text`, nothing selected: where focus lands.
    pub fn at_end(text: &str) -> Self {
        Self {
            cursor: text.len(),
            anchor: None,
        }
    }

    /// The selected range as `(start, end)`, if anything is selected.
    pub fn selection(&self) -> Option<(usize, usize)> {
        let anchor = self.anchor?;
        (anchor != self.cursor).then(|| (anchor.min(self.cursor), anchor.max(self.cursor)))
    }

    /// Whether everything in `text` is selected (and `text` is not empty).
    pub fn selects_all(&self, text: &str) -> bool {
        !text.is_empty() && self.selection() == Some((0, text.len()))
    }

    /// Select the whole of `text`, leaving the cursor at its end.
    pub fn select_all(&mut self, text: &str) {
        self.anchor = Some(0);
        self.cursor = text.len();
    }

    /// [`Self::clamp`] without dropping the selection: the caret stays valid
    /// for `text`, nothing else about it changes.
    pub fn clamp_to(&mut self, text: &str) {
        self.clamp_cursor(text);
    }

    /// Keep the caret valid after the text was changed from outside (a paste,
    /// a reset): back inside the text, on a boundary, nothing selected.
    pub fn clamp(&mut self, text: &str) {
        self.cursor = boundary_at_or_before(text, self.cursor.min(text.len()));
        self.anchor = None;
    }
}

fn boundary_at_or_before(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn previous_boundary(text: &str, at: usize) -> usize {
    text[..at].char_indices().next_back().map_or(0, |(i, _)| i)
}

fn next_boundary(text: &str, at: usize) -> usize {
    text[at..]
        .chars()
        .next()
        .map_or(text.len(), |c| at + c.len_utf8())
}

/// The start of the word before `at`: skip spaces and separators, then the
/// word itself. Separators are anything that is not a letter or digit, so a
/// path or an address moves a piece at a time.
fn word_start(text: &str, at: usize) -> usize {
    let mut i = at;
    let mut seen_word = false;
    while i > 0 {
        let prev = previous_boundary(text, i);
        let c = text[prev..i].chars().next().unwrap_or(' ');
        if c.is_alphanumeric() {
            seen_word = true;
        } else if seen_word {
            break;
        }
        i = prev;
    }
    i
}

/// The end of the word after `at`.
fn word_end(text: &str, at: usize) -> usize {
    let mut i = at;
    let mut seen_word = false;
    while i < text.len() {
        let next = next_boundary(text, i);
        let c = text[i..next].chars().next().unwrap_or(' ');
        if c.is_alphanumeric() {
            seen_word = true;
        } else if seen_word {
            break;
        }
        i = next;
    }
    i
}

fn delete_selection(text: &mut String, caret: &mut Caret) -> bool {
    match caret.selection() {
        Some((start, end)) => {
            text.replace_range(start..end, "");
            caret.cursor = start;
            caret.anchor = None;
            true
        }
        None => {
            caret.anchor = None;
            false
        }
    }
}

/// Put `inserted` at the cursor, replacing the selection, keeping the text at
/// most `max` bytes (what does not fit is dropped from the end of `inserted`).
pub fn insert(text: &mut String, caret: &mut Caret, inserted: &str, max: usize) {
    delete_selection(text, caret);
    let room = max.saturating_sub(text.len());
    let mut take = inserted.len().min(room);
    while take > 0 && !inserted.is_char_boundary(take) {
        take -= 1;
    }
    text.insert_str(caret.cursor, &inserted[..take]);
    caret.cursor += take;
}

/// Move the cursor to `to`, extending the selection when `extend`.
fn go(caret: &mut Caret, to: usize, extend: bool) {
    if extend {
        caret.anchor.get_or_insert(caret.cursor);
    } else {
        caret.anchor = None;
    }
    caret.cursor = to;
}

/// Apply one key to `text` at `caret`. `max` is the longest the text may get.
pub fn apply(text: &mut String, caret: &mut Caret, key: KeyEvent, max: usize) -> Edit {
    caret.clamp_cursor(text);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('a') | KeyCode::Char('A') if ctrl => {
            caret.select_all(text);
            Edit::Moved
        }
        KeyCode::Char('c') | KeyCode::Char('C') if ctrl => match caret.selection() {
            Some((start, end)) => Edit::Copy(text[start..end].to_string()),
            None => Edit::Ignored,
        },
        KeyCode::Char('x') | KeyCode::Char('X') if ctrl => match caret.selection() {
            Some((start, end)) => {
                let cut = text[start..end].to_string();
                delete_selection(text, caret);
                Edit::Cut(cut)
            }
            None => Edit::Ignored,
        },
        KeyCode::Char('u') | KeyCode::Char('U') if ctrl => {
            let changed = !text.is_empty();
            text.clear();
            *caret = Caret::default();
            if changed {
                Edit::Changed
            } else {
                Edit::Moved
            }
        }
        KeyCode::Char('k') | KeyCode::Char('K') if ctrl => {
            let had_selection = delete_selection(text, caret);
            let before = text.len();
            text.truncate(caret.cursor);
            if had_selection || before != text.len() {
                Edit::Changed
            } else {
                Edit::Moved
            }
        }
        KeyCode::Char('w') | KeyCode::Char('W') if ctrl => delete_word_back(text, caret),
        KeyCode::Backspace if ctrl || alt => delete_word_back(text, caret),
        KeyCode::Backspace => {
            if delete_selection(text, caret) {
                return Edit::Changed;
            }
            if caret.cursor == 0 {
                return Edit::Moved;
            }
            let start = previous_boundary(text, caret.cursor);
            text.replace_range(start..caret.cursor, "");
            caret.cursor = start;
            Edit::Changed
        }
        KeyCode::Delete => {
            if delete_selection(text, caret) {
                return Edit::Changed;
            }
            if caret.cursor >= text.len() {
                return Edit::Moved;
            }
            let end = next_boundary(text, caret.cursor);
            text.replace_range(caret.cursor..end, "");
            Edit::Changed
        }
        KeyCode::Left => {
            // With a selection and no Shift, Left collapses to its start.
            if let (Some((start, _)), false) = (caret.selection(), shift) {
                go(caret, start, false);
                return Edit::Moved;
            }
            let to = if ctrl {
                word_start(text, caret.cursor)
            } else {
                previous_boundary(text, caret.cursor)
            };
            go(caret, to, shift);
            Edit::Moved
        }
        KeyCode::Right => {
            if let (Some((_, end)), false) = (caret.selection(), shift) {
                go(caret, end, false);
                return Edit::Moved;
            }
            let to = if ctrl {
                word_end(text, caret.cursor)
            } else {
                next_boundary(text, caret.cursor)
            };
            go(caret, to, shift);
            Edit::Moved
        }
        KeyCode::Home => {
            go(caret, 0, shift);
            Edit::Moved
        }
        KeyCode::End => {
            go(caret, text.len(), shift);
            Edit::Moved
        }
        KeyCode::Char(c) if !ctrl && !alt => {
            let mut buffer = [0u8; 4];
            insert(text, caret, c.encode_utf8(&mut buffer), max);
            Edit::Changed
        }
        _ => Edit::Ignored,
    }
}

fn delete_word_back(text: &mut String, caret: &mut Caret) -> Edit {
    if delete_selection(text, caret) {
        return Edit::Changed;
    }
    let start = word_start(text, caret.cursor);
    if start == caret.cursor {
        return Edit::Moved;
    }
    text.replace_range(start..caret.cursor, "");
    caret.cursor = start;
    Edit::Changed
}

impl Caret {
    /// Pull a stale cursor back inside `text` before an edit uses it.
    fn clamp_cursor(&mut self, text: &str) {
        self.cursor = boundary_at_or_before(text, self.cursor.min(text.len()));
        if let Some(anchor) = self.anchor {
            self.anchor = Some(boundary_at_or_before(text, anchor.min(text.len())));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn plain(code: KeyCode) -> KeyEvent {
        press(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        press(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn typed(text: &mut String, caret: &mut Caret, input: &str) {
        for c in input.chars() {
            apply(text, caret, plain(KeyCode::Char(c)), 256);
        }
    }

    #[test]
    fn typing_inserts_at_the_cursor_and_moves_it() {
        let mut text = String::new();
        let mut caret = Caret::default();
        typed(&mut text, &mut caret, "abd");
        apply(&mut text, &mut caret, plain(KeyCode::Left), 256);
        typed(&mut text, &mut caret, "c");
        assert_eq!(text, "abcd");
        assert_eq!(caret.cursor, 3);
    }

    #[test]
    fn ctrl_a_selects_everything_and_typing_replaces_it() {
        let mut text = "203.0.113.7".to_string();
        let mut caret = Caret::at_end(&text);
        assert_eq!(apply(&mut text, &mut caret, ctrl('a'), 256), Edit::Moved);
        assert!(caret.selects_all(&text));
        typed(&mut text, &mut caret, "9");
        assert_eq!(text, "9", "the first key replaces the whole selection");
        assert_eq!(caret.selection(), None);
    }

    #[test]
    fn backspace_and_delete_remove_the_selection_whole() {
        let mut text = "hello world".to_string();
        let mut caret = Caret::at_end(&text);
        apply(&mut text, &mut caret, ctrl('a'), 256);
        assert_eq!(
            apply(&mut text, &mut caret, plain(KeyCode::Backspace), 256),
            Edit::Changed
        );
        assert_eq!(text, "");

        let mut text = "abcdef".to_string();
        let mut caret = Caret::default();
        for _ in 0..2 {
            apply(&mut text, &mut caret, plain(KeyCode::Right), 256);
        }
        for _ in 0..2 {
            apply(
                &mut text,
                &mut caret,
                press(KeyCode::Right, KeyModifiers::SHIFT),
                256,
            );
        }
        assert_eq!(caret.selection(), Some((2, 4)));
        apply(&mut text, &mut caret, plain(KeyCode::Delete), 256);
        assert_eq!(text, "abef");
        assert_eq!(caret.cursor, 2);
    }

    #[test]
    fn copy_and_cut_hand_back_the_selection() {
        let mut text = "secret value".to_string();
        let mut caret = Caret::at_end(&text);
        assert_eq!(
            apply(&mut text, &mut caret, ctrl('c'), 256),
            Edit::Ignored,
            "nothing selected, nothing to copy: the key goes on to the app"
        );
        apply(&mut text, &mut caret, ctrl('a'), 256);
        assert_eq!(
            apply(&mut text, &mut caret, ctrl('c'), 256),
            Edit::Copy("secret value".into())
        );
        assert_eq!(text, "secret value", "copy leaves the text alone");
        assert_eq!(
            apply(&mut text, &mut caret, ctrl('x'), 256),
            Edit::Cut("secret value".into())
        );
        assert_eq!(text, "");
    }

    #[test]
    fn words_move_and_delete_a_piece_at_a_time() {
        let mut text = "root@host.example.com".to_string();
        let mut caret = Caret::at_end(&text);
        apply(
            &mut text,
            &mut caret,
            press(KeyCode::Left, KeyModifiers::CONTROL),
            256,
        );
        assert_eq!(&text[caret.cursor..], "com");
        apply(&mut text, &mut caret, ctrl('w'), 256);
        assert_eq!(text, "root@host.example.com".replace("example.", ""));
        // Home / End and a selection by Shift+Home.
        apply(&mut text, &mut caret, plain(KeyCode::End), 256);
        apply(
            &mut text,
            &mut caret,
            press(KeyCode::Home, KeyModifiers::SHIFT),
            256,
        );
        assert!(caret.selects_all(&text));
    }

    #[test]
    fn kill_and_clear_lines() {
        let mut text = "abcdef".to_string();
        let mut caret = Caret::default();
        for _ in 0..3 {
            apply(&mut text, &mut caret, plain(KeyCode::Right), 256);
        }
        apply(&mut text, &mut caret, ctrl('k'), 256);
        assert_eq!(text, "abc");
        apply(&mut text, &mut caret, ctrl('u'), 256);
        assert_eq!(text, "");
        assert_eq!(caret, Caret::default());
    }

    #[test]
    fn multibyte_text_never_splits_a_character() {
        let mut text = "سرور۱".to_string();
        let mut caret = Caret::at_end(&text);
        apply(&mut text, &mut caret, plain(KeyCode::Left), 256);
        assert!(text.is_char_boundary(caret.cursor));
        apply(&mut text, &mut caret, plain(KeyCode::Backspace), 256);
        assert!(text.is_char_boundary(caret.cursor));
        assert_eq!(text.chars().count(), 4);
        apply(&mut text, &mut caret, ctrl('a'), 256);
        apply(&mut text, &mut caret, plain(KeyCode::Delete), 256);
        assert_eq!(text, "");
    }

    #[test]
    fn the_length_limit_keeps_whole_characters() {
        let mut text = String::new();
        let mut caret = Caret::default();
        insert(&mut text, &mut caret, "ééééé", 5);
        assert_eq!(
            text, "éé",
            "four bytes fit, a fifth would split a character"
        );
        insert(&mut text, &mut caret, "x", 5);
        assert_eq!(text, "ééx");
    }

    #[test]
    fn left_and_right_collapse_a_selection_to_its_ends() {
        let mut text = "abcdef".to_string();
        let mut caret = Caret::at_end(&text);
        apply(&mut text, &mut caret, ctrl('a'), 256);
        apply(&mut text, &mut caret, plain(KeyCode::Left), 256);
        assert_eq!((caret.cursor, caret.selection()), (0, None));
        apply(&mut text, &mut caret, ctrl('a'), 256);
        apply(&mut text, &mut caret, plain(KeyCode::Right), 256);
        assert_eq!((caret.cursor, caret.selection()), (6, None));
    }

    #[test]
    fn a_stale_caret_is_pulled_back_inside_the_text() {
        let mut text = "ab".to_string();
        let mut caret = Caret {
            cursor: 40,
            anchor: Some(30),
        };
        apply(&mut text, &mut caret, plain(KeyCode::Char('c')), 256);
        assert_eq!(text, "abc");
    }
}
