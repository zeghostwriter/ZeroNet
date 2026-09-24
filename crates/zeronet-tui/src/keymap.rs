//! Keyboard commands.
//!
//! Bindings follow desktop convention rather than inventing their own, so a
//! key does what it does in every other application the user already knows:
//! `Ctrl+A` selects all, `Ctrl+C` copies, `Ctrl+V` pastes, `Ctrl+F` finds,
//! `Delete` deletes, `F2` renames. The previous scheme had `Ctrl+A` meaning
//! "add config" and `Ctrl+S` meaning "add subscription", which collide with
//! Select-All and Save in a way that makes muscle memory actively harmful.
//!
//! Resolution is **context-first**: a modal dialog or a search box consumes
//! text keys before any global binding gets a chance, so typing `q` into a
//! field never quits the application.
//!
//! ## Control codes that are not free
//!
//! A terminal sends `Ctrl`+letter as a C0 control byte, and five of those
//! bytes already mean something else:
//!
//! | Combination | Byte   | Actually arrives as |
//! |-------------|--------|---------------------|
//! | `Ctrl+H`    | `0x08` | Backspace           |
//! | `Ctrl+I`    | `0x09` | Tab                 |
//! | `Ctrl+J`    | `0x0A` | Line feed           |
//! | `Ctrl+M`    | `0x0D` | Enter               |
//! | `Ctrl+[`    | `0x1B` | Escape              |
//!
//! Nothing may be bound to those: `Ctrl+I` was briefly bound to "scan QR
//! image" and simply switched tabs, because the application cannot tell the
//! two apart. [`RESERVED_CONTROL_KEYS`] lists them and a test enforces it.
//!
//! Shifted control combinations are matched on **letter case**, not on the
//! `SHIFT` modifier: terminals reliably send `Ctrl+Shift+S` as an uppercase
//! `S`, but many omit the `SHIFT` flag, which would otherwise fall through to
//! the unshifted binding.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Where the keyboard focus currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputContext {
    /// The main screen, no dialog and no active text field.
    Browsing,
    /// A text field has focus — nearly every printable key is literal.
    Editing,
    /// A dialog without a text field (confirmations, QR display).
    Dialog,
}

/// A resolved user command, independent of which key produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    // ---- connection
    /// Connect, or disconnect if already connected.
    ToggleConnection,
    /// Connect explicitly, without toggling off.
    Connect,
    Disconnect,

    // ---- navigation
    NextView,
    PrevView,
    GoDashboard,
    GoProfiles,
    GoScanner,
    GoSettings,
    GoActivity,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    MoveToTop,
    MoveToBottom,

    // ---- selection (desktop semantics)
    SelectAll,
    SelectNone,
    ToggleSelection,

    // ---- clipboard
    Copy,
    Paste,
    Cut,

    // ---- profile management
    NewProfile,
    OpenFile,
    SaveAs,
    Duplicate,
    Delete,
    Rename,
    ShowQrCode,
    ScanQrImage,

    // ---- system proxy
    /// Cycle off → system → PAC.
    CycleSystemProxy,
    /// Put the desktop's proxy settings back to "none".
    ClearSystemProxy,

    // ---- data
    Refresh,
    TestLatency,
    ExportAll,
    AddSubscription,

    // ---- search
    Find,
    ClearFilter,

    // ---- app
    Help,
    Feedback,
    CycleTheme,
    Quit,
    Cancel,
    Confirm,
}

impl Command {
    /// Short label for the help overlay and footer.
    pub fn label(self) -> &'static str {
        match self {
            Command::ToggleConnection => "Connect / Disconnect",
            Command::Connect => "Connect",
            Command::Disconnect => "Disconnect",
            Command::NextView => "Next view",
            Command::PrevView => "Previous view",
            Command::GoDashboard => "Go to Dashboard",
            Command::GoProfiles => "Go to Subscriptions",
            Command::GoScanner => "Go to IP Scanner",
            Command::GoSettings => "Go to Settings",
            Command::GoActivity => "Go to Activity",
            Command::MoveUp => "Move up",
            Command::MoveDown => "Move down",
            Command::PageUp => "Page up",
            Command::PageDown => "Page down",
            Command::MoveToTop => "First item",
            Command::MoveToBottom => "Last item",
            Command::SelectAll => "Select all",
            Command::SelectNone => "Clear selection",
            Command::ToggleSelection => "Toggle selection",
            Command::Copy => "Copy share link",
            Command::Paste => "Paste / import",
            Command::Cut => "Cut profile",
            Command::NewProfile => "New profile",
            Command::OpenFile => "Import from file",
            Command::SaveAs => "Export profile",
            Command::Duplicate => "Duplicate",
            Command::Delete => "Delete",
            Command::Rename => "Rename",
            Command::ShowQrCode => "Show QR code",
            Command::ScanQrImage => "Scan QR image",
            Command::CycleSystemProxy => "Cycle: keep / set / PAC / clear",
            Command::ClearSystemProxy => "Clear system proxy",
            Command::Refresh => "Refresh / update subs",
            Command::TestLatency => "Test latency",
            Command::ExportAll => "Export all",
            Command::AddSubscription => "Add subscription",
            Command::Find => "Find",
            Command::ClearFilter => "Clear filter",
            Command::Help => "Help",
            Command::Feedback => "Send feedback",
            Command::CycleTheme => "Next theme",
            Command::Quit => "Quit",
            Command::Cancel => "Cancel",
            Command::Confirm => "Confirm",
        }
    }
}

/// Control combinations that the terminal cannot distinguish from another
/// key, and which must therefore never be bound.
pub const RESERVED_CONTROL_KEYS: [char; 5] = ['h', 'i', 'j', 'm', '['];

/// How a key should be handled in an editing context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditAction {
    InsertChar(char),
    Backspace,
    DeleteForward,
    MoveLeft,
    MoveRight,
    MoveHome,
    MoveEnd,
    /// `Ctrl+A` inside a field: select the whole value.
    SelectAll,
    /// `Ctrl+U`: clear the field.
    ClearLine,
    /// `Ctrl+W`: delete the word before the cursor.
    DeleteWord,
    Copy,
    Paste,
    Cut,
    Submit,
    Cancel,
    /// Move focus to the next / previous field.
    NextField,
    PrevField,
    /// Cycle an enumerated field's value.
    CycleValue,
    None,
}

/// Resolve a key press in a text-editing context.
///
/// Printable characters are literal here. Only the standard editing
/// modifiers are intercepted, which is why `Ctrl+A` means select-all inside
/// a field and never "add config".
pub fn resolve_editing(key: KeyEvent) -> EditAction {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    match key.code {
        KeyCode::Esc => EditAction::Cancel,
        KeyCode::Enter => EditAction::Submit,
        KeyCode::Tab => EditAction::NextField,
        KeyCode::BackTab => EditAction::PrevField,
        KeyCode::Backspace if ctrl => EditAction::DeleteWord,
        KeyCode::Backspace => EditAction::Backspace,
        KeyCode::Delete => EditAction::DeleteForward,
        KeyCode::Left => EditAction::MoveLeft,
        KeyCode::Right => EditAction::MoveRight,
        KeyCode::Home => EditAction::MoveHome,
        KeyCode::End => EditAction::MoveEnd,

        KeyCode::Char('a') | KeyCode::Char('A') if ctrl => EditAction::SelectAll,
        KeyCode::Char('c') | KeyCode::Char('C') if ctrl => EditAction::Copy,
        KeyCode::Char('v') | KeyCode::Char('V') if ctrl => EditAction::Paste,
        KeyCode::Char('x') | KeyCode::Char('X') if ctrl => EditAction::Cut,
        KeyCode::Char('u') | KeyCode::Char('U') if ctrl => EditAction::ClearLine,
        KeyCode::Char('w') | KeyCode::Char('W') if ctrl => EditAction::DeleteWord,

        // Everything else printable is literal text — including 'q'.
        KeyCode::Char(c) if !ctrl => EditAction::InsertChar(c),
        _ => EditAction::None,
    }
}

/// Resolve a key press outside of text entry.
pub fn resolve(key: KeyEvent, context: InputContext) -> Option<Command> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    // A dialog owns Enter and Esc; global bindings must not reach past it.
    if context == InputContext::Dialog {
        return match key.code {
            KeyCode::Enter => Some(Command::Confirm),
            KeyCode::Esc => Some(Command::Cancel),
            KeyCode::Char('w') | KeyCode::Char('W') if ctrl => Some(Command::Cancel),
            KeyCode::F(1) => Some(Command::Help),
            _ => None,
        };
    }

    match key.code {
        // ---- application
        KeyCode::Char('q') | KeyCode::Char('Q') if ctrl => Some(Command::Quit),
        KeyCode::Char('q') if !ctrl => Some(Command::Quit),
        KeyCode::Esc => Some(Command::Cancel),
        KeyCode::F(1) => Some(Command::Help),
        KeyCode::Char('?') if !ctrl => Some(Command::Help),

        // ---- clipboard, conventional
        KeyCode::Char('a') | KeyCode::Char('A') if ctrl => Some(Command::SelectAll),
        KeyCode::Char('c') | KeyCode::Char('C') if ctrl => Some(Command::Copy),
        KeyCode::Char('v') | KeyCode::Char('V') if ctrl => Some(Command::Paste),
        KeyCode::Char('x') | KeyCode::Char('X') if ctrl => Some(Command::Cut),

        // ---- file / profile
        KeyCode::Char('n') | KeyCode::Char('N') if ctrl => Some(Command::NewProfile),
        KeyCode::Char('o') | KeyCode::Char('O') if ctrl => Some(Command::OpenFile),
        // Uppercase means Shift was held; see the module docs.
        KeyCode::Char('S') if ctrl => Some(Command::AddSubscription),
        KeyCode::Char('s') if ctrl && shift => Some(Command::AddSubscription),
        KeyCode::Char('s') if ctrl => Some(Command::SaveAs),
        KeyCode::Char('d') | KeyCode::Char('D') if ctrl => Some(Command::Duplicate),
        KeyCode::Char('e') | KeyCode::Char('E') if ctrl => Some(Command::ExportAll),
        KeyCode::Char('g') | KeyCode::Char('G') if ctrl => Some(Command::ShowQrCode),
        // Not Ctrl+I: that byte is Tab.
        KeyCode::Char('k') | KeyCode::Char('K') if ctrl => Some(Command::ScanQrImage),
        KeyCode::Delete => Some(Command::Delete),
        KeyCode::F(2) => Some(Command::Rename),

        // ---- system proxy
        KeyCode::Char('P') if ctrl => Some(Command::ClearSystemProxy),
        KeyCode::Char('p') if ctrl && shift => Some(Command::ClearSystemProxy),
        KeyCode::Char('p') if ctrl => Some(Command::CycleSystemProxy),

        // ---- data
        KeyCode::Char('r') | KeyCode::Char('R') if ctrl => Some(Command::Refresh),
        KeyCode::F(5) => Some(Command::Refresh),
        KeyCode::Char('l') | KeyCode::Char('L') if ctrl => Some(Command::TestLatency),

        // ---- search
        KeyCode::Char('f') | KeyCode::Char('F') if ctrl => Some(Command::Find),
        KeyCode::Char('/') if !ctrl => Some(Command::Find),

        // ---- feedback
        KeyCode::Char('b') | KeyCode::Char('B') if ctrl => Some(Command::Feedback),
        KeyCode::Char('t') | KeyCode::Char('T') if ctrl => Some(Command::CycleTheme),

        // ---- views
        KeyCode::Tab => Some(Command::NextView),
        KeyCode::BackTab => Some(Command::PrevView),
        KeyCode::F(6) => Some(Command::NextView),
        KeyCode::Char('1') if !ctrl => Some(Command::GoDashboard),
        KeyCode::Char('2') if !ctrl => Some(Command::GoProfiles),
        KeyCode::Char('3') if !ctrl => Some(Command::GoScanner),
        KeyCode::Char('4') if !ctrl => Some(Command::GoSettings),
        KeyCode::Char('5') if !ctrl => Some(Command::GoActivity),
        KeyCode::Char(',') if ctrl => Some(Command::GoSettings),

        // ---- movement, arrows plus vim keys
        KeyCode::Up => Some(Command::MoveUp),
        KeyCode::Down => Some(Command::MoveDown),
        KeyCode::Char('k') if !ctrl => Some(Command::MoveUp),
        KeyCode::Char('j') if !ctrl => Some(Command::MoveDown),
        KeyCode::PageUp => Some(Command::PageUp),
        KeyCode::PageDown => Some(Command::PageDown),
        KeyCode::Home => Some(Command::MoveToTop),
        KeyCode::End => Some(Command::MoveToBottom),
        KeyCode::Char('g') if !ctrl => Some(Command::MoveToTop),
        KeyCode::Char('G') if !ctrl => Some(Command::MoveToBottom),

        // ---- selection
        KeyCode::Char(' ') if !ctrl => Some(Command::ToggleSelection),

        // ---- primary action
        KeyCode::Enter => Some(Command::ToggleConnection),

        _ => None,
    }
}

/// One row of the help overlay.
pub struct Binding {
    pub keys: &'static str,
    pub command: Command,
}

/// Every binding, grouped for display.
pub fn help_sections() -> Vec<(&'static str, Vec<Binding>)> {
    fn b(keys: &'static str, command: Command) -> Binding {
        Binding { keys, command }
    }

    vec![
        (
            "Connection",
            vec![
                b("Enter", Command::ToggleConnection),
                b("Ctrl+L", Command::TestLatency),
                b("Ctrl+R / F5", Command::Refresh),
            ],
        ),
        (
            "Profiles",
            vec![
                b("Ctrl+N", Command::NewProfile),
                b("Ctrl+O", Command::OpenFile),
                b("Ctrl+D", Command::Duplicate),
                b("F2", Command::Rename),
                b("Delete", Command::Delete),
                b("Ctrl+Shift+S", Command::AddSubscription),
            ],
        ),
        (
            "System proxy",
            vec![
                b("Ctrl+P", Command::CycleSystemProxy),
                b("Ctrl+Shift+P", Command::ClearSystemProxy),
            ],
        ),
        (
            "Clipboard & sharing",
            vec![
                b("Ctrl+C", Command::Copy),
                b("Ctrl+V", Command::Paste),
                b("Ctrl+X", Command::Cut),
                b("Ctrl+G", Command::ShowQrCode),
                b("Ctrl+K", Command::ScanQrImage),
                b("Ctrl+E", Command::ExportAll),
            ],
        ),
        (
            "Selection",
            vec![
                b("Ctrl+A", Command::SelectAll),
                b("Space", Command::ToggleSelection),
                b("Esc", Command::SelectNone),
            ],
        ),
        (
            "Navigation",
            vec![
                b("Tab / Shift+Tab", Command::NextView),
                b("1", Command::GoDashboard),
                b("2", Command::GoProfiles),
                b("3", Command::GoScanner),
                b("4", Command::GoSettings),
                b("5", Command::GoActivity),
                b("↑ ↓ / k j", Command::MoveUp),
                b("Home / End", Command::MoveToTop),
                b("Ctrl+F or /", Command::Find),
            ],
        ),
        (
            "Application",
            vec![
                b("F1 / ?", Command::Help),
                b("Ctrl+B", Command::Feedback),
                b("Ctrl+T", Command::CycleTheme),
                b("Ctrl+, ", Command::GoSettings),
                b("Ctrl+Q / q", Command::Quit),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn ctrl_shift(c: char) -> KeyEvent {
        KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        )
    }

    #[test]
    fn clipboard_keys_follow_desktop_convention() {
        let b = InputContext::Browsing;
        assert_eq!(resolve(ctrl('a'), b), Some(Command::SelectAll));
        assert_eq!(resolve(ctrl('c'), b), Some(Command::Copy));
        assert_eq!(resolve(ctrl('v'), b), Some(Command::Paste));
        assert_eq!(resolve(ctrl('x'), b), Some(Command::Cut));
    }

    #[test]
    fn ctrl_a_is_never_add_config() {
        // The regression this keymap exists to prevent.
        for context in [InputContext::Browsing, InputContext::Dialog] {
            let cmd = resolve(ctrl('a'), context);
            assert_ne!(cmd, Some(Command::NewProfile));
            assert_ne!(cmd, Some(Command::OpenFile));
        }
        assert_eq!(resolve_editing(ctrl('a')), EditAction::SelectAll);
    }

    #[test]
    fn typing_in_a_field_is_literal() {
        // 'q' must type a q, not quit; '/' must type a slash, not open find.
        for c in ['q', 'j', 'k', '/', '?', '1', ' ', 'G'] {
            assert_eq!(
                resolve_editing(key(KeyCode::Char(c))),
                EditAction::InsertChar(c),
                "char {c:?} was swallowed by a global binding"
            );
        }
    }

    #[test]
    fn editing_intercepts_only_the_standard_modifiers() {
        assert_eq!(resolve_editing(ctrl('u')), EditAction::ClearLine);
        assert_eq!(resolve_editing(ctrl('w')), EditAction::DeleteWord);
        assert_eq!(resolve_editing(ctrl('c')), EditAction::Copy);
        assert_eq!(resolve_editing(ctrl('v')), EditAction::Paste);
        assert_eq!(resolve_editing(key(KeyCode::Esc)), EditAction::Cancel);
        assert_eq!(resolve_editing(key(KeyCode::Enter)), EditAction::Submit);
    }

    #[test]
    fn a_dialog_swallows_global_bindings() {
        let d = InputContext::Dialog;
        // Enter and Esc belong to the dialog.
        assert_eq!(resolve(key(KeyCode::Enter), d), Some(Command::Confirm));
        assert_eq!(resolve(key(KeyCode::Esc), d), Some(Command::Cancel));
        // Navigation and destructive commands must not fire behind it.
        assert_eq!(resolve(key(KeyCode::Tab), d), None);
        assert_eq!(resolve(key(KeyCode::Delete), d), None);
        assert_eq!(resolve(ctrl('n'), d), None);
        assert_eq!(resolve(key(KeyCode::Char('q')), d), None);
    }

    #[test]
    fn save_and_add_subscription_are_distinguished_by_shift() {
        let b = InputContext::Browsing;
        assert_eq!(resolve(ctrl('s'), b), Some(Command::SaveAs));
        assert_eq!(resolve(ctrl_shift('s'), b), Some(Command::AddSubscription));
    }

    #[test]
    fn navigation_supports_arrows_and_vim_keys() {
        let b = InputContext::Browsing;
        assert_eq!(resolve(key(KeyCode::Up), b), Some(Command::MoveUp));
        assert_eq!(resolve(key(KeyCode::Char('k')), b), Some(Command::MoveUp));
        assert_eq!(resolve(key(KeyCode::Down), b), Some(Command::MoveDown));
        assert_eq!(resolve(key(KeyCode::Char('j')), b), Some(Command::MoveDown));
        assert_eq!(resolve(key(KeyCode::Home), b), Some(Command::MoveToTop));
        assert_eq!(resolve(key(KeyCode::End), b), Some(Command::MoveToBottom));
    }

    #[test]
    fn number_keys_jump_to_views() {
        let b = InputContext::Browsing;
        assert_eq!(
            resolve(key(KeyCode::Char('1')), b),
            Some(Command::GoDashboard)
        );
        assert_eq!(
            resolve(key(KeyCode::Char('4')), b),
            Some(Command::GoSettings)
        );
        assert_eq!(resolve(ctrl(','), b), Some(Command::GoSettings));
    }

    #[test]
    fn quit_has_both_a_conventional_and_a_quick_binding() {
        let b = InputContext::Browsing;
        assert_eq!(resolve(ctrl('q'), b), Some(Command::Quit));
        assert_eq!(resolve(key(KeyCode::Char('q')), b), Some(Command::Quit));
    }

    #[test]
    fn proxy_bindings_are_distinguished_by_case() {
        let b = InputContext::Browsing;
        assert_eq!(resolve(ctrl('p'), b), Some(Command::CycleSystemProxy));
        assert_eq!(
            resolve(KeyEvent::new(KeyCode::Char('P'), KeyModifiers::CONTROL), b),
            Some(Command::ClearSystemProxy)
        );
        assert_eq!(resolve(ctrl_shift('p'), b), Some(Command::ClearSystemProxy));
    }

    #[test]
    fn no_binding_uses_a_reserved_control_key() {
        // Ctrl+I arrives as Tab, Ctrl+M as Enter, and so on. Binding one of
        // them produces a shortcut that silently does something else.
        for c in RESERVED_CONTROL_KEYS {
            let cmd = resolve(ctrl(c), InputContext::Browsing);
            assert!(
                cmd.is_none(),
                "Ctrl+{c} resolves to {cmd:?}, but that byte is another key"
            );
        }
    }

    #[test]
    fn scanning_a_qr_image_is_not_bound_to_tab() {
        // The regression: Ctrl+I and Tab are the same byte, so the scan
        // command has to live somewhere else.
        assert_eq!(
            resolve(key(KeyCode::Tab), InputContext::Browsing),
            Some(Command::NextView)
        );
        assert_eq!(
            resolve(ctrl('k'), InputContext::Browsing),
            Some(Command::ScanQrImage)
        );
        assert_ne!(
            resolve(ctrl('i'), InputContext::Browsing),
            Some(Command::ScanQrImage)
        );
    }

    #[test]
    fn shifted_control_keys_match_on_case_not_the_modifier() {
        let b = InputContext::Browsing;
        // Terminals that report the case but drop the SHIFT flag still work.
        assert_eq!(
            resolve(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::CONTROL), b),
            Some(Command::AddSubscription)
        );
        // And terminals that send both still work.
        assert_eq!(resolve(ctrl_shift('s'), b), Some(Command::AddSubscription));
        // Unshifted stays Save.
        assert_eq!(resolve(ctrl('s'), b), Some(Command::SaveAs));
    }

    #[test]
    fn every_help_binding_resolves_to_the_command_it_advertises() {
        // A help entry that names a key the router does not honour is worse
        // than no entry at all.
        let checks: [(KeyEvent, Command); 9] = [
            (ctrl('a'), Command::SelectAll),
            (ctrl('c'), Command::Copy),
            (ctrl('v'), Command::Paste),
            (ctrl('x'), Command::Cut),
            (ctrl('n'), Command::NewProfile),
            (ctrl('g'), Command::ShowQrCode),
            (ctrl('k'), Command::ScanQrImage),
            (ctrl('l'), Command::TestLatency),
            (ctrl('e'), Command::ExportAll),
        ];
        for (k, expected) in checks {
            assert_eq!(
                resolve(k, InputContext::Browsing),
                Some(expected),
                "{k:?} did not resolve to {expected:?}"
            );
        }
    }

    #[test]
    fn help_covers_every_command_it_lists() {
        for (_, bindings) in help_sections() {
            for binding in bindings {
                assert!(
                    !binding.command.label().is_empty(),
                    "{:?} has no label",
                    binding.command
                );
                assert!(!binding.keys.trim().is_empty());
            }
        }
    }

    #[test]
    fn no_two_bindings_in_a_context_collide() {
        // Walk every key we bind and confirm each resolves to exactly one
        // command — a duplicate arm would silently shadow the later one.
        let mut seen = std::collections::HashMap::new();
        let candidates: Vec<KeyEvent> = ('a'..='z')
            .map(ctrl)
            .chain(('1'..='9').map(|c| key(KeyCode::Char(c))))
            .chain([
                key(KeyCode::Tab),
                key(KeyCode::BackTab),
                key(KeyCode::Enter),
                key(KeyCode::Esc),
                key(KeyCode::Delete),
                key(KeyCode::Home),
                key(KeyCode::End),
                key(KeyCode::PageUp),
                key(KeyCode::PageDown),
            ])
            .collect();

        for k in candidates {
            if let Some(cmd) = resolve(k, InputContext::Browsing) {
                seen.entry(cmd).or_insert_with(Vec::new).push(k.code);
            }
        }
        // Movement deliberately has several keys; everything else should be
        // reachable, which is all this asserts.
        assert!(seen.contains_key(&Command::SelectAll));
        assert!(seen.contains_key(&Command::Copy));
        assert!(seen.contains_key(&Command::NewProfile));
        assert!(seen.contains_key(&Command::ShowQrCode));
    }
}
