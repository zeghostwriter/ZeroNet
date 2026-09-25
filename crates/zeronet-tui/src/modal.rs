//! Dialog state.
//!
//! One enum for every dialog the app can show. A dialog owns the keyboard
//! while it is up, and [`ModalState::input_context`] is what tells the key
//! router whether printable keys are text or commands — so typing `q` into a
//! field never quits the app.

use crate::keymap::InputContext;
use crate::manual_profile::ManualProfileForm;
use crate::qr::RenderedQr;

#[derive(Debug, Clone, Default)]
pub enum ModalState {
    #[default]
    None,
    TextInput {
        title: String,
        prompt: String,
        buffer: String,
        /// What to do with the text once it is submitted.
        purpose: TextPurpose,
        created_tick: u64,
        select_all: bool,
    },
    NumberEdit {
        title: String,
        setting_key: String,
        min: u64,
        max: u64,
        buffer: String,
        created_tick: u64,
        select_all: bool,
    },
    AshesWarning {
        title: String,
        message: String,
        created_tick: u64,
    },
    QuitConfirmation {
        created_tick: u64,
    },
    /// A yes/no question about something destructive.
    Confirm {
        title: String,
        message: String,
        action: ConfirmAction,
        created_tick: u64,
    },
    ManualProfile {
        form: ManualProfileForm,
        editing_text: bool,
        input_buffer: String,
        created_tick: u64,
    },
    /// Share a profile: its QR code beside the link itself.
    ShareConfig {
        /// Name of the profile being shared.
        profile: String,
        /// The share link, shown as selectable text next to the code.
        uri: String,
        code: Box<RenderedQr>,
        created_tick: u64,
    },
    /// Asking for the administrator password so TUN can be brought up.
    ///
    /// Its own variant rather than a `TextInput` with a flag: a password
    /// field must never echo, never reach the clipboard, and never be
    /// dismissed by a stray click on the backdrop, and every one of those is
    /// a behaviour the generic text dialog has.
    SudoPassword {
        /// What the password is for, restated so nobody types it blind.
        prompt: String,
        buffer: String,
        /// Why the previous attempt failed, if there was one.
        error: Option<String>,
        created_tick: u64,
    },
    /// The keyboard reference.
    Help {
        scroll: u16,
        created_tick: u64,
    },
    /// An image shown in the terminal, with what was read out of it.
    ///
    /// The decoded image itself lives in app state rather than here: drawing
    /// it needs `&mut` access to terminal-protocol state that cannot be
    /// cloned, and `ModalState` has to stay cheap to copy.
    ImageView {
        title: String,
        /// What scanning the image produced, shown beneath it.
        findings: Vec<String>,
        created_tick: u64,
    },
    /// A newer release: what changed, and the download as it happens.
    Update {
        release: Box<crate::update::Release>,
        phase: UpdatePhase,
        created_tick: u64,
    },
}

/// Where an update stands, as the update dialog shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatePhase {
    /// Offered, not started.
    Available,
    /// Downloading: bytes received of the total.
    Downloading {
        received: u64,
        total: u64,
    },
    /// In place; runs from the next start.
    Installed,
    /// This installation cannot update itself (no file for this system, or
    /// no permission to replace it): the release page is offered instead.
    Manual(String),
    Failed(String),
}

/// What a text dialog's contents are for.
///
/// Carried explicitly rather than inferred from the dialog's title, which
/// meant a retitled dialog silently changed what its input did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextPurpose {
    ImportConfig,
    AddSubscription,
    Feedback,
    CustomDns,
    /// Rename the profile with this id.
    RenameProfile(i64),
    /// Path to an image to scan for a QR code.
    ScanImagePath,
    /// Path to import a config file from.
    ImportFilePath,
    /// Path to export to.
    ExportFilePath,
    /// Name to give the TUN interface.
    TunDeviceName,
    /// SNI the edge scanner presents while probing.
    ScannerSni,
    /// WebSocket path the edge scanner upgrades to.
    ScannerWsPath,
    /// Read-only text, such as the log viewer. Submitting does nothing.
    ViewOnly,
}

/// A destructive action awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAction {
    /// Delete these profiles.
    DeleteProfiles(Vec<i64>),
    /// Delete this subscription and the profiles it brought in.
    DeleteSubscription(i64),
}

impl ModalState {
    pub fn is_active(&self) -> bool {
        !matches!(self, ModalState::None)
    }

    pub fn created_tick(&self) -> u64 {
        match self {
            ModalState::TextInput { created_tick, .. }
            | ModalState::NumberEdit { created_tick, .. }
            | ModalState::AshesWarning { created_tick, .. }
            | ModalState::QuitConfirmation { created_tick }
            | ModalState::Confirm { created_tick, .. }
            | ModalState::ManualProfile { created_tick, .. }
            | ModalState::ShareConfig { created_tick, .. }
            | ModalState::SudoPassword { created_tick, .. }
            | ModalState::Help { created_tick, .. }
            | ModalState::ImageView { created_tick, .. }
            | ModalState::Update { created_tick, .. } => *created_tick,
            ModalState::None => 0,
        }
    }

    /// How keys should be interpreted while this dialog is up.
    ///
    /// Dialogs with a text field report `Editing` so printable characters are
    /// literal. The manual profile form is `Editing` only while a text field
    /// has focus — on a cycler field, Space and the arrows change the value.
    pub fn input_context(&self) -> InputContext {
        match self {
            ModalState::None => InputContext::Browsing,
            ModalState::TextInput { .. }
            | ModalState::NumberEdit { .. }
            | ModalState::SudoPassword { .. } => InputContext::Editing,
            ModalState::ManualProfile { form, .. } => {
                if form.focused_field_is_text() {
                    InputContext::Editing
                } else {
                    InputContext::Dialog
                }
            }
            _ => InputContext::Dialog,
        }
    }

    /// Whether clicking the dimmed area outside this dialog should dismiss
    /// it.
    ///
    /// True for everything the user is only *reading*. The manual profile
    /// form is the exception: it holds typed input, and silently discarding
    /// a hand-entered UUID because of a stray click is worse than making
    /// someone reach for Esc or the close button. That dialog flashes
    /// instead — see `ModalAnimator::nudge`.
    pub fn dismiss_on_backdrop(&self) -> bool {
        !matches!(
            self,
            ModalState::ManualProfile { .. } | ModalState::SudoPassword { .. } | ModalState::None
        )
    }

    /// The title shown in the dialog's border.
    pub fn title(&self) -> &str {
        match self {
            ModalState::None => "",
            ModalState::TextInput { title, .. }
            | ModalState::NumberEdit { title, .. }
            | ModalState::AshesWarning { title, .. }
            | ModalState::Confirm { title, .. }
            | ModalState::ImageView { title, .. } => title,
            ModalState::ShareConfig { .. } => "SHARE CONFIG",
            ModalState::QuitConfirmation { .. } => "EXIT CONFIRMATION",
            ModalState::ManualProfile { .. } => "MANUAL NODE CREATOR",
            ModalState::SudoPassword { .. } => "ADMINISTRATOR PASSWORD",
            ModalState::Help { .. } => "KEYBOARD REFERENCE",
            ModalState::Update { .. } => "UPDATE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_dialogs_capture_printable_keys() {
        let modal = ModalState::TextInput {
            title: "Import".into(),
            prompt: "Paste".into(),
            buffer: String::new(),
            purpose: TextPurpose::ImportConfig,
            created_tick: 0,
            select_all: false,
        };
        assert_eq!(modal.input_context(), InputContext::Editing);
    }

    #[test]
    fn confirmations_do_not_capture_printable_keys() {
        // A yes/no dialog has nothing to type into, so it stays in Dialog
        // context where Enter confirms and Esc cancels.
        let modal = ModalState::Confirm {
            title: "Delete".into(),
            message: "Delete 2 profiles?".into(),
            action: ConfirmAction::DeleteProfiles(vec![1, 2]),
            created_tick: 0,
        };
        assert_eq!(modal.input_context(), InputContext::Dialog);
    }

    #[test]
    fn the_manual_form_switches_context_with_its_focused_field() {
        let mut form = ManualProfileForm::new();

        form.focused_field = 0; // Remark, a text field
        let modal = ModalState::ManualProfile {
            form: form.clone(),
            editing_text: true,
            input_buffer: String::new(),
            created_tick: 0,
        };
        assert_eq!(modal.input_context(), InputContext::Editing);

        form.focused_field = 1; // Protocol, a cycler
        let modal = ModalState::ManualProfile {
            form,
            editing_text: false,
            input_buffer: String::new(),
            created_tick: 0,
        };
        assert_eq!(modal.input_context(), InputContext::Dialog);
    }

    #[test]
    fn every_variant_reports_a_creation_tick_and_a_title() {
        let variants = [
            ModalState::TextInput {
                title: "t".into(),
                prompt: "p".into(),
                buffer: String::new(),
                purpose: TextPurpose::Feedback,
                created_tick: 9,
                select_all: false,
            },
            ModalState::NumberEdit {
                title: "t".into(),
                setting_key: "k".into(),
                min: 0,
                max: 1,
                buffer: String::new(),
                created_tick: 9,
                select_all: false,
            },
            ModalState::AshesWarning {
                title: "t".into(),
                message: "m".into(),
                created_tick: 9,
            },
            ModalState::QuitConfirmation { created_tick: 9 },
            ModalState::Confirm {
                title: "t".into(),
                message: "m".into(),
                action: ConfirmAction::DeleteProfiles(vec![]),
                created_tick: 9,
            },
            ModalState::Help {
                scroll: 0,
                created_tick: 9,
            },
        ];

        for modal in variants {
            assert_eq!(modal.created_tick(), 9, "{modal:?}");
            assert!(modal.is_active());
            assert!(!modal.title().is_empty(), "{modal:?} has no title");
        }

        assert!(!ModalState::None.is_active());
        assert_eq!(ModalState::None.created_tick(), 0);
    }

    #[test]
    fn the_password_dialog_captures_typing_and_resists_stray_clicks() {
        let modal = ModalState::SudoPassword {
            prompt: "TUN mode needs administrator rights".into(),
            buffer: String::new(),
            error: None,
            created_tick: 4,
        };
        // Printable keys are literal, or a password containing `q` would quit.
        assert_eq!(modal.input_context(), InputContext::Editing);
        // A half-typed password thrown away by a stray click is worse than
        // making someone reach for Esc.
        assert!(!modal.dismiss_on_backdrop());
        assert_eq!(modal.created_tick(), 4);
        assert!(!modal.title().is_empty());
    }

    #[test]
    fn purpose_is_carried_explicitly_not_inferred_from_the_title() {
        // Two dialogs can share a title and still do different things.
        let rename = ModalState::TextInput {
            title: "Name".into(),
            prompt: "New name".into(),
            buffer: String::new(),
            purpose: TextPurpose::RenameProfile(7),
            created_tick: 0,
            select_all: false,
        };
        let ModalState::TextInput { purpose, .. } = &rename else {
            panic!()
        };
        assert_eq!(*purpose, TextPurpose::RenameProfile(7));
    }
}
