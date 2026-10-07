//! The automatic WARP setup: one Cloudflare account, made with as little of
//! the person's time as possible.
//!
//! Making an account means reaching `api.cloudflareclient.com`, and in Iran
//! that name is filtered. So the setup asks one short question first — may it
//! use Cloudflare? — and then tries the service directly, with a short
//! deadline so a filtered address cannot hold the person for the full
//! registration timeout.
//!
//! When the service cannot be reached, it borrows a working server for the
//! trip: it brings one up, makes the account through that tunnel, lets the
//! borrowed connection go, and only then dials the account. Dialling it
//! brings the tunnel and its found servers up in the account's order (see
//! `zero_runtime::warp` and `zero_config::HybridMode`).
//!
//! This module is the sequence as a state machine with no I/O of its own: the
//! driver in [`crate::app_warp`] waits, dials, and feeds the outcomes back in,
//! so every step and every way it can fail is unit-testable.
//!
//! The one rule worth stating plainly: once a server has been borrowed it is
//! *always* let go, even when the account could not be made. Otherwise a
//! failure would leave the person connected to a server they never chose.

use zero_discovery::warp::is_unreachable;

/// What the person has said about using Cloudflare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consent {
    /// Never asked.
    #[default]
    Unasked,
    /// Asked, and agreed.
    Yes,
    /// Asked, and declined.
    No,
}

/// The `AppSettings` spelling of an answer. Anything unrecognised reads as
/// "never asked", so a config file edited by hand cannot silently opt someone
/// in.
impl Consent {
    /// Allocation-free on purpose: the Settings page reads this every frame to
    /// decide which of the three it is showing.
    pub fn parse(value: &str) -> Self {
        let value = value.trim();
        const YES: [&str; 3] = ["on", "yes", "agree"];
        const NO: [&str; 3] = ["off", "no", "never"];
        if YES.iter().any(|name| value.eq_ignore_ascii_case(name)) {
            Self::Yes
        } else if NO.iter().any(|name| value.eq_ignore_ascii_case(name)) {
            Self::No
        } else {
            Self::Unasked
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unasked => "",
            Self::Yes => "on",
            Self::No => "off",
        }
    }
}

/// Where the setup has got to. The driver acts on the step it is handed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Show the question and wait for an answer.
    Ask,
    /// Try the service directly, with a short deadline.
    Direct,
    /// Direct failed; a working server has to come up first.
    Borrow,
    /// Make the account. `borrowed` is set when a server was brought up for
    /// the trip, which decides whether it has to be let go afterwards.
    Register { borrowed: bool },
    /// Let the borrowed server go.
    Release,
    /// Dial the account.
    Dial,
    /// The account is up.
    Done,
    /// The person said no; nothing was done.
    Declined,
    /// It did not work, in one sentence.
    Failed(String),
}

/// The setup, mid-flight.
#[derive(Debug, Clone)]
pub struct Bootstrap {
    step: Step,
    /// The person was already online when this began, so the account can be
    /// made through the connection they already have and nothing new has to
    /// be brought up or let go.
    online: bool,
    /// A server has been asked for and may already be dialling, so it has to
    /// be let go once the trip is over. Set when the search starts, not when
    /// the tunnel reports `Connected`: the dial is requested first and the
    /// status follows, and a cancel landing in between must still release.
    borrowed: bool,
    /// A failure noticed while the borrowed server was being let go, held
    /// until the release finishes so the person is never left on it.
    pending: Option<String>,
    /// The person backed out, so the release that follows ends the run
    /// quietly instead of dialling what was never finished.
    cancelled: bool,
}

impl Bootstrap {
    /// Begin the setup. `None` when the person has already declined, in which
    /// case there is nothing to do.
    ///
    /// `online` is whether a tunnel is already up: the service is filtered by
    /// name, so an existing tunnel is the one path there that always works,
    /// and the direct attempt is skipped entirely.
    pub fn start(consent: Consent, online: bool) -> Option<Self> {
        let step = match consent {
            Consent::No => return None,
            Consent::Unasked => Step::Ask,
            Consent::Yes if online => Step::Register { borrowed: false },
            Consent::Yes => Step::Direct,
        };
        Some(Self {
            step,
            online,
            borrowed: false,
            pending: None,
            cancelled: false,
        })
    }

    /// The step to act on.
    pub fn step(&self) -> &Step {
        &self.step
    }

    /// The person answered the question.
    ///
    /// A "no" goes down the same path as backing out, not straight to
    /// [`Step::Declined`]: dismissing the dialog is one of the ways to say no,
    /// and a server borrowed by then still has to be let go before the run
    /// ends.
    pub fn answered(&mut self, consent: Consent) -> Step {
        match consent {
            Consent::No => self.cancelled(),
            _ if self.online => self.to(Step::Register { borrowed: false }),
            _ => self.to(Step::Direct),
        }
    }

    /// The direct attempt finished. An account, or the reason it failed.
    ///
    /// Only "the service could not be reached" is worth a borrowed server; a
    /// rate limit or an HTTP error proves the service *was* reached, and a
    /// tunnel would change nothing.
    pub fn direct(&mut self, result: Result<(), String>) -> Step {
        match result {
            Ok(()) => self.to(Step::Dial),
            Err(error) if is_unreachable(&error) => self.to(Step::Borrow),
            Err(error) => self.to(Step::Failed(error)),
        }
    }

    /// The search for a server to borrow has started. Everything from here on
    /// must end in a [`Step::Release`], because a dial may already be on its
    /// way even though nothing has answered yet.
    pub fn borrowing(&mut self) -> Step {
        self.borrowed = true;
        self.to(Step::Borrow)
    }

    /// A server came up for the trip, or none did.
    pub fn tunnel(&mut self, up: Result<(), String>) -> Step {
        match up {
            // Set again here so a caller that skipped [`Self::borrowing`]
            // still releases a server that genuinely came up.
            Ok(()) => {
                self.borrowed = true;
                self.to(Step::Register { borrowed: true })
            }
            Err(error) => {
                // Nothing came up, so there is nothing to let go.
                self.borrowed = false;
                self.to(Step::Failed(error))
            }
        }
    }

    /// Making the account finished.
    pub fn registered(&mut self, result: Result<(), String>) -> Step {
        match result {
            Ok(()) if self.borrowed => self.to(Step::Release),
            Ok(()) => self.to(Step::Dial),
            // The borrowed connection is let go first, and the reason is kept
            // to report once it has.
            Err(error) if self.borrowed => {
                self.pending = Some(error);
                self.to(Step::Release)
            }
            Err(error) => self.to(Step::Failed(error)),
        }
    }

    /// The borrowed server was let go.
    pub fn released(&mut self, result: Result<(), String>) -> Step {
        self.borrowed = false;
        if std::mem::take(&mut self.cancelled) {
            return self.to(Step::Declined);
        }
        match self.pending.take() {
            Some(error) => self.to(Step::Failed(error)),
            None => match result {
                Ok(()) => self.to(Step::Dial),
                Err(error) => self.to(Step::Failed(error)),
            },
        }
    }

    /// Dialling the account finished.
    pub fn dialled(&mut self, result: Result<(), String>) -> Step {
        match result {
            Ok(()) => self.to(Step::Done),
            Err(error) => self.to(Step::Failed(error)),
        }
    }

    /// The person backed out. A borrowed server is still let go, and the
    /// release ends the run rather than dialling what was never finished.
    pub fn cancelled(&mut self) -> Step {
        if self.borrowed {
            self.cancelled = true;
            self.to(Step::Release)
        } else {
            self.to(Step::Declined)
        }
    }

    fn to(&mut self, step: Step) -> Step {
        self.step = step;
        self.step.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error a filtered Cloudflare produces, as `zero_discovery` builds it.
    const FILTERED: &str =
        "could not reach the WARP service: connecting to api.cloudflareclient.com: timed out";

    #[test]
    fn an_answer_of_no_starts_nothing_and_is_remembered() {
        assert!(Bootstrap::start(Consent::No, false).is_none());
        assert!(Bootstrap::start(Consent::No, true).is_none());
    }

    #[test]
    fn an_unanswered_question_comes_first_and_yes_goes_to_the_direct_try() {
        let mut setup = Bootstrap::start(Consent::Unasked, false).unwrap();
        assert_eq!(*setup.step(), Step::Ask);
        assert_eq!(setup.answered(Consent::Yes), Step::Direct);
        assert_eq!(setup.answered(Consent::No), Step::Declined);
    }

    #[test]
    fn already_online_skips_the_direct_try_and_uses_the_connection_in_hand() {
        // The service is filtered by name; a tunnel already up is the one path
        // there that works, so there is no reason to try direct at all.
        let setup = Bootstrap::start(Consent::Yes, true).unwrap();
        assert_eq!(*setup.step(), Step::Register { borrowed: false });
        // And answering the question reaches the same place.
        let mut asked = Bootstrap::start(Consent::Unasked, true).unwrap();
        assert_eq!(
            asked.answered(Consent::Yes),
            Step::Register { borrowed: false }
        );
    }

    #[test]
    fn a_reachable_service_needs_no_borrowed_server() {
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        assert_eq!(setup.direct(Ok(())), Step::Dial);
        assert_eq!(setup.dialled(Ok(())), Step::Done);
    }

    #[test]
    fn a_filtered_service_borrows_a_server_and_lets_it_go_before_dialling() {
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        assert_eq!(setup.direct(Err(FILTERED.into())), Step::Borrow);
        assert_eq!(setup.tunnel(Ok(())), Step::Register { borrowed: true });
        assert_eq!(setup.registered(Ok(())), Step::Release);
        assert_eq!(setup.released(Ok(())), Step::Dial);
        assert_eq!(setup.dialled(Ok(())), Step::Done);
    }

    #[test]
    fn a_service_that_answered_is_not_borrowed_for() {
        // Reached, and refused: a tunnel would change nothing.
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        let step = setup.direct(Err("the WARP service answered 500".into()));
        assert_eq!(step, Step::Failed("the WARP service answered 500".into()));
    }

    #[test]
    fn a_failure_after_borrowing_still_lets_the_server_go() {
        // The person must never be left on a server they did not choose.
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        setup.borrowing();
        setup.tunnel(Ok(()));
        assert_eq!(
            setup.registered(Err("the WARP service sent something odd".into())),
            Step::Release
        );
        // The reason survives the release and is what the person finally sees.
        assert_eq!(
            setup.released(Ok(())),
            Step::Failed("the WARP service sent something odd".into())
        );
    }

    #[test]
    fn backing_out_after_borrowing_still_lets_the_server_go() {
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        setup.borrowing();
        setup.tunnel(Ok(()));
        assert_eq!(setup.cancelled(), Step::Release);
        assert_eq!(setup.released(Ok(())), Step::Declined);
    }

    #[test]
    fn backing_out_before_borrowing_does_not_release_anything() {
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        assert_eq!(setup.cancelled(), Step::Declined);
    }

    #[test]
    fn saying_no_after_borrowing_still_lets_the_server_go() {
        // Dismissing the dialog is one of the ways to say no, so an answer of
        // "no" has to release a borrowed server like backing out does. Were it
        // to go straight to Declined, the person would be left connected to a
        // server they never chose.
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        setup.tunnel(Ok(()));
        assert_eq!(setup.answered(Consent::No), Step::Release);
        assert_eq!(setup.released(Ok(())), Step::Declined);
    }

    #[test]
    fn saying_no_while_working_still_lets_the_server_go() {
        // The same thing one step later, which is when a person is most likely
        // to press Esc: the dialog is up saying it is working.
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        setup.tunnel(Ok(()));
        setup.registered(Ok(()));
        assert_eq!(setup.answered(Consent::No), Step::Release);
        assert_eq!(setup.released(Ok(())), Step::Declined);
    }

    #[test]
    fn a_server_that_never_came_up_fails_without_a_release() {
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        let step = setup.tunnel(Err("no server answered".into()));
        assert_eq!(step, Step::Failed("no server answered".into()));
        // Nothing came up, so nothing is left waiting to be let go.
        assert_eq!(setup.cancelled(), Step::Declined);
    }

    #[test]
    fn backing_out_while_the_borrowed_server_is_still_dialling_releases_it() {
        // The dial is asked for before the tunnel reports Connected, so a
        // cancel landing in that window must still let the server go rather
        // than leaving the person connected to one they backed out of.
        let mut setup = Bootstrap::start(Consent::Yes, false).unwrap();
        setup.direct(Err(FILTERED.into()));
        setup.borrowing();
        assert_eq!(setup.cancelled(), Step::Release);
        assert_eq!(setup.released(Ok(())), Step::Declined);
    }

    #[test]
    fn the_answer_round_trips_through_settings() {
        for consent in [Consent::Unasked, Consent::Yes, Consent::No] {
            assert_eq!(Consent::parse(consent.as_str()), consent);
        }
        // Anything a hand-edited file might hold reads as "never asked".
        for junk in ["", "  ", "maybe", "TRUE", "1"] {
            assert_eq!(Consent::parse(junk), Consent::Unasked, "{junk:?}");
        }
        assert_eq!(Consent::parse("ON"), Consent::Yes);
        assert_eq!(Consent::parse("off"), Consent::No);
    }
}
