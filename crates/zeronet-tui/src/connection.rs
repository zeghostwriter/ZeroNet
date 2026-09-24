//! Connection intent — what the user asked for, separate from what the
//! engine is currently doing.
//!
//! Desktop VPN clients (NordVPN, Proton, Clash Verge) all draw the same
//! distinction, and it is the one this client was missing:
//!
//! * **Selecting** a server is a browsing action. It never dials.
//! * **Connecting** is an explicit action — the connect control, or Enter.
//! * Once connected, selecting a *different* server switches to it, because
//!   the user has already said they want to be connected.
//!
//! Without that split, clicking a row in the list called `switch_node`
//! unconditionally, so browsing the list while disconnected silently dialled
//! out: disconnect, click another profile, click back, and you were online
//! again without ever pressing connect.
//!
//! [`ConnectionManager`] owns the intent and turns user gestures into the
//! [`EngineAction`] the daemon should perform — nothing more. It holds no
//! sockets and does no I/O, so the whole policy is unit-testable.

/// What the user wants to be true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Intent {
    /// The user wants to be offline. Selecting profiles must not dial.
    #[default]
    Disconnected,
    /// The user has asked to be online, on whichever profile is selected.
    Connected,
}

/// What the daemon should be told to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineAction {
    /// Nothing to do — the gesture changed selection only.
    None,
    /// Start the engine on this profile.
    Connect(i64),
    /// Hot-swap the running engine onto this profile.
    Switch(i64),
    /// Stop the engine.
    Disconnect,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionManager {
    intent: Intent,
    /// The profile highlighted in the list.
    selected: Option<i64>,
    /// The profile the engine was last asked to run.
    dialled: Option<i64>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore the selection without expressing any intent to connect.
    ///
    /// Used at startup: the profile marked active in the database becomes the
    /// selected one, but a fresh launch is always offline until the user says
    /// otherwise.
    pub fn restore_selection(&mut self, profile_id: Option<i64>) {
        self.selected = profile_id;
        self.intent = Intent::Disconnected;
        self.dialled = None;
    }

    pub fn intent(&self) -> Intent {
        self.intent
    }

    pub fn selected(&self) -> Option<i64> {
        self.selected
    }

    /// The profile the engine is running, if any.
    pub fn dialled(&self) -> Option<i64> {
        self.dialled
    }

    /// Whether the user has asked to be online.
    pub fn wants_connection(&self) -> bool {
        self.intent == Intent::Connected
    }

    /// The user highlighted a profile.
    ///
    /// While disconnected this is pure navigation. While connected it is a
    /// server switch, which is what every desktop client does — and it is
    /// skipped when the profile is already the one running, so clicking the
    /// current server does not needlessly tear the tunnel down.
    pub fn select(&mut self, profile_id: i64) -> EngineAction {
        self.selected = Some(profile_id);

        match self.intent {
            Intent::Disconnected => EngineAction::None,
            Intent::Connected => {
                if self.dialled == Some(profile_id) {
                    EngineAction::None
                } else {
                    self.dialled = Some(profile_id);
                    EngineAction::Switch(profile_id)
                }
            }
        }
    }

    /// The user pressed connect.
    pub fn connect(&mut self) -> EngineAction {
        let Some(profile_id) = self.selected else {
            return EngineAction::None;
        };
        self.intent = Intent::Connected;
        self.dialled = Some(profile_id);
        EngineAction::Connect(profile_id)
    }

    /// The user pressed disconnect.
    pub fn disconnect(&mut self) -> EngineAction {
        self.intent = Intent::Disconnected;
        self.dialled = None;
        EngineAction::Disconnect
    }

    /// The user pressed the connect control, whatever it currently means.
    ///
    /// Driven by intent rather than by observed engine status, so pressing it
    /// while a connection is still being established cancels that attempt
    /// instead of starting a second one.
    pub fn toggle(&mut self) -> EngineAction {
        match self.intent {
            Intent::Connected => self.disconnect(),
            Intent::Disconnected => self.connect(),
        }
    }

    /// Connect to a specific profile in one gesture (double-click, or picking
    /// a node from the scanner).
    pub fn connect_to(&mut self, profile_id: i64) -> EngineAction {
        self.selected = Some(profile_id);
        self.connect()
    }

    /// The engine's configuration changed under a live connection — a port
    /// edit, a TUN toggle — and it needs rebuilding on the same profile.
    ///
    /// Returns `None` when offline, so changing a setting never dials.
    pub fn reapply(&self) -> EngineAction {
        match (self.intent, self.dialled) {
            (Intent::Connected, Some(id)) => EngineAction::Switch(id),
            _ => EngineAction::None,
        }
    }

    /// The engine stopped without being asked to — a crash, or a fatal
    /// config error. Intent is cleared so the UI does not keep claiming the
    /// user wants a connection that cannot be made.
    pub fn on_engine_failed(&mut self) {
        self.intent = Intent::Disconnected;
        self.dialled = None;
    }

    /// A profile was rewritten under a new id — a subscription refresh
    /// replaces its rows — and is otherwise the same profile. Selection and
    /// the running profile follow it; nothing is dialled.
    pub fn on_profile_replaced(&mut self, old_id: i64, new_id: i64) {
        if self.selected == Some(old_id) {
            self.selected = Some(new_id);
        }
        if self.dialled == Some(old_id) {
            self.dialled = Some(new_id);
        }
    }

    /// A profile was deleted. If it was the one in use, the connection is no
    /// longer meaningful.
    pub fn on_profile_removed(&mut self, profile_id: i64) -> EngineAction {
        if self.selected == Some(profile_id) {
            self.selected = None;
        }
        if self.dialled == Some(profile_id) {
            self.intent = Intent::Disconnected;
            self.dialled = None;
            return EngineAction::Disconnect;
        }
        EngineAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_while_offline_never_dials() {
        // The reported bug: browsing the list must not connect.
        let mut cm = ConnectionManager::new();
        assert_eq!(cm.select(1), EngineAction::None);
        assert_eq!(cm.select(2), EngineAction::None);
        assert_eq!(cm.select(1), EngineAction::None);
        assert_eq!(cm.intent(), Intent::Disconnected);
        assert_eq!(cm.dialled(), None);
    }

    #[test]
    fn the_exact_reported_sequence_stays_offline() {
        // connect -> disconnect -> switch profile -> switch back.
        // The final state must still be disconnected.
        let mut cm = ConnectionManager::new();
        cm.select(1);
        assert_eq!(cm.connect(), EngineAction::Connect(1));
        assert_eq!(cm.disconnect(), EngineAction::Disconnect);

        assert_eq!(
            cm.select(2),
            EngineAction::None,
            "switching profile re-dialled"
        );
        assert_eq!(
            cm.select(1),
            EngineAction::None,
            "switching back re-dialled"
        );
        assert!(!cm.wants_connection());
    }

    #[test]
    fn selecting_while_online_switches_servers() {
        let mut cm = ConnectionManager::new();
        cm.select(1);
        cm.connect();
        assert_eq!(cm.select(2), EngineAction::Switch(2));
        assert_eq!(cm.dialled(), Some(2));
        assert!(cm.wants_connection());
    }

    #[test]
    fn reselecting_the_running_profile_does_not_reconnect() {
        // Clicking the row you are already on should be inert, not a
        // teardown-and-redial of the tunnel you are using.
        let mut cm = ConnectionManager::new();
        cm.select(1);
        cm.connect();
        assert_eq!(cm.select(1), EngineAction::None);
        assert_eq!(cm.dialled(), Some(1));
    }

    #[test]
    fn toggle_follows_intent_not_observed_status() {
        let mut cm = ConnectionManager::new();
        cm.select(7);

        assert_eq!(cm.toggle(), EngineAction::Connect(7));
        // Pressing again while still dialling cancels rather than stacking a
        // second connect.
        assert_eq!(cm.toggle(), EngineAction::Disconnect);
        assert_eq!(cm.toggle(), EngineAction::Connect(7));
    }

    #[test]
    fn connect_without_a_selection_does_nothing() {
        let mut cm = ConnectionManager::new();
        assert_eq!(cm.connect(), EngineAction::None);
        assert_eq!(cm.intent(), Intent::Disconnected);
    }

    #[test]
    fn connect_to_selects_and_dials_in_one_step() {
        let mut cm = ConnectionManager::new();
        assert_eq!(cm.connect_to(42), EngineAction::Connect(42));
        assert_eq!(cm.selected(), Some(42));
        assert!(cm.wants_connection());
    }

    #[test]
    fn reapply_rebuilds_only_while_connected() {
        let mut cm = ConnectionManager::new();
        cm.select(3);
        assert_eq!(
            cm.reapply(),
            EngineAction::None,
            "a setting change dialled while offline"
        );

        cm.connect();
        assert_eq!(cm.reapply(), EngineAction::Switch(3));
    }

    #[test]
    fn engine_failure_clears_intent() {
        let mut cm = ConnectionManager::new();
        cm.select(1);
        cm.connect();
        cm.on_engine_failed();

        assert!(!cm.wants_connection());
        // And browsing afterwards still does not dial.
        assert_eq!(cm.select(2), EngineAction::None);
    }

    #[test]
    fn removing_the_running_profile_disconnects() {
        let mut cm = ConnectionManager::new();
        cm.select(5);
        cm.connect();
        assert_eq!(cm.on_profile_removed(5), EngineAction::Disconnect);
        assert!(!cm.wants_connection());
        assert_eq!(cm.selected(), None);
    }

    #[test]
    fn removing_an_unrelated_profile_leaves_the_connection_alone() {
        let mut cm = ConnectionManager::new();
        cm.select(5);
        cm.connect();
        assert_eq!(cm.on_profile_removed(9), EngineAction::None);
        assert!(cm.wants_connection());
        assert_eq!(cm.dialled(), Some(5));
    }

    #[test]
    fn a_refreshed_profile_keeps_its_place() {
        let mut m = ConnectionManager::new();
        m.connect_to(5);
        m.on_profile_replaced(5, 42);
        assert_eq!(m.selected(), Some(42));
        assert_eq!(m.dialled(), Some(42));
        // A rebuild now targets the row that exists.
        assert_eq!(m.reapply(), EngineAction::Switch(42));
        // Re-selecting it is not a switch.
        assert_eq!(m.select(42), EngineAction::None);
    }

    #[test]
    fn restore_selection_starts_offline() {
        let mut cm = ConnectionManager::new();
        cm.select(1);
        cm.connect();

        // Simulate a relaunch.
        let mut fresh = ConnectionManager::new();
        fresh.restore_selection(Some(1));
        assert_eq!(fresh.selected(), Some(1));
        assert!(
            !fresh.wants_connection(),
            "a fresh launch must not auto-dial"
        );
    }
}
