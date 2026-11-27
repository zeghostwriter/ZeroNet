//! The WARP dialog: asking before an account is made, showing the work as it
//! happens, and managing a profile that already has one.
//!
//! Getting an account registers a device with Cloudflare, so it starts only
//! from the dialog's own button — the dialog says what will happen and links
//! the terms, which is the person's consent — and never from a keypress alone.

use std::time::Duration;

use super::*;
use app_tasks::BgEvent;
use zero_config::HybridMode;
use zeronet_tui::modal::{move_warp_selection, push_warp_step, WarpPhase, WARP_FIRST_STEP};
use zeronet_tui::warp_bootstrap::{Bootstrap, Consent, Step as BootStep};

/// What a finished WARP job hands back.
#[derive(Debug, Clone)]
pub(crate) struct WarpDone {
    /// The profile it changed, or `None` when it made a new one.
    pub(crate) profile: Option<i64>,
    /// The `warp://` link of the account, exits included.
    pub(crate) link: String,
    /// Servers found that work through it.
    pub(crate) exits: usize,
    /// How it connects (`auto`, `masque-h2`, ...).
    pub(crate) route: String,
    /// The account's public fingerprint.
    pub(crate) fingerprint: Option<String>,
}

/// How many servers to look for, how many to try, and for how long.
const WANT: usize = 4;
const SAMPLE: usize = 100;
const SEARCH_BUDGET: Duration = Duration::from_secs(60);
/// The order a new account is written with: a server first ("hybrid"), so
/// Cloudflare is reached through it and the local network never sees
/// Cloudflare. The manage dialog switches it to "reverse hybrid".
const NEW_ORDER: HybridMode = HybridMode::ServerFirst;

/// Make an account through `api`, then finish it with [`with_servers`].
async fn account_via(
    api: &zero_discovery::warp::Api,
    progress: &impl Fn(&str),
) -> Result<WarpDone, String> {
    progress("Asking Cloudflare for an account…");
    let link = zero_discovery::warp::register_with(api, progress).await?;
    Ok(with_servers(link, progress).await)
}

/// A freshly made account with servers for [`NEW_ORDER`] listed on it, and
/// everything worth storing about it.
///
/// The account is useful on its own, so a search that finds nothing is not a
/// failure: the profile is still made, with the tunnel alone as its path.
/// Every way of making an account ends here, so they all have the same shape.
async fn with_servers(link: String, progress: &impl Fn(&str)) -> WarpDone {
    let exits =
        zero_discovery::warp::gather_exits(&link, NEW_ORDER, WANT, SAMPLE, SEARCH_BUDGET, progress)
            .await
            .unwrap_or_default();
    let link =
        zero_discovery::warp::link_with_exits(&link, &exits, NEW_ORDER, false).unwrap_or(link);
    let route = zero_discovery::warp::summarize(&link)
        .map_or("auto", |summary| summary.route)
        .to_string();
    WarpDone {
        profile: None,
        exits: exits.len(),
        route,
        fingerprint: zero_discovery::warp::fingerprint(&link),
        link,
    }
}

/// A progress reporter that forwards a line to the frame loop.
fn progress_into(tx: tokio::sync::mpsc::UnboundedSender<BgEvent>) -> impl Fn(&str) {
    move |line: &str| {
        let _ = tx.send(BgEvent::WarpProgress(line.to_string()));
    }
}

/// The `warp://` link of a stored profile, if it is one.
/// Whether the account behind `link` carries an inner WireGuard device, so it
/// runs WARP inside WARP and exits abroad.
fn runs_warp_in_warp(link: &str) -> bool {
    zero_config::parse_link(link).is_ok_and(|parsed| {
        matches!(
            &parsed.outbound.protocol,
            zero_config::OutboundProtocol::AmneziaWireguard(warp) if warp.inner.is_some()
        )
    })
}

fn warp_link_of(record: &ConfigRecord) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(&record.raw_content).ok()?;
    value
        .get("outbounds")?
        .as_array()?
        .iter()
        .find_map(|outbound| {
            outbound
                .get("link")?
                .as_str()
                .filter(|link| link.starts_with("warp://"))
                .map(str::to_string)
        })
}

/// `raw` (a stored profile's JSON) with its `warp://` link replaced.
fn with_link(raw: &str, link: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut replaced = false;
    for outbound in value.get_mut("outbounds")?.as_array_mut()? {
        let is_warp = outbound
            .get("link")
            .and_then(|l| l.as_str())
            .is_some_and(|l| l.starts_with("warp://"));
        if is_warp {
            outbound["link"] = link.into();
            replaced = true;
        }
    }
    replaced
        .then(|| serde_json::to_string_pretty(&value).ok())
        .flatten()
}

impl App<'_> {
    /// The selected profile, when it is a WARP one: its id, name and link.
    fn selected_warp_profile(&self) -> Option<(i64, String, String)> {
        let record = *self.visible_configs().get(self.selected_config_idx)?;
        Some((record.id, record.remark.clone(), warp_link_of(record)?))
    }

    /// Open the dialog: the manager when a WARP profile is selected, the offer
    /// otherwise, and the work in progress if there is some.
    pub(crate) fn open_warp_dialog(&mut self) {
        // The setup is already showing what it is doing. Recomputing a phase
        // here would replace its question or its progress with the manager's
        // offer, and the two would then race for the same account.
        if self.bg.warp_boot.is_some() {
            self.warp_dialog_open();
            return;
        }
        let phase = if self.bg.warp_in_flight {
            WarpPhase::Working {
                steps: self.bg.warp_steps.clone(),
            }
        } else if let Some((profile, remark, link)) = self.selected_warp_profile() {
            match zero_discovery::warp::summarize(&link) {
                Some(summary) => WarpPhase::Manage {
                    profile,
                    remark,
                    exits: summary.exits,
                    hybrid: summary.hybrid,
                    prefer_exit: summary.prefer_exit,
                    route: summary.route.to_string(),
                    selected: 0,
                },
                None => WarpPhase::Offer,
            }
        } else {
            WarpPhase::Offer
        };
        self.show_warp(phase, true);
    }

    /// Put `phase` on screen: into the open WARP dialog, or (when `open`)
    /// into a new one.
    fn show_warp(&mut self, phase: WarpPhase, open: bool) {
        if let ModalState::Warp { phase: shown, .. } = &mut self.modal_state {
            *shown = phase;
        } else if open {
            self.modal_state = ModalState::Warp {
                phase,
                created_tick: self.effects.current_tick(),
            };
            self.open_modal_effect();
        }
    }

    fn warp_dialog_open(&self) -> bool {
        matches!(self.modal_state, ModalState::Warp { .. })
    }

    /// The dialog's main button: Enter, or a click.
    pub(crate) async fn warp_primary(&mut self) -> Result<()> {
        let ModalState::Warp { phase, .. } = &self.modal_state else {
            return Ok(());
        };
        match phase.clone() {
            WarpPhase::Consent => self.answer_warp_consent(true),
            WarpPhase::Offer => self.start_warp_registration(),
            WarpPhase::Working { .. } => {}
            WarpPhase::Done { profile, .. } => {
                self.close_modal();
                let action = self.connection.connect_to(profile);
                self.apply_engine_action(action).await?;
            }
            WarpPhase::Failed(_) => match self.bg.warp_target {
                Some(profile) => self.start_warp_search(profile),
                None => self.start_warp_registration(),
            },
            WarpPhase::Manage { selected, .. } => self.warp_option(selected),
        }
        Ok(())
    }

    // ------------------------------------------------ automatic WARP setup
    //
    // The setup the connect flow runs the first time: ask about Cloudflare,
    // make an account (borrowing a server for the trip when Cloudflare cannot
    // be reached from here), let the borrowed server go, and dial the
    // account. The sequence itself is `zeronet_tui::warp_bootstrap`; these
    // methods only wait, dial, and feed outcomes back in.

    /// Whether any profile is a Cloudflare WARP account that runs WARP inside
    /// WARP. An account made before that existed exits in the person's own
    /// country, so it does not count: the setup makes a new one.
    fn has_warp_profile(&self) -> bool {
        self.warp_in_warp_profile().is_some()
    }

    /// The first profile that runs WARP inside WARP: the one a connect with
    /// nothing selected goes to.
    ///
    /// The substring tests come first on purpose: this runs on every connect,
    /// and parsing every stored profile's JSON to answer it would be the most
    /// expensive thing a connect button does. Almost no profile mentions the
    /// scheme, so the parser only ever runs on the rare one that does.
    pub(crate) fn warp_in_warp_profile(&self) -> Option<i64> {
        self.configs
            .iter()
            .filter(|record| {
                record
                    .raw_content
                    .contains(zero_config::share_link::WARP_LINK_SCHEME)
            })
            .find(|record| warp_link_of(record).is_some_and(|link| runs_warp_in_warp(&link)))
            .map(|record| record.id)
    }

    /// Ask about Cloudflare the first time a connection is made, and run the
    /// setup when the answer is yes.
    ///
    /// Returns whether the setup has taken over. When it has, the ordinary
    /// connect must not also run, or two connections would race for the same
    /// tunnel. A connect is always waiting behind it: if the setup ends
    /// without dialling, that connect runs instead, so pressing connect always
    /// connects to something.
    pub(crate) fn offer_warp_bootstrap(&mut self) -> bool {
        if self.bg.warp_boot.is_some() {
            return true;
        }
        if self.bg.warp_boot_spent || self.has_warp_profile() {
            return false;
        }
        let consent = Consent::parse(&self.settings.warp_consent);
        if consent == Consent::No {
            return false;
        }
        let online = self.connection.dialled().is_some();
        let Some(machine) = Bootstrap::start(consent, online) else {
            return false;
        };
        let step = machine.step().clone();
        self.bg.warp_boot = Some(machine);
        self.bg.warp_boot_busy = false;
        self.bg.warp_boot_done = None;
        self.bg.warp_boot_defer_connect = true;
        self.bg.warp_steps = vec![WARP_FIRST_STEP.to_string()];
        self.warp_boot_on(step);
        true
    }

    /// Close the WARP dialog by any route — Esc, the second button, the ✕, a
    /// click on the dimmed area.
    ///
    /// While the setup is running this answers the question rather than only
    /// hiding the dialog. The setup is driven *from* the dialog, so closing it
    /// underneath would leave the machine waiting for an answer nobody can
    /// give: every later connect would be swallowed by "something is already
    /// running", with nothing on screen to say so.
    pub(crate) fn dismiss_warp_dialog(&mut self) {
        if self.bg.warp_boot.is_none() {
            self.close_modal();
            return;
        }
        // Answering the question and backing out of work already under way are
        // different acts, and only the first one is an answer. Saving a "no"
        // because someone pressed Esc while it was still registering would
        // switch Cloudflare off for good on a stray keystroke.
        let asking = matches!(
            self.modal_state,
            ModalState::Warp {
                phase: WarpPhase::Consent,
                ..
            }
        );
        if asking {
            self.answer_warp_consent(false);
        } else {
            // Backing out rather than only hiding the dialog, so a server
            // borrowed by now is still let go before the run ends.
            self.warp_boot_cancel();
        }
    }

    /// Remember the answer to the Cloudflare question, so it is asked once.
    fn persist_warp_consent(&mut self, consent: Consent) {
        if self.settings.warp_consent != consent.as_str() {
            self.settings.warp_consent = consent.as_str().to_string();
            self.persist_settings();
        }
    }

    /// The person answered the Cloudflare question. The answer is kept, so it
    /// is asked once and can be changed in Settings afterwards.
    pub(crate) fn answer_warp_consent(&mut self, yes: bool) {
        let consent = if yes { Consent::Yes } else { Consent::No };
        self.persist_warp_consent(consent);
        let Some(machine) = &mut self.bg.warp_boot else {
            return;
        };
        let step = machine.answered(consent);
        self.warp_boot_on(step);
    }

    /// Carry the setup one step further.
    ///
    /// Called once per frame. Each step either starts a job that reports back
    /// through [`BgEvent::WarpBoot`], or does the one thing that has no
    /// waiting in it: letting the borrowed server go, and dialling.
    pub(crate) async fn warp_boot_step(&mut self) -> Result<()> {
        let Some(step) = self.bg.warp_boot.as_ref().map(|m| m.step().clone()) else {
            // Nothing being set up; a connect that was waiting behind it runs.
            if std::mem::take(&mut self.bg.warp_boot_defer_connect) {
                let action = self.connection.connect();
                self.apply_engine_action(action).await?;
            }
            return Ok(());
        };
        match step {
            // Waiting on the person, or on the health check.
            BootStep::Ask | BootStep::Done => Ok(()),
            // Waiting on the search for a server to borrow.
            BootStep::Borrow => {
                if !self.bg.warp_boot_busy && !self.finder.running() {
                    self.bg.warp_boot_busy = true;
                    // Marked before the search starts, not after the tunnel
                    // comes up: the finder may already have asked for a dial
                    // by the time the person backs out.
                    if let Some(machine) = &mut self.bg.warp_boot {
                        machine.borrowing();
                    }
                    self.warp_boot_borrow();
                }
                Ok(())
            }
            BootStep::Declined | BootStep::Failed(_) => {
                self.bg.warp_boot = None;
                // Nothing was made, so do not offer again this session.
                self.bg.warp_boot_spent = true;
                if std::mem::take(&mut self.bg.warp_boot_defer_connect) {
                    let action = self.connection.connect();
                    self.apply_engine_action(action).await?;
                }
                Ok(())
            }
            BootStep::Direct => {
                if !self.bg.warp_boot_busy {
                    self.bg.warp_boot_busy = true;
                    self.warp_boot_probe();
                }
                Ok(())
            }
            BootStep::Register { .. } => {
                if !self.bg.warp_boot_busy {
                    self.bg.warp_boot_busy = true;
                    self.warp_boot_register();
                }
                Ok(())
            }
            BootStep::Release => {
                if !self.bg.warp_boot_busy {
                    self.bg.warp_boot_busy = true;
                    self.warp_boot_release().await?;
                }
                Ok(())
            }
            BootStep::Dial => {
                if !self.bg.warp_boot_busy {
                    self.bg.warp_boot_busy = true;
                    self.warp_boot_dial().await?;
                }
                Ok(())
            }
        }
    }

    /// Put the step's face on the dialog.
    fn warp_boot_on(&mut self, step: BootStep) {
        match step {
            BootStep::Ask => self.show_warp(WarpPhase::Consent, true),
            BootStep::Declined => self.close_modal(),
            BootStep::Failed(ref error) => {
                // The person asked to connect, so the setup failing must not
                // stop that. Say why in one line, get out of the way, and let
                // the ordinary connect run.
                self.toasts
                    .warning(format!("WARP setup did not work: {error}"));
                self.close_modal();
            }
            _ => {
                let steps = self.bg.warp_steps.clone();
                self.show_warp(WarpPhase::Working { steps }, true);
            }
        }
    }

    /// A step of the setup finished: the account it made, or why it could not.
    pub(crate) fn on_warp_boot(&mut self, result: Result<WarpDone, String>) {
        self.bg.warp_boot_busy = false;
        // The step is read *before* the account is put away. A job that
        // finishes after the setup moved on has still registered a device with
        // Cloudflare, and storing an account nobody will ever connect to would
        // leave it there unmentioned; better to say so and let it go. That
        // holds whether the setup has already been dropped, or is still held
        // but sitting on a later step — a cancel that has reached `Declined`
        // and not yet been cleared is the case that happens in practice.
        let Some(step_now) = self.bg.warp_boot.as_ref().map(|m| m.step().clone()) else {
            self.report_orphan_account(result);
            return;
        };
        let outcome = match &result {
            Ok(done) => {
                self.bg.warp_boot_done = Some(done.clone());
                Ok(())
            }
            Err(error) => Err(error.clone()),
        };
        let step = match (step_now, &mut self.bg.warp_boot) {
            (BootStep::Direct, Some(machine)) => machine.direct(outcome),
            (BootStep::Register { .. }, Some(machine)) => machine.registered(outcome),
            _ => {
                // A step that neither feeds the machine nor stores the account
                // would drop it in silence, and it would leave the machine
                // holding an account nothing will ever dial.
                self.bg.warp_boot_done = None;
                self.report_orphan_account(result);
                return;
            }
        };
        self.warp_boot_on(step);
    }

    /// Say that an account was registered with Cloudflare and then not kept.
    ///
    /// A device really is enrolled either way, so this is worth a line: the
    /// person gave permission for exactly one account, and silence would leave
    /// them with one they never learn about.
    fn report_orphan_account(&mut self, result: Result<WarpDone, String>) {
        if let Ok(done) = result {
            self.toasts.warning(format!(
                "A Cloudflare WARP account was made but not kept. {}",
                Self::warp_done_detail(&done)
            ));
        }
    }

    /// A server came up for the trip: make the account through it.
    ///
    /// Called when the tunnel the setup borrowed reaches `Connected`.
    pub(crate) fn warp_boot_borrow_up(&mut self) {
        let Some(machine) = &mut self.bg.warp_boot else {
            return;
        };
        if *machine.step() != BootStep::Borrow {
            return;
        }
        machine.tunnel(Ok(()));
        self.bg.warp_boot_busy = false;
    }

    /// No server came up to make the account through.
    pub(crate) fn warp_boot_borrow_failed(&mut self, reason: &str) {
        let Some(machine) = &mut self.bg.warp_boot else {
            return;
        };
        if *machine.step() != BootStep::Borrow {
            return;
        }
        let step = machine.tunnel(Err(reason.to_string()));
        self.bg.warp_boot_busy = false;
        self.warp_boot_on(step);
    }

    /// The person backed out of the setup.
    pub(crate) fn warp_boot_cancel(&mut self) {
        self.cancel_finder();
        let Some(machine) = &mut self.bg.warp_boot else {
            return;
        };
        let step = machine.cancelled();
        self.bg.warp_boot_busy = false;
        self.warp_boot_on(step);
    }

    /// Put the setup's dialog back after another modal took the screen.
    ///
    /// The setup is driven *from* its dialog, so a modal that replaces it
    /// mid-run — the sudo prompt, when a borrowed server needs elevating before
    /// it can carry the registration — has to give it back when it closes.
    /// Without this the setup carries on with nothing on screen: no progress,
    /// and no way to cancel it, which strands the run and swallows every
    /// connect behind it.
    ///
    /// Only the steps that are still working are restored. A setup that has
    /// just failed or been declined closes its dialog on purpose, and putting
    /// that back would undo the message the person is being shown.
    pub(crate) fn restore_warp_boot_dialog(&mut self) {
        if self.warp_dialog_open() {
            return;
        }
        let Some(step) = self.bg.warp_boot.as_ref().map(|m| m.step().clone()) else {
            return;
        };
        match step {
            BootStep::Ask => self.show_warp(WarpPhase::Consent, true),
            BootStep::Direct
            | BootStep::Borrow
            | BootStep::Register { .. }
            | BootStep::Release
            | BootStep::Dial => {
                let steps = self.bg.warp_steps.clone();
                self.show_warp(WarpPhase::Working { steps }, true);
            }
            BootStep::Done | BootStep::Declined | BootStep::Failed(_) => {}
        }
    }

    /// Stop the setup for good, because the person asked to disconnect.
    ///
    /// This is not the same as backing out of the dialog. Backing out cancels
    /// the *setup* and the connect they already asked for still happens, which
    /// is what the dialog promises. A disconnect says they want no connection
    /// at all, so the connect waiting behind the setup has to go with it —
    /// otherwise the setup runs to the end and either dials the account or
    /// fires the deferred connect, and pressing disconnect connects.
    ///
    /// The borrowed server is left to the disconnect that follows: it tears the
    /// tunnel down whatever else the setup did with it.
    pub(crate) fn warp_boot_stop(&mut self) {
        if self.bg.warp_boot.is_none() {
            return;
        }
        // The search is part of the setup, so it goes with it: left running it
        // would dial whatever it found next and connect a second time.
        self.cancel_finder();
        self.bg.warp_boot = None;
        self.bg.warp_boot_busy = false;
        self.bg.warp_boot_done = None;
        // The connect that was waiting behind the setup is cancelled with it.
        self.bg.warp_boot_defer_connect = false;
        // Not offered again this session. One deliberate stop is an answer, and
        // running the whole thing again on the next connect would be reading it
        // as a mistake. Nothing is written to disk, so the next launch asks
        // afresh.
        self.bg.warp_boot_spent = true;
        // Only the setup's own dialog: a disconnect can be pressed with
        // something else on screen, and that belongs to whoever raised it.
        if self.warp_dialog_open() {
            self.close_modal();
        }
    }

    /// Try the service directly, with a short deadline. If it answers, the
    /// account is made there and then; if it does not, a server is borrowed.
    fn warp_boot_probe(&mut self) {
        self.bg.warp_steps = vec![WARP_FIRST_STEP.to_string()];
        let tx = self.bg.tx.clone();
        let progress = progress_into(tx.clone());
        tokio::spawn(async move {
            let api = zero_discovery::warp::Api::direct()
                .with_timeout(zero_discovery::warp::DIRECT_PROBE);
            let result = account_via(&api, &progress).await;
            let _ = tx.send(BgEvent::WarpBoot(result));
        });
    }

    /// Make the account through the connection in hand: the borrowed server,
    /// or the one the person was already on.
    fn warp_boot_register(&mut self) {
        let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], self.settings.http_port));
        let tx = self.bg.tx.clone();
        let progress = progress_into(tx.clone());
        tokio::spawn(async move {
            let api = zero_discovery::warp::Api::through(proxy);
            let result = account_via(&api, &progress).await;
            let _ = tx.send(BgEvent::WarpBoot(result));
        });
    }

    /// Bring up a server to make the account through, since Cloudflare cannot
    /// be reached from here.
    fn warp_boot_borrow(&mut self) {
        self.toasts.info(
            "Cloudflare is out of reach from here. Bringing up a server to make the account through, then letting it go.",
        );
        self.start_finder(true);
    }

    /// Let the borrowed server go before the account is dialled, so the
    /// tunnel is not rebuilt on top of itself.
    ///
    /// The forget is the point of the call, not a tidy-up: the borrow left
    /// the server it dialled *selected*, and a raw disconnect would leave it
    /// that way, so the connect waiting behind this setup would dial it again
    /// — putting the person back on the server they never chose, which is the
    /// one thing the setup must never leave them on.
    async fn warp_boot_release(&mut self) -> Result<()> {
        let outcome = self
            .apply_engine_action(EngineAction::Disconnect)
            .await
            .map_err(|error| error.to_string());
        self.connection.forget();
        let step = match &mut self.bg.warp_boot {
            Some(machine) => machine.released(outcome),
            None => return Ok(()),
        };
        self.bg.warp_boot_busy = false;
        self.warp_boot_on(step);
        Ok(())
    }

    /// Store the account and dial it. A WARP profile with servers listed
    /// brings them and the tunnel up in the order the account names.
    async fn warp_boot_dial(&mut self) -> Result<()> {
        let Some(done) = self.bg.warp_boot_done.take() else {
            self.bg.warp_boot_busy = false;
            if let Some(machine) = &mut self.bg.warp_boot {
                let step = machine.dialled(Err("the account was not made".into()));
                self.warp_boot_on(step);
            }
            return Ok(());
        };
        let (id, outcome) = match self.store_warp_done(&done) {
            Ok(id) => {
                self.reload_configs();
                self.focus_profile(id);
                let action = self.connection.connect_to(id);
                let result = self.apply_engine_action(action).await;
                (id, result.map_err(|error| error.to_string()))
            }
            Err(error) => {
                // The account is already enrolled at Cloudflare, so a save
                // failure is not only a failed setup: a device exists that the
                // person never sees. It goes in the message, because the next
                // connect will try again and make another one.
                self.toasts.warning(format!(
                    "A Cloudflare WARP account was made but could not be saved: {error}"
                ));
                (0, Err(error))
            }
        };
        self.bg.warp_boot_busy = false;
        let step = match &mut self.bg.warp_boot {
            Some(machine) => machine.dialled(outcome),
            None => return Ok(()),
        };
        if let BootStep::Done = step {
            let phase = self.warp_done_phase(&done, id);
            self.show_warp(phase, false);
            self.bg.warp_boot = None;
            self.bg.warp_boot_defer_connect = false;
        } else {
            self.warp_boot_on(step);
        }
        Ok(())
    }

    /// Store a made account as a profile and return its id.
    fn store_warp_done(&mut self, done: &WarpDone) -> Result<i64, String> {
        match done.profile {
            Some(id) => self.replace_warp_link(id, &done.link).map(|()| id),
            None => zero_config::parse_link(&done.link)
                .map_err(|error| error.to_string())
                .and_then(|link| self.store_share_link(&link).map_err(|e| e.to_string())),
        }
    }

    /// One sentence about the finished account: how it connects, and what it
    /// kept as a failsafe.
    fn warp_done_detail(done: &WarpDone) -> String {
        let servers = match done.exits {
            0 => "No servers were found that work through it yet; you can look again from this dialog."
                .to_string(),
            1 => "1 server works through it and is kept as a failsafe.".to_string(),
            n => format!("{n} servers work through it and are kept as a failsafe."),
        };
        format!(
            "It connects by {}. {servers}",
            match done.route.as_str() {
                "auto" => "trying every way at once and keeping the first that works",
                other => other,
            }
        )
    }

    /// The "it worked" dialog for a finished account.
    fn warp_done_phase(&self, done: &WarpDone, id: i64) -> WarpPhase {
        WarpPhase::Done {
            profile: id,
            headline: if done.profile.is_some() {
                "Servers updated"
            } else {
                "WARP is ready"
            }
            .into(),
            detail: Self::warp_done_detail(done),
            fingerprint: done.fingerprint.clone(),
            finished_tick: self.effects.current_tick(),
        }
    }

    /// Up and down in the manage list.
    pub(crate) fn warp_move(&mut self, delta: i32) {
        if let ModalState::Warp {
            phase: WarpPhase::Manage { selected, .. },
            ..
        } = &mut self.modal_state
        {
            *selected = move_warp_selection(*selected, delta);
        }
    }

    /// One entry of the manage list, chosen by Enter or a click.
    pub(crate) fn warp_option(&mut self, index: usize) {
        let ModalState::Warp {
            phase:
                WarpPhase::Manage {
                    profile,
                    hybrid,
                    prefer_exit,
                    selected,
                    ..
                },
            ..
        } = &mut self.modal_state
        else {
            return;
        };
        *selected = index;
        let (profile, hybrid, prefer_exit) = (*profile, *hybrid, *prefer_exit);
        match index {
            0 => self.start_warp_search(profile),
            // Flipping means the other order, which is the one that is not in
            // force. The sub-choice only exists in the tunnel-first order, so
            // it resets when moving into the server-first one.
            1 => self.flip_warp_order(
                profile,
                match hybrid {
                    HybridMode::ServerFirst => HybridMode::WarpFirst,
                    HybridMode::WarpFirst => HybridMode::ServerFirst,
                },
                matches!(hybrid, HybridMode::WarpFirst) && prefer_exit,
            ),
            _ => self.start_warp_registration(),
        }
    }

    /// Change which order the tunnel and the servers go in, keeping everything
    /// else.
    ///
    /// The two orders are named for what is dialled first, and the dialog says
    /// which one is in force rather than leaving it to be worked out: a server
    /// first means Cloudflare is never reached directly from here, and the
    /// tunnel first means a server is dialled from inside the tunnel.
    fn flip_warp_order(&mut self, profile: i64, hybrid: HybridMode, prefer_exit: bool) {
        let Some(record) = self.config_by_id(profile).cloned() else {
            return;
        };
        let Some(link) = warp_link_of(&record) else {
            return;
        };
        let previous =
            zero_discovery::warp::summarize(&link).map_or(hybrid, |summary| summary.hybrid);
        let changed = zero_discovery::warp::link_with_order(&link, hybrid, prefer_exit)
            .ok()
            .and_then(|new| with_link(&record.raw_content, &new));
        let Some(raw) = changed else {
            self.toasts.warning(
                "Find servers for this account first; there is nothing to go through yet.",
            );
            return;
        };
        if self
            .db
            .update_config_content(profile, &record.address, record.port, &raw)
            .is_err()
        {
            self.toasts.error("Could not save the change.");
            return;
        }
        self.reload_configs();
        if let ModalState::Warp {
            phase:
                WarpPhase::Manage {
                    hybrid: shown,
                    prefer_exit: shown_prefer,
                    ..
                },
            ..
        } = &mut self.modal_state
        {
            *shown = hybrid;
            *shown_prefer = prefer_exit;
        }
        self.toasts.success(match hybrid {
            HybridMode::ServerFirst => {
                "Hybrid now: a server first, Cloudflare's tunnel through it."
            }
            HybridMode::WarpFirst if prefer_exit => {
                "Reverse hybrid now: the tunnel first, a server carries the traffic."
            }
            HybridMode::WarpFirst => {
                "Reverse hybrid now: the tunnel first, a server as the failsafe."
            }
        });
        // The two orders need different servers (reachable from here for
        // hybrid, through the tunnel for reverse hybrid), so the ones listed
        // were found for the other order. Look again for the right kind.
        if hybrid != previous {
            self.start_warp_search(profile);
        }
    }

    /// Ask Cloudflare for a free account, then look for servers that work
    /// through it, and add it all as a profile.
    pub(crate) fn start_warp_registration(&mut self) {
        if self.bg.warp_in_flight {
            self.open_warp_dialog();
            return;
        }
        self.begin_warp_work(None);
        let tunnel = self
            .connection
            .dialled()
            .map(|_| std::net::SocketAddr::from(([127, 0, 0, 1], self.settings.http_port)));
        let tx = self.bg.tx.clone();
        tokio::spawn(async move {
            let progress = {
                let tx = tx.clone();
                move |line: &str| {
                    let _ = tx.send(BgEvent::WarpProgress(line.to_string()));
                }
            };
            let result = async {
                let relay = std::env::var("ZERONET_WARP_RELAY")
                    .ok()
                    .zip(std::env::var("ZERONET_WARP_RELAY_AUTH").ok());
                let link =
                    zero_discovery::warp::register_anywhere(tunnel, None, relay, true, &progress)
                        .await?;
                Ok(with_servers(link, &progress).await)
            }
            .await;
            let _ = tx.send(BgEvent::WarpFinished(result));
        });
    }

    /// Look for servers that work through the account of `profile`, and list
    /// them on it.
    pub(crate) fn start_warp_search(&mut self, profile: i64) {
        if self.bg.warp_in_flight {
            self.open_warp_dialog();
            return;
        }
        let Some(link) = self.config_by_id(profile).and_then(warp_link_of) else {
            return;
        };
        self.begin_warp_work(Some(profile));
        // Searching again must not quietly change the order the person chose,
        // so both halves are read off the link and written back.
        let order = zero_discovery::warp::summarize(&link)
            .map_or((HybridMode::ServerFirst, false), |s| {
                (s.hybrid, s.prefer_exit)
            });
        let tx = self.bg.tx.clone();
        tokio::spawn(async move {
            let progress = {
                let tx = tx.clone();
                move |line: &str| {
                    let _ = tx.send(BgEvent::WarpProgress(line.to_string()));
                }
            };
            let result = async {
                let exits = zero_discovery::warp::gather_exits(
                    &link,
                    order.0,
                    WANT + 1,
                    SAMPLE,
                    SEARCH_BUDGET,
                    &progress,
                )
                .await?;
                if exits.is_empty() {
                    return Err(
                        "No server answered for this account right now. Try again in a while."
                            .to_string(),
                    );
                }
                let new = zero_discovery::warp::link_with_exits(&link, &exits, order.0, order.1)?;
                let route = zero_discovery::warp::summarize(&new)
                    .map_or("auto", |summary| summary.route)
                    .to_string();
                Ok(WarpDone {
                    profile: Some(profile),
                    exits: exits.len(),
                    route,
                    fingerprint: zero_discovery::warp::fingerprint(&new),
                    link: new,
                })
            }
            .await;
            let _ = tx.send(BgEvent::WarpFinished(result));
        });
    }

    fn begin_warp_work(&mut self, target: Option<i64>) {
        self.bg.warp_in_flight = true;
        self.bg.warp_target = target;
        self.bg.warp_steps = vec![WARP_FIRST_STEP.to_string()];
        self.show_warp(
            WarpPhase::Working {
                steps: self.bg.warp_steps.clone(),
            },
            true,
        );
    }

    /// A line of progress from the running job.
    pub(crate) fn on_warp_progress(&mut self, line: String) {
        push_warp_step(&mut self.bg.warp_steps, line);
        if let ModalState::Warp {
            phase: WarpPhase::Working { steps },
            ..
        } = &mut self.modal_state
        {
            *steps = self.bg.warp_steps.clone();
        }
    }

    /// The running job finished: store what it made and say how it went.
    pub(crate) fn on_warp_finished(&mut self, result: Result<WarpDone, String>) {
        self.bg.warp_in_flight = false;
        let done = match result {
            Ok(done) => done,
            Err(reason) => {
                if self.warp_dialog_open() {
                    self.show_warp(WarpPhase::Failed(reason), false);
                } else {
                    self.toasts.error(reason);
                }
                return;
            }
        };
        let id = match self.store_warp_done(&done) {
            Ok(id) => id,
            Err(reason) => {
                let message = format!("The account was made but could not be saved: {reason}");
                if self.warp_dialog_open() {
                    self.show_warp(WarpPhase::Failed(message), false);
                } else {
                    self.toasts.error(message);
                }
                return;
            }
        };
        self.reload_configs();
        self.focus_profile(id);
        if self.warp_dialog_open() {
            let phase = self.warp_done_phase(&done, id);
            self.show_warp(phase, false);
        } else {
            let headline = if done.profile.is_some() {
                "Servers updated"
            } else {
                "WARP is ready"
            };
            self.toasts
                .success(format!("{headline}. {}", Self::warp_done_detail(&done)));
        }
    }

    /// Swap the link inside a stored profile.
    fn replace_warp_link(&mut self, id: i64, link: &str) -> Result<(), String> {
        let record = self
            .config_by_id(id)
            .cloned()
            .ok_or_else(|| "the profile is gone".to_string())?;
        let raw = with_link(&record.raw_content, link)
            .ok_or_else(|| "the profile is not a WARP profile any more".to_string())?;
        self.db
            .update_config_content(id, &record.address, record.port, &raw)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only an account with an inner device counts as WARP inside WARP; an
    /// older account, or any other link, does not.
    #[test]
    fn warp_in_warp_is_told_apart_from_an_older_account() {
        let account = |inner: bool| zero_discovery::warp::Account {
            device_id: "d".into(),
            wireguard_private_key: [4; 32],
            wireguard_peer_key: [2; 32],
            reserved: [1, 2, 3],
            wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
            addresses: vec!["172.16.0.2".parse().unwrap()],
            masque: Some(zero_discovery::warp::MasqueAccount {
                private_key: zero_transport::masque::MasqueKey::generate()
                    .unwrap()
                    .pkcs8()
                    .to_vec(),
                server_public_key: format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        zero_transport::masque::MasqueKey::generate()
                            .unwrap()
                            .spki_der()
                    )
                ),
            }),
            inner: inner.then(|| {
                Box::new(zero_discovery::warp::Account {
                    device_id: "i".into(),
                    wireguard_private_key: [6; 32],
                    wireguard_peer_key: [7; 32],
                    reserved: [4, 5, 6],
                    wireguard_endpoint: "162.159.192.1:2408".parse().unwrap(),
                    addresses: vec!["172.16.0.3".parse().unwrap()],
                    masque: None,
                    inner: None,
                })
            }),
        };
        assert!(runs_warp_in_warp(&account(true).link("auto")));
        assert!(!runs_warp_in_warp(&account(false).link("auto")));
        assert!(!runs_warp_in_warp(
            "vless://00000000-0000-0000-0000-000000000000@example.com:443#x"
        ));
    }

    #[test]
    fn a_warp_profile_is_recognised_by_its_link_and_the_link_can_be_swapped() {
        let raw = serde_json::json!({
            "outbounds": [
                {"tag": "proxy", "link": "warp://abc#WARP"},
                {"tag": "direct", "protocol": "freedom"}
            ]
        })
        .to_string();
        let swapped = with_link(&raw, "warp://def#WARP").unwrap();
        let value: serde_json::Value = serde_json::from_str(&swapped).unwrap();
        assert_eq!(value["outbounds"][0]["link"], "warp://def#WARP");
        assert_eq!(value["outbounds"][1]["protocol"], "freedom");
        // Anything else is left alone.
        let other =
            serde_json::json!({"outbounds": [{"tag": "proxy", "link": "vless://x"}]}).to_string();
        assert!(with_link(&other, "warp://def").is_none());
        assert!(with_link("not json", "warp://def").is_none());
    }
}
