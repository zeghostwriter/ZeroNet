//! "My server": set up a VPS from the app and see who is using it.
//!
//! This is the state and the key handling of that page; drawing is in
//! `ui_servers`, and the network work (SSH, installing, reading usage) is done
//! by tasks the main loop starts for the [`Effect`]s this returns. Nothing here
//! touches the network, so every screen and every key can be tested.
//!
//! The flow, one screen each:
//!
//! 1. **List** of the servers already set up.
//! 2. **Form**: address, login, what to install, and for MasterDNS the domain.
//! 3. **Identity**: the server's fingerprint, to compare with the hosting
//!    panel. No password has been sent yet.
//! 4. **DNS** (MasterDNS only): the two records to create and a check.
//! 5. **Progress**, then 6. **Result** with the configs, and 7. the **server
//!    page** with live usage.
//!
//! The password lives only in the form and in the install job: it is cleared
//! from the form the moment the job is made.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::caret::{self, Caret, Edit};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zero_provision::guide::{self, DnsRecord};
use zero_provision::install::{self, BinarySource, Preset, Step};
use zero_provision::manage::Usage;
use zero_provision::record::{ServerRecord, Service};
use zero_provision::ssh::{Auth, HostKey, Login};

/// Where the list of records is kept in the database.
pub const STORE_KEY: &str = "servers.v1";

/// The longest any form field may get.
const MAX_FIELD: usize = 256;

/// How long a screen takes to settle in when it opens.
pub const SETTLE: Duration = Duration::from_millis(320);

/// How many usage readings the live graphs remember (at [`POLL_EVERY`]).
pub const HISTORY: usize = 48;

/// How often the open server page asks for fresh figures.
pub const POLL_EVERY: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Name,
    Address,
    SshPort,
    User,
    Password,
    KeyFile,
    Reality,
    Xhttp,
    Zerov1,
    MasterDns,
    Domain,
    Connect,
    Cancel,
}

const ORDER: [Field; 13] = [
    Field::Name,
    Field::Address,
    Field::SshPort,
    Field::User,
    Field::Password,
    Field::KeyFile,
    Field::Reality,
    Field::Xhttp,
    Field::Zerov1,
    Field::MasterDns,
    Field::Domain,
    Field::Connect,
    Field::Cancel,
];

/// The "add a server" form.
#[derive(Clone)]
pub struct Form {
    pub name: String,
    pub address: String,
    pub port: String,
    pub user: String,
    /// The login password, or the key's passphrase when [`Form::key_file`] is set.
    pub password: String,
    /// Path of a private SSH key to log in with instead of a password.
    pub key_file: String,
    pub reality: bool,
    pub xhttp: bool,
    pub zerov1: bool,
    pub masterdns: bool,
    pub domain: String,
    pub focus: Field,
    pub error: Option<String>,
    /// The cursor and selection inside the focused text field.
    pub caret: Caret,
    /// Show the password as typed instead of dots (Ctrl+R).
    pub show_password: bool,
}

impl std::fmt::Debug for Form {
    // The password and key path never print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Form")
            .field("address", &self.address)
            .field("focus", &self.focus)
            .finish_non_exhaustive()
    }
}

impl Default for Form {
    fn default() -> Self {
        Self {
            name: "My server".into(),
            address: String::new(),
            port: "22".into(),
            user: "root".into(),
            password: String::new(),
            key_file: String::new(),
            reality: true,
            xhttp: false,
            zerov1: false,
            masterdns: false,
            domain: String::new(),
            focus: Field::Address,
            error: None,
            caret: Caret::default(),
            show_password: false,
        }
    }
}

impl Form {
    /// Whether the focused field takes typed text.
    pub fn typing(&self) -> bool {
        matches!(
            self.focus,
            Field::Name
                | Field::Address
                | Field::SshPort
                | Field::User
                | Field::Password
                | Field::KeyFile
                | Field::Domain
        )
    }

    fn buffer(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::Name => Some(&mut self.name),
            Field::Address => Some(&mut self.address),
            Field::SshPort => Some(&mut self.port),
            Field::User => Some(&mut self.user),
            Field::Password => Some(&mut self.password),
            Field::KeyFile => Some(&mut self.key_file),
            Field::Domain => Some(&mut self.domain),
            _ => None,
        }
    }

    /// Put pasted text in the focused field (first line only, trimmed).
    pub fn paste(&mut self, text: &str) {
        let line = text.lines().next().unwrap_or("").trim().to_string();
        let mut caret = self.caret;
        if let Some(buffer) = self.buffer() {
            caret.clamp_to(buffer);
            caret::insert(buffer, &mut caret, &line, MAX_FIELD);
        }
        self.caret = caret;
    }

    /// Move focus to `field`, with the cursor at the end of its text.
    pub fn set_focus(&mut self, field: Field) {
        self.focus = field;
        let at_end = self.buffer().map(|text| Caret::at_end(text));
        self.caret = at_end.unwrap_or_default();
    }

    /// The text of the focused field, if it takes text.
    pub fn focused_text(&self) -> Option<&str> {
        match self.focus {
            Field::Name => Some(&self.name),
            Field::Address => Some(&self.address),
            Field::SshPort => Some(&self.port),
            Field::User => Some(&self.user),
            Field::Password => Some(&self.password),
            Field::KeyFile => Some(&self.key_file),
            Field::Domain => Some(&self.domain),
            _ => None,
        }
    }

    /// Whether the service tiles are all ticked (domain needed for DNS aside).
    pub fn all_services(&self) -> bool {
        self.reality && self.xhttp && self.zerov1 && self.masterdns
    }

    /// Tick every service, or untick them all when they already are.
    pub fn toggle_all_services(&mut self) {
        let to = !self.all_services();
        self.reality = to;
        self.xhttp = to;
        self.zerov1 = to;
        self.masterdns = to;
    }

    /// Whether anything in the focused text is selected.
    pub fn has_selection(&self) -> bool {
        self.typing() && self.caret.selection().is_some()
    }

    fn step(&mut self, delta: i32) {
        let at = ORDER.iter().position(|f| *f == self.focus).unwrap_or(0) as i32;
        let n = ORDER.len() as i32;
        let mut next = (at + delta).rem_euclid(n);
        // The domain field is skipped while MasterDNS is not chosen.
        if ORDER[next as usize] == Field::Domain && !self.masterdns {
            next = (next + delta.signum()).rem_euclid(n);
        }
        self.set_focus(ORDER[next as usize]);
    }

    /// Check the form, returning what the install needs or what is wrong.
    pub fn validate(&self) -> Result<Checked, String> {
        let address = self.address.trim();
        if address.is_empty() {
            return Err("Type the server's address (its IP).".into());
        }
        if address.contains(char::is_whitespace) || address.contains("://") {
            return Err("The address is just the IP, like 203.0.113.7.".into());
        }
        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| "The SSH port is a number, usually 22.".to_string())?;
        if self.user.trim().is_empty() {
            return Err("Type the login user (usually root).".into());
        }
        let key = match self.key_file.trim() {
            "" if self.password.is_empty() => {
                return Err("Type the server's password, or the path of your SSH key file.".into())
            }
            "" => None,
            path => Some(read_key_file(path)?),
        };
        if !self.reality && !self.xhttp && !self.zerov1 && !self.masterdns {
            return Err("Choose what to install.".into());
        }
        let domain = if self.masterdns {
            Some(guide::clean_domain(&self.domain).map_err(|e| e.to_string())?)
        } else {
            None
        };
        Ok(Checked {
            address: address.to_string(),
            port,
            user: self.user.trim().to_string(),
            domain,
            key,
        })
    }
}

/// Read a private key file (a leading `~/` is the home folder). Says what is
/// wrong without echoing the file: the usual mistake is picking the `.pub`.
fn read_key_file(path: &str) -> Result<String, String> {
    let full = match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => std::path::Path::new(&home).join(rest),
        _ => std::path::PathBuf::from(path),
    };
    // A private key is a few kilobytes; a big file is not one.
    let meta = std::fs::metadata(&full).map_err(|e| format!("Cannot read {path}: {e}"))?;
    if !meta.is_file() || meta.len() > 64 * 1024 {
        return Err(format!("{path} is not a private key file."));
    }
    let text = std::fs::read_to_string(&full).map_err(|e| format!("Cannot read {path}: {e}"))?;
    if text.contains("PRIVATE KEY") || text.contains("PuTTY-User-Key-File") {
        Ok(text)
    } else {
        Err(format!(
            "{path} is not a private key (it should start with -----BEGIN ... PRIVATE KEY-----). Did you pick the .pub file?"
        ))
    }
}

/// A form that passed [`Form::validate`].
#[derive(Clone)]
pub struct Checked {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub domain: Option<String>,
    /// The private key's text, when a key file was given. Never printed.
    pub key: Option<String>,
}

impl std::fmt::Debug for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checked")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StepState {
    Waiting,
    Running,
    Done,
}

#[derive(Clone, Debug)]
pub struct ProgressView {
    pub steps: Vec<(Step, Option<Preset>, StepState)>,
    pub of: usize,
    pub detail: String,
    /// Set when the install stopped; the person reads it and goes back.
    pub failed: Option<String>,
}

/// How the DNS check came out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsStatus {
    NotChecked,
    Checking,
    /// The `A` record of the name server host points at the server.
    Right,
    /// It resolves, but not to this server.
    Wrong,
    /// No resolver answered, or the record does not exist yet.
    Unknown,
}

#[derive(Clone)]
pub enum Screen {
    List,
    /// Waiting on the network for something short.
    Busy(String),
    Form(Form),
    Identity {
        form: Form,
        checked: Checked,
        key: HostKey,
    },
    Dns {
        form: Form,
        checked: Checked,
        key: HostKey,
        records: Vec<DnsRecord>,
        status: DnsStatus,
    },
    Progress(ProgressView),
    Result {
        record: Box<ServerRecord>,
        notes: Vec<install::Note>,
        /// Which config the QR code shows.
        shown: usize,
    },
    /// The page of one server, live.
    Server {
        id: String,
        shown: usize,
    },
    ConfirmRemove {
        id: String,
        typed: String,
    },
}

/// What the main loop must do. Each is a request, never a result.
pub enum Effect {
    FetchHostKey {
        host: String,
        port: u16,
    },
    CheckDns {
        ns_host: String,
        server: String,
    },
    Install(Box<InstallJob>),
    Usage {
        id: String,
    },
    Remove {
        id: String,
    },
    /// Write what changed to the database.
    Save,
    Copy(String),
    /// Save a service's client files into a folder and say where.
    SaveFiles {
        id: String,
    },
    /// Check from this machine that a MasterDNS server answers.
    Probe {
        id: String,
    },
}

/// Everything the install task needs; the password leaves the form here.
pub struct InstallJob {
    pub login: Login,
    pub host_key: HostKey,
    pub request: install::Request,
}

/// What the tasks report back.
pub enum Event {
    HostKey(Result<HostKey, String>),
    Dns(DnsStatus),
    Install(install::Event),
    Installed(Result<Box<install::Outcome>, String>),
    Usage(String, Result<Usage, String>),
    Removed(String, Result<(), String>),
    Probed(String, String),
}

/// The page's whole state.
pub struct ServersState {
    pub records: Vec<ServerRecord>,
    pub screen: Screen,
    pub selected: usize,
    /// Latest usage per record id, and when it arrived.
    pub usage: HashMap<String, (Usage, Instant)>,
    /// Why the latest usage read failed, per record id.
    pub usage_error: HashMap<String, String>,
    /// A line shown under the page: the last thing that happened.
    pub notice: Option<String>,
    /// Show the config's QR code on its own, large enough to scan.
    pub show_qr: bool,
    /// The form and what it checked, held while the host key is fetched.
    pending: Option<(Form, Checked)>,
    /// A usage read is in flight.
    polling: bool,
    /// When the open server page last asked for figures.
    last_poll: Option<Instant>,
    /// Servers ticked in the list (Space, or Ctrl+A for all of them).
    pub marked: HashSet<String>,
    /// Every config of the open server is selected (Ctrl+A): copy takes all.
    pub all_configs: bool,
    /// Recent readings per server, for the live graphs: devices connected now
    /// and total bytes down, oldest first.
    history: HashMap<String, VecDeque<(u64, u64)>>,
    /// The cursor inside the "type remove" box.
    pub confirm_caret: Caret,
    /// When the screen on show opened, for the settle-in animation, and which
    /// kind of screen it is (to notice a change).
    entered: Instant,
    kind: std::mem::Discriminant<Screen>,
}

impl Default for ServersState {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl ServersState {
    pub fn new(records: Vec<ServerRecord>) -> Self {
        Self {
            records,
            screen: Screen::List,
            selected: 0,
            usage: HashMap::new(),
            usage_error: HashMap::new(),
            notice: None,
            show_qr: false,
            pending: None,
            polling: false,
            last_poll: None,
            marked: HashSet::new(),
            all_configs: false,
            history: HashMap::new(),
            confirm_caret: Caret::default(),
            entered: Instant::now(),
            kind: std::mem::discriminant(&Screen::List),
        }
    }

    /// Parse the stored list; a damaged or newer file is an empty list rather
    /// than a crash, and the person is told.
    pub fn load(json: Option<&str>) -> Self {
        let records = json
            .and_then(|text| serde_json::from_str::<Vec<ServerRecord>>(text).ok())
            .unwrap_or_default();
        Self::new(records)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.records).unwrap_or_else(|_| "[]".into())
    }

    /// Whether printable keys are text right now (the key router must not
    /// treat them as commands).
    pub fn typing(&self) -> bool {
        match &self.screen {
            Screen::Form(form) => form.typing(),
            Screen::ConfirmRemove { .. } => true,
            _ => false,
        }
    }

    /// The record currently open, if any.
    pub fn open(&self) -> Option<&ServerRecord> {
        match &self.screen {
            Screen::Server { id, .. } | Screen::ConfirmRemove { id, .. } => {
                self.records.iter().find(|r| &r.id == id)
            }
            _ => None,
        }
    }

    pub fn record(&self, id: &str) -> Option<&ServerRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Handle a key. `None` means the page did not use it and the app may.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Vec<Effect>> {
        let result = self.on_key_inner(key);
        self.note_screen();
        result
    }

    /// Remember when the screen on show changed, so it can settle in.
    fn note_screen(&mut self) {
        let kind = std::mem::discriminant(&self.screen);
        if kind != self.kind {
            self.kind = kind;
            self.entered = Instant::now();
            self.all_configs = false;
            self.confirm_caret = Caret::default();
        }
    }

    /// How far the screen on show has settled in: 0.0 as it opens, 1.0 once
    /// it is done.
    pub fn settled(&self, now: Instant) -> f64 {
        let t = now.saturating_duration_since(self.entered).as_secs_f64() / SETTLE.as_secs_f64();
        t.clamp(0.0, 1.0)
    }

    /// Whether the next frame would differ from this one without any input:
    /// a screen settling in, or one that is waiting on the network and shows
    /// it moving.
    pub fn animating(&self, now: Instant) -> bool {
        if self.settled(now) < 1.0 {
            return true;
        }
        match &self.screen {
            Screen::Busy(_) => true,
            Screen::Progress(view) => view.failed.is_none(),
            Screen::Dns { status, .. } => *status == DnsStatus::Checking,
            _ => false,
        }
    }

    /// Whether Ctrl+C means "copy" right now (something is selected) and not
    /// "quit": the app asks before it treats the key as its own.
    pub fn wants_ctrl_c(&self) -> bool {
        match &self.screen {
            Screen::Form(form) => form.has_selection(),
            Screen::ConfirmRemove { .. } => self.confirm_caret.selection().is_some(),
            Screen::Server { .. } | Screen::Result { .. } => self.all_configs,
            Screen::List => !self.marked.is_empty(),
            _ => false,
        }
    }

    /// The live readings of one server, oldest first: `(devices now, bytes
    /// down in total)`.
    pub fn history(&self, id: &str) -> Vec<(u64, u64)> {
        self.history
            .get(id)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default()
    }

    fn on_key_inner(&mut self, key: KeyEvent) -> Option<Vec<Effect>> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match self.screen.clone() {
            Screen::List => self.list_key(key),
            Screen::Busy(_) => match key.code {
                KeyCode::Esc => {
                    self.screen = Screen::List;
                    Some(Vec::new())
                }
                _ => Some(Vec::new()),
            },
            Screen::Form(mut form) => {
                // Function keys, and Ctrl combinations a text box has no use
                // for (Ctrl+Q to quit, say), belong to the app, not the form.
                let keeps = "acxukwsrv";
                if matches!(key.code, KeyCode::F(_))
                    || (ctrl
                        && matches!(key.code, KeyCode::Char(c) if !keeps.contains(c.to_ascii_lowercase())))
                {
                    return None;
                }
                let effects = self.form_key(&mut form, key, ctrl);
                if let Screen::Form(_) = self.screen {
                    self.screen = Screen::Form(form);
                }
                Some(effects)
            }
            Screen::Identity {
                form,
                checked,
                key: host_key,
            } => Some(self.identity_key(key, form, checked, host_key)),
            Screen::Dns {
                form,
                checked,
                key: host_key,
                records,
                ..
            } => Some(self.dns_key(key, form, checked, host_key, records)),
            Screen::Progress(view) => {
                if view.failed.is_some() && matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    self.screen = Screen::List;
                }
                Some(Vec::new())
            }
            Screen::Result { record, shown, .. } => Some(self.result_key(key, &record, shown)),
            Screen::Server { id, shown } => self.server_key(key, &id, shown),
            Screen::ConfirmRemove { id, typed } => Some(self.confirm_key(key, &id, typed)),
        }
    }

    fn list_key(&mut self, key: KeyEvent) -> Option<Vec<Effect>> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Select everything: every server in the list is ticked.
            KeyCode::Char('a') | KeyCode::Char('A') if ctrl => {
                self.marked = self.records.iter().map(|r| r.id.clone()).collect();
                self.notice = (!self.records.is_empty()).then(|| {
                    format!(
                        "{} selected.  c copy their configs   r refresh   Esc clear",
                        self.marked.len()
                    )
                });
                Some(Vec::new())
            }
            KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char('n') if !ctrl => {
                self.screen = Screen::Form(Form::default());
                Some(Vec::new())
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Some(Vec::new())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.records.len() {
                    self.selected += 1;
                }
                Some(Vec::new())
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.selected = 0;
                Some(Vec::new())
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.selected = self.records.len().saturating_sub(1);
                Some(Vec::new())
            }
            KeyCode::Char(' ') => {
                let id = self.records.get(self.selected)?.id.clone();
                if !self.marked.remove(&id) {
                    self.marked.insert(id);
                }
                Some(Vec::new())
            }
            KeyCode::Esc if !self.marked.is_empty() => {
                self.marked.clear();
                self.notice = None;
                Some(Vec::new())
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                let text = self.configs_text_of(&self.chosen_ids());
                if text.is_empty() {
                    return None;
                }
                Some(vec![Effect::Copy(text)])
            }
            KeyCode::Char('r') | KeyCode::Char('R') if !self.records.is_empty() => Some(
                self.chosen_ids()
                    .into_iter()
                    .map(|id| Effect::Usage { id })
                    .collect(),
            ),
            KeyCode::Enter => {
                let id = self.records.get(self.selected)?.id.clone();
                self.screen = Screen::Server {
                    id: id.clone(),
                    shown: 0,
                };
                self.show_qr = false;
                self.last_poll = None;
                Some(vec![Effect::Usage { id }])
            }
            _ => None,
        }
    }

    /// The servers an action in the list applies to: the ticked ones, or the
    /// one under the cursor when none is ticked.
    fn chosen_ids(&self) -> Vec<String> {
        if self.marked.is_empty() {
            self.records
                .get(self.selected)
                .map(|r| vec![r.id.clone()])
                .unwrap_or_default()
        } else {
            self.records
                .iter()
                .filter(|r| self.marked.contains(&r.id))
                .map(|r| r.id.clone())
                .collect()
        }
    }

    /// The links (or first file) of every config of the given servers, one
    /// per line, in list order.
    fn configs_text_of(&self, ids: &[String]) -> String {
        self.records
            .iter()
            .filter(|r| ids.contains(&r.id))
            .flat_map(|record| {
                (0..record.client_configs().len()).filter_map(|i| copy_text(record, i))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn form_key(&mut self, form: &mut Form, key: KeyEvent, ctrl: bool) -> Vec<Effect> {
        // Keys that belong to the form as a whole come first; whatever is
        // left is text, when a text field has focus.
        match key.code {
            KeyCode::Esc => {
                // A selection goes first, as in any text box; then the form.
                if form.caret.selection().is_some() {
                    form.caret.anchor = None;
                } else {
                    self.screen = Screen::List;
                }
                return Vec::new();
            }
            KeyCode::Tab | KeyCode::Down => form.step(1),
            KeyCode::BackTab | KeyCode::Up => form.step(-1),
            KeyCode::Enter => {
                if form.focus == Field::Cancel {
                    self.screen = Screen::List;
                    return Vec::new();
                }
                if form.focus == Field::Connect || ctrl {
                    return self.submit(form);
                }
                match form.focus {
                    Field::Reality => form.reality = !form.reality,
                    Field::Xhttp => form.xhttp = !form.xhttp,
                    Field::Zerov1 => form.zerov1 = !form.zerov1,
                    Field::MasterDns => form.masterdns = !form.masterdns,
                    _ => form.step(1),
                }
            }
            KeyCode::Char('s') | KeyCode::Char('S') if ctrl => return self.submit(form),
            KeyCode::Char('r') | KeyCode::Char('R') if ctrl => {
                form.show_password = !form.show_password;
            }
            // Outside a text box Ctrl+A ticks every service (or clears them).
            KeyCode::Char('a') | KeyCode::Char('A') if ctrl && !form.typing() => {
                form.toggle_all_services();
            }
            KeyCode::Char(' ')
                if matches!(
                    form.focus,
                    Field::Reality | Field::Xhttp | Field::Zerov1 | Field::MasterDns
                ) =>
            {
                match form.focus {
                    Field::Reality => form.reality = !form.reality,
                    Field::Xhttp => form.xhttp = !form.xhttp,
                    Field::Zerov1 => form.zerov1 = !form.zerov1,
                    _ => form.masterdns = !form.masterdns,
                }
            }
            // Between the tiles and between the two buttons, Left and Right
            // move like Tab.
            KeyCode::Left
                if matches!(
                    form.focus,
                    Field::Reality
                        | Field::Xhttp
                        | Field::Zerov1
                        | Field::MasterDns
                        | Field::Cancel
                ) =>
            {
                form.step(-1)
            }
            KeyCode::Right
                if matches!(
                    form.focus,
                    Field::Reality
                        | Field::Xhttp
                        | Field::Zerov1
                        | Field::MasterDns
                        | Field::Connect
                ) =>
            {
                form.step(1)
            }
            _ if form.typing() => {
                let max = MAX_FIELD;
                let mut caret = form.caret;
                let focus = form.focus;
                let edit = match form.buffer() {
                    Some(text) => caret::apply(text, &mut caret, key, max),
                    None => Edit::Ignored,
                };
                form.caret = caret;
                let _ = focus;
                match edit {
                    Edit::Copy(text) | Edit::Cut(text) => return vec![Effect::Copy(text)],
                    Edit::Changed | Edit::Moved | Edit::Ignored => {}
                }
            }
            _ => {}
        }
        form.error = None;
        Vec::new()
    }

    fn submit(&mut self, form: &mut Form) -> Vec<Effect> {
        match form.validate() {
            Err(message) => {
                form.error = Some(message);
                Vec::new()
            }
            Ok(checked) => {
                let effect = Effect::FetchHostKey {
                    host: checked.address.clone(),
                    port: checked.port,
                };
                self.pending = Some((form.clone(), checked));
                self.screen = Screen::Busy("Contacting the server…".into());
                vec![effect]
            }
        }
    }

    fn identity_key(
        &mut self,
        key: KeyEvent,
        form: Form,
        checked: Checked,
        host_key: HostKey,
    ) -> Vec<Effect> {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Form(form),
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                return self.after_identity(form, checked, host_key);
            }
            _ => {}
        }
        Vec::new()
    }

    /// The fingerprint was accepted: MasterDNS needs the domain set up first,
    /// anything else installs now.
    fn after_identity(&mut self, form: Form, checked: Checked, host_key: HostKey) -> Vec<Effect> {
        let Some(domain) = checked.domain.clone().filter(|_| form.masterdns) else {
            return self.start_install(form, checked, host_key);
        };
        let records = match checked.address.parse::<IpAddr>() {
            Ok(ip) => guide::delegation_records(&domain, ip),
            // A server given by name: the records need its address, which the
            // person must look up; show the shape with a placeholder.
            Err(_) => guide::delegation_records(&domain, IpAddr::from([0, 0, 0, 0])),
        };
        self.screen = Screen::Dns {
            form,
            checked,
            key: host_key,
            records,
            status: DnsStatus::NotChecked,
        };
        Vec::new()
    }

    fn dns_key(
        &mut self,
        key: KeyEvent,
        form: Form,
        checked: Checked,
        host_key: HostKey,
        records: Vec<DnsRecord>,
    ) -> Vec<Effect> {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Form(form),
            KeyCode::Char('1') | KeyCode::Char('2') | KeyCode::Char('3') | KeyCode::Char('4') => {
                // 1/2 copy the first record's name/value, 3/4 the second's.
                let KeyCode::Char(c) = key.code else {
                    return Vec::new();
                };
                let n = (c as usize - '1' as usize) / 2;
                if let Some(record) = records.get(n) {
                    let text = if (c as usize - '1' as usize).is_multiple_of(2) {
                        record.name.clone()
                    } else {
                        record.value.clone()
                    };
                    return vec![Effect::Copy(text)];
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                let Some(domain) = checked.domain.clone() else {
                    return Vec::new();
                };
                let effect = Effect::CheckDns {
                    ns_host: guide::ns_host(&domain),
                    server: checked.address.clone(),
                };
                self.screen = Screen::Dns {
                    form,
                    checked,
                    key: host_key,
                    records,
                    status: DnsStatus::Checking,
                };
                return vec![effect];
            }
            KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('I') => {
                return self.start_install(form, checked, host_key);
            }
            _ => {}
        }
        Vec::new()
    }

    /// Build the install job. The password leaves the form here and lives only
    /// in the job.
    fn start_install(&mut self, form: Form, checked: Checked, host_key: HostKey) -> Vec<Effect> {
        let login = Login {
            host: checked.address.clone(),
            port: checked.port,
            user: checked.user.clone(),
            auth: match &checked.key {
                Some(pem) => Auth::UserKey {
                    pem: pem.clone(),
                    passphrase: Some(form.password.clone()).filter(|p| !p.is_empty()),
                },
                None => Auth::Password(form.password.clone()),
            },
        };
        let request = install::Request {
            name: form.name.trim().to_string(),
            first_user: "Main".into(),
            reality: form.reality.then(|| install::RealityRequest {
                sni: DEFAULT_SNI.into(),
                port: None,
            }),
            xhttp: form.xhttp.then(|| install::XhttpRequest {
                sni: DEFAULT_SNI.into(),
                port: None,
            }),
            zerov1: form.zerov1.then(|| install::Zerov1Request {
                sni: DEFAULT_SNI.into(),
                port: None,
            }),
            masterdns: checked
                .domain
                .clone()
                .filter(|_| form.masterdns)
                .map(|domain| install::MasterDnsRequest { domain }),
            binary: BinarySource::Release { tag: None },
            keep_access: true,
        };
        self.screen = Screen::Progress(ProgressView {
            steps: Vec::new(),
            of: 0,
            detail: "Starting…".into(),
            failed: None,
        });
        vec![Effect::Install(Box::new(InstallJob {
            login,
            host_key,
            request,
        }))]
    }

    fn result_key(&mut self, key: KeyEvent, record: &ServerRecord, shown: usize) -> Vec<Effect> {
        let count = record.client_configs().len().max(1);
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('a') | KeyCode::Char('A') if ctrl => self.select_all_configs(record),
            KeyCode::Left | KeyCode::Char('h') => {
                self.all_configs = false;
                self.set_shown(shown.checked_sub(1).unwrap_or(count - 1))
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.all_configs = false;
                self.set_shown((shown + 1) % count)
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if let Some(text) = self.copy_selected(record, shown) {
                    return vec![Effect::Copy(text)];
                }
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                return vec![Effect::SaveFiles {
                    id: record.id.clone(),
                }];
            }
            KeyCode::Char('o') | KeyCode::Char('O') => self.show_qr = !self.show_qr,
            KeyCode::Esc if self.show_qr => self.show_qr = false,
            KeyCode::Esc if self.all_configs => self.all_configs = false,
            KeyCode::Enter | KeyCode::Esc => {
                self.last_poll = None;
                self.screen = Screen::Server {
                    id: record.id.clone(),
                    shown,
                };
                return vec![Effect::Usage {
                    id: record.id.clone(),
                }];
            }
            _ => {}
        }
        Vec::new()
    }

    /// Ctrl+A on a server's configs: all of them selected, ready to copy.
    fn select_all_configs(&mut self, record: &ServerRecord) {
        self.all_configs = true;
        self.notice = Some(format!(
            "All {} configs selected.  c copy them   Esc clear",
            record.client_configs().len()
        ));
    }

    /// What `c` copies: every config's link when all are selected, else the
    /// one on show.
    fn copy_selected(&self, record: &ServerRecord, shown: usize) -> Option<String> {
        if self.all_configs {
            let all = self.configs_text_of(std::slice::from_ref(&record.id));
            return (!all.is_empty()).then_some(all);
        }
        copy_text(record, shown)
    }

    fn set_shown(&mut self, to: usize) {
        match &mut self.screen {
            Screen::Result { shown, .. } | Screen::Server { shown, .. } => *shown = to,
            _ => {}
        }
    }

    fn server_key(&mut self, key: KeyEvent, id: &str, shown: usize) -> Option<Vec<Effect>> {
        let record = self.record(id)?.clone();
        let count = record.client_configs().len().max(1);
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('a') | KeyCode::Char('A') if ctrl => self.select_all_configs(&record),
            KeyCode::Esc if self.show_qr => self.show_qr = false,
            KeyCode::Esc if self.all_configs => {
                self.all_configs = false;
                self.notice = None;
            }
            KeyCode::Char('o') | KeyCode::Char('O') => self.show_qr = !self.show_qr,
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Left | KeyCode::Char('h') => {
                self.all_configs = false;
                self.set_shown(shown.checked_sub(1).unwrap_or(count - 1))
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.all_configs = false;
                self.set_shown((shown + 1) % count)
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.last_poll = None;
                return Some(self.tick(Instant::now()));
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if let Some(text) = self.copy_selected(&record, shown) {
                    return Some(vec![Effect::Copy(text)]);
                }
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                return Some(vec![Effect::SaveFiles { id: record.id }]);
            }
            KeyCode::Char('t') | KeyCode::Char('T')
                if record
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::MasterDns(_))) =>
            {
                return Some(vec![Effect::Probe { id: record.id }]);
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.screen = Screen::ConfirmRemove {
                    id: record.id,
                    typed: String::new(),
                };
            }
            _ => return None,
        }
        Some(Vec::new())
    }

    fn confirm_key(&mut self, key: KeyEvent, id: &str, mut typed: String) -> Vec<Effect> {
        let back = |typed: String| Screen::ConfirmRemove {
            id: id.to_string(),
            typed,
        };
        match key.code {
            KeyCode::Esc if self.confirm_caret.selection().is_some() => {
                self.confirm_caret.anchor = None;
            }
            KeyCode::Esc => {
                self.screen = Screen::Server {
                    id: id.to_string(),
                    shown: 0,
                }
            }
            KeyCode::Enter if typed.trim().eq_ignore_ascii_case(CONFIRM_WORD) => {
                self.screen = Screen::Busy("Removing everything from the server…".into());
                return vec![Effect::Remove { id: id.to_string() }];
            }
            _ => {
                let mut caret = self.confirm_caret;
                let edit = caret::apply(&mut typed, &mut caret, key, 16);
                self.confirm_caret = caret;
                self.screen = back(typed);
                if let Edit::Copy(text) | Edit::Cut(text) = edit {
                    return vec![Effect::Copy(text)];
                }
            }
        }
        Vec::new()
    }

    /// Paste into the form's focused field.
    pub fn paste(&mut self, text: &str) {
        if let Screen::Form(form) = &mut self.screen {
            form.paste(text);
        }
    }

    /// Called about once a second: asks for fresh figures while a server's page
    /// is open, never more often than [`POLL_EVERY`] and never two at once.
    pub fn tick(&mut self, now: Instant) -> Vec<Effect> {
        let Screen::Server { id, .. } = &self.screen else {
            return Vec::new();
        };
        if self.polling
            || self
                .last_poll
                .is_some_and(|at| now.duration_since(at) < POLL_EVERY)
        {
            return Vec::new();
        }
        self.polling = true;
        self.last_poll = Some(now);
        vec![Effect::Usage { id: id.clone() }]
    }

    /// Take what a task reports. Returns effects to run after it.
    pub fn on_event(&mut self, event: Event) -> Vec<Effect> {
        let effects = self.on_event_inner(event);
        self.note_screen();
        effects
    }

    fn on_event_inner(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::HostKey(result) => {
                let Some((mut form, checked)) = self.pending.take() else {
                    return Vec::new();
                };
                if !matches!(self.screen, Screen::Busy(_)) {
                    return Vec::new();
                }
                match result {
                    Ok(key) => self.screen = Screen::Identity { form, checked, key },
                    Err(message) => {
                        form.error = Some(message);
                        self.screen = Screen::Form(form);
                    }
                }
            }
            Event::Dns(found) => {
                if let Screen::Dns { status, .. } = &mut self.screen {
                    *status = found;
                }
            }
            Event::Install(event) => {
                if let Screen::Progress(view) = &mut self.screen {
                    match event {
                        install::Event::Step {
                            step, preset, of, ..
                        } => {
                            for (_, _, state) in view.steps.iter_mut() {
                                *state = StepState::Done;
                            }
                            view.steps.push((step, preset, StepState::Running));
                            view.of = of;
                        }
                        install::Event::Detail(text) => view.detail = text,
                    }
                }
            }
            Event::Installed(Ok(outcome)) => {
                let outcome = *outcome;
                let record = outcome.record;
                self.records.retain(|r| r.id != record.id);
                self.records.push(record.clone());
                self.selected = self.records.len() - 1;
                self.screen = Screen::Result {
                    record: Box::new(record),
                    notes: outcome.notes,
                    shown: 0,
                };
                return vec![Effect::Save];
            }
            Event::Installed(Err(message)) => {
                if let Screen::Progress(view) = &mut self.screen {
                    view.failed = Some(message);
                }
            }
            Event::Usage(id, result) => {
                self.polling = false;
                match result {
                    Ok(usage) => {
                        self.usage_error.remove(&id);
                        let down: u64 = usage.inbounds.iter().map(|i| i.downlink).sum();
                        let samples = self.history.entry(id.clone()).or_default();
                        samples.push_back((usage.devices_now(), down));
                        while samples.len() > HISTORY {
                            samples.pop_front();
                        }
                        self.usage.insert(id, (usage, Instant::now()));
                    }
                    Err(message) => {
                        self.usage_error.insert(id, message);
                    }
                }
            }
            Event::Removed(id, Ok(())) => {
                self.records.retain(|r| r.id != id);
                self.usage.remove(&id);
                self.usage_error.remove(&id);
                self.history.remove(&id);
                self.marked.remove(&id);
                self.selected = self.selected.min(self.records.len().saturating_sub(1));
                self.screen = Screen::List;
                self.notice = Some("Removed. The server is clean again.".into());
                return vec![Effect::Save];
            }
            Event::Removed(id, Err(message)) => {
                self.notice = Some(message);
                self.screen = Screen::Server { id, shown: 0 };
            }
            Event::Probed(id, text) => {
                self.notice = Some(text);
                let _ = id;
            }
        }
        Vec::new()
    }
}

/// What "copy" puts on the clipboard for the config at `shown`: its link, or
/// the first file for configs that are files.
pub fn copy_text(record: &ServerRecord, shown: usize) -> Option<String> {
    let configs = record.client_configs();
    let config = configs.get(shown)?;
    config
        .link
        .clone()
        .or_else(|| config.files.first().map(|f| f.text.clone()))
}

/// The word typed to confirm taking a server's setup away.
pub const CONFIRM_WORD: &str = "remove";

/// The website a new REALITY server pretends to be for strangers.
const DEFAULT_SNI: &str = "www.microsoft.com";

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(state: &mut ServersState, text: &str) {
        for c in text.chars() {
            state.on_key(key(KeyCode::Char(c)));
        }
    }

    fn form_ready(state: &mut ServersState) {
        state.on_key(key(KeyCode::Char('a')));
        // Address is focused first.
        type_text(state, "203.0.113.7");
        state.on_key(key(KeyCode::Tab)); // port
        state.on_key(key(KeyCode::Tab)); // user
        state.on_key(key(KeyCode::Tab)); // password
        type_text(state, "hunter2");
    }

    fn fake_key() -> HostKey {
        HostKey {
            fingerprint: "SHA256:abc".into(),
            algorithm: "ssh-ed25519".into(),
        }
    }

    #[test]
    fn validation_says_what_is_wrong() {
        let mut form = Form::default();
        assert!(form.validate().unwrap_err().contains("address"));
        form.address = "https://x".into();
        assert!(form.validate().is_err());
        form.address = "203.0.113.7".into();
        assert!(form.validate().unwrap_err().contains("password"));
        form.password = "pw".into();
        let checked = form.validate().unwrap();
        assert_eq!((checked.port, checked.user.as_str()), (22, "root"));
        form.reality = false;
        assert!(form.validate().unwrap_err().contains("what to install"));
        form.masterdns = true;
        assert!(form.validate().is_err(), "MasterDNS needs a domain");
        form.domain = "T.Example.com".into();
        assert_eq!(
            form.validate().unwrap().domain.as_deref(),
            Some("t.example.com")
        );
    }

    #[test]
    fn typing_fills_the_focused_field_and_skips_a_hidden_domain() {
        let mut state = ServersState::default();
        form_ready(&mut state);
        let Screen::Form(form) = &state.screen else {
            panic!()
        };
        assert_eq!(form.address, "203.0.113.7");
        assert_eq!(form.password, "hunter2");
        assert!(state.typing());
        // Walk to the end: Domain is skipped while MasterDNS is off.
        let mut seen = Vec::new();
        for _ in 0..5 {
            state.on_key(key(KeyCode::Tab));
            if let Screen::Form(f) = &state.screen {
                seen.push(f.focus);
            }
        }
        assert!(!seen.contains(&Field::Domain));
    }

    #[test]
    fn the_password_never_prints() {
        let form = Form {
            password: "hunter2".into(),
            ..Form::default()
        };
        assert!(!format!("{form:?}").contains("hunter2"));
    }

    #[test]
    fn host_key_then_identity_then_install_for_reality_only() {
        let mut state = ServersState::default();
        form_ready(&mut state);
        // Jump to Connect with Ctrl+S.
        let effects = state
            .on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL))
            .unwrap();
        assert!(
            matches!(&effects[0], Effect::FetchHostKey { host, port: 22 } if host == "203.0.113.7")
        );
        assert!(matches!(state.screen, Screen::Busy(_)));
        state.on_event(Event::HostKey(Ok(fake_key())));
        assert!(matches!(state.screen, Screen::Identity { .. }));
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        let Effect::Install(job) = &effects[0] else {
            panic!("expected install")
        };
        assert!(job.request.reality.is_some() && job.request.masterdns.is_none());
        assert_eq!(job.host_key.fingerprint, "SHA256:abc");
        assert!(matches!(state.screen, Screen::Progress(_)));
    }

    #[test]
    fn xhttp_can_be_installed_alone_or_with_reality() {
        let mut form = Form {
            address: "203.0.113.7".into(),
            password: "pw".into(),
            reality: false,
            ..Form::default()
        };
        assert!(form.validate().unwrap_err().contains("what to install"));
        form.xhttp = true;
        assert!(form.validate().is_ok());

        // Space on the XHTTP row flips it, and the request carries it.
        let mut state = ServersState::default();
        form_ready(&mut state);
        if let Screen::Form(f) = &mut state.screen {
            f.focus = Field::Xhttp;
        }
        state.on_key(key(KeyCode::Char(' ')));
        state.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        state.on_event(Event::HostKey(Ok(fake_key())));
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        let Effect::Install(job) = &effects[0] else {
            panic!("expected install")
        };
        assert!(job.request.reality.is_some() && job.request.xhttp.is_some());
        assert!(job.request.masterdns.is_none());
    }

    #[test]
    fn zerov1_can_be_installed_alone_or_beside_the_others() {
        let mut form = Form {
            address: "203.0.113.7".into(),
            password: "pw".into(),
            reality: false,
            ..Form::default()
        };
        assert!(form.validate().unwrap_err().contains("what to install"));
        form.zerov1 = true;
        assert!(form.validate().is_ok());

        // Space on the ZeroV1 row flips it, and the request carries it next
        // to REALITY and XHTTP.
        let mut state = ServersState::default();
        form_ready(&mut state);
        if let Screen::Form(f) = &mut state.screen {
            f.xhttp = true;
            f.focus = Field::Zerov1;
        }
        state.on_key(key(KeyCode::Char(' ')));
        state.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        state.on_event(Event::HostKey(Ok(fake_key())));
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        let Effect::Install(job) = &effects[0] else {
            panic!("expected install")
        };
        assert!(job.request.reality.is_some());
        assert!(job.request.xhttp.is_some() && job.request.zerov1.is_some());
        assert!(job.request.masterdns.is_none());
    }

    fn ctrl_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn two_config_record(id: &str, name: &str) -> ServerRecord {
        use zero_provision::record::{Reality, User};
        ServerRecord {
            version: 1,
            id: id.into(),
            name: name.into(),
            host: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            host_key: fake_key(),
            ssh_key: None,
            os: "Ubuntu".into(),
            zray_version: "0.3.0".into(),
            management_port: 31000,
            verified_download: true,
            services: vec![Service::Reality(Reality {
                tag: "reality-in".into(),
                port: 443,
                sni: "www.microsoft.com".into(),
                public_key: "pk".into(),
                short_id: "ab12".into(),
                users: vec![
                    User {
                        name: "Main".into(),
                        id: "11111111-1111-4111-8111-111111111111".into(),
                    },
                    User {
                        name: "Second".into(),
                        id: "22222222-2222-4222-8222-222222222222".into(),
                    },
                ],
            })],
            created: 0,
        }
    }

    #[test]
    fn ctrl_a_in_a_text_box_selects_its_text_and_typing_replaces_it() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        type_text(&mut state, "203.0.113.7");
        state.on_key(ctrl_key('a'));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert!(form.caret.selects_all(&form.address));
        assert!(form.has_selection());
        type_text(&mut state, "9");
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert_eq!(form.address, "9", "typing replaced the selected text");
    }

    #[test]
    fn copy_and_cut_in_a_text_box_hand_the_selection_to_the_clipboard() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        type_text(&mut state, "10.0.0.5");
        state.on_key(ctrl_key('a'));
        assert!(state.wants_ctrl_c(), "with a selection Ctrl+C copies");
        let copied = state.on_key(ctrl_key('c')).unwrap();
        assert!(matches!(&copied[..], [Effect::Copy(text)] if text == "10.0.0.5"));
        let cut = state.on_key(ctrl_key('x')).unwrap();
        assert!(matches!(&cut[..], [Effect::Copy(text)] if text == "10.0.0.5"));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert_eq!(form.address, "", "cut removed it");
        assert!(
            !state.wants_ctrl_c(),
            "nothing selected: Ctrl+C quits again"
        );
    }

    #[test]
    fn the_cursor_can_move_and_edit_in_the_middle_of_a_field() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        type_text(&mut state, "203.0.113.7");
        for _ in 0..2 {
            state.on_key(key(KeyCode::Left));
        }
        type_text(&mut state, "X");
        state.on_key(key(KeyCode::Home));
        state.on_key(key(KeyCode::Delete));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert_eq!(form.address, "03.0.113X.7");
    }

    #[test]
    fn a_paste_goes_in_at_the_cursor_and_replaces_a_selection() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        type_text(&mut state, "old");
        state.on_key(ctrl_key('a'));
        state.paste("  198.51.100.4\nsecond line ignored ");
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert_eq!(form.address, "198.51.100.4");
    }

    #[test]
    fn ctrl_r_shows_the_password_and_ctrl_a_off_a_text_box_ticks_every_service() {
        let mut state = ServersState::default();
        form_ready(&mut state);
        state.on_key(ctrl_key('r'));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert!(form.show_password);
        // Walk to a service tile: Ctrl+A there ticks all of them.
        if let Screen::Form(f) = &mut state.screen {
            f.set_focus(Field::Xhttp);
        }
        state.on_key(ctrl_key('a'));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert!(form.all_services());
        state.on_key(ctrl_key('a'));
        let Screen::Form(form) = &state.screen else {
            panic!("not the form")
        };
        assert!(!form.reality && !form.xhttp && !form.zerov1 && !form.masterdns);
    }

    #[test]
    fn keys_a_text_box_has_no_use_for_go_on_to_the_app() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        assert!(
            state.on_key(ctrl_key('q')).is_none(),
            "Ctrl+Q quits the app"
        );
        assert!(state.on_key(key(KeyCode::F(1))).is_none(), "F1 opens help");
        assert!(
            state.on_key(ctrl_key('a')).is_some(),
            "Ctrl+A is the text box's"
        );
    }

    #[test]
    fn escape_clears_a_selection_before_it_leaves_the_form() {
        let mut state = ServersState::default();
        state.on_key(key(KeyCode::Char('a')));
        type_text(&mut state, "abc");
        state.on_key(ctrl_key('a'));
        state.on_key(key(KeyCode::Esc));
        assert!(
            matches!(state.screen, Screen::Form(_)),
            "first Esc only deselects"
        );
        state.on_key(key(KeyCode::Esc));
        assert!(matches!(state.screen, Screen::List));
    }

    #[test]
    fn ctrl_a_in_the_list_selects_every_server_and_copy_takes_all_their_configs() {
        let mut state = ServersState::new(vec![
            two_config_record("a", "One"),
            two_config_record("b", "Two"),
        ]);
        state.on_key(ctrl_key('a'));
        assert_eq!(state.marked.len(), 2);
        assert!(state.wants_ctrl_c());
        let effects = state.on_key(key(KeyCode::Char('c'))).unwrap();
        let [Effect::Copy(text)] = &effects[..] else {
            panic!("expected one copy")
        };
        assert_eq!(text.lines().count(), 4, "two servers, two configs each");
        assert!(text.lines().all(|l| l.starts_with("vless://")));
        // Esc clears the ticks; Space ticks the one under the cursor.
        state.on_key(key(KeyCode::Esc));
        assert!(state.marked.is_empty());
        state.on_key(key(KeyCode::Char(' ')));
        assert_eq!(state.marked.len(), 1);
        // 'r' refreshes the chosen servers.
        let refresh = state.on_key(key(KeyCode::Char('r'))).unwrap();
        assert_eq!(refresh.len(), 1);
    }

    #[test]
    fn copy_in_the_list_without_ticks_takes_the_server_under_the_cursor() {
        let mut state = ServersState::new(vec![
            two_config_record("a", "One"),
            two_config_record("b", "Two"),
        ]);
        state.on_key(key(KeyCode::Down));
        let effects = state.on_key(key(KeyCode::Char('c'))).unwrap();
        let [Effect::Copy(text)] = &effects[..] else {
            panic!("expected one copy")
        };
        assert_eq!(text.lines().count(), 2);
        // The list's own keys still move: Home and End jump.
        state.on_key(key(KeyCode::Home));
        assert_eq!(state.selected, 0);
        state.on_key(key(KeyCode::End));
        assert_eq!(state.selected, 1);
    }

    #[test]
    fn ctrl_a_on_a_servers_page_selects_all_its_configs_and_copy_takes_them() {
        let mut state = ServersState::new(vec![two_config_record("a", "One")]);
        state.on_key(key(KeyCode::Enter));
        assert!(matches!(state.screen, Screen::Server { .. }));
        state.on_key(ctrl_key('a'));
        assert!(state.all_configs);
        let effects = state.on_key(key(KeyCode::Char('c'))).unwrap();
        let [Effect::Copy(text)] = &effects[..] else {
            panic!("expected one copy")
        };
        assert_eq!(text.lines().count(), 2, "both configs, one per line");
        // Esc clears the selection first and stays on the page.
        state.on_key(key(KeyCode::Esc));
        assert!(!state.all_configs);
        assert!(matches!(state.screen, Screen::Server { .. }));
        // Moving to another config also ends it.
        state.on_key(ctrl_key('a'));
        state.on_key(key(KeyCode::Right));
        assert!(!state.all_configs);
    }

    #[test]
    fn the_remove_box_edits_like_any_text_box() {
        let mut state = ServersState::new(vec![two_config_record("a", "One")]);
        state.on_key(key(KeyCode::Enter));
        state.on_key(key(KeyCode::Char('d')));
        type_text(&mut state, "rexmove");
        state.on_key(ctrl_key('a'));
        type_text(&mut state, "remove");
        let Screen::ConfirmRemove { typed, .. } = &state.screen else {
            panic!("not the confirm screen")
        };
        assert_eq!(
            typed, "remove",
            "select-all then typing replaced the mistake"
        );
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(&effects[..], [Effect::Remove { .. }]));
    }

    #[test]
    fn readings_build_a_short_history_for_the_graphs() {
        let mut state = ServersState::new(vec![two_config_record("a", "One")]);
        for n in 0..(HISTORY as u64 + 5) {
            state.on_event(Event::Usage(
                "a".into(),
                Ok(Usage {
                    window_secs: 300,
                    inbounds: vec![zero_provision::manage::InboundUsage {
                        tag: "reality-in".into(),
                        sessions: 1,
                        devices_now: n % 3,
                        devices_recent: 3,
                        uplink: n * 10,
                        downlink: n * 100,
                    }],
                }),
            ));
        }
        let history = state.history("a");
        assert_eq!(history.len(), HISTORY, "the oldest readings fall off");
        assert_eq!(history.last().unwrap().1, (HISTORY as u64 + 4) * 100);
        // Removing a server forgets its graph.
        state.on_event(Event::Removed("a".into(), Ok(())));
        assert!(state.history("a").is_empty());
    }

    #[test]
    fn a_new_screen_settles_in_and_a_wait_keeps_moving() {
        let mut state = ServersState::default();
        let now = Instant::now();
        assert!(state.settled(now + SETTLE) >= 1.0);
        state.on_key(key(KeyCode::Char('a')));
        assert!(state.settled(Instant::now()) < 1.0, "just opened");
        assert!(state.animating(Instant::now()));
        let later = Instant::now() + SETTLE * 2;
        assert!(!state.animating(later), "a form at rest does not animate");
        state.screen = Screen::Busy("Contacting the server…".into());
        assert!(state.animating(later), "a wait always moves");
        state.screen = Screen::Progress(ProgressView {
            steps: Vec::new(),
            of: 0,
            detail: String::new(),
            failed: Some("boom".into()),
        });
        assert!(!state.animating(later), "a failed install is still");
    }

    #[test]
    fn a_failed_host_key_returns_to_the_form_with_the_reason() {
        let mut state = ServersState::default();
        form_ready(&mut state);
        state.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        state.on_event(Event::HostKey(Err("Could not reach the server.".into())));
        let Screen::Form(form) = &state.screen else {
            panic!()
        };
        assert_eq!(form.error.as_deref(), Some("Could not reach the server."));
        assert_eq!(form.password, "hunter2", "nothing typed is lost");
    }

    #[test]
    fn masterdns_goes_through_the_dns_screen() {
        let mut state = ServersState::default();
        form_ready(&mut state);
        if let Screen::Form(form) = &mut state.screen {
            form.masterdns = true;
            form.domain = "t.example.com".into();
        }
        state.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        state.on_event(Event::HostKey(Ok(fake_key())));
        assert!(state.on_key(key(KeyCode::Enter)).unwrap().is_empty());
        let Screen::Dns { records, .. } = &state.screen else {
            panic!("expected the DNS screen")
        };
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, "NS");
        // 'c' asks for a check of the name server host.
        let effects = state.on_key(key(KeyCode::Char('c'))).unwrap();
        assert!(
            matches!(&effects[0], Effect::CheckDns { ns_host, .. } if ns_host == "ns.example.com")
        );
        state.on_event(Event::Dns(DnsStatus::Right));
        let Screen::Dns { status, .. } = &state.screen else {
            panic!()
        };
        assert_eq!(*status, DnsStatus::Right);
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        let Effect::Install(job) = &effects[0] else {
            panic!()
        };
        assert_eq!(
            job.request.masterdns.as_ref().unwrap().domain,
            "t.example.com"
        );
    }

    #[test]
    fn progress_tracks_steps_and_failure_returns_to_the_list() {
        let mut state = ServersState {
            screen: Screen::Progress(ProgressView {
                steps: Vec::new(),
                of: 0,
                detail: String::new(),
                failed: None,
            }),
            ..ServersState::default()
        };
        state.on_event(Event::Install(install::Event::Step {
            step: install::Step::Check,
            preset: None,
            number: 1,
            of: 5,
        }));
        state.on_event(Event::Install(install::Event::Step {
            step: install::Step::Download,
            preset: Some(install::Preset::Reality),
            number: 2,
            of: 5,
        }));
        let Screen::Progress(view) = &state.screen else {
            panic!()
        };
        assert_eq!(view.steps[0].2, StepState::Done);
        assert_eq!(view.steps[1].2, StepState::Running);
        state.on_event(Event::Installed(Err("The download failed.".into())));
        // Keys do nothing while it runs, but a failure can be dismissed.
        state.on_key(key(KeyCode::Enter));
        assert!(matches!(state.screen, Screen::List));
    }

    fn sample_record(id: &str) -> ServerRecord {
        ServerRecord {
            version: 1,
            id: id.into(),
            name: "Test".into(),
            host: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            host_key: fake_key(),
            ssh_key: Some("KEY".into()),
            os: "Ubuntu".into(),
            zray_version: "0.0.0".into(),
            management_port: 10085,
            verified_download: true,
            services: vec![Service::Reality(zero_provision::record::Reality {
                tag: "reality".into(),
                port: 443,
                sni: "www.microsoft.com".into(),
                public_key: "pk".into(),
                short_id: "ab12".into(),
                users: vec![zero_provision::record::User {
                    name: "Main".into(),
                    id: "11111111-1111-4111-8111-111111111111".into(),
                }],
            })],
            created: 0,
        }
    }

    #[test]
    fn records_survive_a_round_trip_and_garbage_is_an_empty_list() {
        let state = ServersState::new(vec![sample_record("a")]);
        let json = state.to_json();
        assert_eq!(ServersState::load(Some(&json)).records.len(), 1);
        assert!(ServersState::load(Some("not json")).records.is_empty());
        assert!(ServersState::load(None).records.is_empty());
    }

    #[test]
    fn the_server_page_polls_at_most_once_per_interval_and_never_two_at_once() {
        let mut state = ServersState::new(vec![sample_record("a")]);
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(&effects[0], Effect::Usage { id } if id == "a"));
        let t0 = Instant::now();
        assert_eq!(state.tick(t0).len(), 1);
        assert!(
            state.tick(t0 + Duration::from_secs(1)).is_empty(),
            "one in flight"
        );
        state.on_event(Event::Usage(
            "a".into(),
            Ok(Usage {
                window_secs: 300,
                inbounds: Vec::new(),
            }),
        ));
        assert!(
            state.tick(t0 + Duration::from_secs(2)).is_empty(),
            "too soon"
        );
        assert_eq!(
            state.tick(t0 + POLL_EVERY + Duration::from_secs(1)).len(),
            1
        );
        // Off the server page nothing is asked.
        state.screen = Screen::List;
        assert!(state.tick(t0 + Duration::from_secs(100)).is_empty());
    }

    #[test]
    fn removing_needs_the_word_and_clears_the_record() {
        let mut state = ServersState::new(vec![sample_record("a")]);
        state.on_key(key(KeyCode::Enter));
        state.on_key(key(KeyCode::Char('d')));
        assert!(matches!(state.screen, Screen::ConfirmRemove { .. }));
        assert!(state.typing());
        // Enter without the word does nothing.
        assert!(state.on_key(key(KeyCode::Enter)).unwrap().is_empty());
        type_text(&mut state, CONFIRM_WORD);
        let effects = state.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(&effects[0], Effect::Remove { id } if id == "a"));
        let effects = state.on_event(Event::Removed("a".into(), Ok(())));
        assert!(matches!(effects[0], Effect::Save));
        assert!(state.records.is_empty());
        assert!(matches!(state.screen, Screen::List));
    }

    #[test]
    fn a_failed_removal_keeps_the_record() {
        let mut state = ServersState::new(vec![sample_record("a")]);
        state.screen = Screen::Busy("Removing".into());
        state.on_event(Event::Removed("a".into(), Err("Could not log in.".into())));
        assert_eq!(state.records.len(), 1);
        assert!(matches!(state.screen, Screen::Server { .. }));
        assert_eq!(state.notice.as_deref(), Some("Could not log in."));
    }

    #[test]
    fn o_toggles_the_big_code_and_esc_closes_it_before_leaving() {
        let mut state = ServersState::new(vec![sample_record("a")]);
        state.on_key(key(KeyCode::Enter));
        state.on_key(key(KeyCode::Char('o')));
        assert!(state.show_qr);
        state.on_key(key(KeyCode::Esc));
        assert!(!state.show_qr);
        assert!(
            matches!(state.screen, Screen::Server { .. }),
            "first Esc only closes the code"
        );
        state.on_key(key(KeyCode::Esc));
        assert!(matches!(state.screen, Screen::List));
    }

    #[test]
    fn copy_gives_the_link() {
        let record = sample_record("a");
        let text = copy_text(&record, 0).unwrap();
        assert!(text.starts_with("vless://"), "{text}");
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn a_key_file_replaces_the_password() {
        let dir = std::env::temp_dir().join(format!("zn-keyfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let private = dir.join("id_ed25519");
        let public = dir.join("id_ed25519.pub");
        std::fs::write(
            &private,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(&public, "ssh-ed25519 AAAAC3Nza user@host\n").unwrap();
        let mut form = Form {
            address: "203.0.113.7".into(),
            ..Form::default()
        };
        assert!(form.validate().unwrap_err().contains("key file"));
        // A key file needs no password; the key text comes back with the check.
        form.key_file = private.to_string_lossy().into_owned();
        let checked = form.validate().unwrap();
        assert!(checked.key.as_deref().unwrap().contains("PRIVATE KEY"));
        assert!(
            !format!("{checked:?}").contains("BEGIN"),
            "the key never prints"
        );
        // The usual mistake is explained, and a missing file says so.
        form.key_file = public.to_string_lossy().into_owned();
        assert!(form.validate().unwrap_err().contains(".pub"));
        form.key_file = dir.join("nope").to_string_lossy().into_owned();
        assert!(form.validate().unwrap_err().contains("Cannot read"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
