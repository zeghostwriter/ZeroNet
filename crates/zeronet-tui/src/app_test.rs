//! The connection test: what this network does to plain traffic, and whether
//! the running tunnel gets through, drawn as a path (see [`crate::path_map`]).
//!
//! The probes send a DNS query, one HTTP request and a few TLS hellos, and
//! nothing is kept: the result lives in the dialog and goes when it closes.

use super::*;
use app_tasks::BgEvent;
use zero_discovery::selftest::{self, Check, Status};

impl App<'_> {
    /// Open the dialog and run the test.
    pub(crate) fn open_connection_test(&mut self) {
        if !matches!(self.modal_state, ModalState::Connection { .. }) {
            self.modal_state = ModalState::Connection {
                checks: Vec::new(),
                created_tick: self.effects.current_tick(),
            };
            self.open_modal_effect();
        }
        if !self.bg.test_in_flight {
            self.start_connection_test();
        }
    }

    /// Run the checks again.
    pub(crate) fn start_connection_test(&mut self) {
        if self.bg.test_in_flight {
            return;
        }
        self.bg.test_in_flight = true;
        if let ModalState::Connection { checks, .. } = &mut self.modal_state {
            *checks = selftest::Id::ALL
                .iter()
                .map(|id| Check {
                    id: *id,
                    status: Status::Pending,
                    detail: String::new(),
                })
                .collect();
        }
        // The tunnel is checked through the local HTTP proxy, and only while
        // there is one.
        let proxy = self
            .connection
            .dialled()
            .map(|_| std::net::SocketAddr::from(([127, 0, 0, 1], self.settings.http_port)));
        let tx = self.bg.tx.clone();
        tokio::spawn(async move {
            selftest::run(proxy, |check| {
                let _ = tx.send(BgEvent::TestProgress(check));
            })
            .await;
        });
    }

    /// A check started or finished: into the dialog, and the run is over when
    /// the last one is in.
    pub(crate) fn on_test_progress(&mut self, check: Check) {
        let id = check.id;
        let last = id == *selftest::Id::ALL.last().expect("there are checks");
        let done = last && check.status != Status::Running;
        if let ModalState::Connection { checks, .. } = &mut self.modal_state {
            if let Some(slot) = checks.iter_mut().find(|c| c.id == id) {
                *slot = check;
            }
        }
        if done {
            self.bg.test_in_flight = false;
        }
    }
}
