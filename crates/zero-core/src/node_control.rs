//! Node switching and active profile control.
//!
//! Provides hot-swapping for client nodes / outbounds without dropping
//! the virtual TUN interface or terminating the main networking daemon.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveNodeState {
    pub tag: String,
    pub protocol: String,
    pub server_address: String,
    pub server_port: u16,
    pub latency_ms: Option<f64>,
}

/// A node switch command dispatched through channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlEvent {
    SwitchNode { tag: String },
    ReloadConfig { json_content: String },
    Disconnect,
    Reconnect,
}

/// Atomic active profile indicator for fast lock-free querying.
#[derive(Debug, Default)]
pub struct ActiveProfileSelector {
    active_index: AtomicU32,
}

impl ActiveProfileSelector {
    pub fn new(initial_index: u32) -> Self {
        Self {
            active_index: AtomicU32::new(initial_index),
        }
    }

    pub fn get_index(&self) -> u32 {
        self.active_index.load(Ordering::Relaxed)
    }

    pub fn set_index(&self, index: u32) {
        self.active_index.store(index, Ordering::Relaxed);
    }
}
