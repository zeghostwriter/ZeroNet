//! Delivering job events to the host without flooding it.
//!
//! A discovery sweep produces thousands of events a minute. Crossing into the
//! JVM once per event would cost more CPU than the sweep itself and wake the
//! app's main thread constantly. So every job writes to an [`EventSink`], and
//! one flusher task per job hands the host a *batch*: newline-separated JSON
//! objects, at most one call per [`BATCH_INTERVAL`] (ten a second).
//!
//! The flusher sleeps on the channel when nothing happens — there is no timer
//! running while a job is idle — and exits once every sink handle is dropped,
//! delivering whatever was still queued first. Callers that need the final
//! `done` event to have been delivered await the flusher's handle.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

/// Minimum spacing between two host calls.
pub const BATCH_INTERVAL: Duration = Duration::from_millis(100);
/// Most events carried by one call; a backlog is split rather than handed
/// over as one enormous string.
pub const MAX_BATCH_EVENTS: usize = 500;

/// Receives one batch: newline-separated JSON objects, never empty.
pub type EventCallback = Arc<dyn Fn(String) + Send + Sync>;

/// A cheap, cloneable handle a job writes events to.
#[derive(Clone)]
pub struct EventSink {
    sender: mpsc::UnboundedSender<String>,
}

impl EventSink {
    /// Queue one event. Never blocks; a job whose host has gone away simply
    /// emits into a closed channel.
    pub fn emit(&self, event: serde_json::Value) {
        let _ = self.sender.send(event.to_string());
    }
}

/// Create a sink whose events are batched into `callback` by a flusher task
/// spawned on the current tokio runtime.
///
/// The callback runs on the runtime's blocking pool, so a host call that
/// attaches a thread to a VM or takes a lock never stalls the async workers
/// running the job.
pub fn batching_sink(callback: EventCallback) -> (EventSink, tokio::task::JoinHandle<()>) {
    batching_sink_with_interval(callback, BATCH_INTERVAL)
}

/// [`batching_sink`] with an explicit interval (tests use a short one).
pub fn batching_sink_with_interval(
    callback: EventCallback,
    interval: Duration,
) -> (EventSink, tokio::task::JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::unbounded_channel::<String>();
    let flusher = tokio::spawn(async move {
        let mut last_flush: Option<Instant> = None;
        let mut closed = false;
        while !closed {
            // Park until there is something to say.
            let Some(first) = receiver.recv().await else {
                break;
            };
            let mut batch = vec![first];
            // Respect the rate limit, then take everything that queued up
            // meanwhile.
            if let Some(last) = last_flush {
                let ready_at = last + interval;
                if ready_at > Instant::now() {
                    tokio::time::sleep_until(ready_at).await;
                }
            }
            loop {
                match receiver.try_recv() {
                    Ok(event) => {
                        batch.push(event);
                        if batch.len() >= MAX_BATCH_EVENTS {
                            break;
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            }
            let text = batch.join("\n");
            let callback = Arc::clone(&callback);
            // A panicking host callback must not take the flusher down with
            // it; the next batch is still delivered.
            let _ = tokio::task::spawn_blocking(move || callback(text)).await;
            last_flush = Some(Instant::now());
        }
        // Anything left after the channel closed mid-batch.
        let mut rest = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            rest.push(event);
        }
        for chunk in rest.chunks(MAX_BATCH_EVENTS) {
            let text = chunk.join("\n");
            let callback = Arc::clone(&callback);
            let _ = tokio::task::spawn_blocking(move || callback(text)).await;
        }
    });
    (EventSink { sender }, flusher)
}

/// A sink that collects into memory, for tests and for callers that want the
/// events synchronously.
#[derive(Clone, Default)]
pub struct Collected(pub Arc<std::sync::Mutex<Vec<serde_json::Value>>>);

impl Collected {
    pub fn callback(&self) -> EventCallback {
        let store = Arc::clone(&self.0);
        Arc::new(move |batch: String| {
            let mut store = store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for line in batch.lines() {
                if let Ok(value) = serde_json::from_str(line) {
                    store.push(value);
                }
            }
        })
    }

    pub fn events(&self) -> Vec<serde_json::Value> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Events of one type (`"t"`).
    pub fn of(&self, kind: &str) -> Vec<serde_json::Value> {
        self.events()
            .into_iter()
            .filter(|event| event["t"] == kind)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_are_batched_and_everything_is_delivered_before_the_flusher_ends() {
        let calls = Arc::new(AtomicUsize::new(0));
        let collected = Collected::default();
        let inner = collected.callback();
        let counter = Arc::clone(&calls);
        let callback: EventCallback = Arc::new(move |batch| {
            counter.fetch_add(1, Ordering::SeqCst);
            inner(batch);
        });
        let (sink, flusher) = batching_sink_with_interval(callback, Duration::from_millis(200));
        let started = std::time::Instant::now();
        for index in 0..1000 {
            sink.emit(json!({"t": "progress", "n": index}));
        }
        sink.emit(json!({"t": "done"}));
        drop(sink);
        flusher.await.unwrap();

        let events = collected.events();
        assert_eq!(events.len(), 1001);
        assert_eq!(events.last().unwrap()["t"], "done");
        // In order.
        assert_eq!(events[0]["n"], 0);
        assert_eq!(events[999]["n"], 999);
        // 1001 events in a handful of calls, not a thousand.
        let calls = calls.load(Ordering::SeqCst);
        assert!(calls <= 4, "{calls} calls");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn calls_are_rate_limited() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::<std::time::Instant>::new()));
        let recorder = Arc::clone(&calls);
        let callback: EventCallback = Arc::new(move |_| {
            recorder.lock().unwrap().push(std::time::Instant::now());
        });
        let (sink, flusher) = batching_sink_with_interval(callback, Duration::from_millis(100));
        for _ in 0..5 {
            sink.emit(json!({"t": "x"}));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(sink);
        flusher.await.unwrap();
        let calls = calls.lock().unwrap();
        assert!(calls.len() >= 2);
        for pair in calls.windows(2) {
            assert!(pair[1] - pair[0] >= Duration::from_millis(90));
        }
    }
}
