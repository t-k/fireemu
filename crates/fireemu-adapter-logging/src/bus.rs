//! The log bus: a bounded ring of past frames plus a live broadcast of new ones.
//!
//! The daemon publishes lines here; every connected WebSocket client is first sent the retained
//! history and then every subsequent frame. History is bounded (unlike the official transport,
//! which keeps everything in memory) so an unbounded producer cannot exhaust memory.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::wire::bundle_text;
pub use crate::wire::LogInput;

/// How many past frames the bus retains by default. The functions runner keeps its own last
/// 1000 lines, so this matches: a fresh client sees the same window the UI would.
pub const DEFAULT_HISTORY_CAP: usize = 1000;

/// How many live frames a slow client may fall behind before it is force-resynced. A client at
/// its limit gets a `Lagged` and the server drops the gap rather than stalling every other
/// client; the history it already received still bounds what it missed.
const LIVE_BUFFER: usize = 4096;

/// A bounded, broadcast log bus. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct LogBus {
    inner: Arc<Inner>,
}

struct Inner {
    /// Retained frame texts, oldest first, capped at `cap`.
    history: Mutex<VecDeque<Arc<str>>>,
    cap: usize,
    /// Live fan-out of new frame texts.
    tx: broadcast::Sender<Arc<str>>,
}

/// A client's view of the bus at connect time: the history to replay, then the live stream.
pub struct Subscription {
    /// The frames retained when the client connected, oldest first.
    pub history: Vec<Arc<str>>,
    /// New frames published after the snapshot.
    pub live: broadcast::Receiver<Arc<str>>,
}

impl LogBus {
    /// A bus retaining the default history window.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_HISTORY_CAP)
    }

    /// A bus retaining at most `cap` frames (at least one).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let (tx, _rx) = broadcast::channel(LIVE_BUFFER);
        Self {
            inner: Arc::new(Inner {
                history: Mutex::new(VecDeque::with_capacity(cap.min(DEFAULT_HISTORY_CAP))),
                cap: cap.max(1),
                tx,
            }),
        }
    }

    /// Publishes one line: appends it to the bounded history and fans it out live.
    ///
    /// The history push and the broadcast send happen under one lock, so a client that
    /// subscribes (also under the lock) can never both miss a frame and fail to see it in its
    /// history snapshot.
    pub fn publish(&self, input: &LogInput) {
        let text: Arc<str> = Arc::from(bundle_text(input));
        let mut history = self
            .inner
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.push_back(text.clone());
        while history.len() > self.inner.cap {
            history.pop_front();
        }
        // A send with no live receivers returns Err; that is normal (nobody is connected).
        let _ = self.inner.tx.send(text);
    }

    /// Snapshots the history and subscribes to the live stream atomically.
    #[must_use]
    pub fn subscribe(&self) -> Subscription {
        let history = self
            .inner
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let live = self.inner.tx.subscribe();
        let snapshot = history.iter().cloned().collect();
        drop(history);
        Subscription {
            history: snapshot,
            live,
        }
    }

    /// The number of frames currently retained (for tests and diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether no frame is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for LogBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::LogInput;

    fn line(msg: &str) -> LogInput {
        LogInput::plain("info", msg, 0)
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest() {
        let bus = LogBus::with_capacity(3);
        for i in 0..10 {
            bus.publish(&line(&format!("line {i}")));
        }
        assert_eq!(bus.len(), 3);
        let sub = bus.subscribe();
        let texts: Vec<String> = sub.history.iter().map(ToString::to_string).collect();
        assert!(texts[0].contains("line 7"));
        assert!(texts[2].contains("line 9"));
    }

    #[tokio::test]
    async fn a_subscriber_gets_history_then_live() {
        let bus = LogBus::with_capacity(10);
        bus.publish(&line("past"));
        let mut sub = bus.subscribe();
        assert_eq!(sub.history.len(), 1);
        assert!(sub.history[0].contains("past"));
        bus.publish(&line("future"));
        let got = sub.live.recv().await.unwrap();
        assert!(got.contains("future"));
    }

    #[tokio::test]
    async fn a_frame_is_never_both_missed_and_absent_from_history() {
        // Subscribe, then publish: the frame must arrive live (and it is also in no earlier
        // snapshot, so exactly-once holds across the subscribe boundary).
        let bus = LogBus::with_capacity(10);
        let mut sub = bus.subscribe();
        assert!(sub.history.is_empty());
        bus.publish(&line("only-live"));
        let got = sub.live.recv().await.unwrap();
        assert!(got.contains("only-live"));
    }
}
