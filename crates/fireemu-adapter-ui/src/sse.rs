//! Server-sent event streams: Firestore commits and function logs. Each stream is one task
//! feeding a bounded channel; the task ends when the client goes away (the channel closes).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fireemu_adapter_grpc::local::CommitChangeKind;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{UiBody, UiRequest, UiResponse, UiState};

/// Chunks buffered per client before the producer waits.
const CHANNEL_DEPTH: usize = 64;
/// Keep-alive comment interval (transport only; nothing in the session depends on it).
const HEARTBEAT: Duration = Duration::from_secs(15);
/// How often the log stream looks at the runner (real time; the logs are a real-time
/// side channel of a child process, not session state).
const LOG_POLL: Duration = Duration::from_millis(250);

fn event(name: &str, data: &Value) -> Bytes {
    Bytes::from(format!("event: {name}\ndata: {data}\n\n"))
}

fn stream_response(rx: mpsc::Receiver<Bytes>) -> UiResponse {
    UiResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), "text/event-stream".to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
            ("x-accel-buffering".to_owned(), "no".to_owned()),
        ],
        body: UiBody::Stream(rx),
    }
}

/// Streams open at once across the UI (a page opens a handful; a runaway client cannot
/// pile up tasks that poll the runtime).
pub const MAX_STREAMS: usize = 64;

/// Connection budget shared by the streams of one UI runtime.
#[derive(Default)]
pub struct StreamLimiter {
    open: AtomicUsize,
}

/// One of the [`MAX_STREAMS`] slots; released when the stream's task ends.
struct StreamSlot(Arc<StreamLimiter>);

impl StreamSlot {
    fn acquire(limiter: &Arc<StreamLimiter>) -> Option<Self> {
        let mut open = limiter.open.load(Ordering::SeqCst);
        loop {
            if open >= MAX_STREAMS {
                return None;
            }
            match limiter
                .open
                .compare_exchange(open, open + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Self(limiter.clone())),
                Err(now) => open = now,
            }
        }
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

fn too_many_streams() -> UiResponse {
    UiResponse::error(
        429,
        "RESOURCE_EXHAUSTED : too many event streams are open; close some first",
    )
}

/// `GET firestore/watch?project=&database=`: one `commit` event per commit of the selected
/// project (and database, when given) with the changed paths; `resync` when the client fell
/// behind and events were dropped; `reset` when the backend changed epoch (a session reset
/// or restore ends every subscription).
#[must_use]
pub fn firestore_watch(state: &Arc<UiState>, req: &UiRequest) -> UiResponse {
    if req.method != "GET" {
        return UiResponse::error(405, "METHOD_NOT_ALLOWED");
    }
    let Some(slot) = StreamSlot::acquire(&state.stream_limiter) else {
        return too_many_streams();
    };
    let project = req
        .param("project")
        .unwrap_or_else(|| state.info.project.clone());
    let database = req.param("database");
    let (tx, rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
    let mut commits = state.backend.subscribe();
    tokio::spawn(async move {
        let _slot = slot;
        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        heartbeat.tick().await;
        if tx
            .send(event(
                "ready",
                &json!({"project": project, "database": database}),
            ))
            .await
            .is_err()
        {
            return;
        }
        loop {
            let chunk = tokio::select! {
                _ = heartbeat.tick() => Bytes::from_static(b": keep-alive\n\n"),
                received = commits.recv() => match received {
                    Ok(commit) => {
                        if commit.project != project
                            || database.as_ref().is_some_and(|d| *d != commit.database)
                        {
                            continue;
                        }
                        if commit.reset {
                            let _ = tx.send(event("reset", &json!({}))).await;
                            return;
                        }
                        let changes: Vec<Value> = commit
                            .changes
                            .iter()
                            .map(|c| {
                                let kind = match c.kind {
                                    CommitChangeKind::Created => "created",
                                    CommitChangeKind::Updated => "updated",
                                    CommitChangeKind::Deleted => "deleted",
                                };
                                json!({"path": c.path.to_string(), "kind": kind})
                            })
                            .collect();
                        event("commit", &json!({
                            "project": commit.project,
                            "database": commit.database,
                            "version": commit.version,
                            "changes": changes,
                        }))
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        event("resync", &json!({"dropped": n}))
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let _ = tx.send(event("reset", &json!({}))).await;
                        return;
                    }
                },
            };
            if tx.send(chunk).await.is_err() {
                return;
            }
        }
    });
    stream_response(rx)
}

/// One invocation record on the wire, with the sequence that identifies its position in the
/// runtime's diagnostic stream (two identical outcomes are still distinct records).
fn invocation_json(r: &fireemu_adapter_functions::runtime::SequencedRecord) -> Value {
    json!({
        "sequence": r.sequence,
        "eventId": r.record.event_id.to_string(),
        "function": r.record.function,
        "attempt": r.record.attempt,
        "outcome": r.record.outcome,
    })
}

/// `GET functions/logs`: `log` events with runner lines (stderr and `log` frames), and
/// `invocation` events for every recorded outcome, as they appear; `snapshot` first with
/// what exists already.
///
/// The stream holds a cursor into the runtime's invocation history and asks only for the
/// records after it, so a slow or long-lived client costs the delta rather than a copy of the
/// whole history every poll. When the cursor can no longer be honoured — the runtime reset
/// (a new generation) or the records the client is missing fell out of the retention window —
/// a `resync` event carries the current window and the client replaces what it holds.
#[must_use]
pub fn functions_logs(state: &Arc<UiState>, req: &UiRequest) -> UiResponse {
    if req.method != "GET" {
        return UiResponse::error(405, "METHOD_NOT_ALLOWED");
    }
    let Some(runtime) = state.functions.clone() else {
        return UiResponse::error(404, "NOT_FOUND : no functions runtime is configured");
    };
    let Some(slot) = StreamSlot::acquire(&state.stream_limiter) else {
        return too_many_streams();
    };
    let (tx, rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
    tokio::spawn(async move {
        let _slot = slot;
        let log_snapshot = runtime.runner().logs_since(None);
        let mut log_cursor = Some(log_snapshot.next_seq);
        let mut lines = log_snapshot.lines;
        if log_snapshot.truncated {
            lines.insert(
                0,
                "[fireemu] earlier function logs were truncated".to_owned(),
            );
        }
        let snapshot = runtime.history_since(None);
        let mut cursor = snapshot.cursor;
        if tx
            .send(event(
                "snapshot",
                &json!({
                    "generation": cursor.generation,
                    "logs": lines,
                    "invocations": snapshot.records.iter().map(invocation_json).collect::<Vec<_>>(),
                }),
            ))
            .await
            .is_err()
        {
            return;
        }
        let mut poll = tokio::time::interval(LOG_POLL);
        let mut idle_ticks: u32 = 0;
        loop {
            poll.tick().await;
            let log_slice = runtime.runner().logs_since(log_cursor);
            log_cursor = Some(log_slice.next_seq);
            let slice = runtime.history_since(Some(cursor));
            cursor = slice.cursor;
            let mut sent_something = false;
            if log_slice.truncated {
                sent_something = true;
                if tx
                    .send(event(
                        "log",
                        &json!({"line": "[fireemu] earlier function logs were truncated"}),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            for line in log_slice.lines {
                sent_something = true;
                if tx.send(event("log", &json!({"line": line}))).await.is_err() {
                    return;
                }
            }
            if slice.resync {
                sent_something = true;
                let payload = json!({
                    "generation": cursor.generation,
                    "invocations": slice.records.iter().map(invocation_json).collect::<Vec<_>>(),
                });
                if tx.send(event("resync", &payload)).await.is_err() {
                    return;
                }
            } else {
                for r in &slice.records {
                    sent_something = true;
                    if tx
                        .send(event("invocation", &invocation_json(r)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            if sent_something {
                idle_ticks = 0;
            } else {
                idle_ticks += 1;
                // A comment every ~15 s keeps the connection open and detects a gone client.
                if idle_ticks >= 60 {
                    idle_ticks = 0;
                    if tx
                        .send(Bytes::from_static(b": keep-alive\n\n"))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    stream_response(rx)
}
