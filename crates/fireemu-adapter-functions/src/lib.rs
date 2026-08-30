//! Cloud Functions shell (spec 12, Milestone C): a runner child process speaks a
//! length-prefixed JSON protocol over stdio (`Hello`, `Invoke`, `Result`, `Log`,
//! `Shutdown`); the runtime turns Firestore commits, Storage object events and schedules into
//! `CloudEvents`, dispatches them through the deterministic outbox with retries, enforces
//! timeouts and concurrency, answers `await-idle`, and proxies HTTP / callable functions to
//! the runner's HTTP port.

#![forbid(unsafe_code)]

pub mod callable;
pub mod eventarc;
pub mod events;
pub mod http;
pub mod manifest_json;
pub mod protocol;
pub mod runner;
pub mod runtime;
pub mod zone;
