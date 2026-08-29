//! Cloud Functions core (spec 12, Milestone C): the canonical function manifest, trigger
//! matching for Firestore document paths and Storage objects, cron / App Engine schedules
//! over the virtual clock, and the `CloudEvents` attributes of every event kind. Process
//! management and the runner protocol live in the runtime shell.

#![forbid(unsafe_code)]

pub mod cron;
pub mod event;
pub mod manifest;
pub mod pattern;
