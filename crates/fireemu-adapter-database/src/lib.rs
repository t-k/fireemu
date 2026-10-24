//! Realtime Database transports over [`fireemu_core_database`]: the REST API (`.json` URLs,
//! `ETag`s, queries, streaming with server-sent events) and namespace routing.
//!
//! The REST layer is a synchronous function from a request to a response
//! ([`rest::Database::handle`]), so every answer can be checked without sockets;
//! [`server`] runs it behind hyper and delivers the streaming events.

mod access;
pub mod changes;
pub mod json_parse;
pub mod json_text;
mod listen;
pub mod long_poll;
pub mod namespace;
mod on_disconnect;
pub mod realtime;
pub mod request;
pub mod rest;
pub mod rules_file;
pub mod server;
pub mod target_escape;
pub mod websocket;
