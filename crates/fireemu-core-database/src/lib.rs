//! std-only Realtime Database core.
//!
//! This crate owns the data model of the Realtime Database emulator: keys and paths with the
//! documented validation, the JSON tree with priorities, `set` and multipath `update` with
//! null deletion and pruning of empty parents, server values (`timestamp` and `increment`),
//! the export format, and query evaluation (`orderByKey` / `orderByValue` /
//! `orderByPriority` / `orderByChild`, range bounds and limits) with the ordering of value
//! types the SDKs and the server share.
//!
//! The crate is transport-free and std-only (ADR-001): it parses no JSON text, opens no
//! sockets and reads no clock. Callers hand it a [`Json`] value already parsed by the
//! adapter, and server values take the time from an explicit [`ServerValueContext`].

pub mod error;
pub mod hash;
pub mod json;
pub mod key;
pub mod limits;
pub mod node;
pub mod number;
pub mod path;
pub mod push_id;
pub mod query;
pub mod server_value;
pub mod tree;

pub use error::{DatabaseError, ErrorKind, Result};
pub use json::Json;
pub use limits::Limits;
pub use node::{Content, Format, Leaf, Node, Priority};
pub use number::Number;
pub use path::Path;
pub use query::{Bound, BoundKey, Limit, OrderBy, QueryParams};
pub use server_value::ServerValueContext;
pub use tree::Tree;
