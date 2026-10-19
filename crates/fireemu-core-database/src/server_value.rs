//! Server values: `{".sv": "timestamp"}` and `{".sv": {"increment": n}}`.
//!
//! A placeholder is replaced before the write is applied. `timestamp` becomes the server's
//! time in milliseconds; `increment` adds `n` to the number currently stored at the
//! placeholder's location, or stands for `n` itself when that location holds no number.

use crate::error::Result;
use crate::json::Json;
use crate::node::Node;

/// The `.sv` key.
pub const SERVER_VALUE_KEY: &str = ".sv";

/// What the server knows when it resolves placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerValueContext {
    /// The server time in milliseconds since the Unix epoch.
    pub now_millis: i64,
}

/// `json` with every placeholder replaced; `existing` is the node currently stored where
/// `json` will be written.
pub fn resolve(json: &Json, existing: Option<&Node>, context: &ServerValueContext) -> Result<Json> {
    let _ = (json, existing, context);
    todo!()
}
