//! Server values: `{".sv": "timestamp"}` and `{".sv": {"increment": n}}`.
//!
//! A placeholder is replaced before the write is applied. `timestamp` becomes the server's
//! time in milliseconds; `increment` adds `n` to the number currently stored at the
//! placeholder's location, or stands for `n` itself when that location holds no number.

use std::collections::BTreeMap;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::json::Json;
use crate::node::{Content, Leaf, Node, VALUE_KEY};
use crate::path::PRIORITY_KEY;

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
pub fn resolve(json: &Json, existing: Option<&Node>, context: ServerValueContext) -> Result<Json> {
    let Json::Object(map) = json else {
        if let Json::Array(items) = json {
            let resolved = items
                .iter()
                .enumerate()
                .map(|(index, item)| resolve(item, child(existing, &index.to_string()), context))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Json::Array(resolved));
        }
        return Ok(json.clone());
    };
    if let Some(placeholder) = map.get(SERVER_VALUE_KEY) {
        // A placeholder may carry the priority of the value it stands for, nothing else.
        if map
            .keys()
            .any(|k| k != SERVER_VALUE_KEY && k != PRIORITY_KEY)
        {
            return Err(invalid(
                "a server value may hold only \".priority\" besides \".sv\"",
            ));
        }
        let value = resolve_placeholder(placeholder, existing, context)?;
        return Ok(match map.get(PRIORITY_KEY) {
            None => value,
            Some(priority) => Json::object([
                (VALUE_KEY, value),
                (
                    PRIORITY_KEY,
                    resolve(priority, stored_priority(existing).as_ref(), context)?,
                ),
            ]),
        });
    }
    let resolved = map
        .iter()
        .map(|(key, value)| {
            // `.value` stands for the location itself and `.priority` for its stored
            // priority, as the SDK's `resolveDeferredValue` reads them.
            let resolved = match key.as_str() {
                VALUE_KEY => resolve(value, existing, context)?,
                PRIORITY_KEY => resolve(value, stored_priority(existing).as_ref(), context)?,
                _ => resolve(value, child(existing, key), context)?,
            };
            Ok((key.clone(), resolved))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(Json::Object(resolved))
}

/// The stored priority of `node` as a leaf, the base a priority placeholder resolves
/// against.
pub fn stored_priority(node: Option<&Node>) -> Option<Node> {
    let priority = node?.priority.as_ref()?;
    Some(Node::leaf(priority.as_leaf()))
}

fn child<'a>(node: Option<&'a Node>, key: &str) -> Option<&'a Node> {
    node?.child(key)
}

fn resolve_placeholder(
    placeholder: &Json,
    existing: Option<&Node>,
    context: ServerValueContext,
) -> Result<Json> {
    match placeholder {
        Json::String(name) if name == "timestamp" => Ok(Json::int(context.now_millis)),
        Json::Object(op) if op.len() == 1 => match op.get("increment") {
            Some(Json::Number(delta)) => {
                let sum = match existing.map(|n| &n.content) {
                    Some(Content::Leaf(Leaf::Number(current))) => current.increment(*delta),
                    _ => *delta,
                };
                Ok(Json::Number(sum))
            }
            _ => Err(invalid("an increment needs a numeric delta")),
        },
        _ => Err(invalid("unknown server value")),
    }
}

fn invalid(message: &str) -> DatabaseError {
    DatabaseError::new(ErrorKind::InvalidServerValue, message)
}
