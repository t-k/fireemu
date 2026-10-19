//! Paths: sequences of keys from the root.
//!
//! A path string is split at `/`; empty segments are dropped, so `/a//b/` names `a/b` and
//! both `` and `/` name the root, as in the SDKs. Every segment is a valid key, with two
//! exceptions: `.info` may be the first segment (the read-only connection information) and
//! `.priority` may be the last one (the priority of the parent location).

use std::fmt;

use crate::error::Result;
use crate::limits::Limits;

/// The `.priority` pseudo-key.
pub const PRIORITY_KEY: &str = ".priority";
/// The `.info` root of connection information.
pub const INFO_KEY: &str = ".info";

/// A location in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Path {
    keys: Vec<String>,
}

impl Path {
    /// The root.
    pub fn root() -> Self {
        Self::default()
    }

    /// Parses a path string.
    pub fn parse(path: &str, limits: &Limits) -> Result<Self> {
        let _ = (path, limits);
        todo!()
    }

    /// The path of `keys`, without validation (for paths built from validated keys).
    pub fn from_keys<K: Into<String>>(keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            keys: keys.into_iter().map(Into::into).collect(),
        }
    }

    /// The keys from the root.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether this is the root.
    pub fn is_root(&self) -> bool {
        self.keys.is_empty()
    }

    /// The last key, if any.
    pub fn last(&self) -> Option<&str> {
        self.keys.last().map(String::as_str)
    }

    /// The parent, or `None` for the root.
    pub fn parent(&self) -> Option<Self> {
        let _ = self;
        todo!()
    }

    /// This path extended by `key`.
    #[must_use]
    pub fn child(&self, key: &str) -> Self {
        let mut keys = self.keys.clone();
        keys.push(key.to_owned());
        Self { keys }
    }

    /// This path extended by every key of `relative`.
    #[must_use]
    pub fn join(&self, relative: &Self) -> Self {
        let mut keys = self.keys.clone();
        keys.extend(relative.keys.iter().cloned());
        Self { keys }
    }

    /// Whether `self` equals `other` or is one of its ancestors.
    pub fn contains(&self, other: &Self) -> bool {
        let _ = other;
        todo!()
    }

    /// Whether the path names a priority (its last key is `.priority`).
    pub fn is_priority(&self) -> bool {
        self.last() == Some(PRIORITY_KEY)
    }

    /// Whether the path lies under `.info`.
    pub fn is_info(&self) -> bool {
        self.keys.first().map(String::as_str) == Some(INFO_KEY)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.keys.is_empty() {
            return f.write_str("/");
        }
        for key in &self.keys {
            write!(f, "/{key}")?;
        }
        Ok(())
    }
}
