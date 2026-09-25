//! Bounded process-local storage for replaying previously resolved `IdP` credentials.
//!
//! These are emulator continuation handles, not Google credentials. A continuation is
//! reusable until its local expiry; each use still needs the adapter's current provider
//! policy and signature validation. It is never a substitute for a verified link ID token.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

/// Local continuation lifetime. This is not a claim about a production token lifetime.
pub const PENDING_IDP_TTL_SECONDS: i64 = 300;
/// Local per-namespace handle ceiling, independent of production quotas.
pub const MAX_PENDING_IDP_TOKENS: usize = 256;
/// Local ceiling for serialized assertion request and authority together.
pub const MAX_PENDING_IDP_ENTRY_BYTES: usize = 65_536;
/// Local aggregate logical byte ceiling (includes conservative per-entry overhead).
pub const MAX_PENDING_IDP_BYTES: usize = 1_048_576;

#[derive(Clone)]
struct Entry {
    request: String,
    authority: String,
    issued_at: LogicalInstant,
    expires_at: LogicalInstant,
}

#[derive(Clone, Default)]
pub(crate) struct PendingIdpCache {
    entries: Arc<BTreeMap<String, Arc<Entry>>>,
}

impl fmt::Debug for PendingIdpCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither bearer handles nor provider assertions are included in Debug output.
        f.debug_struct("PendingIdpCache")
            .field("entries", &self.entries.len())
            .field("logical_bytes", &self.bytes())
            .finish()
    }
}

impl PendingIdpCache {
    pub(crate) fn get(&self, token: &str, authority: &str, now: LogicalInstant) -> Option<&str> {
        let entry = self.entries.get(token)?;
        (entry.authority == authority && entry.issued_at <= now && now < entry.expires_at)
            .then_some(entry.request.as_str())
    }

    pub(crate) fn can_insert(&self, request: &str, authority: &str, now: LogicalInstant) -> bool {
        !request.is_empty()
            && !authority.is_empty()
            && request.len().saturating_add(authority.len()) <= MAX_PENDING_IDP_ENTRY_BYTES
            && self.entries.len() < MAX_PENDING_IDP_TOKENS
            && self
                .bytes()
                .saturating_add(request.len())
                .saturating_add(authority.len())
                .saturating_add(512)
                <= MAX_PENDING_IDP_BYTES
            && now
                .checked_add(LogicalDuration::from_seconds(PENDING_IDP_TTL_SECONDS))
                .is_some()
    }

    pub(crate) fn insert(
        &mut self,
        token: String,
        request: String,
        authority: String,
        now: LogicalInstant,
    ) -> bool {
        if token.len() > 256
            || token.is_empty()
            || self.entries.contains_key(&token)
            || !self.can_insert(&request, &authority, now)
        {
            return false;
        }
        let Some(expires_at) =
            now.checked_add(LogicalDuration::from_seconds(PENDING_IDP_TTL_SECONDS))
        else {
            return false;
        };
        Arc::make_mut(&mut self.entries).insert(
            token,
            Arc::new(Entry {
                request,
                authority,
                issued_at: now,
                expires_at,
            }),
        );
        true
    }

    pub(crate) fn sweep(&mut self, now: LogicalInstant) {
        if self.entries.values().any(|entry| now >= entry.expires_at) {
            Arc::make_mut(&mut self.entries).retain(|_, entry| now < entry.expires_at);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.entries.iter().fold(0_usize, |size, (token, entry)| {
            size.saturating_add(token.len())
                .saturating_add(entry.request.len())
                .saturating_add(entry.authority.len())
                .saturating_add(256)
        })
    }

    pub(crate) fn shared_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entries, &other.entries)
    }
}
