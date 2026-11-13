//! The production REST frontend's negative cache for subscriptions.
//!
//! Production Pub/Sub answers a REST request for a subscription with a fast cached 404 for about
//! 10 seconds after a real 404 of the same URL on the same connection, even when the subscription
//! has been created in the meantime. gRPC, topics and snapshots never show it. A cached 404 right
//! after a successful create makes local tests flaky, so this model is **off unless
//! `pubsub.restNegativeCache = "production"` asks for it** (an explicit opt-in, strict profile only;
//! `productionExact` does not select it); the adapter holds it only then.
//!
//! The rule follows packet `PUBSUB-NEGCACHE` recordings 50a305aa54d1 and 331317b47c44, and
//! v5 follow-ups 903d638614a1 and 70602e8b29e0 (see `docs/pubsub-rest-negative-cache.md`):
//!
//! - the entry belongs to one connection: a request on another connection is never answered from it;
//! - a 404 of `GET` or `PATCH` on the plain subscription URL arms it, and the window runs from the
//!   START of the arming request; a failed create, a `:verb`, a snapshot or a request
//!   with a query string does not arm;
//! - `GET`, `PATCH` and `DELETE` of the plain URL are answered with the cached 404 and never reach
//!   the backend (the patch is not applied, the delete does not run); a `:verb` is forwarded;
//! - a hit neither extends nor re-arms the entry, and a create clears nothing.
//!
//! A `GET` 200 seven seconds before a 404 exempted it in both v5 runs; results at four and 13
//! seconds were mixed. DELETE 404 arming and activation for never-created names remain open. The
//! window edge varies between runs: run 4 missed from 10.25 s, run 3 hit at 10.50 s, and the v4
//! runs hit up to 10.20 s. The deterministic window is a known difference, not a sharp production edge.
//!
//! The model is pure: it owns no clock, and every call takes the instant the request started on the
//! virtual clock, so a test (or `await-idle`) moves it by moving that clock.

use std::collections::BTreeMap;

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

/// The window from the arming request's start. The edge varies between runs: run 4 missed from
/// 10.25 s, run 3 hit at 10.50 s, and the v4 runs hit up to 10.20 s. The model chooses 10.35 s;
/// production is nondeterministic in the observed band.
pub const RECORDED_TTL: LogicalDuration = LogicalDuration::from_millis(10_350);

/// The most entries the cache keeps. Expired entries go first, then the oldest, so a client that
/// probes many absent names cannot grow the map without bound.
pub const MAX_ENTRIES: usize = 4096;

/// The deterministic window and recent-success rule chosen for the recorded observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleChoice {
    /// How long an entry serves, from the start of the request that armed it.
    pub ttl: LogicalDuration,
    /// A `GET` 200 within the window keeps a later 404 from arming. Recorded at seven seconds;
    /// four and 13 seconds remain open.
    pub recent_success_exempts: bool,
}

impl RuleChoice {
    /// The recorded rule, with open choices at their documented values.
    pub const RECORDED: Self = Self {
        ttl: RECORDED_TTL,
        recent_success_exempts: true,
    };
}

/// The connection a request arrived on, as the id the server gave it when it accepted the socket.
/// An entry is only ever served on the connection that armed it (recorded: every read on a fresh
/// connection was forwarded). Ids are never reused, so a new connection that gets the same source
/// port does not inherit an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// A request whose connection is not known (an in-process call): one shared pseudo-connection.
    pub const UNATTRIBUTED: Self = Self(0);

    /// The connection with this accept-time id (the server counts from 1).
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// A subscription as the REST URL names it: project and the final segment. The key never includes
/// the `:verb` suffix, the method or the `resource=` of an error.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RestResource {
    project: String,
    id: String,
}

impl RestResource {
    /// Reads `/v1/projects/{p}/subscriptions/{id}`. Snapshots, topics, collections, `:verb` forms,
    /// extra segments and every other path give `None`.
    #[must_use]
    pub fn parse_path(path: &str) -> Option<Self> {
        let mut parts = path.strip_prefix("/v1/")?.split('/');
        let (Some("projects"), Some(project), Some("subscriptions"), Some(id), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        if project.is_empty() || id.is_empty() || id.contains(':') {
            return None;
        }
        Some(Self {
            project: project.to_owned(),
            id: id.to_owned(),
        })
    }

    /// The final path segment, which is what the error message names.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The request as the cache sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestRequest {
    /// `GET` of the resource: served, arms on a 404.
    Get,
    /// `PATCH` of the resource: served, arms on a 404.
    Patch,
    /// `DELETE` of the resource: served, never arms.
    Delete,
    /// Anything else on the resource (a create, a `:verb`): neither served nor arming.
    Other,
}

/// How a dispatched request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestOutcome {
    /// A 2xx answer.
    Success,
    /// A real 404 from the backend.
    NotFound,
    /// Anything else (400, 409, 5xx, ...).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    connection: ConnectionId,
    resource: RestResource,
}

/// The cache. One per REST frontend; shared by every request on it, keyed by connection.
#[derive(Debug, Clone)]
pub struct RestNegativeCache {
    rule: RuleChoice,
    /// Start of the request that armed each live key.
    armed: BTreeMap<Key, LogicalInstant>,
    /// Start of the latest `GET` that answered 200, per key.
    last_success: BTreeMap<Key, LogicalInstant>,
}

impl Default for RestNegativeCache {
    fn default() -> Self {
        Self::new(RuleChoice::RECORDED)
    }
}

impl RestNegativeCache {
    /// A cache with the given rule.
    #[must_use]
    pub const fn new(rule: RuleChoice) -> Self {
        Self {
            rule,
            armed: BTreeMap::new(),
            last_success: BTreeMap::new(),
        }
    }

    /// Whether `request` on `resource`, arriving on `connection` at `now`, is answered from the
    /// cache with a 404 instead of reaching the backend. A hit does not extend the entry.
    pub fn serves(
        &mut self,
        connection: ConnectionId,
        resource: &RestResource,
        request: RestRequest,
        now: LogicalInstant,
    ) -> bool {
        if request == RestRequest::Other {
            return false;
        }
        let key = Key {
            connection,
            resource: resource.clone(),
        };
        let Some(&armed_at) = self.armed.get(&key) else {
            return false;
        };
        if self.is_live(armed_at, now) {
            return true;
        }
        if armed_at <= now {
            self.armed.remove(&key);
        }
        false
    }

    /// Records the outcome of a request that reached the backend (a request served from the
    /// cache must not be recorded: a hit never arms and never extends).
    pub fn observe(
        &mut self,
        connection: ConnectionId,
        resource: &RestResource,
        request: RestRequest,
        started: LogicalInstant,
        outcome: RestOutcome,
    ) {
        self.forget_stale(started);
        let key = Key {
            connection,
            resource: resource.clone(),
        };
        match (request, outcome) {
            (RestRequest::Get, RestOutcome::Success) => self.remember_success(key, started),
            (RestRequest::Get | RestRequest::Patch, RestOutcome::NotFound) => {
                self.arm(key, started);
            }
            _ => {}
        }
    }

    /// Drops everything the cache holds for a connection that has closed.
    pub fn forget_connection(&mut self, connection: ConnectionId) {
        self.armed.retain(|key, _| key.connection != connection);
        self.last_success
            .retain(|key, _| key.connection != connection);
    }

    /// The number of live and not-yet-pruned entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.armed.len()
    }

    /// Whether no entry is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.armed.is_empty()
    }

    fn is_live(&self, armed_at: LogicalInstant, now: LogicalInstant) -> bool {
        now.checked_duration_since(armed_at)
            .is_some_and(|age| age >= LogicalDuration::ZERO && age < self.rule.ttl)
    }

    fn remember_success(&mut self, key: Key, started: LogicalInstant) {
        if self
            .last_success
            .get(&key)
            .is_some_and(|&seen| seen > started)
        {
            return;
        }
        if self.last_success.len() >= MAX_ENTRIES && !self.last_success.contains_key(&key) {
            if let Some((oldest, &seen)) = self.last_success.iter().min_by_key(|(_, &seen)| seen) {
                if seen >= started {
                    return;
                }
                let oldest = oldest.clone();
                self.last_success.remove(&oldest);
            }
        }
        self.last_success.insert(key, started);
    }

    fn arm(&mut self, key: Key, started: LogicalInstant) {
        if self
            .armed
            .get(&key)
            .is_some_and(|&armed_at| armed_at > started || self.is_live(armed_at, started))
        {
            return;
        }
        if self.rule.recent_success_exempts
            && self
                .last_success
                .get(&key)
                .is_some_and(|&seen| self.is_live(seen, started))
        {
            return;
        }
        if self.armed.len() >= MAX_ENTRIES && !self.armed.contains_key(&key) {
            if let Some((oldest, &armed_at)) =
                self.armed.iter().min_by_key(|(_, &armed_at)| armed_at)
            {
                if armed_at >= started {
                    return;
                }
                let oldest = oldest.clone();
                self.armed.remove(&oldest);
            }
        }
        self.armed.insert(key, started);
    }

    /// Drops entries and success marks that are no longer inside the window.
    fn forget_stale(&mut self, now: LogicalInstant) {
        let ttl = self.rule.ttl;
        let live = |at: &LogicalInstant| {
            *at > now
                || now
                    .checked_duration_since(*at)
                    .is_some_and(|age| age >= LogicalDuration::ZERO && age < ttl)
        };
        self.armed.retain(|_, at| live(at));
        self.last_success.retain(|_, at| live(at));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const C1: ConnectionId = ConnectionId::UNATTRIBUTED;

    fn other_connection() -> ConnectionId {
        ConnectionId::new(2)
    }
    fn sub(id: &str) -> RestResource {
        RestResource::parse_path(&format!("/v1/projects/p/subscriptions/{id}")).unwrap()
    }
    fn at(millis: i64) -> LogicalInstant {
        LogicalInstant::from_unix_seconds(1_800_000_000)
            .checked_add(LogicalDuration::from_millis(millis))
            .unwrap()
    }
    const TTL_MS: i64 = 10_350;

    fn serves(cache: &mut RestNegativeCache, r: &RestResource, q: RestRequest, ms: i64) -> bool {
        cache.serves(C1, r, q, at(ms))
    }
    fn observe(
        cache: &mut RestNegativeCache,
        r: &RestResource,
        q: RestRequest,
        ms: i64,
        o: RestOutcome,
    ) {
        cache.observe(C1, r, q, at(ms), o);
    }

    #[test]
    fn parses_only_the_plain_subscription_url() {
        assert_eq!(
            RestResource::parse_path("/v1/projects/p/subscriptions/s"),
            Some(sub("s"))
        );
        for path in [
            "/v1/projects/p/snapshots/z",
            "/v1/projects/p/topics/t",
            "/v1/projects/p/subscriptions/s:pull",
            "/v1/projects/p/subscriptions/s:getIamPolicy",
            "/v1/projects/p/subscriptions/s/extra",
            "/v1/projects/p/subscriptions/s/",
            "/v1/projects/p/subscriptions/",
            "/v1/projects/p/subscriptions",
            "/v1/projects//subscriptions/s",
            "/v2/projects/p/subscriptions/s",
            "projects/p/subscriptions/s",
            "/v1/projects/p/subscriptions/s/x/y",
            "",
        ] {
            assert_eq!(RestResource::parse_path(path), None, "{path}");
        }
        assert_eq!(sub("s").id(), "s");
    }

    #[test]
    fn a_get_404_serves_later_requests_until_the_window_ends() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        assert!(!serves(&mut cache, &x, RestRequest::Get, 0));
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 1));
        assert!(serves(&mut cache, &x, RestRequest::Get, TTL_MS - 1));
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS));
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS + 1));
    }

    #[test]
    fn the_window_reaches_the_recorded_hits_and_ends_before_the_recorded_misses() {
        // 10.202 s was a hit in both runs; 10.501 s was forwarded in 11 of 12 reads.
        assert!(RECORDED_TTL > LogicalDuration::from_millis(10_202));
        assert!(RECORDED_TTL <= LogicalDuration::from_millis(10_501));
        assert_eq!(RECORDED_TTL, LogicalDuration::from_millis(TTL_MS));
    }

    #[test]
    fn a_patch_404_arms_like_a_get_404() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Patch, 0, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 1_000));
    }

    #[test]
    fn an_armed_entry_serves_get_patch_and_delete_and_forwards_anything_else() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 5_000));
        assert!(serves(&mut cache, &x, RestRequest::Patch, 5_000));
        assert!(serves(&mut cache, &x, RestRequest::Delete, 5_000));
        assert!(!serves(&mut cache, &x, RestRequest::Other, 5_000));
    }

    #[test]
    fn a_hit_does_not_extend_the_entry() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 5_000));
        assert!(serves(&mut cache, &x, RestRequest::Delete, 9_000));
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS));
    }

    #[test]
    fn the_entry_belongs_to_the_connection_that_armed_it() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        let second = other_connection();
        cache.observe(C1, &x, RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(cache.serves(C1, &x, RestRequest::Get, at(1_000)));
        assert!(!cache.serves(second, &x, RestRequest::Get, at(1_000)));
        // The other connection's own 404 arms its own entry and does not touch the first.
        cache.observe(
            second,
            &x,
            RestRequest::Get,
            at(2_000),
            RestOutcome::NotFound,
        );
        assert!(cache.serves(second, &x, RestRequest::Get, at(3_000)));
        assert!(!cache.serves(C1, &x, RestRequest::Get, at(TTL_MS + 1)));
        assert!(cache.serves(second, &x, RestRequest::Get, at(TTL_MS + 1)));
    }

    #[test]
    fn only_a_get_or_patch_404_arms() {
        let x = sub("x");
        for (request, outcome) in [
            (RestRequest::Delete, RestOutcome::NotFound),
            (RestRequest::Other, RestOutcome::NotFound),
            (RestRequest::Get, RestOutcome::Other),
            (RestRequest::Patch, RestOutcome::Other),
            (RestRequest::Get, RestOutcome::Success),
            (RestRequest::Patch, RestOutcome::Success),
            (RestRequest::Delete, RestOutcome::Success),
            (RestRequest::Other, RestOutcome::Success),
            (RestRequest::Other, RestOutcome::Other),
        ] {
            let mut cache = RestNegativeCache::default();
            observe(&mut cache, &x, request, 0, outcome);
            assert!(
                !serves(&mut cache, &x, RestRequest::Get, 1),
                "{request:?} {outcome:?}"
            );
            assert!(cache.is_empty(), "{request:?} {outcome:?}");
        }
    }

    #[test]
    fn a_create_clears_nothing() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        observe(
            &mut cache,
            &x,
            RestRequest::Other,
            1_000,
            RestOutcome::Success,
        );
        assert!(serves(&mut cache, &x, RestRequest::Get, 3_000));
    }

    #[test]
    fn a_recent_get_200_keeps_a_later_404_from_arming() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::Success);
        observe(
            &mut cache,
            &x,
            RestRequest::Get,
            3_700,
            RestOutcome::NotFound,
        );
        assert!(!serves(&mut cache, &x, RestRequest::Get, 5_000));
    }

    #[test]
    fn an_old_get_200_no_longer_exempts() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::Success);
        observe(
            &mut cache,
            &x,
            RestRequest::Get,
            TTL_MS - 1,
            RestOutcome::NotFound,
        );
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS));
        let mut cache = RestNegativeCache::default();
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::Success);
        observe(
            &mut cache,
            &x,
            RestRequest::Get,
            TTL_MS,
            RestOutcome::NotFound,
        );
        assert!(serves(&mut cache, &x, RestRequest::Get, TTL_MS + 1));
    }

    #[test]
    fn a_get_200_on_another_connection_does_not_exempt() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(
            other_connection(),
            &x,
            RestRequest::Get,
            at(0),
            RestOutcome::Success,
        );
        cache.observe(C1, &x, RestRequest::Get, at(1_000), RestOutcome::NotFound);
        assert!(cache.serves(C1, &x, RestRequest::Get, at(2_000)));
    }

    #[test]
    fn the_entry_keeps_its_first_anchor_when_a_second_404_reaches_the_backend() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        observe(
            &mut cache,
            &x,
            RestRequest::Patch,
            5_000,
            RestOutcome::NotFound,
        );
        assert!(serves(&mut cache, &x, RestRequest::Get, TTL_MS - 1));
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS));
    }

    #[test]
    fn an_expired_entry_is_armed_again_by_a_new_404() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        assert!(!serves(&mut cache, &x, RestRequest::Get, TTL_MS + 100));
        observe(
            &mut cache,
            &x,
            RestRequest::Get,
            TTL_MS + 200,
            RestOutcome::NotFound,
        );
        assert!(serves(&mut cache, &x, RestRequest::Get, TTL_MS + 300));
        assert!(!serves(&mut cache, &x, RestRequest::Get, 2 * TTL_MS + 200));
    }

    #[test]
    fn a_closed_connection_leaves_nothing_behind_and_the_others_keep_theirs() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        let second = other_connection();
        cache.observe(C1, &x, RestRequest::Get, at(0), RestOutcome::NotFound);
        cache.observe(C1, &sub("y"), RestRequest::Get, at(0), RestOutcome::Success);
        cache.observe(second, &x, RestRequest::Get, at(0), RestOutcome::NotFound);
        cache.forget_connection(C1);
        assert_eq!(cache.len(), 1);
        assert!(!cache.serves(C1, &x, RestRequest::Get, at(1)));
        assert!(cache.serves(second, &x, RestRequest::Get, at(1)));
        // The success mark of the closed connection is gone too: a new 404 under the same id arms.
        cache.observe(
            C1,
            &sub("y"),
            RestRequest::Get,
            at(10),
            RestOutcome::NotFound,
        );
        assert!(cache.serves(C1, &sub("y"), RestRequest::Get, at(20)));
    }

    #[test]
    fn success_marks_are_bounded_too() {
        let mut cache = RestNegativeCache::default();
        // A stationary clock: nothing ever expires, so only the bound limits the marks.
        for index in 0..(MAX_ENTRIES + 50) {
            observe(
                &mut cache,
                &sub(&format!("s{index}")),
                RestRequest::Get,
                0,
                RestOutcome::Success,
            );
        }
        assert_eq!(cache.last_success.len(), MAX_ENTRIES);
        assert!(cache.is_empty());
    }

    #[test]
    fn len_counts_the_live_entries_and_an_expired_one_is_gone_at_the_next_observation() {
        let mut cache = RestNegativeCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        observe(
            &mut cache,
            &sub("x"),
            RestRequest::Get,
            0,
            RestOutcome::NotFound,
        );
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        // At exactly the window length the first entry no longer counts.
        observe(
            &mut cache,
            &sub("y"),
            RestRequest::Get,
            TTL_MS,
            RestOutcome::NotFound,
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn resources_are_keyed_by_project_and_id() {
        let mut cache = RestNegativeCache::default();
        observe(
            &mut cache,
            &sub("x"),
            RestRequest::Get,
            0,
            RestOutcome::NotFound,
        );
        assert!(serves(&mut cache, &sub("x"), RestRequest::Get, 1));
        assert!(!serves(&mut cache, &sub("y"), RestRequest::Get, 1));
        let other_project = RestResource::parse_path("/v1/projects/q/subscriptions/x").unwrap();
        assert!(!serves(&mut cache, &other_project, RestRequest::Get, 1));
    }

    #[test]
    fn an_earlier_probe_does_not_drop_a_newer_entry() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        observe(
            &mut cache,
            &x,
            RestRequest::Get,
            10_000,
            RestOutcome::NotFound,
        );
        assert!(!serves(&mut cache, &x, RestRequest::Get, 9_000));
        assert!(serves(&mut cache, &x, RestRequest::Get, 10_001));
    }

    #[test]
    fn delayed_observation_preserves_another_connections_newer_entry() {
        let mut cache = RestNegativeCache::default();
        let delayed = sub("delayed");
        let newer = sub("newer");
        let second = other_connection();
        cache.observe(
            second,
            &newer,
            RestRequest::Get,
            at(5_000),
            RestOutcome::NotFound,
        );
        cache.observe(
            second,
            &newer,
            RestRequest::Other,
            at(6_000),
            RestOutcome::Success,
        );
        cache.observe(
            C1,
            &delayed,
            RestRequest::Patch,
            at(0),
            RestOutcome::NotFound,
        );
        assert!(cache.serves(second, &newer, RestRequest::Delete, at(8_000)));
    }

    #[test]
    fn the_cache_stays_bounded_and_keeps_the_newest_entries() {
        let mut cache = RestNegativeCache::default();
        for index in 0..(MAX_ENTRIES + 50) {
            let millis = i64::try_from(index).unwrap();
            observe(
                &mut cache,
                &sub(&format!("n{index}")),
                RestRequest::Get,
                millis,
                RestOutcome::NotFound,
            );
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        let newest = MAX_ENTRIES + 49;
        assert!(serves(
            &mut cache,
            &sub(&format!("n{newest}")),
            RestRequest::Get,
            5_000
        ));
        assert!(!serves(&mut cache, &sub("n0"), RestRequest::Get, 5_000));
    }

    #[test]
    fn expired_entries_are_pruned_before_any_live_one_is_evicted() {
        let mut cache = RestNegativeCache::default();
        for index in 0..MAX_ENTRIES {
            observe(
                &mut cache,
                &sub(&format!("old{index}")),
                RestRequest::Get,
                0,
                RestOutcome::NotFound,
            );
        }
        observe(
            &mut cache,
            &sub("fresh"),
            RestRequest::Get,
            TTL_MS + 10,
            RestOutcome::NotFound,
        );
        assert_eq!(cache.len(), 1);
        assert!(serves(
            &mut cache,
            &sub("fresh"),
            RestRequest::Get,
            TTL_MS + 20
        ));
    }

    #[test]
    fn rule_choices_switch_each_open_choice() {
        let rule = RuleChoice {
            recent_success_exempts: false,
            ..RuleChoice::RECORDED
        };
        let mut cache = RestNegativeCache::new(rule);
        let x = sub("x");
        observe(&mut cache, &x, RestRequest::Get, 10, RestOutcome::Success);
        observe(&mut cache, &x, RestRequest::Get, 20, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 30));
        let short = RuleChoice {
            ttl: LogicalDuration::from_millis(100),
            ..RuleChoice::RECORDED
        };
        let mut cache = RestNegativeCache::new(short);
        observe(&mut cache, &x, RestRequest::Get, 0, RestOutcome::NotFound);
        assert!(serves(&mut cache, &x, RestRequest::Get, 99));
        assert!(!serves(&mut cache, &x, RestRequest::Get, 100));
    }

    /// Pairwise rows from the coverage ledger model (`Connection First PriorSuccess GapMs Probe`),
    /// each checked against the closed-form rule: a GET or PATCH 404 arms unless a GET 200 started
    /// within the window before it; a probe at `gap` is served iff it is a GET, PATCH or DELETE on
    /// the arming connection and `gap < ttl`.
    #[test]
    fn pict_rows_agree_with_the_rule_table() {
        const ROWS: &[&str] = &[
            "Same Get404 None 10349 Get",
            "Same Get404 None 10350 Get",
            "Same Patch404 None 5500 Delete",
            "Other Get404 None 5500 Get",
            "Same Get404 Recent 5500 Get",
            "Same Delete404 None 5500 Get",
            "Same Create404 None 5500 Get",
            "Same Get404 Old 5500 Patch",
            "Same Verb404 None 5500 Get",
            "Other Get200 Recent 10349 Other",
            "Same GetOther Old 5500 Other",
            "Other Patch404 Old 10349 Patch",
            "Other GetOther Recent 12000 Delete",
            "Other Patch404 Recent 0 Other",
            "Same Get200 None 0 Patch",
            "Same Get404 None 12000 Other",
            "Other Verb404 Old 12000 Patch",
            "Other Verb404 Old 10350 Delete",
            "Other Delete404 Old 0 Delete",
            "Other Patch404 Recent 10350 Patch",
            "Other Create404 Recent 10349 Delete",
            "Same Get200 Old 5500 Get",
            "Other Verb404 Recent 0 Other",
            "Other GetOther None 10350 Patch",
            "Same GetOther Recent 0 Get",
            "Other Patch404 Recent 12000 Get",
            "Same Create404 Old 10350 Other",
            "Other Get200 None 12000 Delete",
            "Other Create404 Old 12000 Patch",
            "Same Delete404 Recent 12000 Patch",
            "Other Get200 None 10350 Other",
            "Other Delete404 Recent 10350 Other",
            "Same Delete404 None 10349 Patch",
            "Same Verb404 Old 10349 Patch",
            "Same GetOther Recent 10349 Delete",
            "Same Create404 None 0 Get",
            "Other Get404 None 0 Delete",
        ];
        assert_eq!(ROWS.len(), 37);
        for row in ROWS {
            let [connection, first, prior, gap, probe] =
                <[&str; 5]>::try_from(row.split(' ').collect::<Vec<_>>()).unwrap();
            let resource = sub("r");
            let gap: i64 = gap.parse().unwrap();
            let t0 = 20_000;
            let mut cache = RestNegativeCache::default();
            match prior {
                "Recent" => observe(
                    &mut cache,
                    &resource,
                    RestRequest::Get,
                    t0 - 3_000,
                    RestOutcome::Success,
                ),
                "Old" => observe(
                    &mut cache,
                    &resource,
                    RestRequest::Get,
                    t0 - 12_000,
                    RestOutcome::Success,
                ),
                _ => {}
            }
            let (request, outcome, arms) = match first {
                "Get404" => (RestRequest::Get, RestOutcome::NotFound, true),
                "Patch404" => (RestRequest::Patch, RestOutcome::NotFound, true),
                "Delete404" => (RestRequest::Delete, RestOutcome::NotFound, false),
                "Create404" | "Verb404" => (RestRequest::Other, RestOutcome::NotFound, false),
                "GetOther" => (RestRequest::Get, RestOutcome::Other, false),
                "Get200" => (RestRequest::Get, RestOutcome::Success, false),
                other => panic!("unknown first request {other}"),
            };
            observe(&mut cache, &resource, request, t0, outcome);
            let probe_request = match probe {
                "Get" => RestRequest::Get,
                "Patch" => RestRequest::Patch,
                "Delete" => RestRequest::Delete,
                _ => RestRequest::Other,
            };
            let probe_connection = if connection == "Same" {
                C1
            } else {
                other_connection()
            };
            let expected = arms
                && prior != "Recent"
                && probe != "Other"
                && connection == "Same"
                && gap < TTL_MS;
            assert_eq!(
                cache.serves(probe_connection, &resource, probe_request, at(t0 + gap)),
                expected,
                "{row}"
            );
        }
    }

    // ---- Differential test against a deliberately naive reference ------------------------

    #[derive(Debug, Clone, Copy)]
    struct Step {
        connection: u8,
        key: u8,
        dt: u16,
        request: u8,
        outcome: u8,
    }

    fn step() -> impl Strategy<Value = Step> {
        (0u8..2, 0u8..3, 0u16..4_000, 0u8..4, 0u8..3).prop_map(
            |(connection, key, dt, request, outcome)| Step {
                connection,
                key,
                dt,
                request,
                outcome,
            },
        )
    }

    fn connection_of(code: u8) -> ConnectionId {
        if code == 0 {
            C1
        } else {
            other_connection()
        }
    }
    fn request_of(code: u8) -> RestRequest {
        match code {
            0 => RestRequest::Get,
            1 => RestRequest::Patch,
            2 => RestRequest::Delete,
            _ => RestRequest::Other,
        }
    }
    fn outcome_of(code: u8) -> RestOutcome {
        match code {
            0 => RestOutcome::Success,
            1 => RestOutcome::NotFound,
            _ => RestOutcome::Other,
        }
    }

    /// One step of a history: time, connection, key, request code, outcome code.
    type Event = (i64, u8, u8, u8, u8);

    /// The same rule written as a replay of the whole history on every question.
    fn reference_serves(history: &[Event], connection: u8, key: u8, now: i64) -> bool {
        let mut armed: std::collections::HashMap<(u8, u8), i64> = std::collections::HashMap::new();
        let mut success: std::collections::HashMap<(u8, u8), i64> =
            std::collections::HashMap::new();
        let live = |at: i64, t: i64| t - at >= 0 && t - at < TTL_MS;
        for &(t, c, k, request, outcome) in history {
            match (request, outcome) {
                (0, 0) => {
                    success.insert((c, k), t);
                }
                (0 | 1, 1) => {
                    let already = armed.get(&(c, k)).is_some_and(|&a| live(a, t));
                    let exempt = success.get(&(c, k)).is_some_and(|&a| live(a, t));
                    if !already && !exempt {
                        armed.insert((c, k), t);
                    }
                }
                _ => {}
            }
        }
        armed.get(&(connection, key)).is_some_and(|&a| live(a, now))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn delayed_observations_preserve_newer_cross_connection_entries(
            newer in 1_i64..10_000,
            delayed in proptest::collection::vec(0_i64..1_000, 1..30),
        ) {
            let mut cache = RestNegativeCache::default();
            let resource = sub("newer");
            let second = other_connection();
            cache.observe(second, &resource, RestRequest::Get, at(newer + 1_000), RestOutcome::NotFound);
            for started in delayed {
                cache.observe(C1, &sub("delayed"), RestRequest::Patch, at(started), RestOutcome::NotFound);
            }
            prop_assert!(cache.serves(second, &resource, RestRequest::Delete, at(newer + 1_001)));
        }

        #[test]
        fn the_cache_agrees_with_a_replayed_reference(steps in proptest::collection::vec(step(), 1..60)) {
            let mut cache = RestNegativeCache::default();
            let mut history: Vec<Event> = Vec::new();
            let mut clock = 0_i64;
            for step in steps {
                clock += i64::from(step.dt);
                let resource = sub(&format!("k{}", step.key));
                let connection = connection_of(step.connection);
                let request = request_of(step.request);
                if request != RestRequest::Other {
                    let served = cache.serves(connection, &resource, request, at(clock));
                    prop_assert_eq!(served, reference_serves(&history, step.connection, step.key, clock));
                    if served {
                        continue; // a hit never reaches the backend and is not recorded
                    }
                }
                cache.observe(connection, &resource, request, at(clock), outcome_of(step.outcome));
                history.push((clock, step.connection, step.key, step.request, step.outcome));
                for probe_connection in 0u8..2 {
                    for probe_key in 0u8..3 {
                        let expected = reference_serves(&history, probe_connection, probe_key, clock);
                        let mut copy = cache.clone();
                        prop_assert_eq!(
                            copy.serves(
                                connection_of(probe_connection),
                                &sub(&format!("k{probe_key}")),
                                RestRequest::Get,
                                at(clock),
                            ),
                            expected,
                        );
                    }
                }
            }
        }

        #[test]
        fn no_resource_is_served_before_a_404_or_after_the_window(gap in 0_i64..30_000, key in 0u8..4) {
            let mut cache = RestNegativeCache::default();
            let resource = sub(&format!("k{key}"));
            prop_assert!(!cache.serves(C1, &resource, RestRequest::Get, at(0)));
            cache.observe(C1, &resource, RestRequest::Get, at(0), RestOutcome::NotFound);
            prop_assert_eq!(cache.serves(C1, &resource, RestRequest::Get, at(gap)), gap < TTL_MS);
        }

        #[test]
        fn parse_path_accepts_exactly_the_plain_subscription_form(
            project in "[a-z][a-z0-9-]{1,10}", id in "[A-Za-z0-9._~%+-]{1,12}",
            suffix in prop_oneof![Just(""), Just(":pull"), Just("/x"), Just("/")],
            collection in prop_oneof![Just("subscriptions"), Just("snapshots"), Just("topics")],
        ) {
            let path = format!("/v1/projects/{project}/{collection}/{id}{suffix}");
            let parsed = RestResource::parse_path(&path);
            if suffix.is_empty() && collection == "subscriptions" {
                let parsed = parsed.expect("plain form");
                prop_assert_eq!(parsed.id(), id.as_str());
            } else {
                prop_assert!(parsed.is_none());
            }
        }
    }
}
