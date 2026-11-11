//! The production REST frontend's negative cache for subscriptions and snapshots.
//!
//! Production Pub/Sub answers a REST `GET` of a subscription or snapshot with a fast cached
//! 404 for roughly 9.5 seconds after a real 404 on the same URL resource, even when the
//! resource has been created in the meantime. gRPC and topics never show it. A cached 404
//! right after a successful create makes local tests flaky, so this model is **off unless
//! `pubsub.restNegativeCache = "production"` asks for it** (strict profile only, an explicit
//! opt-in); the adapter holds it only then.
//!
//! The rule below is PROVISIONAL (`negcache-v1`). It is the best fit of the recorded
//! production runs (see the issue `pubsub-rest-negative-cache-emulation`), not a verified
//! rule: the arming events, the key, the duration and the exemptions are open until the
//! observation packet has been recorded. Every guess is isolated in one place and named in
//! [`RuleChoice`] so the recording can change it without touching the adapter. Tests whose
//! expectation rests on a guess carry the prefix `provisional_`.
//!
//! The model is pure: it owns no clock, and every call takes the instant the request started
//! on the virtual clock, so a test (or `await-idle`) moves it by moving that clock.

use std::collections::BTreeMap;

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

/// The window, measured from the start of the arming request. Production hits were seen up to
/// 9.47 s and misses from 9.90 s after the start of the last slow 404, so any value in that
/// interval fits; 9.6 s is the provisional choice.
pub const PROVISIONAL_TTL: LogicalDuration = LogicalDuration::from_millis(9_600);

/// The most entries the cache keeps. Expired entries go first, then the oldest, so a client that
/// probes many absent names cannot grow the map without bound.
pub const MAX_ENTRIES: usize = 4096;

/// The guesses the model rests on, each fixed to one value until the observation packet says
/// otherwise. Listed here so a change after the recording is a one-line, one-test edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleChoice {
    /// How long an entry serves, from the start of the request that armed it.
    pub ttl: LogicalDuration,
    /// A failed `PUT` create (for example a 404 for a missing topic) arms the key of its URL.
    pub failed_create_arms: bool,
    /// A `GET` that answered 200 within the window keeps a later 404 from arming (the one
    /// counterexample inside the window was a snapshot read 5 s after such a 200).
    pub recent_success_exempts: bool,
    /// A successful create whose body names another resource clears that resource's entry
    /// (the path/body mismatch runs: a never-created body name stayed slow).
    pub body_name_clears: bool,
}

impl RuleChoice {
    /// The best fit of the recorded production runs.
    pub const PROVISIONAL: Self = Self {
        ttl: PROVISIONAL_TTL,
        failed_create_arms: true,
        recent_success_exempts: true,
        body_name_clears: true,
    };
}

/// What a resource is, as far as the cache is concerned. Topics are never cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestResourceKind {
    /// `projects/{p}/subscriptions/{id}`.
    Subscription,
    /// `projects/{p}/snapshots/{id}`.
    Snapshot,
}

/// A subscription or snapshot as the REST URL names it: kind, project and the final segment.
/// The key never includes the `:verb` suffix, the method or the `resource=` of an error.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RestResource {
    kind: RestResourceKind,
    project: String,
    id: String,
}

impl RestResource {
    /// Reads `/v1/projects/{p}/subscriptions/{id}` or `/v1/projects/{p}/snapshots/{id}`.
    /// Collections, `:verb` forms, extra segments and every other path give `None`.
    #[must_use]
    pub fn parse_path(path: &str) -> Option<Self> {
        Self::parse_segments(path.strip_prefix("/v1/")?)
    }

    /// Reads a full resource name, `projects/{p}/subscriptions/{id}` or
    /// `projects/{p}/snapshots/{id}`.
    #[must_use]
    pub fn parse_full_name(name: &str) -> Option<Self> {
        Self::parse_segments(name)
    }

    fn parse_segments(text: &str) -> Option<Self> {
        let mut parts = text.split('/');
        let (Some("projects"), Some(project), Some(collection), Some(id), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        let kind = match collection {
            "subscriptions" => RestResourceKind::Subscription,
            "snapshots" => RestResourceKind::Snapshot,
            _ => return None,
        };
        if project.is_empty() || id.is_empty() || id.contains(':') {
            return None;
        }
        Some(Self {
            kind,
            project: project.to_owned(),
            id: id.to_owned(),
        })
    }

    /// The kind of resource.
    #[must_use]
    pub const fn kind(&self) -> RestResourceKind {
        self.kind
    }

    /// The final path segment, which is what the error message names.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The request as the cache sees it. Only a `GET` is served from the cache; the others only
/// feed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestRequest {
    /// `GET` of the resource.
    Get,
    /// `PUT` create of the resource, with the `name` the body carried, if it parsed as a
    /// subscription or snapshot name.
    Create {
        /// The body `name`, when present and parseable.
        body_name: Option<RestResource>,
    },
    /// Any other request on the resource (delete, patch, a `:verb`, a read of a different
    /// resource). It neither arms nor clears.
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

/// The cache. One per REST frontend; shared by every request on it.
#[derive(Debug, Clone)]
pub struct RestNegativeCache {
    rule: RuleChoice,
    /// Start of the request that armed each live key.
    armed: BTreeMap<RestResource, LogicalInstant>,
    /// Start of the latest `GET` that answered 200, per key.
    last_success: BTreeMap<RestResource, LogicalInstant>,
}

impl Default for RestNegativeCache {
    fn default() -> Self {
        Self::new(RuleChoice::PROVISIONAL)
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

    /// Whether `request` on `resource`, started at `now`, is answered from the cache with a
    /// 404 instead of reaching the backend. Only a `GET` can be. A hit does not extend the
    /// entry. An entry from a clock that has since moved back is dropped.
    pub fn serves(
        &mut self,
        resource: &RestResource,
        request: &RestRequest,
        now: LogicalInstant,
    ) -> bool {
        if *request != RestRequest::Get {
            return false;
        }
        let Some(&armed_at) = self.armed.get(resource) else {
            return false;
        };
        if self.is_live(armed_at, now) {
            return true;
        }
        self.armed.remove(resource);
        false
    }

    /// Records the outcome of a request that reached the backend (a request served from the
    /// cache must not be recorded: a hit never arms and never extends).
    pub fn observe(
        &mut self,
        resource: &RestResource,
        request: &RestRequest,
        started: LogicalInstant,
        outcome: RestOutcome,
    ) {
        self.forget_stale(started);
        match (request, outcome) {
            (RestRequest::Get, RestOutcome::Success) => {
                self.last_success.insert(resource.clone(), started);
            }
            (RestRequest::Get, RestOutcome::NotFound) => self.arm(resource, started),
            (RestRequest::Create { .. }, RestOutcome::NotFound) if self.rule.failed_create_arms => {
                self.arm(resource, started);
            }
            (RestRequest::Create { body_name }, RestOutcome::Success) => {
                if let Some(named) = body_name.as_ref().filter(|_| self.rule.body_name_clears) {
                    self.armed.remove(named);
                }
            }
            _ => {}
        }
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

    fn arm(&mut self, resource: &RestResource, started: LogicalInstant) {
        if self
            .armed
            .get(resource)
            .is_some_and(|&armed_at| self.is_live(armed_at, started))
        {
            return;
        }
        if self.rule.recent_success_exempts
            && self
                .last_success
                .get(resource)
                .is_some_and(|&seen| self.is_live(seen, started))
        {
            return;
        }
        if self.armed.len() >= MAX_ENTRIES && !self.armed.contains_key(resource) {
            if let Some(oldest) = self
                .armed
                .iter()
                .min_by_key(|(_, &armed_at)| armed_at)
                .map(|(key, _)| key.clone())
            {
                self.armed.remove(&oldest);
            }
        }
        self.armed.insert(resource.clone(), started);
    }

    /// Drops entries and success marks that are no longer inside the window.
    fn forget_stale(&mut self, now: LogicalInstant) {
        let ttl = self.rule.ttl;
        let live = |at: &LogicalInstant| {
            now.checked_duration_since(*at)
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

    fn sub(id: &str) -> RestResource {
        RestResource::parse_full_name(&format!("projects/p/subscriptions/{id}")).unwrap()
    }
    fn snap(id: &str) -> RestResource {
        RestResource::parse_full_name(&format!("projects/p/snapshots/{id}")).unwrap()
    }
    fn at(millis: i64) -> LogicalInstant {
        LogicalInstant::from_unix_seconds(1_800_000_000)
            .checked_add(LogicalDuration::from_millis(millis))
            .unwrap()
    }
    const TTL_MS: i64 = 9_600;

    fn create() -> RestRequest {
        RestRequest::Create { body_name: None }
    }

    #[test]
    fn parses_only_the_plain_subscription_and_snapshot_urls() {
        assert_eq!(
            RestResource::parse_path("/v1/projects/p/subscriptions/s"),
            Some(sub("s"))
        );
        assert_eq!(
            RestResource::parse_path("/v1/projects/p/snapshots/z"),
            Some(snap("z"))
        );
        for path in [
            "/v1/projects/p/subscriptions/s:pull",
            "/v1/projects/p/subscriptions/s:getIamPolicy",
            "/v1/projects/p/subscriptions/s/extra",
            "/v1/projects/p/subscriptions/s/",
            "/v1/projects/p/subscriptions/",
            "/v1/projects/p/subscriptions",
            "/v1/projects/p/topics/t",
            "/v1/projects//subscriptions/s",
            "/v1/projects/p/subscriptions",
            "/v2/projects/p/subscriptions/s",
            "projects/p/subscriptions/s",
            "/v1/projects/p/subscriptions/s/x/y",
            "",
        ] {
            assert_eq!(RestResource::parse_path(path), None, "{path}");
        }
        assert_eq!(RestResource::parse_full_name("projects/p/topics/t"), None);
        assert_eq!(
            RestResource::parse_full_name("/projects/p/subscriptions/s"),
            None
        );
        assert_eq!(sub("s").kind(), RestResourceKind::Subscription);
        assert_eq!(snap("z").kind(), RestResourceKind::Snapshot);
        assert_eq!(sub("s").id(), "s");
    }

    #[test]
    fn a_get_404_serves_later_gets_until_the_window_ends() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        assert!(!cache.serves(&x, &RestRequest::Get, at(0)));
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(1)));
        assert!(cache.serves(&x, &RestRequest::Get, at(TTL_MS - 1)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS + 1)));
    }

    #[test]
    fn a_hit_does_not_extend_the_entry() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(5_000)));
        assert!(cache.serves(&x, &RestRequest::Get, at(9_000)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS)));
    }

    #[test]
    fn only_a_get_is_served() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &create(), at(1)));
        assert!(!cache.serves(&x, &RestRequest::Other, at(1)));
        assert!(cache.serves(&x, &RestRequest::Get, at(1)));
    }

    #[test]
    fn a_successful_create_without_a_body_name_does_not_clear() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        cache.observe(&x, &create(), at(1_000), RestOutcome::Success);
        assert!(cache.serves(&x, &RestRequest::Get, at(3_000)));
    }

    #[test]
    fn provisional_a_failed_create_arms_the_url_resource() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &create(), at(0), RestOutcome::NotFound);
        cache.observe(&x, &create(), at(1_000), RestOutcome::Success);
        assert!(cache.serves(&x, &RestRequest::Get, at(3_000)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS)));
    }

    #[test]
    fn provisional_a_create_that_failed_otherwise_does_not_arm() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &create(), at(0), RestOutcome::Other);
        assert!(!cache.serves(&x, &RestRequest::Get, at(1)));
    }

    #[test]
    fn requests_that_are_neither_get_nor_create_never_arm() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        for outcome in [
            RestOutcome::NotFound,
            RestOutcome::Success,
            RestOutcome::Other,
        ] {
            cache.observe(&x, &RestRequest::Other, at(0), outcome);
        }
        assert!(!cache.serves(&x, &RestRequest::Get, at(1)));
        assert!(cache.is_empty());
    }

    #[test]
    fn a_get_that_failed_otherwise_or_succeeded_does_not_arm() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::Other);
        cache.observe(&x, &RestRequest::Get, at(10), RestOutcome::Success);
        assert!(!cache.serves(&x, &RestRequest::Get, at(20)));
    }

    #[test]
    fn provisional_a_recent_get_200_keeps_a_later_404_from_arming() {
        let mut cache = RestNegativeCache::default();
        let x = snap("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::Success);
        cache.observe(&x, &RestRequest::Get, at(3_700), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &RestRequest::Get, at(5_000)));
    }

    #[test]
    fn provisional_an_old_get_200_no_longer_exempts() {
        let mut cache = RestNegativeCache::default();
        let x = snap("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::Success);
        cache.observe(&x, &RestRequest::Get, at(TTL_MS - 1), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS)));
        let mut cache = RestNegativeCache::default();
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::Success);
        cache.observe(&x, &RestRequest::Get, at(TTL_MS), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(TTL_MS + 1)));
    }

    #[test]
    fn provisional_a_create_naming_the_resource_in_its_body_clears_it() {
        let mut cache = RestNegativeCache::default();
        let named = sub("named");
        let url = sub("url");
        cache.observe(&named, &RestRequest::Get, at(0), RestOutcome::NotFound);
        let request = RestRequest::Create {
            body_name: Some(named.clone()),
        };
        cache.observe(&url, &request, at(1_000), RestOutcome::Success);
        assert!(!cache.serves(&named, &RestRequest::Get, at(3_000)));
    }

    #[test]
    fn provisional_a_failed_create_does_not_clear_the_body_name() {
        let mut cache = RestNegativeCache::default();
        let named = sub("named");
        let url = sub("url");
        cache.observe(&named, &RestRequest::Get, at(0), RestOutcome::NotFound);
        let request = RestRequest::Create {
            body_name: Some(named.clone()),
        };
        cache.observe(&url, &request, at(1_000), RestOutcome::Other);
        assert!(cache.serves(&named, &RestRequest::Get, at(3_000)));
    }

    #[test]
    fn provisional_a_body_name_of_another_kind_clears_nothing_of_this_kind() {
        let mut cache = RestNegativeCache::default();
        cache.observe(&sub("x"), &RestRequest::Get, at(0), RestOutcome::NotFound);
        let request = RestRequest::Create {
            body_name: Some(snap("x")),
        };
        cache.observe(&sub("y"), &request, at(1_000), RestOutcome::Success);
        assert!(cache.serves(&sub("x"), &RestRequest::Get, at(3_000)));
    }

    #[test]
    fn the_entry_keeps_its_first_anchor_when_a_second_404_reaches_the_backend() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        cache.observe(&x, &create(), at(5_000), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(TTL_MS - 1)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS)));
    }

    #[test]
    fn an_expired_entry_is_armed_again_by_a_new_404() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &RestRequest::Get, at(TTL_MS + 100)));
        cache.observe(
            &x,
            &RestRequest::Get,
            at(TTL_MS + 200),
            RestOutcome::NotFound,
        );
        assert!(cache.serves(&x, &RestRequest::Get, at(TTL_MS + 300)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(2 * TTL_MS + 200)));
    }

    #[test]
    fn len_counts_the_live_entries_and_an_expired_one_is_gone_at_the_next_observation() {
        let mut cache = RestNegativeCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.observe(&sub("x"), &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        // At exactly the window length the first entry no longer counts.
        cache.observe(
            &sub("y"),
            &RestRequest::Get,
            at(TTL_MS),
            RestOutcome::NotFound,
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn resources_are_keyed_by_kind_project_and_id() {
        let mut cache = RestNegativeCache::default();
        cache.observe(&sub("x"), &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(cache.serves(&sub("x"), &RestRequest::Get, at(1)));
        assert!(!cache.serves(&snap("x"), &RestRequest::Get, at(1)));
        assert!(!cache.serves(&sub("y"), &RestRequest::Get, at(1)));
        let other_project = RestResource::parse_full_name("projects/q/subscriptions/x").unwrap();
        assert!(!cache.serves(&other_project, &RestRequest::Get, at(1)));
    }

    #[test]
    fn a_clock_that_moved_back_drops_the_entry() {
        let mut cache = RestNegativeCache::default();
        let x = sub("x");
        cache.observe(&x, &RestRequest::Get, at(10_000), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &RestRequest::Get, at(9_000)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(10_001)));
    }

    #[test]
    fn the_cache_stays_bounded_and_keeps_the_newest_entries() {
        let mut cache = RestNegativeCache::default();
        for index in 0..(MAX_ENTRIES + 50) {
            let millis = i64::try_from(index).unwrap();
            cache.observe(
                &sub(&format!("n{index}")),
                &RestRequest::Get,
                at(millis),
                RestOutcome::NotFound,
            );
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        let newest = MAX_ENTRIES + 49;
        assert!(cache.serves(&sub(&format!("n{newest}")), &RestRequest::Get, at(5_000)));
        assert!(!cache.serves(&sub("n0"), &RestRequest::Get, at(5_000)));
    }

    #[test]
    fn expired_entries_are_pruned_before_any_live_one_is_evicted() {
        let mut cache = RestNegativeCache::default();
        for index in 0..MAX_ENTRIES {
            cache.observe(
                &sub(&format!("old{index}")),
                &RestRequest::Get,
                at(0),
                RestOutcome::NotFound,
            );
        }
        cache.observe(
            &sub("fresh"),
            &RestRequest::Get,
            at(TTL_MS + 10),
            RestOutcome::NotFound,
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.serves(&sub("fresh"), &RestRequest::Get, at(TTL_MS + 20)));
    }

    #[test]
    fn rule_choices_switch_each_guess_off() {
        let rule = RuleChoice {
            failed_create_arms: false,
            recent_success_exempts: false,
            body_name_clears: false,
            ..RuleChoice::PROVISIONAL
        };
        let mut cache = RestNegativeCache::new(rule);
        let x = sub("x");
        cache.observe(&x, &create(), at(0), RestOutcome::NotFound);
        assert!(!cache.serves(&x, &RestRequest::Get, at(1)));
        cache.observe(&x, &RestRequest::Get, at(10), RestOutcome::Success);
        cache.observe(&x, &RestRequest::Get, at(20), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(30)));
        let request = RestRequest::Create {
            body_name: Some(x.clone()),
        };
        cache.observe(&sub("y"), &request, at(40), RestOutcome::Success);
        assert!(cache.serves(&x, &RestRequest::Get, at(50)));
        let short = RuleChoice {
            ttl: LogicalDuration::from_millis(100),
            ..RuleChoice::PROVISIONAL
        };
        let mut cache = RestNegativeCache::new(short);
        cache.observe(&x, &RestRequest::Get, at(0), RestOutcome::NotFound);
        assert!(cache.serves(&x, &RestRequest::Get, at(99)));
        assert!(!cache.serves(&x, &RestRequest::Get, at(100)));
    }

    /// Pairwise rows from the coverage ledger model (`Kind First PriorSuccess GapMs Probe`),
    /// each checked against the closed-form rule: a GET 404 or a create 404 arms unless a GET 200
    /// started within the window before it; a GET at `gap` is served iff it is a GET and
    /// `gap < ttl`.
    #[test]
    fn pict_rows_agree_with_the_rule_table() {
        const ROWS: &[&str] = &[
            "Subscription Get404 None 4000 Get",
            "Snapshot Create404 None 9599 Get",
            "Subscription Get404 None 9600 Get",
            "Snapshot Get404 Recent 4000 Get",
            "Subscription Create404 Old 4000 Create",
            "Subscription GetOther Old 9599 Other",
            "Snapshot Create200 Recent 9600 Other",
            "Subscription Create404 Recent 0 Other",
            "Subscription Create200 None 12000 Create",
            "Snapshot Other404 Recent 9599 Create",
            "Snapshot Other404 Old 12000 Other",
            "Snapshot Get404 Recent 12000 Other",
            "Snapshot Create200 Old 9599 Get",
            "Snapshot Create200BodyNameSelf Old 0 Get",
            "Snapshot Create404 None 12000 Get",
            "Subscription Create200BodyNameSelf None 4000 Other",
            "Snapshot GetOther None 0 Create",
            "Subscription Get404 Old 9599 Create",
            "Snapshot Create200 Old 0 Create",
            "Snapshot GetOther Recent 12000 Get",
            "Snapshot Create200BodyNameSelf Recent 12000 Create",
            "Subscription Create200BodyNameSelf Old 9599 Create",
            "Snapshot Create200 Old 4000 Create",
            "Snapshot Create404 Old 9600 Create",
            "Subscription Create200BodyNameSelf Old 9600 Get",
            "Subscription GetOther Old 4000 Other",
            "Subscription GetOther Old 9600 Other",
            "Subscription Other404 None 9600 Get",
            "Snapshot Get404 None 0 Create",
            "Subscription Other404 Old 0 Get",
            "Subscription Other404 None 4000 Create",
        ];
        assert_eq!(ROWS.len(), 31);
        for row in ROWS {
            let [kind, first, prior, gap, probe] =
                <[&str; 5]>::try_from(row.split(' ').collect::<Vec<_>>()).unwrap();
            let resource = if kind == "Snapshot" {
                snap("r")
            } else {
                sub("r")
            };
            let gap: i64 = gap.parse().unwrap();
            let t0 = 20_000;
            let mut cache = RestNegativeCache::default();
            match prior {
                "Recent" => cache.observe(
                    &resource,
                    &RestRequest::Get,
                    at(t0 - 3_000),
                    RestOutcome::Success,
                ),
                "Old" => cache.observe(
                    &resource,
                    &RestRequest::Get,
                    at(t0 - 12_000),
                    RestOutcome::Success,
                ),
                _ => {}
            }
            let (request, outcome, arms) = match first {
                "Get404" => (RestRequest::Get, RestOutcome::NotFound, true),
                "Create404" => (create(), RestOutcome::NotFound, true),
                "GetOther" => (RestRequest::Get, RestOutcome::Other, false),
                "Create200" => (create(), RestOutcome::Success, false),
                "Create200BodyNameSelf" => (
                    RestRequest::Create {
                        body_name: Some(resource.clone()),
                    },
                    RestOutcome::Success,
                    false,
                ),
                "Other404" => (RestRequest::Other, RestOutcome::NotFound, false),
                other => panic!("unknown first request {other}"),
            };
            cache.observe(&resource, &request, at(t0), outcome);
            let probe_request = match probe {
                "Get" => RestRequest::Get,
                "Create" => create(),
                _ => RestRequest::Other,
            };
            let expected = arms && prior != "Recent" && probe == "Get" && gap < TTL_MS;
            assert_eq!(
                cache.serves(&resource, &probe_request, at(t0 + gap)),
                expected,
                "{row}"
            );
        }
    }

    // ---- Differential test against a deliberately naive reference ------------------------

    #[derive(Debug, Clone)]
    enum Step {
        Get {
            key: u8,
            kind: bool,
            dt: u16,
            outcome: u8,
        },
        Create {
            key: u8,
            kind: bool,
            dt: u16,
            outcome: u8,
            body: Option<(u8, bool)>,
        },
        Other {
            key: u8,
            kind: bool,
            dt: u16,
            outcome: u8,
        },
    }

    fn step() -> impl Strategy<Value = Step> {
        let key = 0u8..4;
        let dt = 0u16..4_000;
        let outcome = 0u8..3;
        prop_oneof![
            (key.clone(), any::<bool>(), dt.clone(), outcome.clone()).prop_map(
                |(key, kind, dt, outcome)| Step::Get {
                    key,
                    kind,
                    dt,
                    outcome
                }
            ),
            (
                key.clone(),
                any::<bool>(),
                dt.clone(),
                outcome.clone(),
                proptest::option::of((0u8..4, any::<bool>()))
            )
                .prop_map(|(key, kind, dt, outcome, body)| Step::Create {
                    key,
                    kind,
                    dt,
                    outcome,
                    body
                }),
            (key, any::<bool>(), dt, outcome).prop_map(|(key, kind, dt, outcome)| Step::Other {
                key,
                kind,
                dt,
                outcome
            }),
        ]
    }

    fn resource_of(key: u8, kind: bool) -> RestResource {
        if kind {
            snap(&format!("k{key}"))
        } else {
            sub(&format!("k{key}"))
        }
    }
    fn outcome_of(code: u8) -> RestOutcome {
        match code {
            0 => RestOutcome::Success,
            1 => RestOutcome::NotFound,
            _ => RestOutcome::Other,
        }
    }

    /// One step of a history: time, key, kind, operation, outcome code, body name.
    type Event = (i64, u8, bool, &'static str, u8, Option<(u8, bool)>);

    /// The same rule written as a replay of the whole history on every question.
    fn reference_serves(history: &[Event], key: u8, kind: bool, now: i64) -> bool {
        // Replays each event in order, keeping (armed_at, last_success) per key.
        let mut armed: std::collections::HashMap<(u8, bool), i64> =
            std::collections::HashMap::default();
        let mut success: std::collections::HashMap<(u8, bool), i64> =
            std::collections::HashMap::default();
        let live = |at: i64, t: i64| t - at >= 0 && t - at < TTL_MS;
        for &(t, k, kd, op, code, body) in history {
            match (op, code) {
                ("get", 0) => {
                    success.insert((k, kd), t);
                }
                ("get" | "create", 1) => {
                    let already = armed.get(&(k, kd)).is_some_and(|&a| live(a, t));
                    let exempt = success.get(&(k, kd)).is_some_and(|&a| live(a, t));
                    if !already && !exempt {
                        armed.insert((k, kd), t);
                    }
                }
                ("create", 0) => {
                    if let Some(named) = body {
                        armed.remove(&named);
                    }
                }
                _ => {}
            }
        }
        armed.get(&(key, kind)).is_some_and(|&a| live(a, now))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn provisional_the_cache_agrees_with_a_replayed_reference(steps in proptest::collection::vec(step(), 1..60)) {
            let mut cache = RestNegativeCache::default();
            let mut history: Vec<Event> = Vec::new();
            let mut clock = 0_i64;
            for step in steps {
                let (key, kind, dt, op, code, body) = match step {
                    Step::Get { key, kind, dt, outcome } => (key, kind, dt, "get", outcome, None),
                    Step::Create { key, kind, dt, outcome, body } => (key, kind, dt, "create", outcome, body),
                    Step::Other { key, kind, dt, outcome } => (key, kind, dt, "other", outcome, None),
                };
                clock += i64::from(dt);
                let resource = resource_of(key, kind);
                if op == "get" {
                    let served = cache.serves(&resource, &RestRequest::Get, at(clock));
                    prop_assert_eq!(served, reference_serves(&history, key, kind, clock));
                    if served {
                        continue; // a hit never reaches the backend and is not recorded
                    }
                }
                let request = match op {
                    "get" => RestRequest::Get,
                    "create" => RestRequest::Create {
                        // A body name is the same kind as the create (the reference removes by key and kind).
                        body_name: body.map(|(id, kind)| resource_of(id, kind)),
                    },
                    _ => RestRequest::Other,
                };
                cache.observe(&resource, &request, at(clock), outcome_of(code));
                history.push((clock, key, kind, op, code, body));
                for probe_key in 0u8..4 {
                    for probe_kind in [false, true] {
                        let expected = reference_serves(&history, probe_key, probe_kind, clock);
                        let mut copy = cache.clone();
                        prop_assert_eq!(
                            copy.serves(&resource_of(probe_key, probe_kind), &RestRequest::Get, at(clock)),
                            expected,
                        );
                    }
                }
            }
        }

        #[test]
        fn no_resource_is_served_before_a_404_or_after_the_window(
            gap in 0_i64..30_000, kind in any::<bool>(), key in 0u8..4,
        ) {
            let mut cache = RestNegativeCache::default();
            let resource = resource_of(key, kind);
            prop_assert!(!cache.serves(&resource, &RestRequest::Get, at(0)));
            cache.observe(&resource, &RestRequest::Get, at(0), RestOutcome::NotFound);
            prop_assert_eq!(cache.serves(&resource, &RestRequest::Get, at(gap)), gap < TTL_MS);
        }

        #[test]
        fn parse_path_accepts_exactly_the_two_plain_forms(
            project in "[a-z][a-z0-9-]{1,10}", id in "[A-Za-z0-9._~%+-]{1,12}",
            suffix in prop_oneof![Just(""), Just(":pull"), Just("/x"), Just("/")],
            collection in prop_oneof![Just("subscriptions"), Just("snapshots"), Just("topics")],
        ) {
            let path = format!("/v1/projects/{project}/{collection}/{id}{suffix}");
            let parsed = RestResource::parse_path(&path);
            if suffix.is_empty() && collection != "topics" {
                let parsed = parsed.expect("plain form");
                prop_assert_eq!(parsed.id(), id.as_str());
                prop_assert_eq!(
                    parsed.kind(),
                    if collection == "snapshots" { RestResourceKind::Snapshot } else { RestResourceKind::Subscription }
                );
            } else {
                prop_assert!(parsed.is_none());
            }
        }
    }
}
