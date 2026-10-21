//! Who a request is, and what it may do: the rules loaded for its namespace decide, and a
//! namespace without rules allows everything or, under `productionExact`, only the owner
//! (`RulesMode`, owner ledger 1471 Q4).
//!
//! Credentials are read in one place, [`Access::from_rest`] (and its realtime counterparts),
//! by [`Credentials`] (coordinator ruling Q-R6):
//!
//! - The emulator profile follows the official emulator (firebase-database-emulator
//!   v4.11.2): `Authorization: Bearer <token>` and `access_token=<token>` are OAuth access
//!   tokens, so any of them is an administrator that rules do not apply to. That works only
//!   because the listener is loopback.
//! - The strict profile admits only the emulator's `owner` as an administrator, as Firestore
//!   and Storage do; another access token is refused with 401, since production would have
//!   to verify it and fireemu cannot.
//! - `auth=<ID token>` is the user the token names ([`auth_from_claims`]). Without a
//!   verifier its claims are read unverified, as the official emulator reads them; with one
//!   (fireemu's Auth, which honours `auth.allowUnsignedIdTokens`) only a token it accepts is
//!   a user. Any other value, `auth=owner` included, is anonymous under the emulator profile,
//!   as on the official emulator, and refused with 401 under strict.
//!
//! The emulator's `owner` passes everywhere, `productionExact`'s locked default included.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use fireemu_core_database::rules::{ReadKind, Requester, Rules, RulesError};
use fireemu_core_database::{Json, Path, QueryParams, Tree};

use crate::json_text::{render, Style};
use crate::rest::{Database, RulesMode, SseEvent};
use crate::rules_file;

/// The credential of the local administrator (firebase-tools sends `Bearer owner`).
pub(crate) const OWNER: &str = "owner";

/// Checks an `auth=` ID token presented to a namespace at a time (milliseconds), and answers
/// its claims as JSON text when the token is a user of the namespace's project. The verifier
/// decides which project a namespace belongs to.
pub type IdTokenVerifier = Arc<dyn Fn(&str, &str, i64) -> Option<String> + Send + Sync>;

/// How credentials are read.
#[derive(Clone, Default)]
pub struct Credentials {
    /// The strict profile: only `owner` is an administrator, and a credential that names no
    /// one is refused instead of being anonymous.
    pub strict: bool,
    /// The verifier of `auth=` ID tokens; `None` reads their claims unverified.
    pub id_tokens: Option<IdTokenVerifier>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("strict", &self.strict)
            .field("id_tokens", &self.id_tokens.is_some())
            .finish()
    }
}

impl Credentials {
    /// The `auth` of an ID token presented to `namespace`, if it names a user.
    pub(crate) fn user(&self, token: &str, namespace: &str, now: i64) -> Option<Json> {
        let claims = match &self.id_tokens {
            Some(verify) => crate::json_parse::parse(&verify(token, namespace, now)?).ok()?,
            None => crate::realtime::jwt_claims(token)?,
        };
        let Json::Object(claims) = claims else {
            return None;
        };
        auth_from_claims(&claims).ok()
    }
}

/// A credential the strict profile refuses (answered 401).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refused;

/// Who a request or a realtime connection is.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Access {
    /// The emulator's `owner`.
    Owner,
    /// Another administrator credential (an OAuth access token).
    Admin,
    /// A signed-in user: the `auth` value rules see.
    User(Json),
    /// No usable credential.
    Anonymous,
}

impl Access {
    /// The access of a REST request to `namespace`: its `Authorization` header,
    /// `access_token` or `auth`.
    pub(crate) fn from_rest(
        authorization: Option<&str>,
        params: &BTreeMap<String, String>,
        credentials: &Credentials,
        namespace: &str,
        now: i64,
    ) -> Result<Self, Refused> {
        let bearer = authorization.and_then(|v| v.strip_prefix("Bearer "));
        if let Some(token) = bearer.or_else(|| params.get("access_token").map(String::as_str)) {
            return Self::administrator(token, credentials);
        }
        let Some(token) = params.get("auth") else {
            return Ok(Self::Anonymous);
        };
        match credentials.user(token, namespace, now) {
            Some(auth) => Ok(Self::User(auth)),
            None if credentials.strict => Err(Refused),
            None => Ok(Self::Anonymous),
        }
    }

    /// The access an OAuth access token (or a realtime `gauth` credential) gives.
    pub(crate) fn administrator(token: &str, credentials: &Credentials) -> Result<Self, Refused> {
        if token == OWNER {
            Ok(Self::Owner)
        } else if credentials.strict {
            Err(Refused)
        } else {
            Ok(Self::Admin)
        }
    }

    /// `auth` as rules see it.
    fn auth(&self) -> Json {
        match self {
            Self::User(auth) => auth.clone(),
            _ => Json::Null,
        }
    }
}

/// Claims that stay in `auth.token` only.
const RESERVED_CLAIMS: [&str; 10] = [
    "sub",
    "uid",
    "iat",
    "exp",
    "nbf",
    "aud",
    "iss",
    "jti",
    "auth_time",
    "firebase",
];

/// Builds `auth` from token claims, as the official emulator does: `provider` from
/// `firebase.sign_in_provider` (else `anonymous`) and `token` the claims, then every other
/// claim as a member of its own (so a `provider` or `token` claim replaces those), then `uid`
/// from `sub`. The error names the missing claim.
pub(crate) fn auth_from_claims(claims: &BTreeMap<String, Json>) -> Result<Json, &'static str> {
    let Some(Json::String(subject)) = claims.get("sub") else {
        return Err("sub");
    };
    if !matches!(claims.get("iat"), Some(Json::Number(_))) {
        return Err("iat");
    }
    let provider = match claims.get("firebase") {
        Some(Json::Object(firebase)) => firebase.get("sign_in_provider").cloned(),
        _ => None,
    };
    let mut auth = BTreeMap::from([
        ("token".to_owned(), Json::Object(claims.clone())),
        (
            "provider".to_owned(),
            provider.unwrap_or_else(|| Json::string("anonymous")),
        ),
    ]);
    for (name, value) in claims {
        if !RESERVED_CLAIMS.contains(&name.as_str()) {
            auth.insert(name.clone(), value.clone());
        }
    }
    auth.insert("uid".to_owned(), Json::String(subject.clone()));
    Ok(Json::Object(auth))
}

/// Rules loaded for a namespace, with the text they were loaded from.
#[derive(Debug, Clone)]
pub(crate) struct LoadedRules {
    pub text: String,
    pub rules: Rules,
}

/// The rules text the official emulator answers for a namespace without rules.
fn default_rules_text(open: bool) -> String {
    format!(
        "{{\n    \"rules\": {{\n        \".read\": {open},\n        \".write\": {open}\n    }}\n}}"
    )
}

/// A write to check: what it does to the tree, and the locations it writes.
pub(crate) enum WriteOp<'a> {
    /// A set of `value` at `path`.
    Set(&'a Path, &'a Json),
    /// An update of `entries` (paths relative to `base`).
    Update(&'a Path, &'a [(String, Json)]),
}

impl Database {
    fn bypasses(&self, access: &Access) -> bool {
        match access {
            Access::Owner => true,
            Access::Admin => self.options().rules == RulesMode::AllowAll,
            _ => false,
        }
    }

    /// Whether `access` may read `path` of `namespace` (with `query`).
    pub(crate) fn may_read(
        &self,
        namespace: &str,
        path: &Path,
        query: Option<&QueryParams>,
        kind: ReadKind,
        access: &Access,
        now: i64,
    ) -> bool {
        if self.bypasses(access) {
            return true;
        }
        let Some(loaded) = self.loaded_rules(namespace) else {
            return self.options().rules == RulesMode::AllowAll;
        };
        let auth = access.auth();
        let requester = Requester { auth: &auth, now };
        let root = self.tree(namespace).and_then(Tree::root);
        loaded
            .rules
            .can_read_as(root, path, query, kind, &requester)
    }

    /// Whether `access` may make `op` in `namespace` now. A write the tree refuses is left to
    /// the caller, which answers it with its own refusal.
    pub(crate) fn may_write(
        &self,
        namespace: &str,
        op: &WriteOp<'_>,
        access: &Access,
        now: i64,
    ) -> bool {
        if self.bypasses(access) {
            return true;
        }
        let Some(loaded) = self.loaded_rules(namespace) else {
            return self.options().rules == RulesMode::AllowAll;
        };
        let limits = self.options().limits;
        let before = self
            .tree(namespace)
            .cloned()
            .unwrap_or_else(|| Tree::new(limits));
        let mut after = before.clone();
        let context = fireemu_core_database::ServerValueContext { now_millis: now };
        let written: Vec<Path> = match op {
            WriteOp::Set(path, value) => {
                if after.set(path, value, context).is_err() {
                    return true;
                }
                vec![(*path).clone()]
            }
            WriteOp::Update(base, entries) => {
                if after.update(base, entries, context).is_err() {
                    return true;
                }
                entries
                    .iter()
                    .filter_map(|(key, _)| Path::parse(key, &limits).ok())
                    .map(|relative| base.join(&relative))
                    .collect()
            }
        };
        let auth = access.auth();
        let requester = Requester { auth: &auth, now };
        loaded
            .rules
            .can_write(before.root(), after.root(), &written, &requester)
    }

    /// The rules text of `namespace`: what was loaded, or the default the official emulator
    /// answers (open, or closed under `productionExact`).
    pub fn rules_text(&self, namespace: &str) -> String {
        self.loaded_rules(namespace).map_or_else(
            || default_rules_text(self.options().rules == RulesMode::AllowAll),
            |loaded| loaded.text.clone(),
        )
    }

    /// Loads `text` as the rules of `namespace`. Listens and event streams the new rules no
    /// longer allow are cancelled: the returned events go to the streams, the realtime
    /// cancellations wait among the pushes.
    pub fn set_rules(
        &mut self,
        namespace: &str,
        text: &str,
        now: i64,
    ) -> Result<Vec<(u64, SseEvent)>, RulesError> {
        let rules = rules_file::compile(text)?;
        self.store_rules(
            namespace,
            LoadedRules {
                text: text.to_owned(),
                rules,
            },
        );
        Ok(self.revoke(namespace, None, now))
    }

    /// Loads `text` as the rules of `namespace` from outside a request (a rules file at
    /// startup or after it changed), as `PUT /.settings/rules.json` would. The cancelled
    /// streams hear of it through the flush queue. The error is what that request would answer.
    pub fn load_rules(&mut self, namespace: &str, text: &str, now: i64) -> Result<(), String> {
        crate::namespace::route(Some(namespace), None, namespace)
            .map_err(|_| "Invalid Firebase database name".to_owned())?;
        let events = self
            .set_rules(namespace, text, now)
            .map_err(|error| error.to_string())?;
        self.queue_events(events);
        Ok(())
    }

    /// Records the access of a realtime connection (after `auth`, `gauth` or `unauth`) and
    /// cancels its listens that access no longer allows.
    pub(crate) fn set_client_access(
        &mut self,
        client: u64,
        namespace: &str,
        access: Access,
        now: i64,
    ) {
        self.store_client_access(client, access);
        let _ = self.revoke(namespace, Some(client), now);
    }

    /// Cancels the listens (of `client`, or of everyone) and the event streams of
    /// `namespace` that may no longer read what they follow.
    pub(crate) fn revoke(
        &mut self,
        namespace: &str,
        client: Option<u64>,
        now: i64,
    ) -> Vec<(u64, SseEvent)> {
        let listens: Vec<(u64, u64, Path, Option<QueryParams>)> = self
            .listen_entries(namespace)
            .into_iter()
            .filter(|(_, owner, _, _)| client.is_none_or(|c| c == *owner))
            .collect();
        for (id, owner, path, query) in listens {
            let access = self.client_access(owner);
            if !self.may_read(
                namespace,
                &path,
                query.as_ref(),
                ReadKind::Stream,
                &access,
                now,
            ) {
                self.drop_listen(id);
                self.push_raw(owner, cancel_frame(&path, query.as_ref()));
            }
        }
        let mut events = Vec::new();
        if client.is_none() {
            for (id, path, query, access) in self.subscription_entries(namespace) {
                if !self.may_read(
                    namespace,
                    &path,
                    query.as_ref(),
                    ReadKind::Stream,
                    &access,
                    now,
                ) {
                    self.unsubscribe(id);
                    events.push((id, SseEvent::cancel()));
                }
            }
        }
        self.wake();
        events
    }
}

/// The `c` message that cancels a listen, with its query as the official emulator writes
/// it: `i` (left out for priority order), `sn`, `sp`, `sin`, `en`, `ep`, `ein`, `l`, `vf`.
pub(crate) fn cancel_frame(path: &Path, query: Option<&QueryParams>) -> String {
    let q = query.map_or_else(
        || "null".to_owned(),
        |q| format!("[{}]", wire_query_text(q)),
    );
    format!(
        "{{\"t\":\"d\",\"d\":{{\"b\":{{\"p\":{},\"q\":{q}}},\"a\":\"c\"}}}}",
        render(&Json::String(path.keys().join("/")), Style::Compact)
    )
}

fn wire_query_text(q: &QueryParams) -> String {
    use fireemu_core_database::{BoundKey, Limit, OrderBy};
    let mut members: Vec<(&str, String)> = Vec::new();
    let text = |json: &Json| render(json, Style::Compact);
    match &q.order_by {
        OrderBy::Priority => {}
        OrderBy::Key => members.push(("i", text(&Json::string(".key")))),
        OrderBy::Value => members.push(("i", text(&Json::string(".value")))),
        OrderBy::Child(path) => members.push(("i", text(&Json::String(path.keys().join("/"))))),
    }
    for (bound, name, value, inclusive) in
        [(&q.start, "sn", "sp", "sin"), (&q.end, "en", "ep", "ein")]
    {
        match bound {
            Some(bound) => {
                if let BoundKey::Name(key) = &bound.key {
                    members.push((name, text(&Json::String(key.clone()))));
                }
                members.push((value, text(&bound.value)));
                members.push((inclusive, bound.inclusive.to_string()));
            }
            None => members.push((inclusive, "true".to_owned())),
        }
    }
    match q.limit {
        Some(Limit::First(n)) => {
            members.push(("l", n.to_string()));
            members.push(("vf", text(&Json::string("l"))));
        }
        Some(Limit::Last(n)) => {
            members.push(("l", n.to_string()));
            members.push(("vf", text(&Json::string("r"))));
        }
        None => {}
    }
    let body: Vec<String> = members
        .into_iter()
        .map(|(name, value)| format!("\"{name}\":{value}"))
        .collect();
    format!("{{{}}}", body.join(","))
}
