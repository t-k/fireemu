//! The project-scoped App Check registry (specification sections 7.1, 8, 9 and 14).
//!
//! The registry owns registered apps, the project-number binding in both directions, the
//! static and dynamic debug-token digests, the project session epoch and the per-epoch token
//! counter that makes `jti` unique. It never sees a raw debug secret, only its digest.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::claims::AppCheckClaims;
use crate::limits::{
    MAX_APPS, MAX_APP_ID_BYTES, MAX_COUNTER_KEYS_PER_PROJECT, MAX_DEBUG_TOKENS_PER_APP,
    MAX_DISPLAY_NAME_BYTES, MAX_OBSERVED_PROJECTS, MAX_OBSERVED_PROJECT_ID_BYTES,
    MAX_RETAINED_OBSERVATIONS_PER_PROJECT, MAX_TOKEN_TTL_SECONDS, MIN_TOKEN_TTL_SECONDS,
};
use crate::observe::{Observation, ObservationCounterKey};

/// The SHA-256 digest of a canonical debug token.
///
/// `Debug` redacts the bytes: a digest is a credential verifier, and section 16 forbids it in
/// trace, snapshot, log, UI and error output. Only [`Self::prefix`] is publishable.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugTokenDigest([u8; 32]);

impl DebugTokenDigest {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses the canonical configuration form: exactly 64 lowercase hexadecimal characters.
    pub fn parse_hex(text: &str) -> Result<Self, RegistryError> {
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RegistryError::InvalidDigest);
        }
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(RegistryError::InvalidDigest);
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_value(text.as_bytes()[i * 2]).ok_or(RegistryError::InvalidDigest)?;
            let lo = hex_value(text.as_bytes()[i * 2 + 1]).ok_or(RegistryError::InvalidDigest)?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// The raw digest bytes, for the constant-time comparison in the shell.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first eight hexadecimal characters: the only part a list response may show.
    #[must_use]
    pub fn prefix(&self) -> String {
        let mut out = String::with_capacity(8);
        for byte in &self.0[..4] {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0F));
        }
        out
    }
}

impl fmt::Debug for DebugTokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DebugTokenDigest([redacted])")
    }
}

const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

/// A project session epoch: an unpredictable 128-bit value regenerated at project creation and
/// at every invalidating lifecycle transition (reset, restore, deletion).
///
/// `Debug` redacts it (section 7.2). The raw value necessarily appears in the signed
/// `fireemu_epoch` claim, which is what makes local tokens non-portable across a reset; it must
/// never appear in configuration output, traces, snapshots, logs, UI responses or panics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProjectEpoch(u128);

impl ProjectEpoch {
    /// Wraps a raw 128-bit epoch. Callers draw it from the OS CSPRNG, or from a seeded
    /// generator in tests.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The claim text: 32 lowercase hexadecimal characters.
    #[must_use]
    pub fn claim_text(self) -> String {
        let mut out = String::with_capacity(32);
        for shift in (0..32).rev() {
            out.push(hex_digit(((self.0 >> (shift * 4)) & 0xF) as u8));
        }
        out
    }

    /// The raw value. Only the token issuer and the verifier may call this.
    #[must_use]
    pub const fn expose(self) -> u128 {
        self.0
    }
}

impl fmt::Debug for ProjectEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectEpoch([redacted])")
    }
}

/// A dynamically registered debug token (section 9). The raw secret is never stored.
#[derive(Clone, PartialEq, Eq)]
pub struct DebugTokenRecord {
    /// Stable identifier used by the management routes.
    pub id: String,
    /// Display name, at most [`MAX_DISPLAY_NAME_BYTES`] bytes.
    pub display_name: String,
    /// Logical creation time.
    pub created_at: LogicalInstant,
    /// SHA-256 digest of the canonical secret.
    pub digest: DebugTokenDigest,
}

impl fmt::Debug for DebugTokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugTokenRecord")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("created_at", &self.created_at)
            .field("digest", &self.digest)
            .finish()
    }
}

/// One app as canonical configuration declares it (`appCheck.apps[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRegistration {
    /// Firebase project ID.
    pub project_id: String,
    /// Firebase project number: decimal ASCII digits, compared as a string.
    pub project_number: String,
    /// Firebase app ID.
    pub app_id: String,
    /// Whether the app may exchange and whether its tokens still verify.
    pub enabled: bool,
    /// Static debug-token digests from configuration.
    pub debug_token_digests: Vec<DebugTokenDigest>,
}

/// A registered app and the debug-token digests bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredApp {
    project_id: String,
    project_number: String,
    app_id: String,
    enabled: bool,
    static_digests: Vec<DebugTokenDigest>,
    dynamic: Vec<DebugTokenRecord>,
}

impl RegisteredApp {
    /// Firebase project ID.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Firebase project number.
    #[must_use]
    pub fn project_number(&self) -> &str {
        &self.project_number
    }

    /// Firebase app ID.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Whether the app is enabled. A disabled app refuses new exchanges and its previously
    /// issued tokens stop verifying, because the state is read on every request.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Every digest bound to the app, static configuration first.
    #[must_use]
    pub fn digests(&self) -> Vec<DebugTokenDigest> {
        let mut out = self.static_digests.clone();
        out.extend(self.dynamic.iter().map(|r| r.digest));
        out
    }

    /// Digests bound to the app.
    #[must_use]
    pub fn digest_count(&self) -> usize {
        self.static_digests.len() + self.dynamic.len()
    }

    /// The dynamically registered debug tokens, oldest first.
    #[must_use]
    pub fn dynamic_tokens(&self) -> &[DebugTokenRecord] {
        &self.dynamic
    }
}

/// Why a registration, lookup or configuration value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// More than [`MAX_APPS`] apps.
    TooManyApps,
    /// More than [`MAX_DEBUG_TOKENS_PER_APP`] digests on one app.
    TooManyDebugTokens,
    /// The same `(projectId, appId)` twice.
    DuplicateApp,
    /// One project ID mapped to two project numbers.
    ProjectNumberConflict,
    /// One project number mapped to two project IDs.
    ProjectIdConflict,
    /// One app ID used by two projects.
    AppIdReused,
    /// `projectNumber` is not decimal ASCII digits, is empty, or has a leading zero.
    InvalidProjectNumber,
    /// The project ID is empty or too long.
    InvalidProjectId,
    /// The app ID is empty or longer than [`MAX_APP_ID_BYTES`].
    InvalidAppId,
    /// A standard `1:{projectNumber}:{platform}:{opaque}` app ID names another project number.
    AppIdProjectNumberMismatch,
    /// A digest is not 64 lowercase hexadecimal characters.
    InvalidDigest,
    /// The display name is empty or longer than [`MAX_DISPLAY_NAME_BYTES`].
    InvalidDisplayName,
    /// No such project, or no such app in it.
    UnknownApp,
    /// The project has no App Check registration.
    UnknownProject,
    /// The project has no epoch yet; nothing can be issued or verified for it.
    NoEpoch,
    /// The app is registered but disabled.
    AppDisabled,
    /// The token TTL is outside 1800..=604800 seconds.
    InvalidTokenTtl,
    /// No debug token with that identifier.
    UnknownDebugToken,
    /// A dynamic debug-token identifier was reused.
    DuplicateDebugToken,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooManyApps => "at most 1024 App Check apps may be configured",
            Self::TooManyDebugTokens => "at most 128 debug-token digests may be registered per app",
            Self::DuplicateApp => "duplicate (projectId, appId) registration",
            Self::ProjectNumberConflict => "one project ID maps to exactly one project number",
            Self::ProjectIdConflict => "one project number maps to exactly one project ID",
            Self::AppIdReused => "one app ID belongs to exactly one project",
            Self::InvalidProjectNumber => {
                "projectNumber must be decimal ASCII digits without a leading zero"
            }
            Self::InvalidProjectId => "projectId must be a non-empty name of at most 63 bytes",
            Self::InvalidAppId => "appId must be non-empty and at most 256 UTF-8 bytes",
            Self::AppIdProjectNumberMismatch => {
                "the project number embedded in the app ID does not match projectNumber"
            }
            Self::InvalidDigest => "debugTokenSha256 must be 64 lowercase hexadecimal characters",
            Self::InvalidDisplayName => {
                "the display name must be non-empty and at most 128 UTF-8 bytes"
            }
            Self::UnknownApp => "no such App Check app in this project",
            Self::UnknownProject => "this project has no App Check registration",
            Self::NoEpoch => "this project has no App Check session epoch",
            Self::AppDisabled => "the App Check app is disabled",
            Self::InvalidTokenTtl => {
                "tokenTtlSeconds must be between 1800 and 604800 seconds inclusive"
            }
            Self::UnknownDebugToken => "no such debug token",
            Self::DuplicateDebugToken => "duplicate debug-token identifier",
        };
        f.write_str(text)
    }
}

impl std::error::Error for RegistryError {}

/// Validates a project number: decimal ASCII digits, non-empty, no leading zero.
pub fn validate_project_number(number: &str) -> Result<(), RegistryError> {
    if number.is_empty()
        || number.len() > 32
        || !number.bytes().all(|b| b.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
        || number == "0"
    {
        return Err(RegistryError::InvalidProjectNumber);
    }
    Ok(())
}

/// The project number embedded in a standard `1:{projectNumber}:{platform}:{opaque}` app ID.
#[must_use]
pub fn embedded_project_number(app_id: &str) -> Option<&str> {
    let mut parts = app_id.split(':');
    if parts.next()? != "1" {
        return None;
    }
    let number = parts.next()?;
    // A standard app ID has exactly four colon-separated parts.
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(number)
}

/// Validates one configuration entry without registering it.
pub fn validate_registration(app: &AppRegistration) -> Result<(), RegistryError> {
    if app.project_id.is_empty() || app.project_id.len() > 63 {
        return Err(RegistryError::InvalidProjectId);
    }
    validate_project_number(&app.project_number)?;
    if app.app_id.is_empty() || app.app_id.len() > MAX_APP_ID_BYTES {
        return Err(RegistryError::InvalidAppId);
    }
    if let Some(embedded) = embedded_project_number(&app.app_id) {
        if embedded != app.project_number {
            return Err(RegistryError::AppIdProjectNumberMismatch);
        }
    }
    if app.debug_token_digests.len() > MAX_DEBUG_TOKENS_PER_APP {
        return Err(RegistryError::TooManyDebugTokens);
    }
    Ok(())
}

/// Validates a debug-token display name.
pub fn validate_display_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() || name.len() > MAX_DISPLAY_NAME_BYTES || name.chars().any(char::is_control)
    {
        return Err(RegistryError::InvalidDisplayName);
    }
    Ok(())
}

/// Per-project mutable state that issuance touches with a shared reference.
#[derive(Debug)]
struct ProjectState {
    epoch: ProjectEpoch,
    /// Counter inside the current epoch; `jti` is epoch plus this value.
    counter: AtomicU64,
    /// Non-secret policy generation, bumped by every epoch rotation.
    generation: AtomicU64,
}

/// What one project observed: its own bounded ring and its own counters (section 15).
///
/// One project per ring is the point. A runtime-wide ring would let heavy traffic to one
/// project evict another project's recent observations, so what the control API answered for
/// a session would depend on what unrelated sessions were doing.
#[derive(Debug, Default)]
struct ProjectObservations {
    /// The retained observations, oldest first.
    ring: VecDeque<Observation>,
    /// Counters over every observation ever recorded for the project in this epoch of the
    /// project's lifecycle, including those the ring has already dropped.
    counters: BTreeMap<ObservationCounterKey, u64>,
    /// When this ring was last written, for the bounded table's eviction order.
    touched: u64,
}

impl ProjectObservations {
    /// Counts one observation under its bounded key.
    fn count(&mut self, observation: &Observation) {
        let key = ObservationCounterKey::of(observation);
        if let Some(count) = self.counters.get_mut(&key) {
            *count = count.saturating_add(1);
            return;
        }
        if self.counters.len() < MAX_COUNTER_KEYS_PER_PROJECT {
            self.counters.insert(key, 1);
            return;
        }
        // The label space of this project is full: fold the count into the key that carries
        // no identity rather than dropping it or letting the map grow.
        let folded = key.aggregated();
        if let Some(count) = self.counters.get_mut(&folded) {
            *count = count.saturating_add(1);
        } else if self.counters.len() < MAX_COUNTER_KEYS_PER_PROJECT {
            self.counters.insert(folded, 1);
        }
    }

    /// Retains one observation, dropping this project's oldest beyond the bound.
    fn retain(&mut self, observation: Observation) {
        if self.ring.len() >= MAX_RETAINED_OBSERVATIONS_PER_PROJECT {
            self.ring.pop_front();
        }
        self.ring.push_back(observation);
    }
}

/// The observation rings of every observed project, and the clock that orders them.
#[derive(Debug, Default)]
struct ObservationLog {
    projects: BTreeMap<String, ProjectObservations>,
    next_touch: u64,
}

/// The App Check registry of one daemon.
///
/// Apps come only from canonical configuration in the initial delivery; dynamic debug tokens
/// come from the privileged management routes.
#[derive(Debug)]
pub struct AppCheckRegistry {
    apps: BTreeMap<(String, String), RegisteredApp>,
    number_of_project: BTreeMap<String, String>,
    project_of_number: BTreeMap<String, String>,
    project_of_app: BTreeMap<String, String>,
    projects: BTreeMap<String, ProjectState>,
    token_ttl_seconds: i64,
    next_debug_token_seq: AtomicU64,
    observations: Mutex<ObservationLog>,
}

impl AppCheckRegistry {
    /// A registry with the configured session-token lifetime.
    pub fn new(token_ttl_seconds: i64) -> Result<Self, RegistryError> {
        if !(MIN_TOKEN_TTL_SECONDS..=MAX_TOKEN_TTL_SECONDS).contains(&token_ttl_seconds) {
            return Err(RegistryError::InvalidTokenTtl);
        }
        Ok(Self {
            apps: BTreeMap::new(),
            number_of_project: BTreeMap::new(),
            project_of_number: BTreeMap::new(),
            project_of_app: BTreeMap::new(),
            projects: BTreeMap::new(),
            token_ttl_seconds,
            next_debug_token_seq: AtomicU64::new(1),
            observations: Mutex::new(ObservationLog::default()),
        })
    }

    /// The configured session-token lifetime in seconds.
    #[must_use]
    pub const fn token_ttl_seconds(&self) -> i64 {
        self.token_ttl_seconds
    }

    /// The session-token lifetime as a logical duration.
    #[must_use]
    pub const fn token_ttl(&self) -> LogicalDuration {
        LogicalDuration::from_seconds(self.token_ttl_seconds)
    }

    /// Registers one configured app, enforcing every binding rule of section 8.
    pub fn register_app(&mut self, app: AppRegistration) -> Result<(), RegistryError> {
        validate_registration(&app)?;
        if self.apps.len() >= MAX_APPS {
            return Err(RegistryError::TooManyApps);
        }
        let key = (app.project_id.clone(), app.app_id.clone());
        if self.apps.contains_key(&key) {
            return Err(RegistryError::DuplicateApp);
        }
        match self.number_of_project.get(&app.project_id) {
            Some(existing) if existing != &app.project_number => {
                return Err(RegistryError::ProjectNumberConflict)
            }
            _ => {}
        }
        match self.project_of_number.get(&app.project_number) {
            Some(existing) if existing != &app.project_id => {
                return Err(RegistryError::ProjectIdConflict)
            }
            _ => {}
        }
        if let Some(owner) = self.project_of_app.get(&app.app_id) {
            if owner != &app.project_id {
                return Err(RegistryError::AppIdReused);
            }
        }
        self.number_of_project
            .insert(app.project_id.clone(), app.project_number.clone());
        self.project_of_number
            .insert(app.project_number.clone(), app.project_id.clone());
        self.project_of_app
            .insert(app.app_id.clone(), app.project_id.clone());
        self.apps.insert(
            key,
            RegisteredApp {
                project_id: app.project_id,
                project_number: app.project_number,
                app_id: app.app_id,
                enabled: app.enabled,
                static_digests: app.debug_token_digests,
                dynamic: Vec::new(),
            },
        );
        Ok(())
    }

    /// Installs the first epoch of a project, or replaces it (reset, restore, deletion).
    /// Rotation also resets the per-epoch `jti` counter and bumps the policy generation, so a
    /// counter value can never recreate a token ID from a previous epoch.
    pub fn set_project_epoch(&mut self, project_id: &str, epoch: ProjectEpoch) {
        match self.projects.get_mut(project_id) {
            Some(state) => {
                state.epoch = epoch;
                state.counter.store(0, Ordering::SeqCst);
                state.generation.fetch_add(1, Ordering::SeqCst);
            }
            None => {
                self.projects.insert(
                    project_id.to_owned(),
                    ProjectState {
                        epoch,
                        counter: AtomicU64::new(0),
                        generation: AtomicU64::new(1),
                    },
                );
            }
        }
    }

    /// The current epoch of a project.
    #[must_use]
    pub fn project_epoch(&self, project_id: &str) -> Option<ProjectEpoch> {
        self.projects.get(project_id).map(|s| s.epoch)
    }

    /// The non-secret policy generation of a project (section 15).
    #[must_use]
    pub fn policy_generation(&self, project_id: &str) -> u64 {
        self.projects
            .get(project_id)
            .map_or(0, |s| s.generation.load(Ordering::SeqCst))
    }

    /// Resolves a route selector, which may be the project ID or the project number, to the
    /// project ID. Only statically registered projects resolve.
    #[must_use]
    pub fn resolve_project(&self, selector: &str) -> Option<&str> {
        if let Some((id, _)) = self.number_of_project.get_key_value(selector) {
            return Some(id.as_str());
        }
        self.project_of_number.get(selector).map(String::as_str)
    }

    /// The project number of a registered project.
    #[must_use]
    pub fn project_number(&self, project_id: &str) -> Option<&str> {
        self.number_of_project.get(project_id).map(String::as_str)
    }

    /// Whether a project number belongs to any registered project.
    #[must_use]
    pub fn knows_project_number(&self, number: &str) -> bool {
        self.project_of_number.contains_key(number)
    }

    /// The project an app ID belongs to, whatever project the request named.
    #[must_use]
    pub fn project_of_app(&self, app_id: &str) -> Option<&str> {
        self.project_of_app.get(app_id).map(String::as_str)
    }

    /// One registered app.
    #[must_use]
    pub fn app(&self, project_id: &str, app_id: &str) -> Option<&RegisteredApp> {
        self.apps.get(&(project_id.to_owned(), app_id.to_owned()))
    }

    /// Registered apps, ordered by project then app ID.
    pub fn apps(&self) -> impl Iterator<Item = &RegisteredApp> {
        self.apps.values()
    }

    /// How many apps are registered.
    #[must_use]
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }

    /// The next `jti` for a project: the epoch plus an atomic per-epoch counter. Concurrent
    /// exchanges never share one.
    #[must_use]
    pub fn next_token_id(&self, project_id: &str) -> Option<String> {
        let state = self.projects.get(project_id)?;
        let counter = state.counter.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        Some(format!("{}-{counter}", state.epoch.claim_text()))
    }

    /// Issues the claims of a session token for an enabled registered app.
    pub fn issue_claims(
        &self,
        project_id: &str,
        app_id: &str,
        now: LogicalInstant,
    ) -> Result<AppCheckClaims, RegistryError> {
        let app = self
            .app(project_id, app_id)
            .ok_or(RegistryError::UnknownApp)?;
        if !app.enabled {
            return Err(RegistryError::AppDisabled);
        }
        let epoch = self
            .project_epoch(project_id)
            .ok_or(RegistryError::NoEpoch)?;
        let jti = self
            .next_token_id(project_id)
            .ok_or(RegistryError::NoEpoch)?;
        Ok(AppCheckClaims::issue(
            app,
            epoch,
            jti,
            now,
            self.token_ttl_seconds,
        ))
    }

    /// Registers a dynamic debug-token digest under an app (section 9).
    pub fn add_debug_token(
        &mut self,
        project_id: &str,
        app_id: &str,
        display_name: &str,
        digest: DebugTokenDigest,
        created_at: LogicalInstant,
    ) -> Result<DebugTokenRecord, RegistryError> {
        validate_display_name(display_name)?;
        let id = format!(
            "dbg-{}",
            self.next_debug_token_seq.fetch_add(1, Ordering::SeqCst)
        );
        let app = self
            .apps
            .get_mut(&(project_id.to_owned(), app_id.to_owned()))
            .ok_or(RegistryError::UnknownApp)?;
        if app.digest_count() >= MAX_DEBUG_TOKENS_PER_APP {
            return Err(RegistryError::TooManyDebugTokens);
        }
        if app.dynamic.iter().any(|r| r.id == id) {
            return Err(RegistryError::DuplicateDebugToken);
        }
        let record = DebugTokenRecord {
            id,
            display_name: display_name.to_owned(),
            created_at,
            digest,
        };
        app.dynamic.push(record.clone());
        Ok(record)
    }

    /// The dynamic debug tokens of an app.
    pub fn list_debug_tokens(
        &self,
        project_id: &str,
        app_id: &str,
    ) -> Result<&[DebugTokenRecord], RegistryError> {
        self.app(project_id, app_id)
            .map(RegisteredApp::dynamic_tokens)
            .ok_or(RegistryError::UnknownApp)
    }

    /// Removes a dynamic debug token. Already issued session tokens are not revoked.
    pub fn delete_debug_token(
        &mut self,
        project_id: &str,
        app_id: &str,
        token_id: &str,
    ) -> Result<(), RegistryError> {
        let app = self
            .apps
            .get_mut(&(project_id.to_owned(), app_id.to_owned()))
            .ok_or(RegistryError::UnknownApp)?;
        let before = app.dynamic.len();
        app.dynamic.retain(|r| r.id != token_id);
        if app.dynamic.len() == before {
            return Err(RegistryError::UnknownDebugToken);
        }
        Ok(())
    }

    /// Drops every dynamic debug token of a project (project deletion, snapshot restore).
    pub fn clear_dynamic_debug_tokens(&mut self, project_id: &str) {
        for ((project, _), app) in &mut self.apps {
            if project == project_id {
                app.dynamic.clear();
            }
        }
    }

    /// Copies the dynamic debug-token registrations of every project `accept` admits
    /// (section 14). Static registrations are configuration and are never captured.
    #[must_use]
    pub fn capture_dynamic_debug_tokens<A: Fn(&str) -> bool>(
        &self,
        accept: A,
    ) -> DynamicDebugTokens {
        DynamicDebugTokens {
            apps: self
                .apps
                .iter()
                .filter(|((project, _), _)| accept(project))
                .map(|((project, app_id), app)| {
                    (
                        (project.clone(), app_id.clone()),
                        app.dynamic.iter().map(Clone::clone).collect(),
                    )
                })
                .collect(),
        }
    }

    /// Puts a captured set of dynamic debug tokens back, replacing rather than merging: a
    /// registration created after the snapshot disappears and one deleted after it returns
    /// (section 14). Apps the snapshot did not cover keep what they have.
    pub fn restore_dynamic_debug_tokens<A: Fn(&str) -> bool>(
        &mut self,
        accept: A,
        captured: &DynamicDebugTokens,
    ) {
        for (key, app) in &mut self.apps {
            if !accept(&key.0) {
                continue;
            }
            app.dynamic = captured.apps.get(key).cloned().unwrap_or_default();
        }
    }

    /// Records one secret-free observation in its own project's ring and counters.
    ///
    /// The project's ring is created on first use and holds
    /// [`MAX_RETAINED_OBSERVATIONS_PER_PROJECT`] observations, so a project that is hammered
    /// evicts only its own history. The table of rings is bounded in turn: a target project is
    /// resolved from a request path before anything validates it, so an observation for an ID
    /// no session could ever name, or one arriving when the table is full of registered
    /// projects, is dropped rather than allocated. A project the registry knows displaces the
    /// least recently used ring of one it does not, so unregistered traffic cannot crowd the
    /// real sessions out of the table.
    pub fn record_observation(&self, observation: Observation) {
        let Ok(mut guard) = self.observations.lock() else {
            return;
        };
        let log = &mut *guard;
        let project = observation.project_id.as_str();
        if !log.projects.contains_key(project) {
            if project.is_empty() || project.len() > MAX_OBSERVED_PROJECT_ID_BYTES {
                return;
            }
            if log.projects.len() >= MAX_OBSERVED_PROJECTS {
                let victim = log
                    .projects
                    .iter()
                    .filter(|(observed, _)| !self.projects.contains_key(observed.as_str()))
                    .min_by_key(|(_, entry)| entry.touched)
                    .map(|(observed, _)| observed.clone());
                let Some(victim) = victim else {
                    return;
                };
                log.projects.remove(&victim);
            }
            log.projects
                .insert(project.to_owned(), ProjectObservations::default());
        }
        log.next_touch = log.next_touch.wrapping_add(1);
        let touch = log.next_touch;
        let Some(entry) = log.projects.get_mut(project) else {
            return;
        };
        entry.touched = touch;
        entry.count(&observation);
        entry.retain(observation);
    }

    /// The retained observations of one project, oldest first.
    ///
    /// A project with no ring answers with nothing, which is also what a project whose ring
    /// was just cleared answers: the two are deliberately indistinguishable.
    #[must_use]
    pub fn observations(&self, project_id: &str) -> Vec<Observation> {
        self.observations
            .lock()
            .ok()
            .and_then(|log| {
                log.projects
                    .get(project_id)
                    .map(|entry| entry.ring.iter().cloned().collect())
            })
            .unwrap_or_default()
    }

    /// The counters of one project, in counter-key order (section 15).
    ///
    /// They count every observation recorded since the project's state was last reset, not
    /// only the ones the ring still holds, so eviction never rewrites history.
    #[must_use]
    pub fn observation_counters(&self, project_id: &str) -> Vec<(ObservationCounterKey, u64)> {
        self.observations
            .lock()
            .ok()
            .and_then(|log| {
                log.projects.get(project_id).map(|entry| {
                    entry
                        .counters
                        .iter()
                        .map(|(key, count)| (key.clone(), *count))
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// The projects that currently hold an observation ring, in project order.
    #[must_use]
    pub fn observed_projects(&self) -> Vec<String> {
        self.observations
            .lock()
            .map(|log| log.projects.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Drops the ring and the counters of every project `accept` admits: counters reset with
    /// project state, and a deleted project keeps nothing at all (section 14).
    pub fn clear_observations<A: Fn(&str) -> bool>(&self, accept: A) {
        if let Ok(mut log) = self.observations.lock() {
            log.projects.retain(|project, _| !accept(project));
        }
    }
}

/// The dynamic debug-token registrations of one scope, as a snapshot part (section 14).
///
/// This is sensitive process memory: it carries digests, so `Debug` shows only how much it
/// holds. It is never serialized to disk.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DynamicDebugTokens {
    apps: BTreeMap<(String, String), Vec<DebugTokenRecord>>,
}

impl DynamicDebugTokens {
    /// A cheap, saturating estimate of heap bytes retained by a session snapshot.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        const BTREE_ENTRY_OVERHEAD: u64 = 128;

        fn bytes(value: usize) -> u64 {
            u64::try_from(value).unwrap_or(u64::MAX)
        }

        self.apps
            .iter()
            .fold(0u64, |total, ((project, app), records)| {
                let total = total
                    .saturating_add(BTREE_ENTRY_OVERHEAD)
                    .saturating_add(bytes(project.capacity()))
                    .saturating_add(bytes(app.capacity()))
                    .saturating_add(
                        bytes(records.capacity())
                            .saturating_mul(bytes(core::mem::size_of::<DebugTokenRecord>())),
                    );
                records.iter().fold(total, |total, record| {
                    total
                        .saturating_add(bytes(record.id.capacity()))
                        .saturating_add(bytes(record.display_name.capacity()))
                })
            })
    }

    /// How many apps the capture covers.
    #[must_use]
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }

    /// How many dynamic registrations the capture holds.
    #[must_use]
    pub fn token_count(&self) -> usize {
        self.apps.values().map(Vec::len).sum()
    }
}

impl fmt::Debug for DynamicDebugTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicDebugTokens")
            .field("apps", &self.apps.len())
            .field("tokens", &self.token_count())
            .finish()
    }
}

#[cfg(test)]
mod dynamic_snapshot_size_tests {
    use super::*;

    #[test]
    fn app_keys_and_dynamic_records_contribute_to_the_snapshot_estimate() {
        let mut apps = BTreeMap::new();
        apps.insert(
            ("demo-app".repeat(8), "app-id".repeat(8)),
            vec![DebugTokenRecord {
                id: "token-id".repeat(8),
                display_name: "display-name".repeat(8),
                created_at: LogicalInstant::UNIX_EPOCH,
                digest: DebugTokenDigest::from_bytes([7; 32]),
            }],
        );
        let captured = DynamicDebugTokens { apps };

        assert!(captured.retained_bytes() > 0);
    }
}
