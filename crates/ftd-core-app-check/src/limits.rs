//! The bounded sizes of the App Check surface (specification section 8).
//!
//! Every one of these is a hard input budget: the loader, the registry and the HTTP routes
//! refuse anything above them instead of allocating first.

/// Apps that may be configured per daemon.
pub const MAX_APPS: usize = 1024;

/// Debug-token digests that may be registered per app, static and dynamic together.
pub const MAX_DEBUG_TOKENS_PER_APP: usize = 128;

/// Longest accepted Firebase app ID.
pub const MAX_APP_ID_BYTES: usize = 256;

/// Longest accepted debug-token display name.
pub const MAX_DISPLAY_NAME_BYTES: usize = 128;

/// Longest accepted `X-Firebase-AppCheck` header value or JWT.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Longest accepted debug-token exchange request body.
pub const MAX_EXCHANGE_BODY_BYTES: usize = 16 * 1024;

/// Default session-token lifetime in seconds (`appCheck.tokenTtlSeconds`).
pub const DEFAULT_TOKEN_TTL_SECONDS: i64 = 3600;

/// Shortest accepted session-token lifetime in seconds.
pub const MIN_TOKEN_TTL_SECONDS: i64 = 1800;

/// Longest accepted session-token lifetime in seconds.
pub const MAX_TOKEN_TTL_SECONDS: i64 = 604_800;

/// Observations retained per project before that project's oldest is dropped (section 15:
/// bounded buckets, never an unbounded label set).
///
/// The ring is per project, so traffic to one project never evicts another project's recent
/// observations; the bound on the whole runtime is this times [`MAX_OBSERVED_PROJECTS`].
pub const MAX_RETAINED_OBSERVATIONS_PER_PROJECT: usize = 256;

/// Projects that may hold an observation ring at once.
///
/// A target project is resolved from a request path before anything validates it, so the set
/// of observed project IDs is caller-influenced and needs a hard bound of its own. A project
/// the registry knows is never displaced by one it does not.
pub const MAX_OBSERVED_PROJECTS: usize = 256;

/// Longest project ID that may open an observation ring.
///
/// A session names its project with at most 63 characters, so an observation for a longer ID
/// could never be read back through the control API; it is dropped instead of allocated.
pub const MAX_OBSERVED_PROJECT_ID_BYTES: usize = 63;

/// Distinct counter keys one project may hold (section 15: bounded buckets).
///
/// The key space is bounded by construction -- a fixed service set, verified app IDs or the
/// `unknown` label, four categories, two outcomes and the declared callables -- and this is
/// the backstop that keeps a misconfigured registry from turning it into a label explosion.
pub const MAX_COUNTER_KEYS_PER_PROJECT: usize = 1024;
