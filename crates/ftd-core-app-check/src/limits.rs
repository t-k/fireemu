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

/// Observations retained per registry before the oldest is dropped (section 15: bounded
/// buckets, never an unbounded label set).
pub const MAX_RETAINED_OBSERVATIONS: usize = 256;
