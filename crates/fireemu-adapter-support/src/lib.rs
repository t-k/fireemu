//! Small shared utilities for HTTP-facing adapters.
//!
//! This leaf crate deliberately owns no product policy. Callers retain their Firebase-specific
//! size limits, status codes, response bodies, headers and credential requirements.

pub mod api_error;
pub mod body;
pub mod secret;
