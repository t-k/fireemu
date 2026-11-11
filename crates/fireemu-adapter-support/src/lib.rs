//! Small shared utilities for HTTP-facing adapters.
//!
//! This leaf crate deliberately owns no product policy. Callers retain their Firebase-specific
//! size limits, status codes, response bodies, headers and credential requirements.

pub mod accept;
pub mod api_error;
pub mod body;
pub mod connection;
pub mod entropy;
pub mod notice_limit;
pub mod secret;

pub mod diagnostics;
pub mod lexical;
