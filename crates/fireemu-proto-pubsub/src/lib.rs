//! Generated protobuf and gRPC types for the Cloud Pub/Sub v1 API.
//!
//! The `.proto` sources under `proto/` are vendored from googleapis at the commit recorded in
//! `proto/UPSTREAM_COMMIT`; the Rust code under `src/generated/` is produced by
//! `tools/proto-gen` and checked in (ADR-008). A normal build never needs `protoc`.
//!
//! Generated code is excluded from lints, coverage and mutation testing.

#![allow(missing_docs, clippy::all, clippy::pedantic, rustdoc::all)]

/// Googleapis packages.
pub mod google {
    /// `google.api`.
    pub mod api {
        include!("generated/google.api.rs");
    }
    /// `google.pubsub.v1`.
    pub mod pubsub {
        /// `google.pubsub.v1`.
        pub mod v1 {
            include!("generated/google.pubsub.v1.rs");
        }
    }
}

/// Upstream googleapis commit the vendored protos come from.
pub const UPSTREAM_COMMIT: &str = include_str!("generated/UPSTREAM_COMMIT");
