//! gRPC shell for the Firestore v1 API (Phase FS-0 strict gateway, spec 8.1).
//!
//! Wire types never reach the core: [`decode`] turns protobuf requests into canonical commands,
//! [`gateway`] runs the strict checks (query canonicalization, Standard query limits, index
//! validation) and [`service`] exposes the `Firestore` gRPC service. Requests that pass the
//! checks are forwarded to an optional upstream (official Emulator or real service); without an
//! upstream they are answered with `UNIMPLEMENTED` (never a silent local success).

pub mod decode;
pub mod encode;
pub mod gateway;
pub mod local;
pub mod service;
