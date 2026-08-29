//! std-only Cloud Storage for Firebase core (spec 9, Milestone D).
//!
//! Object names are opaque UTF-8 strings (never filesystem paths, never normalized);
//! metadata and blobs are separate; `generation` / `metageneration` follow the documented
//! semantics with preconditions; listing works on the object namespace with `prefix` /
//! `delimiter`; resumable uploads are an explicit state machine on the virtual clock.
//! Hashes (MD5, CRC32C) are implemented in-crate so the core stays dependency-free.

pub mod hash;
pub mod name;
pub mod store;
