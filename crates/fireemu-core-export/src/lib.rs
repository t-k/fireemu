//! Local Emulator Suite import and export artifacts.
//!
//! This crate reads and writes the on-disk format `firebase emulators:export` produces with
//! `firebase-tools@15.28.2`, so that a fixture recorded with the official suite can be
//! imported into fireemu and an export fireemu writes can be imported back into the official
//! suite. It is std-only, like every other `fireemu-core-*` crate: the JSON documents are
//! parsed with [`fireemu_core_types::json`] and written by [`json`], and the Firestore
//! managed export -- a legacy proto2 schema with groups, which `prost` cannot express -- is
//! encoded directly against the protocol buffer wire format in [`wire`].
//!
//! ```text
//! <export dir>/
//!   firebase-export-metadata.json     the manifest ([`metadata`])
//!   auth_export/
//!     accounts.json                   the default tenant's users ([`auth`])
//!     accounts-<tenant>.json          one file per tenant
//!     config.json                     the project's Auth configuration
//!   firestore_export/                 the managed export ([`firestore`])
//!     firestore_export.overall_export_metadata
//!     all_namespaces/all_kinds/all_namespaces_all_kinds.export_metadata
//!     all_namespaces/all_kinds/output-0
//!   storage_export/                   ([`storage`])
//!     buckets.json
//!     blobs/<id>                      the object bytes
//!     metadata/<id>.json              the object metadata
//! ```
//!
//! # Sensitive material
//!
//! An Auth export carries password hashes, salts, MFA secrets and phone numbers. The crate
//! itself only produces the bytes; the caller is responsible for the file permissions, and
//! `fireemu` writes every export directory and file with owner-only access. fireemu's own
//! session snapshots and App Check debug secrets are deliberately *not* part of this format
//! and never reach an export directory.

pub mod auth;
pub mod firestore;
pub mod json;
pub mod leveldb;
pub mod metadata;
pub mod storage;
pub mod wire;
