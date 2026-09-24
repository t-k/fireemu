//! The Firestore Admin API (`google.firestore.admin.v1`) served over REST and gRPC for the
//! `FS-CONFIG-LIFECYCLE` parent: the database lifecycle, locations, operations, indexes, managed
//! export and import, and bulk delete. See `spec/compatibility/closure/FS-CONFIG-LIFECYCLE.json`
//! for what is in scope (and the managed-infrastructure methods that are not).

pub mod catalog;
pub mod fields;
pub mod grpc;
pub mod index_rest;
pub mod indexes;
pub mod locations;
pub mod managed;
pub mod operations;
pub mod rest;
#[cfg(test)]
mod rest_tests;
