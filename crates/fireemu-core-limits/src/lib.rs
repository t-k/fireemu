//! std-only versioned limit catalog and usage disposition (spec 8.10, 13.5).
//!
//! Limit values never live in runtime code. They are declared in `spec/limits/*.json`,
//! turned into the Rust constants under `src/generated/` by `tools/limit-catalog-gen`, and the
//! generated files are checked in. A normal build never runs the generator.

pub mod evaluate;
pub mod model;
pub mod plan;

/// Generated catalogs. Do not edit by hand; run `cargo run -p limit-catalog-gen -- generate`.
#[path = "generated/mod.rs"]
pub mod catalogs;
