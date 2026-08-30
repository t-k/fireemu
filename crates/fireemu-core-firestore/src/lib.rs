//! std-only Firestore core: field paths, document paths, value ordering, the official
//! storage-size formula, the canonical query AST with Standard query limits, and the
//! conservative index validator (Milestone B, spec 8.5 - 8.10).

pub mod field_path;
pub mod index;
pub mod limits;
pub mod path;
pub mod pipeline;
pub mod query;
pub mod size;
pub mod store;
pub mod text_index;
pub mod value;
