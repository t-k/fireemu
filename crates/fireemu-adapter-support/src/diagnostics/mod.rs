//! Pure failure diagnostics bundles.
mod bundle;
mod html;
pub mod redact;

pub use bundle::*;
pub use html::to_html;
