//! std-only Security Rules core: lexer / parser for the native subset, AST, and the static
//! limit linter (`RULES-LINT-1`, spec 13.4 - 13.7). Runtime evaluation arrives in Milestone H.

pub mod ast;
pub mod lint;
pub mod parse;
