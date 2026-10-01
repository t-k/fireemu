//! Whether an open file descriptor carries extended ACL entries, read without a path lookup.
//!
//! The session RSA cache refuses a directory or key file with ACL entries, because an entry
//! can grant other users access that the owner-only mode bits do not show. On macOS the ACL
//! has to be read through the descriptor the cache opened: reading `/dev/fd/N` by path does
//! not work, since Darwin answers `ENOENT` for it on every descriptor, even when the file has
//! ACL entries.
//!
//! This crate is the only place in the workspace where unsafe code is allowed. The unsafe
//! code is three calls into the C library (`acl_get_fd_np`, `acl_get_entry` and `acl_free`)
//! in one private module. The public API is the safe `fd_has_extended_acl` on macOS. On
//! other platforms the crate is empty.

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::fd_has_extended_acl;
