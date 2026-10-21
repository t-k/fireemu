//! The small macOS ACL binding missing from exacl's path-only public API.
//!
//! Only borrowed, live descriptors cross this interface. ACL allocations are independent
//! copies, owned by `Acl` and freed exactly once; none of these calls resolves a pathname.

use nix::libc::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::ptr::NonNull;

const EXTENDED: c_int = 0x100;
const FIRST_ENTRY: c_int = 0;

unsafe extern "C" {
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_valid(acl: *mut c_void) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
}

struct Acl(NonNull<c_void>);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: this pointer came from acl_init or acl_get_fd_np, is owned here, and is freed once.
        unsafe {
            acl_free(self.0.as_ptr());
        }
    }
}

/// Clears only the object pinned by `directory`, even if its former name has been replaced.
pub(super) fn clear(directory: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: zero entries is a valid empty extended ACL; the returned allocation is checked.
    let acl = NonNull::new(unsafe { acl_init(0) }).ok_or_else(io::Error::last_os_error)?;
    let acl = Acl(acl);
    // SAFETY: the borrowed descriptor stays live, and acl owns a valid empty ACL for this call.
    if unsafe { acl_set_fd_np(directory.as_raw_fd(), acl.0.as_ptr(), EXTENDED) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Reads the extended ACL of the held object; no ACL is distinct from an unreadable ACL.
pub(super) fn is_empty(directory: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: the borrowed descriptor stays live; EXTENDED is the SDK's ACL_TYPE_EXTENDED.
    let pointer = unsafe { acl_get_fd_np(directory.as_raw_fd(), EXTENDED) };
    let Some(pointer) = NonNull::new(pointer) else {
        let error = io::Error::last_os_error();
        // macOS returns ENOENT when a live fd has no extended ACL (also used by exacl).
        // The fd, unlike a pathname, still holds the object after any rename or unlink.
        return missing_acl(error);
    };
    let acl = Acl(pointer);
    // SAFETY: acl owns the allocation returned by acl_get_fd_np.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: acl is valid and owned; entry points to initialized, writable pointer storage.
    let result = unsafe { acl_get_entry(acl.0.as_ptr(), FIRST_ENTRY, &raw mut entry) };
    if result == 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    // Darwin reports EINVAL when FIRST_ENTRY is beyond a valid ACL's empty entry list.
    if error.raw_os_error() == Some(nix::libc::EINVAL) {
        Ok(true)
    } else {
        Err(error)
    }
}

/// ENOENT on a held object means no extended ACL; other errors prove no such thing.
fn missing_acl(error: io::Error) -> io::Result<bool> {
    if error.raw_os_error() == Some(nix::libc::ENOENT) {
        Ok(true)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_acl_is_not_treated_as_an_empty_acl() {
        for code in [
            nix::libc::EACCES,
            nix::libc::EBADF,
            nix::libc::EIO,
            nix::libc::ENOTSUP,
            nix::libc::EINVAL,
        ] {
            let error = missing_acl(io::Error::from_raw_os_error(code)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
        }
        assert!(missing_acl(io::Error::from_raw_os_error(nix::libc::ENOENT)).unwrap());
    }
}
