//! The process-wide `Host` policy: the default before any is installed, and the installed one
//! after. One test in its own binary, because the policy is process-wide.

use fireemu_core_session::host_guard::{admits_request, current, install, AllowedHost, HostPolicy};

#[test]
fn the_installed_policy_is_the_one_every_listener_reads() {
    assert_eq!(*current(), HostPolicy::default());
    assert!(admits_request(false, [b"localhost:9199".as_slice()]).is_ok());
    assert!(admits_request(false, [b"evil.example".as_slice()]).is_err());
    assert!(admits_request(false, [b"site.example".as_slice()]).is_err());
    assert!(admits_request(true, [b"evil.example".as_slice()]).is_ok());

    let policy = HostPolicy::new(vec![AllowedHost::parse("site.example").unwrap()], true);
    install(policy.clone());
    assert_eq!(*current(), policy);
    assert!(admits_request(false, [b"site.example:9199".as_slice()]).is_ok());
    assert!(admits_request(false, [b"fireemu".as_slice()]).is_ok());
    assert!(admits_request(false, [b"evil.example".as_slice()]).is_err());
}
