//! Canonical loopback policy boundaries shared by all emulator adapters.

use fireemu_core_session::loopback::{authority_is_loopback, origin_is_local};

#[test]
fn authority_policy_is_strict_and_shared_across_loopback_addresses() {
    for authority in [
        "localhost",
        "LOCALHOST:4400",
        "127.0.0.1",
        "127.0.0.2:8080",
        "[::1]",
        "[::1]:4400",
    ] {
        assert!(authority_is_loopback(authority), "{authority}");
    }

    for authority in [
        "",
        "localhost.",
        "localhost:",
        "localhost:65536",
        "user@localhost",
        "127.attacker.example",
        "127.0.0.1.attacker.example",
        "[::1",
        "[::1]suffix",
        "::1",
        "0.0.0.0",
        "example.test",
    ] {
        assert!(!authority_is_loopback(authority), "{authority}");
    }
}

#[test]
fn origin_policy_accepts_only_http_loopback_origins_without_url_components() {
    for origin in [
        "http://localhost",
        "https://LOCALHOST:4400",
        "http://127.0.0.2:8080",
        "https://[::1]",
        "https://[::1]:4400/",
    ] {
        assert!(origin_is_local(origin), "{origin}");
    }

    for origin in [
        "null",
        "file://localhost",
        "http://localhost.",
        "http://127.evil",
        "http://127.0.0.1.attacker.example",
        "http://user@localhost",
        "http://localhost/path",
        "http://localhost?query",
        "http://localhost#fragment",
    ] {
        assert!(!origin_is_local(origin), "{origin}");
    }
}
