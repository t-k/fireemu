//! Canonical loopback authority and browser-origin policy for every emulator surface.

use std::net::IpAddr;

/// Whether an HTTP authority is exactly `localhost` or a loopback IP address, with an
/// optional valid port. IPv6 addresses must use bracket notation. Trailing DNS dots,
/// userinfo, paths, and hostname prefixes are rejected so DNS rebinding names cannot pass.
#[must_use]
pub fn authority_is_loopback(authority: &str) -> bool {
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !valid_port_suffix(suffix) {
            return false;
        }
        host
    } else {
        let mut parts = authority.split(':');
        let Some(host) = parts.next() else {
            return false;
        };
        if let Some(port) = parts.next() {
            if parts.next().is_some() || port.is_empty() || port.parse::<u16>().is_err() {
                return false;
            }
        }
        host
    };

    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

/// Whether a serialized browser origin is HTTP(S) and names a loopback authority. A single
/// trailing slash is accepted for URI callers; paths, queries, fragments, and userinfo are
/// not part of an origin and are rejected.
#[must_use]
pub fn origin_is_local(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#']) {
        return false;
    }
    authority_is_loopback(authority)
}
