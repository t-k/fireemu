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

/// Request fields whose presence marks a request as issued by a web page rather than by a
/// process.
///
/// `Origin` alone is not enough to rely on: it is attached to the requests a page makes that
/// need CORS, but the decision of a privileged route must not hinge on one header an old or
/// unusual browser may omit. `Sec-Fetch-*` is attached by every current browser and cannot be
/// set by page script; `Referer` and `Cookie` are attached by browsers that predate
/// `Sec-Fetch-*`. A process-issued request (a test library running under Node, the CLI) sends
/// none of them, which is what keeps the unauthenticated compatibility paths working.
pub const BROWSER_METADATA_HEADERS: &[&str] = &[
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "cookie",
];

/// Whether any [`BROWSER_METADATA_HEADERS`] field is present, through a case-insensitive
/// lookup the caller supplies (surfaces carry their headers in different shapes).
///
/// A field present but empty counts as absent: the Storage transport spells a duplicated
/// header that way, and an empty `Origin` is not an origin.
pub fn carries_browser_metadata<'a>(header: impl Fn(&str) -> Option<&'a str>) -> bool {
    BROWSER_METADATA_HEADERS
        .iter()
        .any(|name| header(name).is_some_and(|value| !value.is_empty()))
}

/// What a privileged route does with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedAdmission {
    /// The request may run.
    Admit,
    /// The request came from a page on another site.
    ForeignOrigin,
    /// The request came from a page and presented no control token, or the wrong one.
    ControlTokenRequired,
}

/// The one browser policy every privileged emulator route applies: a request with no browser
/// metadata is a process and runs unauthenticated (the emulator serves loopback without a
/// credential); a request from a page must come from a loopback origin and must present the
/// run's control token.
///
/// `token_ok` is computed by the caller so that the comparison stays constant-time in the
/// crate that owns the secret.
#[must_use]
pub fn privileged_route_admission(
    from_browser: bool,
    origin: Option<&str>,
    token_ok: bool,
) -> PrivilegedAdmission {
    if origin.is_some_and(|origin| !origin_is_local(origin)) {
        return PrivilegedAdmission::ForeignOrigin;
    }
    if !from_browser || token_ok {
        PrivilegedAdmission::Admit
    } else {
        PrivilegedAdmission::ControlTokenRequired
    }
}
