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

/// Request fields whose presence is evidence that a request was issued by a web page rather
/// than by a process.
///
/// `Origin` alone is not enough to rely on: it is attached to the requests a page makes that
/// need CORS, but the decision of a privileged route must not hinge on one header an old or
/// unusual browser may omit. `Sec-Fetch-Site` and `Sec-Fetch-Dest` are attached by every
/// current browser to every request and cannot be set or removed by page script; `Referer`
/// and `Cookie` are attached by browsers that predate `Sec-Fetch-*`.
///
/// `Sec-Fetch-Mode` is deliberately not in this set. Node's built-in `fetch` (undici, Node 18
/// and later) attaches `sec-fetch-mode: cors` to every request it makes and a script cannot
/// remove it (it is a forbidden header name), while it attaches nothing else from this list.
/// That is the shape `@firebase/rules-unit-testing` 5.x sends from `clearFirestore()`,
/// `loadFirestoreRules` and `loadStorageRules` (they call the global `fetch`), so counting
/// `Sec-Fetch-Mode` as browser evidence would refuse the very process clients the
/// unauthenticated compatibility paths exist for. A browser never sends `Sec-Fetch-Mode`
/// without `Sec-Fetch-Site` and `Sec-Fetch-Dest`, so leaving it out loses no browser evidence.
pub const BROWSER_METADATA_HEADERS: &[&str] = &[
    "origin",
    "sec-fetch-site",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(headers: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> {
        move |name| {
            headers
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| *value)
        }
    }

    /// The exact header set Node 24's built-in `fetch` (undici) attaches to a request a script
    /// issues with no headers of its own (probe against a loopback listener, 2026-09-21):
    /// `host`, `connection`, `accept`, `accept-language`, `sec-fetch-mode`, `user-agent`,
    /// `accept-encoding`. This is what `@firebase/rules-unit-testing` 5.0.2 sends from
    /// `clearFirestore()`, and it is a process, not a page.
    #[test]
    fn the_undici_header_set_is_not_browser_evidence() {
        let undici = [
            ("host", "127.0.0.1:8080"),
            ("connection", "keep-alive"),
            ("accept", "*/*"),
            ("accept-language", "*"),
            ("sec-fetch-mode", "cors"),
            ("user-agent", "node"),
            ("accept-encoding", "gzip, deflate"),
        ];
        assert!(!carries_browser_metadata(lookup(&undici)));
        assert!(!carries_browser_metadata(lookup(&[(
            "Sec-Fetch-Mode",
            "navigate"
        )])));
    }

    /// Every current browser attaches `Sec-Fetch-Site` and `Sec-Fetch-Dest` to every request
    /// it makes, with or without `Origin`, so a real page-issued request is recognised.
    #[test]
    fn a_browser_header_set_is_browser_evidence() {
        let chrome_cors = [
            ("origin", "http://localhost:5173"),
            ("sec-fetch-site", "same-site"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
        ];
        assert!(carries_browser_metadata(lookup(&chrome_cors)));
        let chrome_same_origin_without_origin_header = [
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
        ];
        assert!(carries_browser_metadata(lookup(
            &chrome_same_origin_without_origin_header
        )));
    }

    /// Each field of the set is sufficient on its own: the decision must not hinge on one
    /// header an old or unusual browser may omit.
    #[test]
    fn each_browser_metadata_field_alone_is_browser_evidence() {
        for field in [
            "origin",
            "sec-fetch-site",
            "sec-fetch-dest",
            "referer",
            "cookie",
        ] {
            assert!(carries_browser_metadata(lookup(&[(field, "x")])), "{field}");
            assert!(
                carries_browser_metadata(lookup(&[(&field.to_ascii_uppercase(), "x")])),
                "{field} looked up case-insensitively"
            );
        }
        assert!(!BROWSER_METADATA_HEADERS.contains(&"sec-fetch-mode"));
    }

    /// A field present but empty counts as absent.
    #[test]
    fn an_empty_field_is_absent() {
        for field in BROWSER_METADATA_HEADERS {
            assert!(!carries_browser_metadata(lookup(&[(field, "")])), "{field}");
        }
        assert!(!carries_browser_metadata(lookup(&[])));
    }

    #[test]
    fn a_process_request_is_admitted_and_a_page_needs_a_loopback_origin_and_the_token() {
        assert_eq!(
            privileged_route_admission(false, None, false),
            PrivilegedAdmission::Admit
        );
        assert_eq!(
            privileged_route_admission(true, Some("http://localhost:5173"), false),
            PrivilegedAdmission::ControlTokenRequired
        );
        assert_eq!(
            privileged_route_admission(true, None, false),
            PrivilegedAdmission::ControlTokenRequired
        );
        assert_eq!(
            privileged_route_admission(true, Some("http://localhost:5173"), true),
            PrivilegedAdmission::Admit
        );
        assert_eq!(
            privileged_route_admission(true, Some("https://evil.example"), true),
            PrivilegedAdmission::ForeignOrigin
        );
        assert_eq!(
            privileged_route_admission(false, Some("https://evil.example"), false),
            PrivilegedAdmission::ForeignOrigin
        );
    }
}
