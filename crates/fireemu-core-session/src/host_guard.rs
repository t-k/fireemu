//! The DNS-rebinding defence of every product HTTP listener: which `Host` a request may name.
//!
//! A page on a name its owner controls can re-point that name at the developer's loopback
//! address after it loaded. The browser then treats requests to the emulator as same-origin:
//! no `Origin`, and over plain HTTP no Fetch Metadata or `Referer` either. The emulator serves
//! loopback without a credential, so such a page could read (and, through simple requests,
//! drive) local data. What still gives the request away is its `Host`, which names the
//! attacker's domain. The guard admits only names an attacker cannot serve a page from:
//!
//! - no `Host` at all (HTTP/1.0; a browser always sends one);
//! - any IP address literal (IPv4, or bracketed IPv6): a page served from an address is not
//!   a rebinding, and this keeps `10.0.2.2` (the Android emulator), LAN addresses and bridge
//!   addresses working;
//! - `localhost` and names under `.localhost` (RFC 6761, never delegated);
//! - `host.docker.internal` and `host.containers.internal`, the names Docker and Podman give
//!   a container for its host (`.internal` is reserved for private use and never delegated);
//! - names under `.firebaseio.com` and `.firebasedatabase.app`, which the Realtime Database
//!   routes namespaces by, as the official emulator does (Google owns both);
//! - with `network.allowNonLoopbackHosts`, single-label names such as a Compose service name
//!   (public DNS answers no single-label name);
//! - the names listed in `network.allowedHosts` (exact, `.suffix` for a domain and its
//!   subdomains, or `*` for any well-formed name).
//!
//! The name is compared without case and without one trailing dot; any valid port passes,
//! because port forwarding changes it. HTTP/2 requests are not checked: no browser speaks
//! cleartext HTTP/2, and gRPC clients name their target, not the listener, in `:authority`.
//! A repeated `Host` is refused rather than resolved to one of its values.
//!
//! The official emulator (firebase-tools) checks no `Host`; this guard is a local-only
//! defence with no production counterpart and applies to both profiles alike.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, PoisonError, RwLock};

/// The longest host name DNS can carry, and so the longest one the guard parses.
const MAX_NAME_BYTES: usize = 253;

/// Names admitted under every policy.
const DEFAULT_NAMES: &[&str] = &[
    "localhost",
    "host.docker.internal",
    "host.containers.internal",
];

/// Domains whose subdomains are admitted under every policy (the domain itself is not).
const DEFAULT_SUFFIXES: &[&str] = &[".localhost", ".firebaseio.com", ".firebasedatabase.app"];

/// One `network.allowedHosts` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedHost {
    /// `*`: every well-formed name.
    Any,
    /// A name, matched exactly (lowercase, without a trailing dot).
    Exact(String),
    /// `.example.com`: the domain and its subdomains (stored with the leading dot).
    Suffix(String),
}

impl AllowedHost {
    /// Parses one entry: `*`, a host name, or a host name with a leading dot.
    ///
    /// # Errors
    /// Why the entry is not one: a port, a scheme, a path, an IP address, a wildcard other
    /// than `*`, or a character outside letters, digits, `-`, `_` and `.`.
    pub fn parse(entry: &str) -> Result<Self, String> {
        if entry == "*" {
            return Ok(Self::Any);
        }
        let (suffix, name) = match entry.strip_prefix('.') {
            Some(rest) => (true, rest),
            None => (false, entry),
        };
        let Some(name) = normalize_name(name) else {
            return Err(format!(
                "{entry:?} is not a host name: write a name without scheme, port or path (letters, digits, '-', '_' and '.'), a name with a leading '.' for a domain and its subdomains, or \"*\""
            ));
        };
        if name.parse::<IpAddr>().is_ok() {
            return Err(format!(
                "{entry:?} is an IP address: every IP address is already admitted"
            ));
        }
        Ok(if suffix {
            Self::Suffix(format!(".{name}"))
        } else {
            Self::Exact(name)
        })
    }
}

impl std::fmt::Display for AllowedHost {
    /// The entry as configuration spells it, normalized: `*`, `name` or `.domain`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Exact(name) | Self::Suffix(name) => f.write_str(name),
        }
    }
}

/// Which names a listener admits beyond the defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostPolicy {
    allowed: Vec<AllowedHost>,
    single_label: bool,
}

impl HostPolicy {
    /// A policy with the `network.allowedHosts` entries and, when `single_label` (set by
    /// `network.allowNonLoopbackHosts`), single-label names.
    #[must_use]
    pub fn new(allowed: Vec<AllowedHost>, single_label: bool) -> Self {
        Self {
            allowed,
            single_label,
        }
    }

    fn admits_name(&self, name: &str) -> bool {
        DEFAULT_NAMES.contains(&name)
            || DEFAULT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
            || (self.single_label && !name.contains('.'))
            || self.allowed.iter().any(|entry| match entry {
                AllowedHost::Any => true,
                AllowedHost::Exact(exact) => exact == name,
                AllowedHost::Suffix(suffix) => {
                    name.ends_with(suffix.as_str()) || name == &suffix[1..]
                }
            })
    }
}

/// A refused `Host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRefusal {
    /// The normalized name, when the value was a well-formed authority; a malformed value is
    /// never echoed.
    name: Option<String>,
}

impl HostRefusal {
    /// The message of the 403 answer.
    #[must_use]
    pub fn message(&self) -> String {
        let named = self.name.as_ref().map_or_else(
            || "this Host header".to_owned(),
            |name| format!("Host {name:?}"),
        );
        format!(
            "fireemu does not answer {named}: as a defence against DNS rebinding it answers localhost, IP addresses, host.docker.internal, host.containers.internal and the names listed in network.allowedHosts (single-label names too with network.allowNonLoopbackHosts)"
        )
    }

    /// The JSON body of the 403 answer, in the Google RPC error shape.
    #[must_use]
    pub fn body(&self) -> String {
        let message = self.message().replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "{{\"error\":{{\"code\":403,\"message\":\"{message}\",\"status\":\"PERMISSION_DENIED\"}}}}"
        )
    }
}

/// Whether a request with these `Host` values may be served. `http2` requests are not
/// checked (see the module documentation).
///
/// # Errors
/// The refusal, when the request must be answered 403.
pub fn admits<'a>(
    policy: &HostPolicy,
    http2: bool,
    hosts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), HostRefusal> {
    if http2 {
        return Ok(());
    }
    let mut hosts = hosts.into_iter();
    let Some(host) = hosts.next() else {
        return Ok(());
    };
    if hosts.next().is_some() {
        return Err(HostRefusal { name: None });
    }
    match parse_authority(host) {
        Some(Authority::Address) => Ok(()),
        Some(Authority::Name(name)) if policy.admits_name(&name) => Ok(()),
        Some(Authority::Name(name)) => Err(HostRefusal { name: Some(name) }),
        None => Err(HostRefusal { name: None }),
    }
}

enum Authority {
    Address,
    Name(String),
}

/// Parses `host[:port]`: an IPv4 literal, a bracketed IPv6 literal or a host name, and a
/// port of plain digits that fits in 16 bits.
fn parse_authority(raw: &[u8]) -> Option<Authority> {
    let raw = std::str::from_utf8(raw).ok()?;
    if let Some(rest) = raw.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']')?;
        address.parse::<Ipv6Addr>().ok()?;
        return port_suffix_ok(suffix).then_some(Authority::Address);
    }
    let (host, port) = match raw.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (raw, None),
    };
    if let Some(port) = port {
        if !port_ok(port) {
            return None;
        }
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(Authority::Address);
    }
    normalize_name(host).map(Authority::Name)
}

fn port_suffix_ok(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(port_ok)
}

fn port_ok(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

/// A host name lowercased and without one trailing dot, when every label is non-empty and
/// holds letters, digits, `-` and `_` only.
fn normalize_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return None;
    }
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    labels_ok.then(|| name.to_ascii_lowercase())
}

static POLICY: RwLock<Option<Arc<HostPolicy>>> = RwLock::new(None);

/// Installs the process's policy, read from its configuration before its listeners serve.
/// One suite runs per process, so the policy is process-wide like the listeners themselves.
pub fn install(policy: HostPolicy) {
    *POLICY.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(policy));
}

/// The installed policy, or the default one (no extra names) before any is installed.
#[must_use]
pub fn current() -> Arc<HostPolicy> {
    POLICY
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .unwrap_or_default()
}

/// The `Content-Type` of [`HostRefusal::body`].
pub const REFUSAL_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// [`admits`] against the installed policy.
///
/// # Errors
/// The refusal, when the request must be answered 403.
pub fn admits_request<'a>(
    http2: bool,
    hosts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), HostRefusal> {
    admits(&current(), http2, hosts)
}
