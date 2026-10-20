//! Which database namespace a request addresses.
//!
//! The official emulator takes the `ns` query parameter, else the first label of a host name
//! with dots (`<ns>.firebaseio.com`, `<ns>.<region>.firebasedatabase.app`, `<ns>.localhost`),
//! else its default namespace. Names are lowercased; a name that does not start with a letter
//! or digit, or holds anything but letters, digits and hyphens, is refused with 403
//! "Invalid Firebase database name".

/// A namespace name the server refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidNamespace;

/// The namespace of a request.
pub fn route(
    ns: Option<&str>,
    host: Option<&str>,
    default: &str,
) -> Result<String, InvalidNamespace> {
    if let Some(ns) = ns {
        return validate(ns);
    }
    match host.and_then(host_label) {
        Some(label) => validate(label),
        None => Ok(default.to_owned()),
    }
}

/// The first label of a host name that has dots and is not an IP address literal.
fn host_label(host: &str) -> Option<&str> {
    let name = if host.starts_with('[') {
        // An IPv6 literal (`[::1]:9000`) names no namespace.
        return None;
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    let (label, _) = name.split_once('.')?;
    if name
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(label)
}

fn validate(name: &str) -> Result<String, InvalidNamespace> {
    let lower = name.to_ascii_lowercase();
    let mut bytes = lower.bytes();
    let starts_well = bytes.next().is_some_and(|b| b.is_ascii_alphanumeric());
    if starts_well && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(lower)
    } else {
        Err(InvalidNamespace)
    }
}
