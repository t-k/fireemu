//! Which database namespace a request addresses.

/// The namespace of a request: the `ns` query parameter, else the first label of a host
/// name with dots (`<ns>.firebaseio.com`, `<ns>.<region>.firebasedatabase.app`,
/// `<ns>.localhost`), else `default`. Names are lowercased; a name that does not start with
/// a letter or digit, or holds anything but letters, digits and hyphens, is refused.
pub fn route<'a>(ns: Option<&str>, host: Option<&str>, default: &'a str) -> Result<String, InvalidNamespace> {
    let _ = (ns, host, default);
    todo!()
}

/// A namespace name the server refuses ("Invalid Firebase database name").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidNamespace;
