//! Guarded, bounded fronts to this runtime's actual RTDB listener, including its event delivery.
use crate::{UiBody, UiRequest, UiResponse, UiState, MAX_JSON_BODY_BYTES};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Trusted runtime wiring. Neither the endpoint nor configured ownership comes from a request.
#[derive(Clone, Debug)]
pub struct DatabaseEndpoint {
    /// The actual bound RTDB listener, or its unspecified bind address.
    pub address: SocketAddr,
    /// The daemon's Auth project: every non-default named instance belongs to this project.
    pub project: String,
    /// Configured instance names and their projects, resolved by runtime configuration.
    pub configured_instances: BTreeMap<String, String>,
}
impl DatabaseEndpoint {
    /// Connect only to loopback at the bound port, preserving its address family.
    #[must_use]
    pub fn loopback(&self) -> SocketAddr {
        SocketAddr::new(
            match self.address.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            self.address.port(),
        )
    }
    /// Runtime instance ownership, deliberately different from adapter namespace reset mapping.
    #[must_use]
    pub fn project_of<'a>(&'a self, name: &'a str) -> &'a str {
        self.configured_instances.get(name).map_or_else(
            || {
                name.strip_suffix("-default-rtdb")
                    .filter(|p| !p.is_empty())
                    .unwrap_or(&self.project)
            },
            String::as_str,
        )
    }
}
/// A validated finite request. Membership is checked against trusted/discovered names before send.
#[derive(Debug)]
pub struct DatabasePlan {
    /// Selected session name.
    pub session: String,
    /// Selected session project.
    pub project: String,
    /// Instance name, absent for listing.
    pub namespace: Option<String>,
    /// Encoded data/settings target, never an authority or URL.
    pub target: String,
    /// The raw JSON source, unchanged.
    pub body: Vec<u8>,
    /// Only administrative data/Rules actions carry the internal owner credential.
    pub administrator: bool,
}
fn invalid(message: &str) -> UiResponse {
    UiResponse::error(400, message)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && name == name.to_ascii_lowercase()
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
fn decode(text: &str) -> Result<String, UiResponse> {
    String::from_utf8(fireemu_core_types::codec::percent_decode_bytes(
        text,
        fireemu_core_types::codec::PlusMode::Literal,
    ))
    .map_err(|_| invalid("Invalid UTF-8 in query"))
}
fn parameters(query: &str) -> Result<BTreeMap<String, String>, UiResponse> {
    if !fireemu_core_types::codec::percent_escapes_are_well_formed(query) {
        return Err(invalid("Malformed query escape"));
    }
    let mut result = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode(name)?;
        let value = decode(value)?;
        if crate::has_control_chars(&name)
            || crate::has_control_chars(&value)
            || result.insert(name, value).is_some()
        {
            return Err(invalid("Ambiguous or invalid query"));
        }
    }
    Ok(result)
}
/// Validate session/target/query before any network request. This does not grant membership.
#[allow(clippy::too_many_lines)]
pub fn prepare(
    endpoint: &DatabaseEndpoint,
    sessions: &BTreeMap<String, String>,
    action: &str,
    request: &UiRequest,
) -> Result<DatabasePlan, UiResponse> {
    if request.body.len() > MAX_JSON_BODY_BYTES {
        return Err(UiResponse::error(413, "PAYLOAD_TOO_LARGE"));
    }
    let params = parameters(&request.query)?;
    if params.keys().any(|name| {
        !matches!(
            name.as_str(),
            "session" | "project" | "namespace" | "path" | "query"
        )
    }) {
        return Err(invalid("Unsupported request parameter"));
    }
    let session = params
        .get("session")
        .ok_or_else(|| invalid("Session is required"))?;
    let project = params
        .get("project")
        .ok_or_else(|| invalid("Project is required"))?;
    if sessions.get(session) != Some(project) {
        return Err(UiResponse::error(
            404,
            "The session/project no longer exists",
        ));
    }
    if !matches!(action, "instances" | "data" | "rules" | "request") {
        return Err(UiResponse::error(404, "NOT_FOUND"));
    }
    let allowed = match action {
        "instances" => request.method == "GET",
        "rules" => matches!(request.method.as_str(), "GET" | "PUT"),
        _ => matches!(request.method.as_str(), "GET" | "PUT" | "PATCH" | "DELETE"),
    };
    if !allowed {
        return Err(UiResponse::error(405, "METHOD_NOT_ALLOWED"));
    }
    if action == "instances" {
        if params.len() != 2 || !request.body.is_empty() {
            return Err(invalid(
                "Only session/project are allowed for instance listing",
            ));
        }
        return Ok(DatabasePlan {
            session: session.clone(),
            project: project.clone(),
            namespace: None,
            target: String::new(),
            body: Vec::new(),
            administrator: true,
        });
    }
    let namespace = params
        .get("namespace")
        .filter(|name| valid_name(name))
        .ok_or_else(|| invalid("Invalid database instance"))?;
    if endpoint.project_of(namespace) != project {
        return Err(UiResponse::error(
            404,
            "Instance does not belong to the selected project",
        ));
    }
    let mut target = if action == "rules" {
        if params.contains_key("path") || params.contains_key("query") {
            return Err(invalid("Rules target is fixed"));
        }
        "/.settings/rules.json".to_owned()
    } else {
        let path = params.get("path").map_or("/", String::as_str);
        if path.chars().any(|c| ".#$[]".contains(c) || c.is_control()) || path.contains("//") {
            return Err(invalid("Invalid database path"));
        }
        let encoded = path
            .trim_matches('/')
            .split('/')
            .map(encode)
            .collect::<Vec<_>>()
            .join("/");
        format!("/{encoded}.json")
    };
    let _ = write!(target, "?ns={}", encode(namespace));
    if let Some(query) = params.get("query") {
        for (name, value) in parameters(query)? {
            if !matches!(
                name.as_str(),
                "orderBy"
                    | "startAt"
                    | "endAt"
                    | "equalTo"
                    | "limitToFirst"
                    | "limitToLast"
                    | "shallow"
                    | "format"
                    | "print"
                    | "writeSizeLimit"
                    | "timeout"
            ) {
                return Err(invalid("Unsupported data query parameter"));
            }
            let _ = write!(target, "&{}={}", encode(&name), encode(&value));
        }
    }
    if matches!(request.method.as_str(), "GET" | "DELETE") && !request.body.is_empty() {
        return Err(invalid("This method does not accept a body"));
    }
    Ok(DatabasePlan {
        session: session.clone(),
        project: project.clone(),
        namespace: Some(namespace.clone()),
        target,
        body: request.body.clone(),
        administrator: action != "request",
    })
}
async fn forward(
    endpoint: &DatabaseEndpoint,
    method: &str,
    target: &str,
    body: &[u8],
    administrator: bool,
) -> Result<UiResponse, UiResponse> {
    let mut headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("x-firebase-etag".to_owned(), "true".to_owned()),
    ];
    if administrator {
        headers.push(("authorization".to_owned(), "Bearer owner".to_owned()));
    }
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        fireemu_adapter_functions::http::forward(
            &endpoint.loopback().to_string(),
            method,
            target,
            &headers,
            body,
        ),
    )
    .await
    .map_err(|_| {
        UiResponse::error(
            504,
            "Database response timed out; a write outcome is unknown",
        )
    })?
    .map_err(|_| UiResponse::error(502, "Database transport failed; a write outcome is unknown"))?;
    if result.body.len() > 4 * 1024 * 1024 {
        return Err(UiResponse::error(
            502,
            "Database response exceeds the console limit",
        ));
    }
    let mut headers: Vec<_> = result
        .headers
        .into_iter()
        .filter(|(name, _)| matches!(name.to_ascii_lowercase().as_str(), "content-type" | "etag"))
        .collect();
    headers.extend([
        ("cache-control".to_owned(), "no-store".to_owned()),
        ("x-content-type-options".to_owned(), "nosniff".to_owned()),
    ]);
    Ok(UiResponse {
        status: result.status,
        headers,
        body: UiBody::Full(result.body.into()),
    })
}
async fn instances(endpoint: &DatabaseEndpoint) -> Result<BTreeMap<String, String>, UiResponse> {
    let seed = endpoint
        .configured_instances
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| format!("{}-default-rtdb", endpoint.project));
    if !valid_name(&seed) {
        return Err(UiResponse::error(500, "Invalid configured instance"));
    }
    let response = forward(
        endpoint,
        "GET",
        &format!("/.inspect/databases.json?ns={seed}"),
        &[],
        true,
    )
    .await?;
    if response.status != 200 {
        return Err(UiResponse::error(502, "Cannot discover database instances"));
    }
    let names: Vec<Value> = response
        .body_json()
        .and_then(|value| value.as_array().cloned())
        .ok_or_else(|| UiResponse::error(502, "Invalid instance discovery response"))?;
    let mut names_by_project = endpoint.configured_instances.clone();
    for row in names {
        let name = row
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| valid_name(name))
            .ok_or_else(|| UiResponse::error(502, "Invalid discovered instance"))?;
        names_by_project.insert(name.to_owned(), endpoint.project_of(name).to_owned());
    }
    Ok(names_by_project)
}
fn member(membership: &BTreeMap<String, String>, namespace: &str, project: &str) -> bool {
    membership
        .get(namespace)
        .is_some_and(|owner| owner == project)
}

/// The original UI guard is applied by `handle` before this dispatcher.
pub async fn route(state: &Arc<UiState>, action: &str, request: &UiRequest) -> UiResponse {
    let Some(endpoint) = &state.database else {
        return UiResponse::error(503, "Realtime Database is not enabled");
    };
    let sessions = match state.control.sessions.lock() {
        Ok(sessions) => sessions.clone(),
        Err(_) => return UiResponse::error(503, "Session registry unavailable"),
    };
    let plan = match prepare(endpoint, &sessions, action, request) {
        Ok(plan) => plan,
        Err(error) => return error,
    };
    let membership = match instances(endpoint).await {
        Ok(membership) => membership,
        Err(error) => return error,
    };
    if !state
        .control
        .sessions
        .lock()
        .is_ok_and(|sessions| sessions.get(&plan.session) == Some(&plan.project))
    {
        return UiResponse::error(404, "The session/project no longer exists");
    }
    if let Some(namespace) = &plan.namespace {
        if !member(&membership, namespace, &plan.project) {
            return UiResponse::error(404, "Unknown database instance for this project");
        }
        forward(
            endpoint,
            &request.method,
            &plan.target,
            &plan.body,
            plan.administrator,
        )
        .await
        .unwrap_or_else(|error| error)
    } else {
        let list: Vec<_> = membership
            .into_iter()
            .filter(|(_, project)| project == &plan.project)
            .map(|(name, project)| json!({"name":name,"project":project}))
            .collect();
        let mut response = UiResponse::json(200, &json!({"instances":list}));
        response
            .headers
            .push(("cache-control".to_owned(), "no-store".to_owned()));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_requires_both_a_known_name_and_its_exact_project() {
        let membership = BTreeMap::from([
            ("named".to_owned(), "demo-a".to_owned()),
            ("other-default-rtdb".to_owned(), "other".to_owned()),
        ]);
        assert!(member(&membership, "named", "demo-a"));
        assert!(!member(&membership, "unknown", "demo-a"));
        assert!(!member(&membership, "named", "other"));
        assert!(!member(&membership, "other-default-rtdb", "demo-a"));
    }

    fn assert_query_error(query: &str, message: &str) {
        let response = parameters(query).unwrap_err();
        assert_eq!(response.status, 400, "{query}");
        assert_eq!(
            response.body_json(),
            invalid(message).body_json(),
            "{query}"
        );
    }

    #[test]
    fn query_codec_obeys_strict_utf8_for_every_single_byte_escape() {
        for byte in 0..=u8::MAX {
            let query = format!("key=%{byte:02X}");
            let bytes = [byte];
            match std::str::from_utf8(&bytes) {
                Ok(value) if crate::has_control_chars(value) => {
                    assert_query_error(&query, "Ambiguous or invalid query");
                }
                Ok(value) => assert_eq!(parameters(&query).unwrap()["key"], value),
                Err(_) => assert_query_error(&query, "Invalid UTF-8 in query"),
            }
        }
    }

    #[test]
    fn query_codec_preserves_generated_pairwise_contracts() {
        // PICT pairwise rows, including all nine mandatory regression seeds.
        let rows = "Content\tEscape\tPlus\tPosition\nascii\tvalid\tabsent\tvalue\nascii\tvalid\traw\tvalue\nascii\tvalid\tencoded\tvalue\nunicode\tvalid\tabsent\tvalue\ndelimiters\tvalid\tabsent\tvalue\nnested\tvalid\tabsent\tvalue\nascii\tmalformed\tabsent\tvalue\nascii\tinvalid_utf8\tabsent\tvalue\nascii\tprecedence\tabsent\tvalue\nnested\tinvalid_utf8\tencoded\tname\nnested\tmalformed\traw\tname\ndelimiters\tinvalid_utf8\traw\tname\nunicode\tinvalid_utf8\tencoded\tname\nunicode\tmalformed\traw\tname\nunicode\tprecedence\tencoded\tname\ndelimiters\tprecedence\tencoded\tname\nascii\tmalformed\tencoded\tname\ndelimiters\tmalformed\tabsent\tname\nnested\tprecedence\traw\tvalue\nascii\tvalid\tencoded\tname\n";
        for row in rows.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let (raw, decoded) = match columns[0] {
                "ascii" => ("child", "child"),
                "unicode" => ("%C3%A9", "é"),
                "delimiters" => ("a%26b%3Dc%2fd", "a&b=c/d"),
                "nested" => ("orderBy%3D%2522name%2522", "orderBy=%22name%22"),
                other => panic!("Unknown generated content: {other}"),
            };
            let suffix = match columns[2] {
                "absent" => "",
                "raw" => "+",
                "encoded" => "%2B",
                other => panic!("Unknown generated plus mode: {other}"),
            };
            let raw = format!("{raw}{suffix}");
            let decoded = format!("{decoded}{}", if suffix.is_empty() { "" } else { "+" });
            let (query, expected) = match columns[3] {
                "name" => (
                    format!("{raw}=value"),
                    BTreeMap::from([(decoded, "value".to_owned())]),
                ),
                "value" => (
                    format!("key={raw}"),
                    BTreeMap::from([("key".to_owned(), decoded)]),
                ),
                other => panic!("Unknown generated position: {other}"),
            };
            match columns[1] {
                "valid" => assert_eq!(parameters(&query).unwrap(), expected, "{row}"),
                "malformed" => assert_query_error(&format!("{query}%"), "Malformed query escape"),
                "invalid_utf8" => {
                    assert_query_error(&format!("{query}%80"), "Invalid UTF-8 in query");
                }
                "precedence" => {
                    assert_query_error(&format!("early=%FF&{query}%"), "Malformed query escape");
                }
                other => panic!("Unknown generated escape class: {other}"),
            }
        }
    }

    #[test]
    fn query_codec_refuses_malformed_utf8_duplicate_and_control_inputs() {
        for escape in ["%", "%2", "%2G", "%+f", "%-1", "%é"] {
            assert_query_error(&format!("path={escape}"), "Malformed query escape");
        }
        for escape in ["%80", "%FF", "%C3%28"] {
            assert_query_error(&format!("path={escape}"), "Invalid UTF-8 in query");
        }
        for query in ["path=a&%70ath=b", "path=%00", "%0A=x"] {
            assert_query_error(query, "Ambiguous or invalid query");
        }
    }

    #[test]
    fn query_codec_preserves_scoped_targets_and_exact_nested_decode_layers() {
        let endpoint = DatabaseEndpoint {
            address: "127.0.0.1:1".parse().unwrap(),
            project: "demo-a".to_owned(),
            configured_instances: BTreeMap::new(),
        };
        let sessions = BTreeMap::from([("main".to_owned(), "demo-a".to_owned())]);
        let prefix = "session=main&project=demo-a&namespace=demo-a-default-rtdb";
        for (extra, target) in [
            ("", "/.json?ns=demo-a-default-rtdb"),
            ("&path=a+b", "/a%2Bb.json?ns=demo-a-default-rtdb"),
            ("&path=a%2Bb", "/a%2Bb.json?ns=demo-a-default-rtdb"),
            (
                "&path=%2fa%2Fb%20%C3%A9",
                "/a/b%20%C3%A9.json?ns=demo-a-default-rtdb",
            ),
            (
                "&query=orderBy%3D%2522a%252Bb%2522",
                "/.json?ns=demo-a-default-rtdb&orderBy=%22a%2Bb%22",
            ),
            (
                "&query=orderBy%3D%2522a%25252Bb%2522",
                "/.json?ns=demo-a-default-rtdb&orderBy=%22a%252Bb%22",
            ),
        ] {
            let request = UiRequest {
                method: "GET".to_owned(),
                path: String::new(),
                query: format!("{prefix}{extra}"),
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
            let plan = prepare(&endpoint, &sessions, "data", &request).unwrap();
            assert_eq!(plan.target, target, "{extra}");
            assert_eq!(plan.session, "main");
            assert_eq!(plan.project, "demo-a");
            assert_eq!(plan.namespace.as_deref(), Some("demo-a-default-rtdb"));
            assert!(plan.administrator);
            assert!(plan.body.is_empty());
            assert!(
                !prepare(&endpoint, &sessions, "request", &request)
                    .unwrap()
                    .administrator
            );
        }
    }
}
