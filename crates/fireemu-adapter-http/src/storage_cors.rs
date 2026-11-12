//! Bucket CORS configuration (`storage.cors`): the GCS `cors` JSON of a bucket and the
//! decisions Cloud Storage takes with it.
//!
//! A bucket's configuration is a list of rules, each `{origin, method, responseHeader,
//! maxAgeSeconds}`. A request that carries an `Origin` is matched against the rules in order and
//! the first rule that matches decides the answer (Cloud Storage's documented behaviour,
//! "Cross-origin resource sharing (CORS)"):
//!
//! - an actual request matches when its origin is listed (or `*` is) and its method is listed (or
//!   `*` is); the answer then carries `Access-Control-Allow-Origin`, `Vary: Origin` when the
//!   origin was echoed, and `Access-Control-Expose-Headers` for the `responseHeader` list;
//! - a preflight matches when, besides that, every header named in
//!   `Access-Control-Request-Headers` is in `responseHeader` (or `*` is); the answer then also
//!   carries `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` and
//!   `Access-Control-Max-Age`;
//! - a request no rule matches is answered without any CORS header, and succeeds all the same:
//!   a browser, not Cloud Storage, refuses to hand the answer to the page.
//!
//! RECORDED (storage-signed-put, two recordings on a bucket with no CORS configuration): the
//! answers of the XML API to an `OPTIONS` preflight and to a `PUT` that carried an `Origin` are
//! `200` with no `Access-Control-*` header. UNRECORDED: every answer of a bucket that has a
//! configuration (the echoed origin against `*`, the value of `Access-Control-Allow-Methods`, the
//! default of `maxAgeSeconds`, the status of a preflight no rule matches); they follow the
//! documentation. No key material or request data is logged here.

use serde_json::Value;

/// `Access-Control-Max-Age` when a rule names no `maxAgeSeconds`, Cloud Storage's documented
/// default.
pub const DEFAULT_MAX_AGE_SECONDS: u32 = 3600;

/// A configuration holds at most this many rules (a malformed or hostile file must not grow the
/// per-request matching without bound).
const MAX_RULES: usize = 100;
/// A rule names at most this many origins, methods or headers each.
const MAX_ENTRIES: usize = 100;
/// The longest origin or header name read.
const MAX_ENTRY_BYTES: usize = 512;

/// A configuration that does not parse; the message names the field and never echoes more than
/// the field's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsConfigError(pub String);

impl std::fmt::Display for CorsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One entry of a bucket's `cors` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsRule {
    origins: Vec<String>,
    methods: Vec<String>,
    response_headers: Vec<String>,
    max_age_seconds: u32,
}

/// The headers an answer is given, in the order they are written.
pub type CorsHeaders = Vec<(String, String)>;

impl CorsRule {
    fn matches_origin(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == "*" || o == origin)
    }

    fn matches_method(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == "*" || m == method)
    }

    fn allows_header(&self, header: &str) -> bool {
        self.response_headers
            .iter()
            .any(|h| h == "*" || h.eq_ignore_ascii_case(header))
    }

    fn allow_origin_value(&self, origin: &str) -> (String, bool) {
        if self.origins.iter().any(|o| o == "*") {
            ("*".to_owned(), false)
        } else {
            (origin.to_owned(), true)
        }
    }
}

/// The `cors` list of one bucket. An empty list is a bucket with no CORS configuration, which is
/// what a new bucket in production has: no request is given a CORS header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketCors {
    rules: Vec<CorsRule>,
}

impl BucketCors {
    /// Reads the `cors` list of a bucket as the GCS JSON writes it. Unknown keys, wrong types,
    /// empty or control-character strings and over-long lists are refused (fail closed), so a
    /// typo such as `origins` cannot silently configure nothing.
    ///
    /// # Errors
    /// A [`CorsConfigError`] naming the offending path.
    pub fn from_json(value: &Value) -> Result<Self, CorsConfigError> {
        let list = value
            .as_array()
            .ok_or_else(|| CorsConfigError("must be an array of CORS rules".to_owned()))?;
        if list.len() > MAX_RULES {
            return Err(CorsConfigError(format!(
                "has more than {MAX_RULES} CORS rules"
            )));
        }
        let rules = list
            .iter()
            .enumerate()
            .map(|(i, rule)| parse_rule(rule).map_err(|e| CorsConfigError(format!("[{i}]: {e}"))))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules })
    }

    /// Whether no rule is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The CORS headers of an actual (non-preflight) answer to a request with `Origin: origin`
    /// and `method`, or `None` when no rule matches.
    #[must_use]
    pub fn actual(&self, origin: &str, method: &str) -> Option<CorsHeaders> {
        let rule = self
            .rules
            .iter()
            .find(|r| r.matches_origin(origin) && r.matches_method(method))?;
        let (value, echoed) = rule.allow_origin_value(origin);
        let mut headers = vec![("access-control-allow-origin".to_owned(), value)];
        if echoed {
            headers.push(("vary".to_owned(), "Origin".to_owned()));
        }
        if !rule.response_headers.is_empty() {
            headers.push((
                "access-control-expose-headers".to_owned(),
                rule.response_headers.join(","),
            ));
        }
        Some(headers)
    }

    /// The CORS headers of the answer to a preflight (`Access-Control-Request-Method` and the
    /// comma-separated `Access-Control-Request-Headers`), or `None` when no rule matches.
    #[must_use]
    pub fn preflight(
        &self,
        origin: &str,
        request_method: &str,
        request_headers: Option<&str>,
    ) -> Option<CorsHeaders> {
        let wanted: Vec<&str> = request_headers
            .map(|h| {
                h.split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let rule = self.rules.iter().find(|r| {
            r.matches_origin(origin)
                && r.matches_method(request_method)
                && wanted.iter().all(|h| r.allows_header(h))
        })?;
        let (value, echoed) = rule.allow_origin_value(origin);
        let mut headers = vec![
            ("access-control-allow-origin".to_owned(), value),
            (
                "access-control-allow-methods".to_owned(),
                request_method.to_owned(),
            ),
        ];
        if let Some(requested) = request_headers.filter(|_| !wanted.is_empty()) {
            headers.push((
                "access-control-allow-headers".to_owned(),
                requested.to_owned(),
            ));
        }
        headers.push((
            "access-control-max-age".to_owned(),
            rule.max_age_seconds.to_string(),
        ));
        if echoed {
            headers.push(("vary".to_owned(), "Origin".to_owned()));
        }
        Some(headers)
    }
}

fn parse_rule(rule: &Value) -> Result<CorsRule, String> {
    let object = rule
        .as_object()
        .ok_or_else(|| "must be an object".to_owned())?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "origin" | "method" | "responseHeader" | "maxAgeSeconds"
        ) {
            return Err(format!(
                "has an unknown key {key:?} (expected origin, method, responseHeader, maxAgeSeconds)"
            ));
        }
    }
    let origins = string_list(object.get("origin"), "origin", valid_origin)?;
    let methods = string_list(object.get("method"), "method", valid_method)?;
    let response_headers = string_list(
        object.get("responseHeader"),
        "responseHeader",
        valid_header_name,
    )?;
    let max_age_seconds = match object.get("maxAgeSeconds") {
        None => DEFAULT_MAX_AGE_SECONDS,
        Some(value) => value
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| "maxAgeSeconds must be a non-negative whole number".to_owned())?,
    };
    Ok(CorsRule {
        origins,
        methods,
        response_headers,
        max_age_seconds,
    })
}

fn string_list(
    value: Option<&Value>,
    field: &str,
    valid: fn(&str) -> bool,
) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of strings"))?;
    if list.len() > MAX_ENTRIES {
        return Err(format!("{field} has more than {MAX_ENTRIES} entries"));
    }
    list.iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|s| s.len() <= MAX_ENTRY_BYTES && valid(s))
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} holds an entry that is not valid"))
        })
        .collect()
}

/// An origin is `*` or a non-empty string of printable ASCII without spaces or backslashes (a
/// carriage return or line feed is not printable, so a header cannot be split).
fn valid_origin(origin: &str) -> bool {
    origin == "*"
        || (!origin.is_empty() && origin.bytes().all(|b| b.is_ascii_graphic() && b != b'\\'))
}

/// A method is `*` or an upper-case HTTP method token.
fn valid_method(method: &str) -> bool {
    method == "*"
        || (!method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-'))
}

/// A header name is `*` or an HTTP token.
fn valid_header_name(name: &str) -> bool {
    name == "*"
        || (!name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn cors(value: &Value) -> BucketCors {
        BucketCors::from_json(value).unwrap()
    }

    fn header<'a>(headers: &'a CorsHeaders, name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn an_empty_configuration_matches_nothing() {
        let c = cors(&json!([]));
        assert!(c.is_empty());
        assert_eq!(c.actual("http://localhost:3000", "GET"), None);
        assert_eq!(c.preflight("http://localhost:3000", "GET", None), None);
    }

    #[test]
    fn an_actual_request_is_matched_on_origin_and_method() {
        let c = cors(&json!([{
            "origin": ["http://localhost:3000"],
            "method": ["GET", "PUT"],
            "responseHeader": ["Content-Type", "x-goog-meta-a"],
        }]));
        let hit = c.actual("http://localhost:3000", "PUT").unwrap();
        assert_eq!(
            header(&hit, "access-control-allow-origin"),
            Some("http://localhost:3000")
        );
        assert_eq!(header(&hit, "vary"), Some("Origin"));
        assert_eq!(
            header(&hit, "access-control-expose-headers"),
            Some("Content-Type,x-goog-meta-a")
        );
        assert_eq!(
            c.actual("http://localhost:3001", "PUT"),
            None,
            "another origin"
        );
        assert_eq!(
            c.actual("http://localhost:3000", "DELETE"),
            None,
            "another method"
        );
        assert_eq!(
            c.actual("http://localhost:3000", "get"),
            None,
            "methods are case-sensitive"
        );
        assert_eq!(
            c.actual("HTTP://localhost:3000", "GET"),
            None,
            "origins are exact"
        );
    }

    #[test]
    fn a_wildcard_origin_answers_a_star_without_vary() {
        let c = cors(&json!([{"origin": ["*"], "method": ["GET"]}]));
        let hit = c.actual("http://localhost:5173", "GET").unwrap();
        assert_eq!(header(&hit, "access-control-allow-origin"), Some("*"));
        assert_eq!(header(&hit, "vary"), None);
        assert_eq!(header(&hit, "access-control-expose-headers"), None);
    }

    #[test]
    fn a_preflight_needs_every_requested_header_in_the_response_header_list() {
        let c = cors(&json!([{
            "origin": ["http://localhost:3000"],
            "method": ["PUT"],
            "responseHeader": ["Content-Type", "X-Goog-Content-Length-Range"],
            "maxAgeSeconds": 120,
        }]));
        let hit = c
            .preflight(
                "http://localhost:3000",
                "PUT",
                Some("content-type, x-goog-content-length-range"),
            )
            .unwrap();
        assert_eq!(header(&hit, "access-control-allow-methods"), Some("PUT"));
        assert_eq!(
            header(&hit, "access-control-allow-headers"),
            Some("content-type, x-goog-content-length-range")
        );
        assert_eq!(header(&hit, "access-control-max-age"), Some("120"));
        assert_eq!(
            c.preflight(
                "http://localhost:3000",
                "PUT",
                Some("content-type,authorization")
            ),
            None,
            "a header the list does not name"
        );
        assert_eq!(c.preflight("http://localhost:3000", "GET", None), None);
        let bare = c.preflight("http://localhost:3000", "PUT", None).unwrap();
        assert_eq!(header(&bare, "access-control-allow-headers"), None);
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let c = cors(&json!([
            {"origin": ["http://localhost:3000"], "method": ["GET"], "maxAgeSeconds": 1},
            {"origin": ["*"], "method": ["*"], "maxAgeSeconds": 2},
        ]));
        let first = c.preflight("http://localhost:3000", "GET", None).unwrap();
        assert_eq!(header(&first, "access-control-max-age"), Some("1"));
        let second = c.preflight("http://localhost:3000", "PUT", None).unwrap();
        assert_eq!(header(&second, "access-control-max-age"), Some("2"));
        assert_eq!(header(&second, "access-control-allow-origin"), Some("*"));
    }

    #[test]
    fn max_age_defaults_to_an_hour() {
        let c = cors(&json!([{"origin": ["*"], "method": ["GET"]}]));
        let hit = c.preflight("http://localhost:1", "GET", None).unwrap();
        assert_eq!(header(&hit, "access-control-max-age"), Some("3600"));
    }

    #[test]
    fn a_malformed_configuration_is_refused() {
        let long = "x".repeat(MAX_ENTRY_BYTES + 1);
        for bad in [
            json!({}),
            json!("GET"),
            json!([1]),
            json!([{"origins": ["*"]}]),
            json!([{"origin": "*"}]),
            json!([{"origin": [""]}]),
            json!([{"origin": [1]}]),
            json!([{"origin": ["http://a\r\nb"]}]),
            json!([{"origin": [long]}]),
            json!([{"method": ["get"]}]),
            json!([{"method": [""]}]),
            json!([{"responseHeader": ["bad header"]}]),
            json!([{"responseHeader": ["a\nb"]}]),
            json!([{"maxAgeSeconds": -1}]),
            json!([{"maxAgeSeconds": 1.5}]),
            json!([{"maxAgeSeconds": "10"}]),
            json!([{"maxAgeSeconds": 4_294_967_296_u64}]),
            json!(vec![json!({}); MAX_RULES + 1]),
            json!([{"origin": vec!["*"; MAX_ENTRIES + 1]}]),
        ] {
            assert!(BucketCors::from_json(&bad).is_err(), "{bad}");
        }
        let err = BucketCors::from_json(&json!([{}, {"origins": []}])).unwrap_err();
        assert!(err.0.starts_with("[1]: has an unknown key"), "{err}");
    }

    #[test]
    fn the_size_limits_are_inclusive() {
        let rules = vec![json!({}); MAX_RULES];
        assert_eq!(
            BucketCors::from_json(&json!(rules)).unwrap().rules.len(),
            MAX_RULES
        );
        let entries = vec!["*"; MAX_ENTRIES];
        assert!(BucketCors::from_json(&json!([{"origin": entries}])).is_ok());
        let longest = "o".repeat(MAX_ENTRY_BYTES);
        assert!(BucketCors::from_json(&json!([{"origin": [longest]}])).is_ok());
    }

    #[test]
    fn a_configured_bucket_is_not_empty_and_errors_print_their_message() {
        assert!(!cors(&json!([{"origin": ["*"], "method": ["*"]}])).is_empty());
        assert!(!cors(&json!([{}])).is_empty());
        let error = BucketCors::from_json(&json!({})).unwrap_err();
        assert_eq!(error.to_string(), "must be an array of CORS rules");
    }

    #[test]
    fn origins_may_not_carry_spaces_backslashes_or_line_breaks() {
        for bad in ["a b", "a\\b", "a\rb", "a\nb", "a\tb", "", "\u{e9}"] {
            assert!(!valid_origin(bad), "{bad:?}");
        }
        for good in ["*", "http://localhost:3000", "https://[::1]:5173"] {
            assert!(valid_origin(good), "{good:?}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// A reference model over a fixed two-rule configuration: a request gets headers iff
        /// some rule lists its origin (or `*`) and its method (or `*`), and the first such rule
        /// supplies the echoed value.
        #[test]
        fn actual_follows_the_reference_model(origin in 0usize..4, method in 0usize..4) {
            let origins = ["http://localhost:3000", "http://localhost:3001", "http://localhost:3002", "http://127.0.0.1:1"];
            let methods = ["GET", "PUT", "DELETE", "POST"];
            let c = cors(&json!([
                {"origin": [origins[0]], "method": [methods[0], methods[1]]},
                {"origin": [origins[1], origins[2]], "method": ["*"]},
            ]));
            let expected = (origin == 0 && method <= 1) || origin == 1 || origin == 2;
            let got = c.actual(origins[origin], methods[method]);
            prop_assert_eq!(got.is_some(), expected);
            if let Some(h) = got {
                prop_assert_eq!(header(&h, "access-control-allow-origin"), Some(origins[origin]));
            }
        }

        /// A preflight is a refinement of the actual-request match: it never matches where the
        /// actual request would not, and matches iff the requested headers are all listed.
        #[test]
        fn preflight_is_the_actual_match_plus_the_header_check(
            origin in 0usize..3,
            method in 0usize..3,
            headers in proptest::collection::vec(0usize..4, 0..4),
        ) {
            let origins = ["http://localhost:3000", "http://localhost:3001", "*"];
            let methods = ["GET", "PUT", "*"];
            let names = ["content-type", "Authorization", "x-goog-meta-a", "range"];
            let c = cors(&json!([{
                "origin": [origins[0]],
                "method": ["GET", "PUT"],
                "responseHeader": ["Content-Type", "X-Goog-Meta-A"],
            }]));
            let requested: Vec<&str> = headers.iter().map(|i| names[*i]).collect();
            let joined = requested.join(", ");
            let request_headers = (!requested.is_empty()).then_some(joined.as_str());
            let preflight = c.preflight(origins[origin], methods[method], request_headers);
            let actual = c.actual(origins[origin], methods[method]);
            if preflight.is_some() {
                prop_assert!(actual.is_some());
            }
            let all_listed = requested.iter().all(|h| {
                h.eq_ignore_ascii_case("content-type") || h.eq_ignore_ascii_case("x-goog-meta-a")
            });
            prop_assert_eq!(preflight.is_some(), actual.is_some() && all_listed);
        }

        /// Whatever the JSON, parsing never panics.
        #[test]
        fn parsing_never_panics(text in ".{0,200}") {
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                let _ = BucketCors::from_json(&value);
            }
            let _ = BucketCors::from_json(&json!([{"origin": [text.clone()], "method": [text.clone()], "responseHeader": [text]}]));
        }
    }
}
