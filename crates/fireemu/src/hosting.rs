//! Local Hosting: pinned-oracle routing with capability-confined static assets.

mod files;
mod matcher;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use serde_json::Value;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Body = BoxBody<Bytes, std::io::Error>;
fn full(value: impl Into<Bytes>) -> Body {
    Full::new(value.into())
        .map_err(|never| match never {})
        .boxed()
}
fn response(status: u16, body: impl Into<Bytes>, content_type: Option<&str>) -> Response<Body> {
    let mut response = Response::builder().status(status);
    if let Some(content_type) = content_type {
        response = response.header("content-type", content_type);
    }
    response
        .body(full(body))
        .expect("constant Hosting response headers")
}

/// Parsed Hosting site configuration; filesystem authority is acquired only at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    data: Value,
    public: PathBuf,
}
impl Config {
    /// Loads one configured site without reading its public files or any credentials.
    pub fn parse(data: &Value, base: &Path) -> Result<Self, String> {
        let object = data
            .as_object()
            .ok_or("hosting must be one site object; multiple sites are not implemented")?;
        let public = object
            .get("public")
            .and_then(Value::as_str)
            .ok_or("hosting.public must be a string")?;
        for key in ["cleanUrls", "trailingSlash"] {
            if object.get(key).is_some_and(|v| !v.is_boolean()) {
                return Err(format!("hosting.{key} must be a boolean"));
            }
        }
        for key in ["rewrites", "redirects", "headers"] {
            if let Some(value) = object.get(key) {
                let rules = value
                    .as_array()
                    .ok_or_else(|| format!("hosting.{key} must be an array"))?;
                for rule in rules {
                    if !rule.is_object() {
                        return Err(format!("hosting.{key} entries must be objects"));
                    }
                    if let Some(regex) = rule.get("regex") {
                        regex::Regex::new(regex.as_str().ok_or("hosting regex must be a string")?)
                            .map_err(|e| format!("hosting regex: {e}"))?;
                    }
                }
            }
        }
        Ok(Self {
            data: data.clone(),
            public: base.join(public),
        })
    }
}

struct UpstreamTask(tokio::task::JoinHandle<Result<(), hyper::Error>>);
impl Drop for UpstreamTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct ProxyBody {
    body: Incoming,
    _connection: UpstreamTask,
}
impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.body)
            .poll_frame(cx)
            .map(|frame| frame.map(|frame| frame.map_err(std::io::Error::other)))
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::Body::size_hint(&self.body)
    }
    fn is_end_stream(&self) -> bool {
        hyper::body::Body::is_end_stream(&self.body)
    }
}

struct Site {
    data: Value,
    /// `None` when the public directory does not exist: every asset lookup misses.
    root: Option<Arc<cap_std::fs::Dir>>,
    project: String,
    upstream: Option<std::net::SocketAddr>,
    emulators: Value,
}

/// Files firebase-tools never uploads whatever the configuration says (`listFiles` in
/// firebase-tools 15.28.2), so production serves them as absent.
const DEPLOY_ALWAYS_IGNORED: [&str; 3] = [
    "**/firebase-debug.log",
    "**/firebase-debug.*.log",
    ".firebase/*",
];

impl Site {
    fn rules(&self, name: &str) -> &[Value] {
        self.data
            .get(name)
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    fn custom_headers(&self, path: &str, response: &mut Response<Body>) {
        for rule in self
            .rules("headers")
            .iter()
            .filter(|rule| matcher::matches(rule, path))
        {
            for header in rule
                .get("headers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(name), Some(value)) =
                    (header["key"].as_str(), header["value"].as_str())
                {
                    if let (Ok(name), Ok(value)) = (
                        hyper::header::HeaderName::try_from(name),
                        hyper::header::HeaderValue::try_from(value),
                    ) {
                        response.headers_mut().insert(name, value);
                    }
                }
            }
        }
    }
    fn candidates(&self, path: &str, headers: &hyper::HeaderMap) -> Vec<String> {
        let mut paths = Vec::new();
        if let Some(root) = self
            .data
            .get("i18n")
            .and_then(|v| v.get("root"))
            .and_then(Value::as_str)
        {
            let header = |key: &str| headers.get(key).and_then(|v| v.to_str().ok()).unwrap_or("");
            let cookie = |key: &str| {
                header("cookie")
                    .split(';')
                    .map(str::trim)
                    .find_map(|cookie| cookie.strip_prefix(&format!("{key}=")))
                    .unwrap_or("")
            };
            let language_override = cookie("firebase-language-override");
            let languages: Vec<_> = if language_override.is_empty() {
                header("accept-language")
                    .split(',')
                    .map(|v| v.split('-').next().unwrap_or(""))
                    .filter(|s| !s.is_empty())
                    .collect()
            } else {
                language_override.split(',').collect()
            };
            let country_override = cookie("firebase-country-override");
            let country = if country_override.is_empty() {
                header("x-country-code")
            } else {
                country_override
            };
            if !country.is_empty() {
                for language in &languages {
                    paths.push(format!("/{root}/{language}_{country}{path}"));
                }
                paths.push(format!("/{root}/ALL_{country}{path}"));
            }
            for language in languages {
                paths.push(format!("/{root}/{language}_ALL{path}"));
                paths.push(format!("/{root}/{language}{path}"));
            }
        }
        paths.push(path.to_owned());
        paths
    }
    async fn asset(
        &self,
        path: &str,
        headers: &hyper::HeaderMap,
    ) -> Option<(String, files::Asset)> {
        files::find(
            self.root.clone(),
            self.candidates(path, headers),
            DEPLOY_ALWAYS_IGNORED
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .chain(
                    self.rules("ignore")
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                )
                .collect(),
        )
        .await
    }
    fn file_response(path: &str, asset: files::Asset, status: u16, head: bool) -> Response<Body> {
        let mime = match path.rsplit('.').next().unwrap_or("") {
            "html" | "htm" => "text/html; charset=utf-8",
            "json" => "application/json; charset=utf-8",
            "js" | "mjs" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "txt" => "text/plain; charset=utf-8",
            "svg" => "image/svg+xml",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "wasm" => "application/wasm",
            _ => "application/octet-stream",
        };
        let mut response = Response::builder()
            .status(status)
            .header("content-type", mime)
            .header("content-length", asset.bytes)
            .header("etag", asset.etag);
        if let Some(modified) = asset.modified {
            response = response.header("last-modified", httpdate::fmt_http_date(modified));
        }
        if mime.starts_with("text/")
            || mime.starts_with("application/json")
            || mime == "image/svg+xml"
        {
            response = response.header("vary", "Accept-Encoding");
        }
        response
            .body(if head {
                full(Bytes::new())
            } else {
                files::FileBody::new(asset.file, asset.bytes).boxed()
            })
            .expect("asset headers")
    }
    fn redirect(destination: &str, status: u16, head: bool) -> Response<Body> {
        let mut result = response(
            status,
            if head {
                String::new()
            } else {
                format!("Redirecting to {destination}")
            },
            Some("text/html; charset=utf-8"),
        );
        if let Ok(location) = hyper::header::HeaderValue::try_from(destination) {
            result.headers_mut().insert("location", location);
        } else {
            return response(400, "Invalid redirect", None);
        }
        result
    }
    async fn route(self: Arc<Self>, request: Request<Incoming>) -> Response<Body> {
        let path = request.uri().path().to_owned();
        let query = request
            .uri()
            .query()
            .map_or(String::new(), |q| format!("?{q}"));
        let head = request.method() == hyper::Method::HEAD;
        let Some(decoded) = files::decode_uri(&path) else {
            return response(400, "Malformed URL", None);
        };
        // The published Hosting priority gives supported reserved routes precedence.
        // The pinned local middleware instead inserts init handling after redirects.
        let reserved = path == "/__/firebase/init.json"
            || path == "/__/firebase/init.js"
            || (path.starts_with("/__/firebase/") && path.split('/').count() >= 5);
        for rule in self.rules("redirects").iter().filter(|_| !reserved) {
            match configured_redirect(rule, &decoded, &query) {
                None => {}
                Some(Err(())) => return response(400, "Malformed URL", None),
                Some(Ok(location)) => {
                    let status = rule
                        .get("type")
                        .and_then(Value::as_u64)
                        .and_then(|v| u16::try_from(v).ok())
                        .unwrap_or(301);
                    return Self::redirect(&location, status, head);
                }
            }
        }
        let result = self
            .clone()
            .after_redirects(request, &path, &query, head)
            .await;
        let mut result = result;
        self.custom_headers(&path, &mut result);
        result
    }
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // The pinned Hosting cleanUrls rule is case-sensitive.
    async fn static_response(
        &self,
        path: &str,
        query: &str,
        head: bool,
        headers: &hyper::HeaderMap,
    ) -> Option<Response<Body>> {
        let mut normalized = path.to_owned();
        while normalized.contains("//") {
            normalized = normalized.replace("//", "/");
        }
        let path = normalized.as_str();
        let clean = self.data["cleanUrls"].as_bool().unwrap_or(false);
        let slash = self.data["trailingSlash"].as_bool();
        if let Some((file, asset)) = self.asset(path, headers).await {
            if clean && path.ends_with(".html") {
                let mut target = path.trim_end_matches(".html").to_owned();
                if target.ends_with("/index") {
                    target.truncate(target.len() - 6);
                }
                if slash == Some(true) && !target.ends_with('/') {
                    target.push('/');
                }
                if target.is_empty() {
                    target.push('/');
                }
                target.push_str(query);
                return Some(Self::redirect(&target, 301, head));
            }
            return Some(Self::file_response(
                &file,
                asset,
                if path == "/404.html" { 404 } else { 200 },
                head,
            ));
        }
        let has_slash = path.ends_with('/');
        let index = format!("{}/index.html", path.trim_end_matches('/'));
        if let Some((file, asset)) = self.asset(&index, headers).await {
            if (slash.is_none() && !has_slash && !clean) || (slash == Some(true) && !has_slash) {
                return Some(Self::redirect(&format!("{path}/{query}"), 301, head));
            }
            if slash == Some(false) && has_slash && path != "/" {
                return Some(Self::redirect(
                    &format!("{}{query}", path.trim_end_matches('/')),
                    301,
                    head,
                ));
            }
            return Some(Self::file_response(&file, asset, 200, head));
        }
        if clean {
            let appended = if has_slash && slash.is_some() {
                format!("{}.html", path.trim_end_matches('/'))
            } else if !has_slash {
                format!("{path}.html")
            } else {
                path.to_owned()
            };
            if let Some((file, asset)) = self.asset(&appended, headers).await {
                if slash == Some(false) && has_slash {
                    return Some(Self::redirect(
                        &format!("{}{query}", path.trim_end_matches('/')),
                        301,
                        head,
                    ));
                }
                if slash == Some(true) && !has_slash {
                    return Some(Self::redirect(&format!("{path}/{query}"), 301, head));
                }
                if appended.ends_with("/index.html") {
                    let target = appended.trim_end_matches("/index.html");
                    return Some(Self::redirect(
                        &format!("{}{query}", if target.is_empty() { "/" } else { target }),
                        301,
                        head,
                    ));
                }
                return Some(Self::file_response(&file, asset, 200, head));
            }
        }
        None
    }
    fn init_config(&self) -> Value {
        // This nonsecret key only enables local SDK initialization; it is not a cloud credential.
        serde_json::json!({"projectId": self.project, "apiKey": "fireemu-local-only"})
    }
    async fn after_redirects(
        self: Arc<Self>,
        request: Request<Incoming>,
        path: &str,
        query: &str,
        head: bool,
    ) -> Response<Body> {
        if path == "/__/firebase/init.json" {
            return response(
                200,
                if head {
                    String::new()
                } else {
                    self.init_config().to_string()
                },
                Some("application/json"),
            );
        }
        if path == "/__/firebase/init.js" {
            let emulators = if query
                .split(['?', '&'])
                .any(|part| part == "useEmulator=true")
            {
                self.emulators.clone()
            } else {
                Value::Null
            };
            let script=format!("if(typeof firebase==='undefined')throw new Error('Firebase SDK not detected');var config={};firebase.initializeApp(config);var endpoints={};if(endpoints)Object.keys(endpoints).forEach(function(name){{if(typeof firebase[name]==='function'){{var endpoint=endpoints[name];if(name==='auth')firebase[name]().useEmulator('http://'+endpoint.hostAndPort);else firebase[name]().useEmulator(endpoint.host,endpoint.port);}}}});",self.init_config(),emulators);
            return response(
                200,
                if head { String::new() } else { script },
                Some("application/javascript"),
            );
        }
        if path.starts_with("/__/firebase/") && path.split('/').count() >= 5 {
            return response(
                503,
                "External Firebase SDK downloads are unavailable offline",
                None,
            );
        }
        if let Some(response) = self
            .static_response(path, query, head, request.headers())
            .await
        {
            return response;
        }
        if let Some(rule) = self
            .rules("rewrites")
            .iter()
            .find(|rule| matcher::matches(rule, path))
        {
            if let Some(destination) = rule["destination"].as_str() {
                if let Some((file, asset)) = self.asset(destination, &hyper::HeaderMap::new()).await
                {
                    let etag_match = request
                        .headers()
                        .get("if-none-match")
                        .is_some_and(|v| v.as_bytes() == asset.etag.as_bytes());
                    let time_match = request
                        .headers()
                        .get("if-modified-since")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| httpdate::parse_http_date(v).ok())
                        .is_some_and(|time| asset.modified.is_some_and(|modified| modified < time));
                    if etag_match || time_match {
                        return response(304, Bytes::new(), None);
                    }
                    return Self::file_response(
                        &file,
                        asset,
                        if destination == "/404.html" { 404 } else { 200 },
                        head,
                    );
                }
            } else if rule.get("function").is_some() || rule.get("run").is_some() {
                return self.proxy(request, rule).await;
            }
        }
        if let Some((file, asset)) = self.asset("/404.html", request.headers()).await {
            let mut result = Self::file_response(&file, asset, 404, head);
            self.custom_headers("/404.html", &mut result);
            return result;
        }
        let escaped = path
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;");
        response(
            404,
            if head {
                String::new()
            } else {
                format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot {} {escaped}</pre>\n</body>\n</html>\n",request.method())
            },
            Some("text/html; charset=utf-8"),
        )
    }
    async fn proxy(&self, request: Request<Incoming>, rule: &Value) -> Response<Body> {
        let Some(upstream) = self.upstream else {
            return response(
                503,
                "Hosting rewrite requires a registered local Functions runtime",
                None,
            );
        };
        let target = rule
            .get("function")
            .or_else(|| rule.get("run"))
            .expect("rewriter");
        let id = target
            .as_str()
            .or_else(|| {
                target
                    .get("functionId")
                    .or_else(|| target.get("serviceId"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("");
        let region = target
            .get("region")
            .or_else(|| rule.get("region"))
            .and_then(Value::as_str)
            .unwrap_or("us-central1");
        if id.is_empty()
            || [id, region]
                .iter()
                .any(|v| v.contains(['/', '\\', '?', '#']))
        {
            return response(400, "Invalid local rewrite target", None);
        }
        let (parts, body) = request.into_parts();
        let Ok(body) = fireemu_adapter_support::body::collect_limited(body, 32 * 1024 * 1024).await
        else {
            return response(413, "Hosting request body too large", None);
        };
        let uri = format!(
            "/{}/{region}/{id}{}",
            self.project,
            parts
                .uri
                .path_and_query()
                .map_or("/", hyper::http::uri::PathAndQuery::as_str)
        );
        let mut outbound = Request::builder().method(parts.method).uri(uri);
        for (name, value) in &parts.headers {
            if !matches!(
                name.as_str(),
                "host" | "connection" | "transfer-encoding" | "content-length" | "upgrade"
            ) {
                outbound = outbound.header(name, value);
            }
        }
        outbound = outbound
            .header("host", upstream.to_string())
            .header("x-original-url", parts.uri.to_string());
        if let Some(host) = parts.headers.get("host") {
            outbound = outbound.header("x-forwarded-host", host);
        }
        let Ok(outbound) = outbound.body(Full::new(body)) else {
            return response(400, "Invalid rewrite request", None);
        };
        Self::forward(upstream, outbound).await
    }
    async fn forward(
        upstream: std::net::SocketAddr,
        outbound: Request<Full<Bytes>>,
    ) -> Response<Body> {
        let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let socket = tokio::net::TcpStream::connect(upstream)
                .await
                .map_err(|e| e.to_string())?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
                    .await
                    .map_err(|e| e.to_string())?;
            let connection = UpstreamTask(tokio::spawn(connection));
            let result = sender
                .send_request(outbound)
                .await
                .map_err(|e| e.to_string());
            // The connection task is owned by the response body until consumption completes.
            match result {
                Ok(result) => Ok((result, connection)),
                Err(error) => {
                    drop(connection);
                    Err(error)
                }
            }
        })
        .await;
        match result {
            Ok(Ok((result, connection))) => {
                let (mut parts, body) = result.into_parts();
                let body = ProxyBody {
                    body,
                    _connection: connection,
                }
                .boxed();
                if !parts.headers.contains_key("cache-control") {
                    parts.headers.insert(
                        "cache-control",
                        hyper::header::HeaderValue::from_static("private"),
                    );
                }
                parts.headers.insert(
                    "vary",
                    hyper::header::HeaderValue::from_static(
                        "Accept-Encoding, Authorization, Cookie",
                    ),
                );
                Response::from_parts(parts, body)
            }
            _ => response(502, "Local Hosting rewrite failed", None),
        }
    }
}

// Match encodeURI for an already decoded configured redirect. Canonical asset
// redirects retain their original encoded path and must not pass this boundary.
fn encode_redirect_uri(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b";/?:@&=+$,#-_.!~*'()".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

/// The `Location` of a matching configured redirect, `Err` for a malformed query.
fn configured_redirect(rule: &Value, decoded: &str, query: &str) -> Option<Result<String, ()>> {
    let (authority, mut destination) = redirect_destination(rule, decoded)?;
    if !query.is_empty() {
        destination.push(if destination.contains('?') { '&' } else { '?' });
        let Some(decoded_query) = files::decode_uri(&query[1..]) else {
            return Some(Err(()));
        };
        destination.push_str(&decoded_query);
    }
    Some(Ok(format!(
        "{authority}{}",
        encode_redirect_uri(&destination)
    )))
}

fn redirect_parts<'a>(destination: &'a str, source: Option<&str>) -> Option<(&'a str, &'a str)> {
    let capture_names: Vec<_> = source
        .into_iter()
        .flat_map(|value| value.split('/'))
        .filter_map(|part| part.strip_prefix(':'))
        .collect();
    let tokens = regex::Regex::new(r":([A-Za-z0-9_]+)").expect("constant capture token");
    let has_capture = |value: &str| {
        tokens
            .captures_iter(value)
            .any(|token| capture_names.contains(&&token[1]))
    };
    let start = if destination
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        Some(8)
    } else if destination
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
    {
        Some(7)
    } else if destination.starts_with("//") {
        Some(2)
    } else {
        None
    };
    if let Some(start) = start {
        let end = destination[start..]
            .find(['/', '?', '#'])
            .map_or(destination.len(), |n| start + n);
        let authority = &destination[start..end];
        let uri = format!("http://{authority}/").parse::<hyper::Uri>().ok()?;
        let parsed = uri.authority()?;
        if parsed.host().is_empty() {
            return None;
        }
        let host_port = authority.rsplit('@').next()?;
        let port = &host_port[parsed.host().len()..];
        if !port.is_empty() {
            let port = port.strip_prefix(':')?;
            if port.is_empty()
                || !port.bytes().all(|b| b.is_ascii_digit())
                || port.parse::<u16>().is_err()
            {
                return None;
            }
        }
        if authority
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| has_capture(userinfo))
        {
            return None;
        }
        // Keep the original literal authority: ports and IPv6 colons are not capture tokens.
        return Some((&destination[..end], &destination[end..]));
    }
    let first_segment = destination.split('/').next()?;
    if has_capture(first_segment) || (first_segment.contains(':') && has_capture(destination)) {
        return None;
    }
    Some(("", destination))
}

fn redirect_destination(rule: &Value, path: &str) -> Option<(String, String)> {
    let destination = rule.get("destination")?.as_str()?;
    let (authority, destination) =
        redirect_parts(destination, rule.get("source").and_then(Value::as_str))?;
    if let Some(source) = rule.get("source").and_then(Value::as_str) {
        if source.contains(':') && destination.contains(':') {
            let source: Vec<_> = source.split('/').collect();
            let path: Vec<_> = path.split('/').collect();
            if source.len() != path.len() {
                return None;
            }
            let mut captures = std::collections::BTreeMap::new();
            for (pattern, part) in source.iter().zip(path) {
                if let Some(name) = pattern.strip_prefix(':') {
                    if part.is_empty() {
                        return None;
                    }
                    captures.insert(name, part);
                } else if *pattern != part {
                    return None;
                }
            }
            // Expand original destination tokens once; captured text is never reparsed.
            let tokens = regex::Regex::new(r":([A-Za-z0-9_]+)").expect("constant capture token");
            return Some((
                authority.to_owned(),
                tokens
                    .replace_all(destination, |token: &regex::Captures<'_>| {
                        captures
                            .get(&token[1])
                            .copied()
                            .unwrap_or(&token[0])
                            .to_owned()
                    })
                    .into_owned(),
            ));
        }
    }
    matcher::matches(rule, path).then(|| (authority.to_owned(), destination.to_owned()))
}

/// A site whose configured root has been acquired before readiness publication.
pub struct PreparedSite(Arc<Site>);

/// Acquires the public-root capability before publishing a ready endpoint.
pub fn prepare(
    config: Config,
    project: String,
    upstream: Option<std::net::SocketAddr>,
    emulators: Value,
) -> Result<PreparedSite, String> {
    // firebase-tools 15.28.2 only logs a missing public directory at debug level and serves.
    let root =
        match cap_std::fs::Dir::open_ambient_dir(&config.public, cap_std::ambient_authority()) {
            Ok(root) => Some(Arc::new(root)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("hosting.public: {error}")),
        };
    Ok(PreparedSite(Arc::new(Site {
        data: config.data,
        root,
        project,
        upstream,
        emulators,
    })))
}

/// Serves Hosting until the owning suite drops this future; all connection tasks are owned.
pub async fn serve(
    listener: tokio::net::TcpListener,
    prepared: PreparedSite,
) -> Result<(), String> {
    let site = prepared.0;
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (stream,_)=accepted.map_err(|e|e.to_string())?;let site=site.clone();
                connections.spawn(async move {
                    let service=hyper::service::service_fn(move |request|{let site=site.clone();async move{Ok::<_,Infallible>(site.route(request).await)}});
                    let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
                });
            }
            _=connections.join_next(),if !connections.is_empty()=>{}
        }
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn location(destination: &str, raw_path: &str, raw_query: &str) -> Option<Result<String, ()>> {
        let rule = json!({"source": "/go/:name", "destination": destination, "type": 302});
        let decoded = files::decode_uri(raw_path).expect("well-formed test path");
        configured_redirect(&rule, &decoded, raw_query)
    }

    // Review 2026-11-07 P1: a captured `%5c` must not become `/\evil.example`.
    #[test]
    fn a_captured_backslash_stays_an_encoded_path_byte() {
        assert_eq!(
            location("/:name", "/go/%5cevil.example", ""),
            Some(Ok("/%5Cevil.example".to_owned()))
        );
        assert_eq!(
            location("/:name", "/go/%5c%5cevil.example", "?a=%5c"),
            Some(Ok("/%5C%5Cevil.example?a=%5C".to_owned()))
        );
        assert_eq!(
            location("/:name", "/go/%2fevil.example", ""),
            Some(Ok("/%252fevil.example".to_owned()))
        );
        assert_eq!(location("/:name", "/go/", ""), None);
        assert_eq!(location("/:name", "/go/x", "?%zz"), Some(Err(())));
        assert_eq!(location(":name", "/go/evil.example", ""), None);
        assert_eq!(location("http://:name/", "/go/evil.example", ""), None);
    }

    fn encode_component(value: &str) -> String {
        value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    proptest! {
        // A capture or query can never change the origin, add a scheme, or inject a
        // header byte, whatever text it carries (the review's backslash, `//`, CR/LF,
        // `javascript:` and encoded-slash shapes are all in this space).
        #[test]
        fn captures_and_queries_never_change_the_redirect_origin(
            segment in "\\PC{1,12}|[\\\\/:%?#@ \\t\\r\\na.]{1,12}",
            query in "\\PC{0,8}|[\\\\/:%?#@\\r\\n]{0,8}",
        ) {
            let raw_path = format!("/go/{}", encode_component(&segment));
            let raw_query = if query.is_empty() { String::new() } else { format!("?{}", encode_component(&query)) };
            for (destination, prefix) in [
                ("/:name", "/"),
                ("/next/:name", "/next/"),
                ("folder/:name", "folder/"),
                ("https://example.test/:name", "https://example.test/"),
                ("HTTPS://example.test:444/:name", "HTTPS://example.test:444/"),
                ("//example.test:1234/:name", "//example.test:1234/"),
                ("http://[::1]/:name", "http://[::1]/"),
            ] {
                let Some(Ok(location)) = location(destination, &raw_path, &raw_query) else {
                    prop_assert!(false, "{destination} {raw_path}{raw_query} must redirect");
                    unreachable!();
                };
                prop_assert!(location.starts_with(prefix), "{location}");
                let rest = &location[prefix.len()..];
                prop_assert!(!rest.starts_with('/'), "{location}");
                prop_assert!(
                    location.bytes().all(|b| b.is_ascii_graphic() && b != b'\\'),
                    "{location:?}"
                );
                prop_assert!(hyper::header::HeaderValue::try_from(location.as_str()).is_ok());
            }
        }
    }
}
