//! Local Hosting: pinned-oracle routing with capability-confined static assets.

mod content_types;
mod files;
mod matcher;
mod mime;
mod production;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use serde_json::Value;
use sha2::Digest as _;
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
    public_root: String,
    project: String,
    upstream: Option<std::net::SocketAddr>,
    emulators: Value,
    /// The strict profile answers as Hosting production does (see `production`); the emulator
    /// profile answers as the pinned local oracle does.
    strict: bool,
}

/// When the process first served a generated file: its `Last-Modified`.
static STARTED: std::sync::OnceLock<std::time::SystemTime> = std::sync::OnceLock::new();

/// Which configured header rules apply to a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderPolicy {
    All,
    /// Production's `304` carries the `Cache-Control` of the representation and nothing else
    /// that the rules set (`v01.cond-etag`).
    OnlyCacheControl,
    /// Production's `OPTIONS` answer keeps its own `Cache-Control: no-cache`.
    ExceptCacheControl,
}

/// What a response is, for the headers production adds to it (`finish_strict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Bytes of a deployed file (or a generated stand-in for one): cacheable for an hour.
    File,
    /// A redirect, an error page or anything else with no default `Cache-Control`.
    Other,
    /// A response of a local Functions runtime: its own headers stand.
    Passthrough,
}
fn marked(mut response: Response<Body>, kind: Kind) -> Response<Body> {
    response.extensions_mut().insert(kind);
    response
}

/// A body of unknown length, so that HTTP/1.1 sends it chunked, as production does for `400`.
struct Chunked(Full<Bytes>);
impl hyper::body::Body for Chunked {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.0)
            .poll_frame(cx)
            .map(|frame| frame.map(|frame| frame.map_err(|never| match never {})))
    }
}

/// Every run of slashes as one, as superstatic's `normalizeMultiSlashes` does.
fn collapse_slashes(path: &str) -> String {
    let mut collapsed = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch != '/' || !collapsed.ends_with('/') {
            collapsed.push(ch);
        }
    }
    collapsed
}

/// One localized candidate, `join(root, directory, path)` of superstatic's i18n lookup: the parts
/// are joined with slashes under a leading one and every run of slashes collapses, so a root
/// written `/locales`, `locales/` or `//locales` finds the same files as `locales`.
fn i18n_path(root: &str, directory: &str, path: &str) -> String {
    collapse_slashes(&format!("//{root}/{directory}/{path}"))
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
    fn matches(&self, rule: &Value, path: &str) -> bool {
        if self.strict {
            matcher::matches_production(rule, path)
        } else {
            matcher::matches(rule, path)
        }
    }
    fn custom_headers(&self, path: &str, response: &mut Response<Body>) {
        self.custom_headers_with(path, response, HeaderPolicy::All);
    }
    fn custom_headers_with(&self, path: &str, response: &mut Response<Body>, policy: HeaderPolicy) {
        for rule in self
            .rules("headers")
            .iter()
            .filter(|rule| self.matches(rule, path))
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
                    let is_cache_control = name.eq_ignore_ascii_case("cache-control");
                    let skipped = match policy {
                        HeaderPolicy::All => false,
                        HeaderPolicy::OnlyCacheControl => !is_cache_control,
                        HeaderPolicy::ExceptCacheControl => is_cache_control,
                    };
                    if skipped {
                        continue;
                    }
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
            // An empty root is no root: superstatic tests `i18n?.root` for truthiness.
            .filter(|root| !root.is_empty())
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
            let languages: Vec<String> = if language_override.is_empty() {
                if self.strict {
                    production::accept_languages(header("accept-language"))
                } else {
                    header("accept-language")
                        .split(',')
                        .map(|v| v.split('-').next().unwrap_or("").to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
            } else {
                language_override.split(',').map(str::to_owned).collect()
            };
            let country_override = cookie("firebase-country-override");
            // Production decides the country at its edge: a header or cookie the client sends
            // does not (`v07.country-header`, `v07.country-cookie`, runs 658bb2 and 9a8d57).
            let country = if self.strict {
                ""
            } else if country_override.is_empty() {
                header("x-country-code")
            } else {
                country_override
            };
            if !country.is_empty() {
                for language in &languages {
                    paths.push(i18n_path(root, &format!("{language}_{country}"), path));
                }
                paths.push(i18n_path(root, &format!("ALL_{country}"), path));
            }
            for language in &languages {
                paths.push(i18n_path(root, &format!("{language}_ALL"), path));
                paths.push(i18n_path(root, language, path));
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
            self.public_root.clone(),
        )
        .await
    }
    fn file_response(path: &str, asset: files::Asset, status: u16, head: bool) -> Response<Body> {
        // The pinned oracle sends the literal `false` for a file whose extension mime-types does
        // not know; a generic binary type is sent instead, and it is not compressible.
        let (mime, compressible) =
            mime::content_type(path).unwrap_or(("application/octet-stream", false));
        let mut response = Response::builder()
            .status(status)
            .header("content-type", mime)
            .header("content-length", asset.bytes)
            .header("etag", asset.etag);
        if let Some(modified) = asset.modified {
            response = response.header("last-modified", httpdate::fmt_http_date(modified));
        }
        // The compression middleware varies on the encoding of every compressible type.
        if compressible {
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
    /// A deployed file as the profile answers it. The emulator profile answers as the pinned oracle
    /// does (`file_response`); strict adds what production adds: a quoted SHA-256 `ETag`, `304`
    /// for a matching `If-None-Match` or a not older `If-Modified-Since`, and single `Range`s.
    async fn serve_asset(
        &self,
        path: &str,
        asset: files::Asset,
        status: u16,
        head: bool,
        request: &hyper::HeaderMap,
    ) -> Response<Body> {
        if !self.strict {
            return Self::file_response(path, asset, status, head);
        }
        let etag = format!("\"{}\"", asset.sha256);
        let header = |name: &str| request.get(name).and_then(|value| value.to_str().ok());
        if status == 200
            && production::not_modified(
                header("if-none-match"),
                header("if-modified-since"),
                &etag,
                asset.modified,
            )
        {
            let not_modified = Response::builder()
                .status(304)
                .header("etag", etag)
                .body(full(Bytes::new()))
                .expect("304 headers");
            return marked(not_modified, Kind::File);
        }
        let mut builder = Response::builder()
            .header(
                "content-type",
                production::content_type(mime::content_type(path).map(|(mime, _)| mime)),
            )
            .header("etag", etag);
        if let Some(modified) = asset.modified {
            builder = builder.header("last-modified", httpdate::fmt_http_date(modified));
        }
        let length = asset.bytes;
        let outcome = if status == 200 {
            production::range(header("range"), length)
        } else {
            production::RangeOutcome::Whole
        };
        let result = match outcome {
            production::RangeOutcome::Whole => builder
                .status(status)
                .header("content-length", length)
                .body(if head {
                    full(Bytes::new())
                } else {
                    files::FileBody::new(asset.file, length).boxed()
                }),
            production::RangeOutcome::Unsatisfiable => {
                let mut refusal = response(416, Bytes::new(), None);
                if let Ok(value) = hyper::header::HeaderValue::try_from(format!("bytes */{length}"))
                {
                    refusal.headers_mut().insert("content-range", value);
                }
                return marked(refusal, Kind::Other);
            }
            production::RangeOutcome::Partial { start, end } => {
                let size = end - start + 1;
                let data = if head {
                    Ok(Vec::new())
                } else {
                    let mut file = asset.file;
                    tokio::task::spawn_blocking(move || {
                        use std::io::{Read, Seek};
                        file.seek(std::io::SeekFrom::Start(start))?;
                        let mut data = vec![0u8; usize::try_from(size).unwrap_or(0)];
                        file.read_exact(&mut data)?;
                        Ok::<_, std::io::Error>(data)
                    })
                    .await
                    .unwrap_or_else(|error| Err(std::io::Error::other(error)))
                };
                let Ok(data) = data else {
                    return response(500, "Could not read the file", None);
                };
                builder
                    .status(206)
                    .header("content-range", format!("bytes {start}-{end}/{length}"))
                    .header("content-length", size)
                    .body(full(data))
            }
        };
        marked(result.expect("asset headers"), Kind::File)
    }
    fn redirect(&self, destination: &str, status: u16, head: bool) -> Response<Body> {
        let mut result = response(
            status,
            if head {
                String::new()
            } else {
                format!("Redirecting to {destination}")
            },
            Some(if self.strict {
                "text/plain; charset=utf-8"
            } else {
                "text/html; charset=utf-8"
            }),
        );
        if head && self.strict {
            // `v01.head-redirect`: the length the body would have
            result.headers_mut().insert(
                "content-length",
                hyper::header::HeaderValue::from(format!("Redirecting to {destination}").len()),
            );
        }
        if let Ok(location) = hyper::header::HeaderValue::try_from(destination) {
            result.headers_mut().insert("location", location);
        } else {
            return response(400, "Invalid redirect", None);
        }
        result
    }
    /// `400` for a malformed target. Production answers `400 Bad Request` as plain text of unknown
    /// length (`v01.safety-bad-percent`).
    fn bad_request(&self) -> Response<Body> {
        if !self.strict {
            return response(400, "Malformed URL", None);
        }
        let body: Body = Chunked(Full::new(Bytes::from_static(b"400 Bad Request"))).boxed();
        let mut result = Response::builder()
            .status(400)
            .header("content-type", "text/plain; charset=utf-8")
            .header("accept-ranges", "bytes")
            .body(body)
            .expect("constant 400 headers");
        result.extensions_mut().insert(Kind::Other);
        result
    }
    /// What production adds to every answer it generates: `Accept-Ranges`, `Vary` (the request
    /// headers it varies on) and, for file bytes, `Cache-Control: max-age=3600`. Configured header
    /// rules are applied afterwards and win.
    fn finish_strict(&self, response: &mut Response<Body>) {
        let kind = response
            .extensions()
            .get::<Kind>()
            .copied()
            .unwrap_or(Kind::Other);
        if kind == Kind::Passthrough {
            return;
        }
        let status = response.status().as_u16();
        let localized = self
            .data
            .get("i18n")
            .and_then(|v| v.get("root"))
            .and_then(Value::as_str)
            .is_some_and(|root| !root.is_empty());
        let headers = response.headers_mut();
        headers.remove("vary");
        if status != 304 {
            headers.insert(
                "accept-ranges",
                hyper::header::HeaderValue::from_static("bytes"),
            );
        }
        if status != 400 {
            headers.insert(
                "vary",
                hyper::header::HeaderValue::from_static(if localized && kind == Kind::File {
                    "accept-language, x-country-code, x-fh-requested-host, accept-encoding"
                } else {
                    "x-fh-requested-host, accept-encoding"
                }),
            );
        }
        if kind == Kind::File && !headers.contains_key("cache-control") {
            headers.insert(
                "cache-control",
                hyper::header::HeaderValue::from_static("max-age=3600"),
            );
        }
    }
    async fn route(self: Arc<Self>, request: Request<Incoming>) -> Response<Body> {
        if let Err(refusal) = fireemu_core_session::host_guard::admits_request(
            request.version() == hyper::Version::HTTP_2,
            request
                .headers()
                .get_all(hyper::header::HOST)
                .iter()
                .map(hyper::header::HeaderValue::as_bytes),
        ) {
            // DNS rebinding: a page whose name was re-pointed at this listener would read the
            // site and reach the rewrites' Functions as same-origin.
            return response(
                403,
                refusal.body(),
                Some(fireemu_core_session::host_guard::REFUSAL_CONTENT_TYPE),
            );
        }
        let path = request.uri().path().to_owned();
        let query = request
            .uri()
            .query()
            .map_or(String::new(), |q| format!("?{q}"));
        let head = request.method() == hyper::Method::HEAD;
        let Some(decoded) = files::decode_uri(&path) else {
            return self.bad_request();
        };
        // Production matches the parts of a path one by one and decodes every escape of a
        // captured part (`%2f`, `%3A`, `%3F`) before it builds the `Location` (`v01.edge-1-03`,
        // `-08`, `-10`); header rules see the ordinarily decoded path (`v01.encoded-static`).
        if self.strict && files::decode_uri_full(&path).is_none() {
            return self.bad_request();
        }
        // The published Hosting priority gives supported reserved routes precedence.
        // The pinned local middleware instead inserts init handling after redirects.
        // Production keeps `/__/auth/handler` and the SDK files out of the redirects, but not
        // `init.json` and `init.js` (`v09.reserved-json`, `v09.reserved-auth-handler`).
        let sdk = path.starts_with("/__/firebase/") && path.split('/').count() >= 5;
        let reserved = if self.strict {
            path == "/__/auth/handler" || sdk
        } else {
            path == "/__/firebase/init.json" || path == "/__/firebase/init.js" || sdk
        };
        for rule in self.rules("redirects").iter().filter(|_| !reserved) {
            match configured_redirect(rule, &decoded, &path, &query, self.strict) {
                None => {}
                Some(Err(())) => return self.bad_request(),
                Some(Ok(location)) => {
                    let status = rule
                        .get("type")
                        .and_then(Value::as_u64)
                        .and_then(|v| u16::try_from(v).ok())
                        .unwrap_or(301);
                    let mut result = self.redirect(&location, status, head);
                    if self.strict {
                        // Production's configured redirects carry the configured headers too
                        // (`v01.redirect-first`: `X-Fixture`).
                        self.finish_strict(&mut result);
                        self.custom_headers(&decoded, &mut result);
                    }
                    return result;
                }
            }
        }
        let method = request.method().clone();
        if self.strict && path == "/__/auth/handler" {
            let mut answer = Self::auth_handler(head);
            // an edge-generated page: no configured headers (`v01.reserved-auth-handler`)
            self.finish_strict(&mut answer);
            return answer;
        }
        let result = self
            .clone()
            .after_redirects(request, &path, &query, head)
            .await;
        let mut result = result;
        if self.strict {
            self.finish_strict(&mut result);
            let policy = match (result.status().as_u16(), &method) {
                (304, _) => HeaderPolicy::OnlyCacheControl,
                (200, &hyper::Method::OPTIONS) => HeaderPolicy::ExceptCacheControl,
                _ => HeaderPolicy::All,
            };
            self.custom_headers_with(&decoded, &mut result, policy);
        } else {
            self.custom_headers(&path, &mut result);
        }
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
        let normalized = collapse_slashes(path);
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
                return Some(self.redirect(&target, 301, head));
            }
            return Some(
                self.serve_asset(
                    &file,
                    asset,
                    // Production serves `/404.html` as the file it is (`v01.not-found-direct`).
                    if path == "/404.html" && !self.strict {
                        404
                    } else {
                        200
                    },
                    head,
                    headers,
                )
                .await,
            );
        }
        let has_slash = path.ends_with('/');
        let index = format!("{}/index.html", path.trim_end_matches('/'));
        if let Some((file, asset)) = self.asset(&index, headers).await {
            if (slash.is_none() && !has_slash && !clean) || (slash == Some(true) && !has_slash) {
                return Some(self.redirect(&format!("{path}/{query}"), 301, head));
            }
            if slash == Some(false) && has_slash && path != "/" {
                return Some(self.redirect(
                    &format!("{}{query}", path.trim_end_matches('/')),
                    301,
                    head,
                ));
            }
            return Some(self.serve_asset(&file, asset, 200, head, headers).await);
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
                    return Some(self.redirect(
                        &format!("{}{query}", path.trim_end_matches('/')),
                        301,
                        head,
                    ));
                }
                if slash == Some(true) && !has_slash {
                    return Some(self.redirect(&format!("{path}/{query}"), 301, head));
                }
                if appended.ends_with("/index.html") {
                    let target = appended.trim_end_matches("/index.html");
                    return Some(self.redirect(
                        &format!("{}{query}", if target.is_empty() { "/" } else { target }),
                        301,
                        head,
                    ));
                }
                return Some(self.serve_asset(&file, asset, 200, head, headers).await);
            }
        }
        None
    }
    /// A generated body that production serves as a deployed file would be (`init.json`, `init.js`:
    /// quoted SHA-256 `ETag`, `Last-Modified`, cacheable). The emulator profile sends the bare body.
    fn generated_file(&self, body: String, head: bool, content_type: &str) -> Response<Body> {
        if !self.strict {
            return response(
                200,
                if head { String::new() } else { body },
                Some(content_type),
            );
        }
        let started = *STARTED.get_or_init(std::time::SystemTime::now);
        let etag = format!("\"{:x}\"", sha2::Sha256::digest(body.as_bytes()));
        let length = body.len();
        let mut answer = Response::builder()
            .status(200)
            .header("content-type", content_type)
            .header("content-length", length)
            .header("etag", etag)
            .header("last-modified", httpdate::fmt_http_date(started))
            .body(full(if head { String::new() } else { body }))
            .expect("generated file headers");
        answer.extensions_mut().insert(Kind::File);
        answer
    }
    /// `v01.options-static`: an empty `200` that names the methods a deployed file serves.
    async fn options_response(
        &self,
        path: &str,
        headers: &hyper::HeaderMap,
    ) -> Option<Response<Body>> {
        self.asset(path, headers).await?;
        let mut answer = response(200, Bytes::new(), Some("text/html; charset=UTF-8"));
        answer.headers_mut().insert(
            "allow",
            hyper::header::HeaderValue::from_static("GET, HEAD, OPTIONS"),
        );
        answer.headers_mut().insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("no-cache"),
        );
        Some(answer)
    }
    /// `v02.assetlinks`, `v02.apple-app-site-association`: with `appAssociation: "AUTO"` the two
    /// documents are generated and never cached.
    fn association_response(&self, path: &str, head: bool) -> Option<Response<Body>> {
        if !self.strict || self.data["appAssociation"].as_str() != Some("AUTO") {
            return None;
        }
        let document = production::app_association(path)?;
        let mut answer = response(
            200,
            if head {
                String::new()
            } else {
                document.to_owned()
            },
            Some("application/json; charset=utf-8"),
        );
        answer.headers_mut().insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("private, no-store"),
        );
        answer.headers_mut().insert(
            "pragma",
            hyper::header::HeaderValue::from_static("no-cache"),
        );
        Some(answer)
    }
    /// `/__/auth/handler`: production answers `200` with its handler page (`462` bytes on the
    /// recorded `HEAD`), outside the redirects. The page itself was not recorded, so a stand-in
    /// page answers.
    fn auth_handler(head: bool) -> Response<Body> {
        let mut answer = response(
            200,
            if head {
                String::new()
            } else {
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Authentication</title></head><body></body></html>\n".to_owned()
            },
            Some("text/html; charset=utf-8"),
        );
        answer.headers_mut().insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("max-age=1800"),
        );
        answer
    }
    /// The `init.js` body: the SDK initialization, with the emulator endpoints on request.
    fn init_script(&self, query: &str) -> String {
        let emulators = if query
            .split(['?', '&'])
            .any(|part| part == "useEmulator=true")
        {
            self.emulators.clone()
        } else {
            Value::Null
        };
        format!("if(typeof firebase==='undefined')throw new Error('Firebase SDK not detected');var config={};firebase.initializeApp(config);var endpoints={};if(endpoints)Object.keys(endpoints).forEach(function(name){{if(typeof firebase[name]==='function'){{var endpoint=endpoints[name];if(name==='auth')firebase[name]().useEmulator('http://'+endpoint.hostAndPort);else firebase[name]().useEmulator(endpoint.host,endpoint.port);}}}});",self.init_config(),emulators)
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
        if request.method() == hyper::Method::OPTIONS && self.strict {
            if let Some(answer) = self.options_response(path, request.headers()).await {
                return answer;
            }
        }
        if path == "/__/firebase/init.json" {
            let body = self.init_config().to_string();
            return self.generated_file(body, head, "application/json");
        }
        if path == "/__/firebase/init.js" {
            let script = self.init_script(query);
            return self.generated_file(
                script,
                head,
                if self.strict {
                    "text/javascript; charset=utf-8"
                } else {
                    "application/javascript"
                },
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
        if let Some(answer) = self.association_response(path, head) {
            return answer;
        }
        if let Some(rule) = self
            .rules("rewrites")
            .iter()
            .find(|rule| self.matches(rule, path))
        {
            if let Some(destination) = rule["destination"].as_str() {
                if let Some((file, asset)) = self.asset(destination, &hyper::HeaderMap::new()).await
                {
                    if self.strict {
                        return self
                            .serve_asset(
                                &file,
                                asset,
                                if destination == "/404.html" { 404 } else { 200 },
                                head,
                                request.headers(),
                            )
                            .await;
                    }
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
                return marked(self.proxy(request, rule).await, Kind::Passthrough);
            }
        }
        if let Some((file, asset)) = self.asset("/404.html", request.headers()).await {
            let mut result = self
                .serve_asset(&file, asset, 404, head, request.headers())
                .await;
            self.custom_headers("/404.html", &mut result);
            return result;
        }
        Self::default_not_found(request.method(), path, head)
    }
    /// The page for a path nothing answers and no `404.html` covers. Production's own page is
    /// 21,376 bytes and was not recorded as text, so this one is shorter (a known difference).
    fn default_not_found(method: &hyper::Method, path: &str, head: bool) -> Response<Body> {
        let escaped = path
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;");
        marked(
            response(
                404,
                if head {
                    String::new()
                } else {
                    format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot {method} {escaped}</pre>\n</body>\n</html>\n")
                },
                Some("text/html; charset=utf-8"),
            ),
            Kind::File,
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
fn configured_redirect(
    rule: &Value,
    decoded: &str,
    raw: &str,
    query: &str,
    strict: bool,
) -> Option<Result<String, ()>> {
    let (authority, mut destination) = redirect_destination(rule, decoded, raw, strict)?;
    if strict {
        // Production appends the query as sent (`v01.edge-1-11`: `x=%5c` stays lowercase) and
        // folds the runs of slashes a decoded capture can leave (`v01.edge-1-03`: `%2f` -> `/`).
        let mut location = encode_redirect_uri(&collapse_slashes(&destination));
        if !query.is_empty() {
            location.push(if location.contains('?') { '&' } else { '?' });
            location.push_str(&query[1..]);
        }
        return Some(Ok(format!("{authority}{location}")));
    }
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

/// The name of a `:name` source part and the literal that follows it. Production reads a name as
/// letters and `_` only, so `:id2` is the parameter `id` followed by a literal `2`
/// (`v01.redirect-capture-prefix`, `-literal`: the source `/capture/:id/:id2` never matched).
fn capture_part(part: &str, strict: bool) -> Option<(&str, &str)> {
    let name = part.strip_prefix(':')?;
    if !strict {
        return Some((name, ""));
    }
    let end = name
        .find(|ch: char| !(ch.is_ascii_alphabetic() || ch == '_'))
        .unwrap_or(name.len());
    Some((&name[..end], &name[end..]))
}

fn capture_token(strict: bool) -> regex::Regex {
    regex::Regex::new(if strict {
        r":([A-Za-z_]+)"
    } else {
        r":([A-Za-z0-9_]+)"
    })
    .expect("constant capture token")
}

fn redirect_parts<'a>(
    destination: &'a str,
    source: Option<&str>,
    strict: bool,
) -> Option<(&'a str, &'a str)> {
    let capture_names: Vec<_> = source
        .into_iter()
        .flat_map(|value| value.split('/'))
        .filter_map(|part| capture_part(part, strict).map(|(name, _)| name))
        .collect();
    let tokens = capture_token(strict);
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

fn redirect_destination(
    rule: &Value,
    path: &str,
    raw: &str,
    strict: bool,
) -> Option<(String, String)> {
    let destination = rule.get("destination")?.as_str()?;
    let (authority, destination) = redirect_parts(
        destination,
        rule.get("source").and_then(Value::as_str),
        strict,
    )?;
    if let Some(source) = rule.get("source").and_then(Value::as_str) {
        if source.contains(':') && destination.contains(':') {
            let source: Vec<_> = source.split('/').collect();
            // Strict: the parts are those of the path as sent, each decoded on its own.
            let decoded_parts: Vec<String>;
            let path: Vec<&str> = if strict {
                decoded_parts = raw
                    .split('/')
                    .map(|part| files::decode_uri_full(part).unwrap_or_default())
                    .collect();
                decoded_parts.iter().map(String::as_str).collect()
            } else {
                path.split('/').collect()
            };
            if source.len() != path.len() {
                return None;
            }
            let mut captures = std::collections::BTreeMap::new();
            for (pattern, part) in source.iter().zip(path) {
                if let Some((name, literal)) = capture_part(pattern, strict) {
                    let value = part.strip_suffix(literal)?;
                    if value.is_empty() {
                        return None;
                    }
                    captures.insert(name, value);
                } else if *pattern != part {
                    return None;
                }
            }
            // Expand original destination tokens once; captured text is never reparsed.
            let tokens = capture_token(strict);
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
    let matched = if strict {
        matcher::matches_production(rule, path)
    } else {
        matcher::matches(rule, path)
    };
    matched.then(|| (authority.to_owned(), destination.to_owned()))
}

/// A site whose configured root has been acquired before readiness publication.
pub struct PreparedSite(Arc<Site>);

/// Acquires the public-root capability before publishing a ready endpoint.
pub fn prepare(
    config: Config,
    project: String,
    upstream: Option<std::net::SocketAddr>,
    emulators: Value,
    strict: bool,
) -> Result<PreparedSite, String> {
    // firebase-tools 15.28.2 only logs a missing public directory at debug level and serves.
    let root =
        match cap_std::fs::Dir::open_ambient_dir(&config.public, cap_std::ambient_authority()) {
            Ok(root) => Some(Arc::new(root)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("hosting.public: {error}")),
        };
    let absolute =
        std::path::absolute(&config.public).map_err(|error| format!("hosting.public: {error}"))?;
    let mut public_root = PathBuf::new();
    for component in absolute.components() {
        if component == std::path::Component::ParentDir {
            public_root.pop();
        } else {
            public_root.push(component.as_os_str());
        }
    }
    Ok(PreparedSite(Arc::new(Site {
        public_root: public_root.to_string_lossy().replace('\\', "/"),
        data: config.data,
        root,
        project,
        upstream,
        emulators,
        strict,
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
        configured_redirect(&rule, &decoded, raw_path, raw_query, false)
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

    fn strict_location(
        source: &str,
        destination: &str,
        raw_path: &str,
        raw_query: &str,
    ) -> Option<String> {
        let rule = json!({"source": source, "destination": destination, "type": 302});
        let decoded = files::decode_uri(raw_path).expect("well-formed test path");
        configured_redirect(&rule, &decoded, raw_path, raw_query, true).map(|found| found.unwrap())
    }

    // The rows `v01.edge-*` and `v01.redirect-capture-*` of the production recording.
    #[test]
    fn strict_redirects_decode_each_capture_and_keep_the_query_as_sent() {
        for (destination, path, query, expected) in [
            ("/:name", "/go1/%2fevil.example", "", "/evil.example"),
            (
                "/next/:name",
                "/go2/%2fevil.example",
                "",
                "/next/evil.example",
            ),
            (
                "https://example.test/:name",
                "/go3/%2fevil.example",
                "",
                "https://example.test/evil.example",
            ),
            ("/:name", "/go1/%3Aother", "", "/:other"),
            ("/:name", "/go1/a%3Fb", "", "/a?b"),
            ("/:name", "/go1/plain", "?x=%5c", "/plain?x=%5c"),
            ("/:name", "/go1/%5cevil.example", "", "/%5Cevil.example"),
            ("/:name", "/go1/%255cevil.example", "", "/%255cevil.example"),
            ("/:name", "/go1/a%25b", "", "/a%25b"),
        ] {
            let source = format!("/{}/:name", path.split('/').nth(1).unwrap());
            assert_eq!(
                strict_location(&source, destination, path, query).as_deref(),
                Some(expected),
                "{path}{query}"
            );
        }
        // a query joins a destination that has one with `&`
        assert_eq!(
            strict_location("/go1/:name", "/x/:name?a=1", "/go1/b", "?q=2").as_deref(),
            Some("/x/b?a=1&q=2")
        );
    }

    #[test]
    fn strict_capture_names_are_letters_and_underscores() {
        assert_eq!(capture_part(":id2", true), Some(("id", "2")));
        assert_eq!(capture_part(":my_id", true), Some(("my_id", "")));
        assert_eq!(capture_part(":id2", false), Some(("id2", "")));
        assert_eq!(capture_part("id", true), None);
        // `/capture/:id/:id2` never matched in production, `/capture/:name` did
        assert_eq!(
            strict_location("/capture/:id/:id2", "/new/:id2/:id", "/capture/one/two", ""),
            None
        );
        assert_eq!(
            strict_location(
                "/capture/:id/:id2",
                "/new/:id2/:id",
                "/capture/:id2/two",
                ""
            ),
            None
        );
        assert_eq!(
            strict_location(
                "/capture/:id/:id2",
                "/new/:id2/:id",
                "/capture/one/two2",
                ""
            )
            .as_deref(),
            Some("/new/two2/two"),
            "the `2` is a literal after the parameter `id`, which the second part then sets to `two`"
        );
        assert_eq!(
            strict_location("/capture/:name", "/new/:name", "/capture/name", "").as_deref(),
            Some("/new/name")
        );
        // the emulator profile reads digits into the name
        let rule =
            json!({"source": "/capture/:id/:id2", "destination": "/new/:id2/:id", "type": 302});
        assert_eq!(
            configured_redirect(&rule, "/capture/one/two", "/capture/one/two", "", false),
            Some(Ok("/new/two/one".to_owned()))
        );
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

#[cfg(test)]
mod i18n_path_tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn site(root: &str) -> Site {
        Site {
            data: json!({"i18n": {"root": root}}),
            root: None,
            public_root: "/public".to_owned(),
            project: "demo".to_owned(),
            upstream: None,
            emulators: Value::Null,
            strict: false,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut map = hyper::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                hyper::header::HeaderName::try_from(*name).unwrap(),
                hyper::header::HeaderValue::try_from(*value).unwrap(),
            );
        }
        map
    }

    // Measured against the pinned superstatic 10.0.0 `i18nContentOptions` (2026-11-09).
    #[test]
    fn the_candidates_keep_the_oracle_order_for_every_spelling_of_the_root() {
        for root in [
            "locales",
            "/locales",
            "locales/",
            "/locales/",
            "//locales",
            "/locales//",
        ] {
            let paths = site(root).candidates(
                "/page.html",
                &headers(&[("accept-language", "fr-CA,ja"), ("x-country-code", "US")]),
            );
            assert_eq!(
                paths,
                [
                    "/locales/fr_US/page.html",
                    "/locales/ja_US/page.html",
                    "/locales/ALL_US/page.html",
                    "/locales/fr_ALL/page.html",
                    "/locales/fr/page.html",
                    "/locales/ja_ALL/page.html",
                    "/locales/ja/page.html",
                    "/page.html",
                ],
                "root {root:?}"
            );
        }
    }

    #[test]
    fn no_i18n_root_means_only_the_plain_path() {
        let plain = Site {
            data: json!({}),
            ..site("")
        };
        assert_eq!(
            plain.candidates("/page.html", &headers(&[("accept-language", "fr")])),
            ["/page.html"]
        );
        assert_eq!(
            site("").candidates("/page.html", &headers(&[("accept-language", "fr")])),
            ["/page.html"],
            "an empty root is no root, as in superstatic"
        );
    }

    #[test]
    fn a_run_of_slashes_collapses_to_one() {
        for (input, expected) in [
            ("", ""),
            ("/", "/"),
            ("//", "/"),
            ("a//b///c", "a/b/c"),
            ("///a/", "/a/"),
            ("/a//", "/a/"),
            ("a/b", "a/b"),
            ("\u{e9}//\u{e9}", "\u{e9}/\u{e9}"),
        ] {
            assert_eq!(collapse_slashes(input), expected, "{input:?}");
        }
    }

    proptest! {
        #[test]
        fn collapsing_matches_a_split_and_join_model(input in "[a-c/]{0,16}") {
            let mut model = String::new();
            let mut previous_slash = false;
            for part in input.split_inclusive('/') {
                for ch in part.chars() {
                    if ch == '/' && previous_slash { continue; }
                    previous_slash = ch == '/';
                    model.push(ch);
                }
            }
            prop_assert_eq!(collapse_slashes(&input), model);
            prop_assert!(!collapse_slashes(&input).contains("//"));
            prop_assert_eq!(collapse_slashes(&collapse_slashes(&input)), collapse_slashes(&input));
        }

        // Slashes around the parts never change the candidate.
        #[test]
        fn extra_slashes_around_the_root_and_path_change_nothing(
            root in "[a-z]{1,5}(/[a-z]{1,5}){0,2}",
            lead in "/{0,3}",
            trail in "/{0,3}",
            gap in "/{1,3}",
            file in "[a-z]{1,5}\\.html",
        ) {
            let canonical = i18n_path(&root, "fr_ALL", &format!("/{file}"));
            prop_assert_eq!(&canonical, &format!("/{root}/fr_ALL/{file}"));
            let spelled = i18n_path(&format!("{lead}{root}{trail}"), "fr_ALL", &format!("{gap}{file}"));
            prop_assert_eq!(spelled, canonical);
        }
    }
}
