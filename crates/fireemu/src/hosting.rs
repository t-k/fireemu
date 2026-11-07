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
    root: Arc<cap_std::fs::Dir>,
    project: String,
    upstream: Option<std::net::SocketAddr>,
    emulators: Value,
}
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
        files::find(self.root.clone(), self.candidates(path, headers)).await
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
        for rule in self.rules("redirects") {
            let destination = redirect_destination(rule, &decoded);
            if let Some(mut destination) = destination {
                if !query.is_empty() {
                    destination.push(if destination.contains('?') { '&' } else { '?' });
                    destination.push_str(&query[1..]);
                }
                let status = rule
                    .get("type")
                    .and_then(Value::as_u64)
                    .and_then(|v| u16::try_from(v).ok())
                    .unwrap_or(301);
                return Self::redirect(&destination, status, head);
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
                    serde_json::json!({"projectId":self.project}).to_string()
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
            let script=format!("if(typeof firebase==='undefined')throw new Error('Firebase SDK not detected');var config={};firebase.initializeApp(config);var endpoints={};if(endpoints)Object.keys(endpoints).forEach(function(name){{if(typeof firebase[name]==='function'){{var endpoint=endpoints[name];if(name==='auth')firebase[name]().useEmulator('http://'+endpoint.hostAndPort);else firebase[name]().useEmulator(endpoint.host,endpoint.port);}}}});",serde_json::json!({"projectId":self.project}),emulators);
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
                if let Some((file, asset)) =
                    files::find(self.root.clone(), vec![destination.to_owned()]).await
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

fn redirect_destination(rule: &Value, path: &str) -> Option<String> {
    let destination = rule.get("destination")?.as_str()?;
    if let Some(source) = rule.get("source").and_then(Value::as_str) {
        if source.contains(':') && destination.contains(':') {
            let source: Vec<_> = source.split('/').collect();
            let path: Vec<_> = path.split('/').collect();
            if source.len() != path.len() {
                return None;
            }
            let mut result = destination.to_owned();
            for (pattern, part) in source.iter().zip(path) {
                if let Some(name) = pattern.strip_prefix(':') {
                    result = result.replace(&format!(":{name}"), part);
                } else if *pattern != part {
                    return None;
                }
            }
            return Some(result);
        }
    }
    matcher::matches(rule, path).then(|| destination.to_owned())
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
    let root = cap_std::fs::Dir::open_ambient_dir(&config.public, cap_std::ambient_authority())
        .map_err(|e| format!("hosting.public: {e}"))?;
    Ok(PreparedSite(Arc::new(Site {
        data: config.data,
        root: Arc::new(root),
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
