//! The functions HTTP port: `http://HOST:PORT/{project}/{region}/{function}[/path]` is
//! proxied to the runner's HTTP server, which hosts `onRequest` / `onCall` handlers. The
//! proxy speaks plain HTTP/1.1 with `Connection: close` (one request per connection).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::fmt::Write as _;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::runtime::FunctionsRuntime;

/// Maximum request body forwarded to a function.
pub const MAX_FUNCTION_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Maximum response body accepted from a function (responses are buffered).
pub const MAX_FUNCTION_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

fn simple(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    typed(status, "text/plain; charset=utf-8", text)
}

/// A plain body with an explicit content type.
///
/// The two 404s the functions port answers carry different ones, because the official
/// emulator produces them two different ways: `res.sendStatus(404)` sends the status text as
/// `text/plain`, and `res.status(404).send("Function ... does not exist ...")` sends a string,
/// which express types as `text/html`.
fn typed(status: StatusCode, content_type: &str, text: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(text.to_owned())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// A forwarded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedResponse {
    /// Status.
    pub status: u16,
    /// Headers (hop-by-hop ones removed).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

/// Sends one HTTP/1.1 request to `addr` and reads the whole response.
pub async fn forward(
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<ProxiedResponse, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("cannot reach the functions runner at {addr}: {e}"))?;
    let mut req = format!("{method} {path_and_query} HTTP/1.1\r\n");
    let mut has_host = false;
    for (k, v) in headers {
        // This writer frames the request by hand. Everything it is handed today comes from
        // hyper, which already refuses a control character in a field name or value, but the
        // check belongs at the sink: a future caller that builds a field from anywhere else
        // would otherwise turn one header into request smuggling.
        if !is_framable_name(k) || !is_framable_value(v) {
            return Err(format!("refusing to forward the unframable header {k:?}"));
        }
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection" | "content-length" | "transfer-encoding" | "keep-alive" | "expect"
        ) {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        let _ = write!(req, "{k}: {v}\r\n");
    }
    if !has_host {
        let _ = write!(req, "host: {addr}\r\n");
    }
    let _ = write!(
        req,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream
        .take(MAX_FUNCTION_RESPONSE_BYTES + 1)
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("reading the runner's response: {e}"))?;
    if raw.len() as u64 > MAX_FUNCTION_RESPONSE_BYTES {
        return Err(format!(
            "function response exceeds {MAX_FUNCTION_RESPONSE_BYTES} bytes"
        ));
    }
    parse_response(&raw, method)
}

/// A field name that cannot break the framing: an RFC 9110 token.
fn is_framable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&\'*+-.^_`|~".contains(&b))
}

/// A field value that cannot break the framing: visible ASCII, spaces and tabs only.
fn is_framable_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7E).contains(&b))
}

/// Parses a complete HTTP/1.1 response (`Content-Length`, chunked or close-delimited body)
/// to a `method` request; only HEAD responses and body-less statuses may omit a declared
/// body.
pub fn parse_response(raw: &[u8], method: &str) -> Result<ProxiedResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed response from the functions runner".to_owned())?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            match k.to_ascii_lowercase().as_str() {
                "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
                "content-length" => content_length = v.parse().ok(),
                "connection" | "keep-alive" => {}
                _ => headers.push((k.to_owned(), v.to_owned())),
            }
        }
    }
    let rest = &raw[header_end + 4..];
    let bodyless = method.eq_ignore_ascii_case("HEAD")
        || matches!(status, 204 | 304)
        || (100..200).contains(&status);
    let body = if bodyless {
        Vec::new()
    } else if chunked {
        decode_chunked(rest)?
    } else if let Some(n) = content_length {
        rest.get(..n)
            .ok_or_else(|| "truncated response body".to_owned())?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(ProxiedResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked body".to_owned())?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "malformed chunk size".to_owned())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(
            rest.get(..size)
                .ok_or_else(|| "truncated chunk".to_owned())?,
        );
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

/// An answer produced instead of proxying: a 404, a denial, a refused origin.
type Refusal = Box<Response<Full<Bytes>>>;

/// The route a request resolved to: its region, its function name and the runner to reach.
type Route<'a> = (&'a str, &'a str, crate::runtime::HttpTarget);

/// Resolves `/{project}/{region}/{function}` against the manifest, or the 404 the official
/// emulator answers instead.
///
/// There are two of those and they are not the same: a path that is not a function route at
/// all falls through to `hub.all("*")` and gets express's `res.sendStatus(404)` -- the status
/// text as `text/plain` -- while a route whose function does not exist gets
/// `handleHttpsTrigger`'s sentence naming the key it looked for and every key it holds
/// (`functionsEmulator.js:145`, `:1244`).
fn resolve_route<'a>(runtime: &FunctionsRuntime, path: &'a str) -> Result<Route<'a>, Refusal> {
    let segments: Vec<&str> = path.trim_start_matches('/').splitn(4, '/').collect();
    let [project, region, function, ..] = segments.as_slice() else {
        return Err(Box::new(simple(StatusCode::NOT_FOUND, "Not Found")));
    };
    if project.is_empty()
        || region.is_empty()
        || function.is_empty()
        || *project != runtime.project()
    {
        return Err(Box::new(simple(StatusCode::NOT_FOUND, "Not Found")));
    }
    match runtime.http_target(project, region, function) {
        Some(target) => Ok((region, function, target)),
        None => Err(Box::new(typed(
            StatusCode::NOT_FOUND,
            "text/html; charset=utf-8",
            &format!(
                "Function {region}-{function} does not exist, valid functions are: {}",
                runtime.trigger_keys().join(", ")
            ),
        ))),
    }
}

/// Puts a callable's credentials through the trust boundary, or answers the denial.
///
/// An `onRequest` function keeps receiving the raw field list, because application code owns
/// custom-backend verification there (specification section 7.3); a callable only reaches the
/// runner once the daemon has verified and re-inserted both credentials.
fn sanitize_credentials(
    runtime: &FunctionsRuntime,
    function: &str,
    raw: &hyper::HeaderMap,
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, Refusal> {
    let (Some(trust), Some(enforce_app_check)) = (
        runtime.callable_trust(),
        runtime.callable_enforces_app_check(function),
    ) else {
        return Ok(headers);
    };
    // The credential fields are collected separately and lossily: a value that is not
    // renderable as text must still count as an instance, or a second copy could hide behind
    // one byte the general collection dropped (spec 7.3).
    let presented_app_check = field_values(raw, fireemu_core_app_check::header::APP_CHECK_HEADER);
    let presented_auth = field_values(raw, "authorization");
    match trust.sanitize(&crate::callable::CallableRequest {
        function,
        enforce_app_check,
        headers: &headers,
        app_check: &presented_app_check,
        authorization: &presented_auth,
        now: runtime.now(),
    }) {
        crate::callable::CallableDecision::Forward { headers, .. } => Ok(headers),
        crate::callable::CallableDecision::Unauthenticated { .. } => {
            let denial = crate::callable::unauthenticated_response();
            let mut builder = Response::builder().status(denial.status);
            for (k, v) in denial.headers {
                builder = builder.header(k, v);
            }
            Err(Box::new(
                builder
                    .body(Full::new(Bytes::from(denial.body)))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            ))
        }
    }
}

async fn respond(
    runtime: Arc<FunctionsRuntime>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    // Like the other ports: a page on another site must not drive this loopback runtime. The
    // official emulator does let it -- its runtime runs with `enableCors: true`, which wraps
    // every handler in `cors({origin: true})` and reflects any origin, so a page anywhere on
    // the internet can POST to a developer's callable and read the result. That is the one
    // documented divergence of this port, recorded in
    // `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`.
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(origin) = &origin {
        if !origin_is_local(origin) {
            return Ok(simple(StatusCode::FORBIDDEN, "forbidden origin"));
        }
    }
    let (_region, function, target) = match resolve_route(&runtime, &path) {
        Ok(resolved) => resolved,
        Err(answer) => return Ok(*answer),
    };
    let method = req.method().as_str().to_owned();
    // The CORS the official emulator's `enableCors` gives an `onRequest` function, for the
    // loopback origins this port serves. A callable answers its own preflight (v2 `onCall`
    // enables CORS itself, and the recorded oracle shows `POST` where an `onRequest` shows the
    // whole method list), so a callable's request is forwarded untouched.
    let plain_http = matches!(
        runtime.manifest().get(function).map(|f| &f.trigger),
        Some(fireemu_core_functions::manifest::Trigger::Http {
            callable: false,
            ..
        })
    );
    if plain_http && method == "OPTIONS" {
        if let Some(origin) = &origin {
            if req.headers().contains_key("access-control-request-method") {
                return Ok(preflight_answer(origin, req.headers()));
            }
        }
    }
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let headers = match sanitize_credentials(&runtime, function, req.headers(), headers) {
        Ok(headers) => headers,
        Err(denial) => return Ok(*denial),
    };
    let body = match Limited::new(req.into_body(), MAX_FUNCTION_BODY_BYTES)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(simple(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ))
        }
    };
    let path_and_query = match query {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let proxied = runtime
        .invoke_http(&target, &method, &path_and_query, &headers, &body)
        .await;
    match proxied {
        Ok(r) => {
            let mut builder = Response::builder().status(r.status);
            let answered_cors = r
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"));
            for (k, v) in r.headers {
                builder = builder.header(k, v);
            }
            // `cors({origin: true})` also marks the ordinary answer, not only the preflight.
            // A handler that sets its own header keeps it.
            if plain_http && !answered_cors {
                if let Some(origin) = &origin {
                    builder = builder
                        .header("access-control-allow-origin", origin.as_str())
                        .header("vary", "Origin");
                }
            }
            Ok(builder
                .body(Full::new(Bytes::from(r.body)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
        }
        // A `dropConnection` fault: the connection closes without a response.
        Err(e) if e == crate::runtime::DROP_CONNECTION => Err(std::io::Error::other(e)),
        Err(e) => Ok(simple(StatusCode::BAD_GATEWAY, &e)),
    }
}

/// Every instance of one field, in wire order, with an unrenderable value as an empty string.
///
/// The empty string is not a value anything accepts: it classifies as malformed for App Check
/// and fails ID token verification. What matters is that it still counts as an instance, so a
/// second copy cannot hide behind a byte that does not render.
fn field_values(headers: &hyper::HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().map_or_else(|_| String::new(), str::to_owned))
        .collect()
}

/// The preflight answer `cors({origin: true})` produces, which is what the official
/// emulator's `enableCors` debug feature puts in front of every handler.
///
/// Recorded from the oracle: `204`, the origin reflected, the full default method list, the
/// requested headers echoed, and `Vary: Origin, Access-Control-Request-Headers`. The handler
/// is not invoked.
fn preflight_answer(origin: &str, headers: &hyper::HeaderMap) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", origin)
        .header(
            "access-control-allow-methods",
            "GET,HEAD,PUT,PATCH,POST,DELETE",
        )
        .header("vary", "Origin, Access-Control-Request-Headers")
        .header("content-length", "0");
    if let Some(requested) = headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
    {
        builder = builder.header("access-control-allow-headers", requested);
    }
    builder
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// Whether a browser `Origin` is a loopback origin.
#[must_use]
pub fn origin_is_local(origin: &str) -> bool {
    // `null` (sandboxed or opaque contexts) is not a loopback origin.
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split(']').next())
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// Serves the functions port.
pub async fn serve_functions(
    listener: TcpListener,
    runtime: Arc<FunctionsRuntime>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| respond(runtime.clone(), req));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
