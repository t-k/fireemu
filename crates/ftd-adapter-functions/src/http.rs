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

fn simple(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
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
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("reading the runner's response: {e}"))?;
    parse_response(&raw)
}

/// Parses a complete HTTP/1.1 response (`Content-Length`, chunked or close-delimited body).
pub fn parse_response(raw: &[u8]) -> Result<ProxiedResponse, String> {
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
    let body = if chunked {
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

async fn respond(
    runtime: Arc<FunctionsRuntime>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    if req.method() == hyper::Method::OPTIONS {
        // Browser preflight for callable functions.
        let requested = req
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("authorization, content-type")
            .to_owned();
        return Ok(Response::builder()
            .status(204)
            .header("access-control-allow-origin", "*")
            .header(
                "access-control-allow-methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )
            .header("access-control-allow-headers", requested)
            .header("access-control-max-age", "3600")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    let segments: Vec<&str> = path.trim_start_matches('/').splitn(4, '/').collect();
    let (project, region, function) = match segments.as_slice() {
        [p, r, f, ..] if !p.is_empty() && !r.is_empty() && !f.is_empty() => (*p, *r, *f),
        _ => {
            return Ok(simple(
                StatusCode::NOT_FOUND,
                "functions are served at /{project}/{region}/{function}",
            ))
        }
    };
    let Some(target) = runtime.http_target(project, region, function) else {
        return Ok(simple(
            StatusCode::NOT_FOUND,
            &format!("no HTTP function {function} in {project}/{region}"),
        ));
    };
    let method = req.method().as_str().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
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
            for (k, v) in r.headers {
                builder = builder.header(k, v);
            }
            Ok(builder
                .body(Full::new(Bytes::from(r.body)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
        }
        Err(e) => Ok(simple(StatusCode::BAD_GATEWAY, &e)),
    }
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
