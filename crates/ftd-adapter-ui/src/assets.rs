//! The embedded single-page app: static files with content types and cache policy, the
//! runtime configuration injected into `index.html`, and the SPA fallback.

use include_dir::{include_dir, Dir};
use serde_json::Value;

/// The built app (or the placeholder page, see `build.rs`).
static UI_DIR: Dir<'_> = include_dir!("$OUT_DIR/ui");

/// Whether the binary carries the real app rather than the placeholder page.
#[must_use]
pub fn bundled() -> bool {
    UI_DIR
        .get_file("ftd-ui.json")
        .and_then(|f| f.contents_utf8())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("bundled").and_then(Value::as_bool))
        .unwrap_or(false)
}

/// One static file ready to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// `Content-Type`.
    pub content_type: &'static str,
    /// `Cache-Control`.
    pub cache_control: &'static str,
    /// Bytes.
    pub body: Vec<u8>,
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" | "webmanifest" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Serialises `config` for a `<script>` block: `<` is escaped so no value can close the
/// script element, whatever it contains.
fn script_json(config: &Value) -> String {
    config.to_string().replace('<', "\\u003c")
}

/// `index.html` with `window.__FTD__` (the runtime configuration the app needs before its
/// first request) injected at the end of `<head>` as a script carrying `nonce` (the page's
/// Content Security Policy allows only it and the bundle).
#[must_use]
pub fn index_html(config: &Value, nonce: &str) -> Vec<u8> {
    let template = UI_DIR
        .get_file("index.html")
        .and_then(|f| f.contents_utf8())
        .unwrap_or("<!doctype html><html><head></head><body></body></html>");
    let script = format!(
        "<script nonce=\"{nonce}\">window.__FTD__ = {};</script>",
        script_json(config)
    );
    let injected = match template.find("</head>") {
        Some(at) => format!("{}{script}{}", &template[..at], &template[at..]),
        None => format!("{script}{template}"),
    };
    injected.into_bytes()
}

/// Resolves a request path under `/ui` (already stripped of the prefix; `""` or `"/"` is the
/// app root). Unknown paths that look like app routes (no file extension) fall back to
/// `index.html` so a deep link loads the app; unknown files are `None`.
#[must_use]
pub fn resolve(path: &str, config: &Value, nonce: &str) -> Option<Asset> {
    let rel = path.trim_start_matches('/');
    if rel.is_empty() || rel == "index.html" {
        return Some(Asset {
            content_type: content_type("index.html"),
            cache_control: "no-cache",
            body: index_html(config, nonce),
        });
    }
    if rel == "ftd-ui.json" || rel.contains("..") {
        return None;
    }
    if let Some(file) = UI_DIR.get_file(rel) {
        let immutable = rel.starts_with("assets/");
        return Some(Asset {
            content_type: content_type(rel),
            cache_control: if immutable {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            },
            body: file.contents().to_vec(),
        });
    }
    let last = rel.rsplit('/').next().unwrap_or(rel);
    if last.contains('.') {
        return None;
    }
    Some(Asset {
        content_type: content_type("index.html"),
        cache_control: "no-cache",
        body: index_html(config, nonce),
    })
}
