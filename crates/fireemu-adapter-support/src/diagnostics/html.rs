use super::Bundle;

/// Renders a standalone HTML document with escaped bundle data.
pub fn to_html(bundle: &Bundle) -> String {
    let text = super::to_json(bundle)
        .replace("\\\"", "\"")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>Diagnostics bundle</title></head><body><h1>Diagnostics bundle</h1><h2>Omitted or redacted</h2><p>Redactions: {}</p><pre>{text}</pre></body></html>", bundle.redactions)
}
