//! Root-only framing for the selected single Document success envelope.

use serde_json::Value;

/// Keep scalar escaping and every nested value with `serde_json`, while ordering the root.
pub(crate) fn to_vec(body: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let document = body.as_object().expect("selected Document is an object");
    let mut bytes = b"{\n".to_vec();
    let mut first = true;
    for key in ["name", "fields", "createTime", "updateTime"] {
        let Some(value) = document.get(key) else {
            continue;
        };
        if !first {
            bytes.extend_from_slice(b",\n");
        }
        first = false;
        bytes.extend_from_slice(b"  ");
        bytes.extend_from_slice(&serde_json::to_vec(key)?);
        bytes.extend_from_slice(b": ");
        let encoded = serde_json::to_vec_pretty(value)?;
        for (index, line) in encoded.split(|byte| *byte == b'\n').enumerate() {
            if index > 0 {
                bytes.extend_from_slice(b"\n  ");
            }
            bytes.extend_from_slice(line);
        }
    }
    bytes.extend_from_slice(b"\n}\n");
    Ok(bytes)
}
