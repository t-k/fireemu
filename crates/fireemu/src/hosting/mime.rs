//! The Content-Type of a served file, as the pinned Hosting oracle chooses it: superstatic sends
//! `mime.contentType(path.extname(file))` of mime-types (see `content_types.rs` for the exact
//! versions) and the compression middleware then adds `Vary: Accept-Encoding` for a compressible type.

use super::content_types::CONTENT_TYPES;

/// Node's `path.posix.extname`: the last dot of the final path segment through its end, or empty
/// when the segment has no dot after its first character (a dotfile has no extension).
pub(super) fn extname(file: &str) -> &str {
    // A port of the loop in Node's lib/path.js, over bytes: `.` and `/` are ASCII, so a byte index
    // is always a character boundary.
    let bytes = file.as_bytes();
    let (mut start_dot, mut start_part, mut end) = (None, 0, None);
    let mut matched_slash = true;
    // 0: no dot yet or only dots so far, 1: dots only (a candidate for "..") and -1: a non-dot seen.
    let mut pre_dot_state = 0_i8;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b'/' => {
                if !matched_slash {
                    start_part = i + 1;
                    break;
                }
            }
            code => {
                if end.is_none() {
                    matched_slash = false;
                    end = Some(i + 1);
                }
                if code == b'.' {
                    if start_dot.is_none() {
                        start_dot = Some(i);
                    } else if pre_dot_state != 1 {
                        pre_dot_state = 1;
                    }
                } else if start_dot.is_some() {
                    pre_dot_state = -1;
                }
            }
        }
    }
    match (start_dot, end) {
        (Some(dot), Some(end))
            if pre_dot_state != 0
                && !(pre_dot_state == 1 && dot + 1 == end && dot == start_part + 1) =>
        {
            &file[dot..end]
        }
        _ => "",
    }
}

/// The content type and whether it is compressible for `file`, or `None` when mime-types has no type
/// for its extension (the lookup lower-cases the extension).
pub(super) fn content_type(file: &str) -> Option<(&'static str, bool)> {
    let extension = extname(file).strip_prefix('.')?.to_lowercase();
    CONTENT_TYPES
        .binary_search_by(|(known, _, _)| (*known).cmp(extension.as_str()))
        .ok()
        .map(|index| (CONTENT_TYPES[index].1, CONTENT_TYPES[index].2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    // Rows produced by generate-content-types.mjs from the Node lookup itself.
    fn samples() -> Vec<Value> {
        let all: Value =
            serde_json::from_str(include_str!("content-type-samples.json")).expect("samples");
        all["samples"].as_array().expect("samples array").clone()
    }

    #[test]
    fn extname_and_content_type_replay_the_node_lookup() {
        let rows = samples();
        assert!(rows.len() > 300, "a sample of the whole table, not a handful");
        for row in rows {
            let file = row["file"].as_str().unwrap();
            assert_eq!(extname(file), row["extname"].as_str().unwrap(), "extname of {file:?}");
            let expected = row["contentType"]
                .as_str()
                .map(|value| (value, row["compressible"].as_bool().unwrap()));
            assert_eq!(content_type(file), expected, "content type of {file:?}");
        }
    }

    #[test]
    fn the_table_is_sorted_unique_lower_case_and_complete_enough() {
        assert!(CONTENT_TYPES.len() > 1000);
        for pair in CONTENT_TYPES.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
        }
        for (ext, _, _) in CONTENT_TYPES {
            assert!(!ext.is_empty() && *ext == ext.to_lowercase() && ext.is_ascii());
        }
    }

    #[test]
    fn the_common_web_types_have_the_oracle_charsets() {
        for (file, expected) in [
            ("a.html", "text/html; charset=utf-8"),
            ("a.js", "application/javascript; charset=utf-8"),
            ("a.mjs", "application/javascript; charset=utf-8"),
            ("a.json", "application/json; charset=utf-8"),
            ("a.css", "text/css; charset=utf-8"),
            ("a.txt", "text/plain; charset=utf-8"),
            ("a.svg", "image/svg+xml"),
            ("a.png", "image/png"),
            ("a.woff2", "font/woff2"),
            ("a.ico", "image/vnd.microsoft.icon"),
            ("a.wasm", "application/wasm"),
        ] {
            assert_eq!(content_type(file).map(|t| t.0), Some(expected), "{file}");
        }
        assert_eq!(content_type("a.svg").map(|t| t.1), Some(true));
        assert_eq!(content_type("a.png").map(|t| t.1), Some(false));
    }

    #[test]
    fn no_extension_and_unknown_extensions_have_no_type() {
        for file in ["a", ".hidden", "a.", "a.nosuchext", "dir.v1/file", "a. html", "a.html "] {
            assert_eq!(content_type(file), None, "{file:?}");
        }
    }

    // A second phrasing of Node's extname, to compare with the port on arbitrary names.
    fn extname_model(file: &str) -> String {
        let trimmed = file.trim_end_matches('/');
        let base = trimmed.rsplit('/').next().unwrap_or("");
        if base == ".." {
            return String::new();
        }
        let rest = base.strip_prefix('.').unwrap_or(base);
        rest.rfind('.').map_or(String::new(), |i| rest[i..].to_owned())
    }

    proptest! {
        #[test]
        fn extname_agrees_with_the_model(file in "[a-c./]{0,12}") {
            prop_assert_eq!(extname(&file), extname_model(&file));
        }

        // The lookup ignores the case of the extension, including a non-ASCII letter that lower-cases
        // into an ASCII one (the Kelvin sign).
        #[test]
        fn a_table_extension_resolves_in_any_case(index in 0..CONTENT_TYPES.len(), mask in any::<u64>()) {
            let (ext, kind, compressible) = CONTENT_TYPES[index];
            let mixed: String = ext
                .chars()
                .enumerate()
                .map(|(i, c)| if mask >> (i % 64) & 1 == 1 { c.to_ascii_uppercase() } else { c })
                .collect();
            prop_assert_eq!(content_type(&format!("dir/f.{mixed}")), Some((kind, compressible)));
        }

        #[test]
        fn the_directory_part_never_changes_the_result(dir in "[a-c.]{0,6}", name in "[a-c]{1,4}(\\.[a-c]{1,3}){0,2}") {
            prop_assert_eq!(content_type(&format!("{dir}/{name}")), content_type(&name));
        }
    }

    #[test]
    fn the_kelvin_sign_lower_cases_into_an_ascii_extension() {
        assert_eq!(content_type("a.\u{212A}ml"), content_type("a.kml"));
        assert!(content_type("a.kml").is_some());
    }
}
