//! The dotenv dialect the official CLI reads for a Functions codebase, and the file order it
//! reads it in.
//!
//! Everything here follows `firebase-tools@15.28.2` `lib/functions/env.js`, which is the only
//! definition of the format that matters: the emulator, `firebase deploy` and the parameter
//! machinery all go through it, so a value fireemu resolves differently is a value a project
//! sees change when it switches emulators.
//!
//! What that file does, and what this module reproduces:
//!
//! - **Order.** `.env`, then `.env.<projectId>`, then `.env.<projectAlias>` when an alias is
//!   in play, then `.env.local` -- the last only under the emulator (`findEnvfiles`,
//!   `FUNCTIONS_EMULATOR_DOTENV`). A later file overrides an earlier one, key by key.
//! - **One project file.** Having both `.env.<projectId>` and `.env.<alias>` is refused
//!   (`loadUserEnvs`), because which of the two wins would otherwise be alphabetical accident.
//! - **Strict parsing.** A line that is neither blank, a comment nor an assignment fails the
//!   whole file, and so does a key that is reserved, misspelled or under a reserved prefix
//!   (`parseStrict`, `validateKey`).
//! - **Quoting.** A single-quoted value is literal; a double-quoted value expands `\n`, `\r`,
//!   `\t`, `\v`, `\\`, `\'` and `\"`; an unquoted value ends at the first `#`.
//!
//! One deliberate difference, in fireemu's favour and recorded because it is a difference:
//! the official `parse` normalises only the *first* CRLF in a file (`data.replace(/\r\n?/,
//! "\n")` carries no `g` flag). This module normalises all of them. Every value the official
//! parser produces from a CRLF file is the same, because `\r` is whitespace to its line
//! regular expression and terminates its unquoted-value class; the difference is only that a
//! file this module accepts cannot depend on that.

use std::collections::BTreeMap;

/// The emulator-only dotenv file, applied last (`FUNCTIONS_EMULATOR_DOTENV`).
pub const EMULATOR_DOTENV: &str = ".env.local";

/// The local override file for `defineSecret` parameters (`LOCAL_SECRETS_FILE`,
/// `functionsEmulatorShared.js:301`).
pub const LOCAL_SECRETS_FILE: &str = ".secret.local";

/// The legacy `functions.config()` file, passed to the runtime as `CLOUD_RUNTIME_CONFIG`.
pub const RUNTIME_CONFIG_FILE: &str = ".runtimeconfig.json";

/// Key prefixes a user environment may not use (`RESERVED_PREFIXES`).
pub const RESERVED_PREFIXES: [&str; 4] = ["X_GOOGLE_", "FIREBASE_", "EXT_", "KIT_"];

/// Prefixes carved back out of [`RESERVED_PREFIXES`] (`RESERVED_PREFIX_ALLOWLIST`). A key
/// equal to one of these, with nothing after it, is still refused.
pub const RESERVED_PREFIX_ALLOWLIST: [&str; 3] = [
    "FIREBASE_SECRET_REF_",
    "EXT_MIGRATED_SYSTEM_",
    "EXT_SELECTED_EVENTS",
];

/// Keys the runtime owns (`RESERVED_KEYS`). A dotenv file that sets one is refused rather
/// than silently losing to the value the emulator sets.
pub const RESERVED_KEYS: [&str; 19] = [
    "FIREBASE_CONFIG",
    "CLOUD_RUNTIME_CONFIG",
    "EVENTARC_CLOUD_EVENT_SOURCE",
    "ENTRY_POINT",
    "GCP_PROJECT",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT",
    "FUNCTION_TRIGGER_TYPE",
    "FUNCTION_NAME",
    "FUNCTION_MEMORY_MB",
    "FUNCTION_TIMEOUT_SEC",
    "FUNCTION_IDENTITY",
    "FUNCTION_REGION",
    "FUNCTION_TARGET",
    "FUNCTION_SIGNATURE_TYPE",
    "K_SERVICE",
    "K_REVISION",
    "PORT",
    "K_CONFIGURATION",
];

/// Why a key may not be set from a dotenv file. The text is the official message
/// (`KeyValidationError`), so a project moving between the two CLIs reads the same sentence.
pub fn validate_key(key: &str) -> Result<(), String> {
    if RESERVED_KEYS.contains(&key) {
        return Err(format!("Key {key} is reserved for internal use."));
    }
    let shaped = {
        let mut chars = key.chars();
        match chars.next() {
            Some(c) if c.is_ascii_uppercase() || c == '_' => {
                chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            }
            _ => false,
        }
    };
    if !shaped {
        return Err(format!(
            "Key {key} must start with an uppercase ASCII letter or underscore, and then \
             consist of uppercase ASCII letters, digits, and underscores."
        ));
    }
    if RESERVED_PREFIXES.iter().any(|p| key.starts_with(p))
        && !RESERVED_PREFIX_ALLOWLIST
            .iter()
            .any(|known| key.starts_with(known))
    {
        return Err(format!(
            "Key {key} starts with a reserved prefix ({})",
            RESERVED_PREFIXES.join(" ")
        ));
    }
    if RESERVED_PREFIX_ALLOWLIST.contains(&key) {
        return Err(format!("Key {key} is a known prefix with an empty suffix"));
    }
    Ok(())
}

/// One parsed dotenv file: its assignments in file order, and the lines that were neither
/// blank, a comment nor an assignment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Assignments, last one per key winning, as the official parser's object does.
    pub envs: BTreeMap<String, String>,
    /// Lines the format does not describe. `parse_strict` refuses a file that has any.
    pub errors: Vec<String>,
}

/// Whether a byte may appear in a dotenv key (`[\w./]` in the official line pattern).
fn is_key_byte(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/'
}

/// Parses one dotenv file, collecting the lines it could not read rather than failing on the
/// first (`parse`).
#[must_use]
pub fn parse(data: &str) -> Parsed {
    let data = data.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = Parsed::default();
    let mut rest: &str = &data;
    while !rest.is_empty() {
        let (line, tail) = match rest.find('\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        rest = tail;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let assignment = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .trim_start();
        let Some(eq) = assignment.find('=') else {
            out.errors.push(trimmed.to_owned());
            continue;
        };
        let key = assignment[..eq].trim();
        if key.is_empty() || !key.chars().all(is_key_byte) {
            out.errors.push(trimmed.to_owned());
            continue;
        }
        // A quoted value may run past the end of its line; the official pattern's `s` flag
        // lets its quoted alternatives cross newlines.
        let after = assignment[eq + 1..].trim_start_matches([' ', '\t', '\u{b}', '\u{c}']);
        let (value, remainder) = read_value(after, rest);
        rest = remainder;
        out.envs.insert(key.to_owned(), value);
    }
    out
}

/// Reads one value starting at `head` (the rest of its own line), continuing into `tail` (the
/// rest of the file) when it opens a quote that its line does not close.
fn read_value<'a>(head: &str, tail: &'a str) -> (String, &'a str) {
    let quote = head.chars().next().filter(|c| *c == '\'' || *c == '"');
    let Some(quote) = quote else {
        // Unquoted: everything up to the first `#`, trimmed.
        let end = head.find('#').unwrap_or(head.len());
        return (head[..end].trim().to_owned(), tail);
    };
    let body = &head[quote.len_utf8()..];
    if let Some(end) = find_close(body, quote) {
        return (unescape(&body[..end], quote), tail);
    }
    // Unterminated on this line: keep taking lines until the quote closes. A value that never
    // closes swallows the rest of the file, exactly as the official pattern's greedy quoted
    // alternative does.
    let mut value = String::from(body);
    let mut rest = tail;
    loop {
        if rest.is_empty() {
            return (unescape(&value, quote), rest);
        }
        let (line, next) = match rest.find('\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        rest = next;
        value.push('\n');
        if let Some(end) = find_close(line, quote) {
            value.push_str(&line[..end]);
            return (unescape(&value, quote), rest);
        }
        value.push_str(line);
    }
}

/// The offset of the closing `quote` in `body`, skipping a backslash-escaped one.
fn find_close(body: &str, quote: char) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote as u8 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Expands the escape sequences a double-quoted value carries
/// (`ESCAPE_SEQUENCES_TO_CHARACTERS`). A single-quoted value is literal.
fn unescape(value: &str, quote: char) -> String {
    if quote == '\'' {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('v') => out.push('\u{b}'),
            Some(c @ ('\\' | '\'' | '"')) => out.push(c),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Parses one dotenv file and refuses it whole when a line or a key is wrong (`parseStrict`).
///
/// The two messages are the official ones, so a file the Firebase CLI rejects is rejected
/// here with the same sentence.
pub fn parse_strict(data: &str) -> Result<BTreeMap<String, String>, String> {
    let parsed = parse(data);
    if !parsed.errors.is_empty() {
        return Err(format!(
            "Invalid dotenv file, error on lines: {}",
            parsed.errors.join(",")
        ));
    }
    let mut invalid = Vec::new();
    for key in parsed.envs.keys() {
        if let Err(why) = validate_key(key) {
            invalid.push(format!("Failed to validate key {key}: {why}"));
        }
    }
    if invalid.is_empty() {
        Ok(parsed.envs)
    } else {
        Err(format!("Validation failed: {}", invalid.join("; ")))
    }
}

/// The dotenv file names a Functions codebase is read from, in the order they are applied
/// (`findEnvfiles`). `alias` is the `.firebaserc` alias `--project` resolved through, when it
/// differs from the project ID.
#[must_use]
pub fn env_file_order(project_id: &str, alias: Option<&str>) -> Vec<String> {
    let mut files = vec![".env".to_owned(), format!(".env.{project_id}")];
    if let Some(alias) = alias {
        files.push(format!(".env.{alias}"));
    }
    files.push(EMULATOR_DOTENV.to_owned());
    files
}

/// The refusal for a codebase that carries both a project-ID and a project-alias dotenv file
/// (`loadUserEnvs`). The official sentence spells the first one `env.<projectId>`, without the
/// leading dot; it is quoted rather than corrected so the two CLIs say the same thing.
#[must_use]
pub fn both_project_files_error(project_id: &str, alias: &str) -> String {
    format!(
        "Can't have both dotenv files with projectId (env.{project_id}) and projectAlias \
         (.env.{alias}) as extensions."
    )
}

#[cfg(test)]
mod tests {
    use super::{
        both_project_files_error, env_file_order, parse, parse_strict, validate_key, Parsed,
    };

    fn envs(data: &str) -> Vec<(String, String)> {
        parse(data).envs.into_iter().collect()
    }

    #[test]
    fn the_quoting_rules_follow_the_official_parser() {
        assert_eq!(
            envs("A=1\nexport B = two \nC=# not a comment marker only\n"),
            vec![
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "two".to_owned()),
                ("C".to_owned(), String::new()),
            ]
        );
        // Single quotes are literal; double quotes expand the seven escapes.
        assert_eq!(
            envs(r"S='a\nb'").first().map(|(_, v)| v.clone()),
            Some(r"a\nb".to_owned())
        );
        assert_eq!(
            envs(r#"D="a\nb\tc\\d\"e""#).first().map(|(_, v)| v.clone()),
            Some("a\nb\tc\\d\"e".to_owned())
        );
        // An unquoted value ends at the first `#`, wherever it is.
        assert_eq!(
            envs("U=value # trailing").first().map(|(_, v)| v.clone()),
            Some("value".to_owned())
        );
        // A quoted value may cross lines.
        assert_eq!(
            envs("K=\"line one\nline two\"\nAFTER=1"),
            vec![
                ("AFTER".to_owned(), "1".to_owned()),
                ("K".to_owned(), "line one\nline two".to_owned()),
            ]
        );
    }

    #[test]
    fn a_line_that_is_not_an_assignment_is_an_error_line_not_a_silent_skip() {
        let parsed = parse("# comment\n\nGOOD=1\nnot an assignment\nBAD KEY=2\n");
        assert_eq!(
            parsed,
            Parsed {
                envs: [("GOOD".to_owned(), "1".to_owned())].into_iter().collect(),
                errors: vec!["not an assignment".to_owned(), "BAD KEY=2".to_owned()],
            }
        );
        let e = parse_strict("GOOD=1\nnot an assignment\n").expect_err("strict refuses it");
        assert_eq!(e, "Invalid dotenv file, error on lines: not an assignment");
    }

    #[test]
    fn reserved_keys_prefixes_and_shapes_are_refused_with_the_official_sentences() {
        assert_eq!(
            validate_key("FUNCTION_TARGET"),
            Err("Key FUNCTION_TARGET is reserved for internal use.".to_owned())
        );
        assert!(validate_key("lower")
            .unwrap_err()
            .contains("must start with"));
        assert!(validate_key("9START")
            .unwrap_err()
            .contains("must start with"));
        assert_eq!(
            validate_key("FIREBASE_THING"),
            Err(
                "Key FIREBASE_THING starts with a reserved prefix (X_GOOGLE_ FIREBASE_ EXT_ KIT_)"
                    .to_owned()
            )
        );
        // The allowlist carves a prefix back out, but the bare prefix is still refused.
        assert!(validate_key("FIREBASE_SECRET_REF_A").is_ok());
        assert_eq!(
            validate_key("EXT_SELECTED_EVENTS"),
            Err("Key EXT_SELECTED_EVENTS is a known prefix with an empty suffix".to_owned())
        );
        assert!(validate_key("MY_KEY").is_ok());
        assert!(validate_key("_LEADING").is_ok());
        let e = parse_strict("lower=1\n").expect_err("an invalid key refuses the file");
        assert!(
            e.starts_with("Validation failed: Failed to validate key lower:"),
            "{e}"
        );
    }

    #[test]
    fn the_file_order_is_the_official_one() {
        assert_eq!(
            env_file_order("demo-app", None),
            vec![".env", ".env.demo-app", ".env.local"]
        );
        assert_eq!(
            env_file_order("demo-app", Some("staging")),
            vec![".env", ".env.demo-app", ".env.staging", ".env.local"]
        );
        assert!(both_project_files_error("demo-app", "staging")
            .contains("projectId (env.demo-app) and projectAlias (.env.staging)"));
    }
}
