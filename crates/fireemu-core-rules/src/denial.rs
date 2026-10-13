//! What a Security Rules denial is reported with while developing.
//!
//! The client is answered with production's denial (Firestore's `PERMISSION_DENIED` "Missing or
//! insufficient permissions.", Storage's 403), which does not say which rule refused. A [`RulesDenial`] carries what the
//! daemon found instead: the request, the reason and every `allow` condition the request
//! evaluated with what it took, so a log line or a page can name the failing rule at once. It
//! never carries a token or a claim other than the subject the rule saw as `request.auth.uid`.

use std::fmt::Write as _;
use std::sync::Arc;

use crate::coverage::{CoverageEntry, ExprValue};
use crate::eval::DenyReason;

/// Receives every denial of an end-user request.
pub type DenialLog = Arc<dyn Fn(&RulesDenial) + Send + Sync>;

/// The longest excerpt of a condition's source a summary prints.
const EXCERPT_MAX_CHARS: usize = 120;

/// One denied request.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesDenial {
    /// `firestore` or `storage`.
    pub service: &'static str,
    /// Where the request went, as a summary names it: `database (default)`, `bucket b`.
    pub location: String,
    /// `get`, `list`, `create`, `update` or `delete`.
    pub method: &'static str,
    /// The document, collection or object the request named, relative to its location.
    pub path: String,
    /// `request.auth.uid`, when the request carried a signed-in user.
    pub uid: Option<String>,
    /// Why it was denied, in fireemu's words.
    pub reason: String,
    /// Every `allow` condition the request evaluated, in source order.
    pub conditions: Vec<DeniedCondition>,
}

/// One `allow` condition a denied request evaluated.
#[derive(Debug, Clone, PartialEq)]
pub struct DeniedCondition {
    /// 1-based line of the condition.
    pub line: u32,
    /// 1-based column of the condition.
    pub column: u32,
    /// The condition's source, whitespace collapsed and shortened, when the source is known.
    pub excerpt: Option<String>,
    /// What it evaluated to, in words (`false`, `an error: ...`).
    pub outcome: String,
}

impl DeniedCondition {
    /// The condition `entry` of `source` (the loaded rules text, when known).
    #[must_use]
    pub fn from_entry(entry: &CoverageEntry, source: Option<&str>) -> Self {
        Self {
            line: entry.span.line,
            column: entry.span.column,
            excerpt: source
                .and_then(|source| source.get(entry.span.offset..entry.end))
                .map(excerpt),
            outcome: entry
                .values
                .iter()
                .map(|(value, _)| outcome(value))
                .collect::<Vec<_>>()
                .join(", then "),
        }
    }
}

/// `text` on one line: every run of whitespace (control characters included) becomes one
/// space, and a long condition ends in an ellipsis.
fn excerpt(text: &str) -> String {
    let collapsed = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.chars().count() <= EXCERPT_MAX_CHARS {
        return collapsed;
    }
    let mut short: String = collapsed.chars().take(EXCERPT_MAX_CHARS - 1).collect();
    short.push('…');
    short
}

fn outcome(value: &ExprValue) -> String {
    match value {
        ExprValue::Bool(b) => b.to_string(),
        // Only where: an error's message can carry an evaluated value (`missing key <claim>`).
        // The request trace (`GET /v1/sessions/default/rules/requests`, behind the control
        // token) keeps the message.
        ExprValue::Undefined(cause) => {
            format!("an error at {}:{}", cause.span.line, cause.span.column)
        }
        // Only the type: a condition such as `request.auth.token.secret` would otherwise print a
        // claim or document value into the log.
        ExprValue::Null => "null, not a boolean".to_owned(),
        ExprValue::Int(_) => "an int, not a boolean".to_owned(),
        ExprValue::Float(_) => "a float, not a boolean".to_owned(),
        ExprValue::String(_) => "a string, not a boolean".to_owned(),
        ExprValue::Composite(kind) => format!("a {kind}, not a boolean"),
    }
}

/// Why the evaluator denied a request, in fireemu's words.
#[must_use]
pub fn deny_reason_text(reason: &DenyReason) -> String {
    match reason {
        DenyReason::NoMatchingRule => "no match block covers this path".to_owned(),
        DenyReason::NoMatchingAllow => "no allow statement evaluated to true".to_owned(),
        DenyReason::Unsupported(m) => format!("unsupported rules feature: {m}"),
        DenyReason::BudgetExceeded {
            limit_id,
            current,
            maximum,
        } => format!("{limit_id}: {current} exceeds {maximum}"),
    }
}

/// [`deny_reason_text`] for a denial line: the same words, except that an unsupported feature
/// is named by its kind only, because its message can quote an evaluated value (a regular
/// expression built from a claim). The request trace keeps the full text.
#[must_use]
pub fn deny_reason_summary(reason: &DenyReason) -> String {
    match reason {
        DenyReason::Unsupported(_) => {
            "a rules feature the evaluator does not support (the request trace has the detail)"
                .to_owned()
        }
        other => deny_reason_text(other),
    }
}

impl RulesDenial {
    /// The denial on one line, for a log.
    #[must_use]
    pub fn summary(&self) -> String {
        let caller = self.uid.as_ref().map_or_else(
            || "no request.auth".to_owned(),
            |uid| format!("request.auth.uid {:?}", excerpt(uid)),
        );
        // The path and the location come from the client: quoted (`{:?}` escapes control and
        // format characters such as U+202E), they cannot pass for the line's own text.
        let mut line = format!(
            "{}: Security Rules denied {} on {:?} in {:?} ({caller}): {}",
            self.service,
            self.method,
            excerpt(&self.path),
            excerpt(&self.location),
            excerpt(&self.reason)
        );
        for condition in &self.conditions {
            // Writing into a String cannot fail.
            let _ = write!(line, "; line {}:{}", condition.line, condition.column);
            if let Some(excerpt) = &condition.excerpt {
                let _ = write!(line, " `{excerpt}`");
            }
            let _ = write!(line, " was {}", condition.outcome);
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::{deny_reason_summary, excerpt, DeniedCondition, RulesDenial, EXCERPT_MAX_CHARS};
    use crate::eval::DenyReason;

    #[test]
    fn an_unsupported_reason_is_named_without_its_message() {
        let summary = deny_reason_summary(&DenyReason::Unsupported(
            "unknown POSIX class [:s3cr3t:]".to_owned(),
        ));
        assert!(!summary.contains("s3cr3t"), "{summary}");
        assert!(summary.contains("does not support"), "{summary}");
        assert_eq!(
            deny_reason_summary(&DenyReason::NoMatchingAllow),
            "no allow statement evaluated to true"
        );
    }
    use crate::ast::Span;
    use crate::coverage::{CoverageEntry, ExprValue, UndefinedCause};

    fn entry(source: &str, needle: &str, values: Vec<(ExprValue, u64)>) -> CoverageEntry {
        let offset = source.find(needle).unwrap();
        CoverageEntry {
            span: Span {
                line: 3,
                column: 21,
                offset,
            },
            end: offset + needle.len(),
            values,
        }
    }

    #[test]
    fn a_summary_names_the_request_the_reason_and_each_condition_with_its_value() {
        let source = "x\n\n      allow update: if request.auth.uid ==\n   resource.data.owner;\n";
        let failed = entry(
            source,
            "request.auth.uid ==\n   resource.data.owner",
            vec![(ExprValue::Bool(false), 1)],
        );
        let erred = entry(
            source,
            "resource.data.owner",
            vec![(
                ExprValue::Undefined(UndefinedCause {
                    span: Span {
                        line: 4,
                        column: 4,
                        offset: 0,
                    },
                    end: 1,
                    message: "missing key s3cr3t-claim".to_owned(),
                }),
                1,
            )],
        );
        let denial = RulesDenial {
            service: "firestore",
            location: "database (default)".to_owned(),
            method: "update",
            path: "notes/n1".to_owned(),
            uid: Some("bob".to_owned()),
            reason: "no allow statement evaluated to true".to_owned(),
            conditions: vec![
                DeniedCondition::from_entry(&failed, Some(source)),
                DeniedCondition::from_entry(&erred, None),
            ],
        };
        assert_eq!(
            denial.summary(),
            "firestore: Security Rules denied update on \"notes/n1\" in \"database (default)\" (request.auth.uid \"bob\"): no allow statement evaluated to true; line 3:21 `request.auth.uid == resource.data.owner` was false; line 3:21 was an error at 4:4"
        );
        assert!(!denial.summary().contains("s3cr3t"), "{}", denial.summary());
        let anonymous = RulesDenial {
            uid: None,
            conditions: Vec::new(),
            ..denial
        };
        assert!(anonymous.summary().contains("(no request.auth)"));
        // A client-chosen path cannot forge a condition or hide text behind a bidi override.
        let forged = RulesDenial {
            path: "x`; line 1:1 `true` was true\u{202e}".to_owned(),
            ..anonymous
        };
        let summary = forged.summary();
        assert!(
            summary.contains("on \"x`; line 1:1 `true` was true\\u{202e}\" in"),
            "{summary}"
        );
    }

    #[test]
    fn a_condition_that_took_several_values_lists_them_in_order() {
        let source = "allow list: if resource.data.n > 1;";
        let condition = DeniedCondition::from_entry(
            &entry(
                source,
                "resource.data.n > 1",
                vec![(ExprValue::Bool(true), 2), (ExprValue::Bool(false), 1)],
            ),
            Some(source),
        );
        assert_eq!(condition.outcome, "true, then false");
        // A non-boolean value is named by its type, never printed: it can be a token claim.
        for (value, expected) in [
            (ExprValue::Null, "null, not a boolean"),
            (ExprValue::Int(31_337), "an int, not a boolean"),
            (ExprValue::Float(2.5), "a float, not a boolean"),
            (
                ExprValue::String("s3cr3t-claim".to_owned()),
                "a string, not a boolean",
            ),
            (ExprValue::Composite("map"), "a map, not a boolean"),
        ] {
            let condition = DeniedCondition::from_entry(
                &entry(source, "resource", vec![(value, 1)]),
                Some(source),
            );
            assert_eq!(condition.outcome, expected);
        }
    }

    #[test]
    fn an_excerpt_is_one_line_and_bounded() {
        assert_eq!(excerpt("a\n\t b\u{0}c"), "a b c");
        let long = "x ".repeat(200);
        let short = excerpt(&long);
        assert_eq!(short.chars().count(), EXCERPT_MAX_CHARS);
        assert!(short.ends_with('…'));
        let exact = "y".repeat(EXCERPT_MAX_CHARS);
        assert_eq!(excerpt(&exact), exact);
    }
}
