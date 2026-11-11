//! Integration tests for the diagnostics bundle: JSON round trip, HTML escaping, redaction and limits.
use fireemu_adapter_support::diagnostics::*;
use proptest::prelude::*;
use serde_json::json;

fn input(text: String) -> BundleInput {
    BundleInput {
        generated_at: text.clone(),
        versions: Versions {
            fireemu: text.clone(),
            runtimes: vec![],
            sdks: vec![],
        },
        config: vec![(text.clone(), ConfigValue::Str(text.clone()))],
        functions: FunctionsSection {
            events: vec![json!(text.clone())],
            attempts: vec![],
            retries: vec![],
            log_gaps: false,
        },
        rules: RulesSection {
            history_enabled: true,
            retention: 1,
            history_started_at: None,
            denials: vec![],
            dropped: 0,
        },
        indexes: vec![],
        pending: PendingSection {
            tasks: vec![],
            resources: vec![],
        },
        logs: LogSection {
            lines: vec![text],
            dropped_ranges: vec![],
        },
    }
}

proptest! {
    #[test]
    fn round_trip_and_html(text in ".{0,100}") {
        let b = Bundle::from_input(input(text), Limits::default());
        prop_assert_eq!(from_json(&to_json(&b)).unwrap(), b.clone());
        prop_assert!(!to_html(&b).contains("<script"));
    }
    #[test]
    fn truncation_counts(n in 0usize..30, limit in 0usize..30) {
        let mut i = input(String::new());
        i.functions.events = vec![json!(null); n];
        i.logs.lines = vec![String::new(); n];
        i.rules.denials = vec![RuleDenial { service: String::new(), location: String::new(), method: String::new(), path: String::new(), uid: None, reason: String::new(), conditions: vec![] }; n];
        let b = Bundle::from_input(i, Limits { max_events: limit, max_log_lines: limit, max_denials: limit });
        prop_assert!(b.functions.events.len() <= limit);
        prop_assert!(b.logs.lines.len() <= limit);
        prop_assert!(b.rules.denials.len() <= limit);
        for t in &b.truncations { prop_assert_eq!(t.kept as u64 + t.dropped, n as u64); }
    }
    #[test]
    fn html_payload_is_escaped(prefix in "[a-z]{0,20}") {
        let payload = format!("{prefix}<script>&\"'");
        let b = Bundle::from_input(input(payload.clone()), Limits::default());
        let html = to_html(&b);
        prop_assert!(!html.contains(&payload));
        prop_assert!(html.contains(&format!("{prefix}&lt;script&gt;&amp;&quot;&#39;")), "escaped payload missing");
    }
    #[test]
    fn planted_pattern_is_scrubbed(suffix in "[a-zA-Z0-9]{10,40}") {
        let secret = format!("{}{}", "ya29.", suffix);
        let (once, _) = redact::scrub(&secret);
        let (twice, _) = redact::scrub(&once);
        prop_assert!(!once.contains(&secret));
        prop_assert_eq!(once, twice);
    }
    #[test]
    fn scrub_idempotent(text in ".{0,100}") {
        let (once, _) = redact::scrub(&text);
        let (twice, _) = redact::scrub(&once);
        prop_assert_eq!(once, twice);
    }
}

#[test]
fn secrets_and_home_are_removed() {
    let secrets = vec![
        format!("{}{}", "Authorization: ", "Bearer abcdefghijk"),
        format!("{}{}", "ya29.", "abcdef"),
        format!("{}{}", "AIza", "a".repeat(35)),
        format!("{}{}", "-----BEGIN ", "PRIVATE KEY-----"),
        format!("{}{}", "eyJabcdefgh", ".abcdefghij.abcdefghij"),
    ];
    let mut i = input(secrets.join(" "));
    i.versions.runtimes.push(Component {
        name: "runtime".into(),
        version: "1".into(),
        path: Some(["/Users/", "HOMEDIR/project/src/lib.rs"].concat()),
    });
    i.rules.denials.push(RuleDenial {
        service: "s".into(),
        location: "l".into(),
        method: "m".into(),
        path: "p".into(),
        uid: None,
        reason: String::new(),
        conditions: vec![RuleCondition {
            line: 1,
            column: 1,
            excerpt: Some(secrets.join(" ")),
            outcome: "deny".into(),
        }],
    });
    let b = Bundle::from_input(i, Limits::default());
    let json = to_json(&b);
    let html = to_html(&b);
    for s in secrets {
        assert!(!json.contains(&s));
        assert!(!html.contains(&s));
    }
    assert!(b.redactions >= 6);
    assert!(json.contains("~/project/src/lib.rs"));
}

#[test]
fn near_misses_and_schema() {
    let text = ["authority", "Bearer", "AIzaabcdefghij"].join(".");
    assert_eq!(redact::scrub(&text).0, text);
    let b = Bundle::from_input(input(String::new()), Limits::default());
    let mut v = to_value(&b);
    assert_eq!(v["schemaVersion"], 1);
    v["schemaVersion"] = json!(42);
    assert!(from_json(&v.to_string()).unwrap_err().contains("42"));
}

#[test]
fn html_escapes_user_text() {
    let b = Bundle::from_input(input("a<b>&\"'".into()), Limits::default());
    let html = to_html(&b);
    assert!(html.contains("a&lt;b&gt;&amp;&quot;&#39;"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
    assert!(html.contains("Omitted or redacted"));
}
