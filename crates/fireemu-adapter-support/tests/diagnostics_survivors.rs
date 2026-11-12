//! Cases that pin the behaviour the mutation pass found untested: the exact limit, the count of
//! redactions, every configuration value kind through `from_value`, and the `_`, `-` and offset
//! rules of the credential scan.

use fireemu_adapter_support::diagnostics::redact::scrub;
use fireemu_adapter_support::diagnostics::{
    from_value, to_value, Bundle, BundleInput, ConfigValue, FunctionsSection, Limits, LogSection,
    PendingSection, RuleCondition, RuleDenial, RulesSection, Versions,
};

fn denial(i: u32) -> RuleDenial {
    RuleDenial {
        service: "firestore".into(),
        location: "database (default)".into(),
        method: "get".into(),
        path: format!("notes/n{i}"),
        uid: None,
        reason: "no allow".into(),
        conditions: vec![RuleCondition {
            line: 1,
            column: 2,
            excerpt: None,
            outcome: "false".into(),
        }],
    }
}

fn input(denials: usize, config: Vec<(String, ConfigValue)>, logs: Vec<String>) -> BundleInput {
    BundleInput {
        generated_at: "2026-11-12T00:00:00Z".into(),
        versions: Versions {
            fireemu: "0.50.0".into(),
            runtimes: vec![],
            sdks: vec![],
        },
        config,
        functions: FunctionsSection {
            events: vec![],
            attempts: vec![],
            retries: vec![],
            log_gaps: false,
        },
        rules: RulesSection {
            history_enabled: false,
            retention: 7,
            history_started_at: None,
            denials: (0..denials)
                .map(|i| denial(u32::try_from(i).expect("small test count")))
                .collect(),
            dropped: 3,
        },
        indexes: vec![],
        pending: PendingSection {
            tasks: vec![],
            resources: vec![],
        },
        logs: LogSection {
            lines: logs,
            dropped_ranges: vec![],
        },
    }
}

#[test]
fn a_list_exactly_at_its_limit_is_kept_whole_and_one_over_is_cut() {
    let limits = Limits {
        max_denials: 5,
        ..Limits::default()
    };
    let at = Bundle::from_input(input(5, vec![], vec![]), limits);
    assert_eq!(at.rules.denials.len(), 5);
    assert!(
        at.truncations.iter().all(|t| t.section != "rules.denials"),
        "{:?}",
        at.truncations
    );
    let over = Bundle::from_input(input(6, vec![], vec![]), limits);
    assert_eq!(over.rules.denials.len(), 5);
    let cut = over
        .truncations
        .iter()
        .find(|t| t.section == "rules.denials")
        .expect("truncation");
    assert_eq!((cut.kept, cut.dropped), (5, 1));
}

#[test]
fn redactions_are_counted_once_each_across_sections() {
    let secret_a = format!("{}{}", "Author", "ization: one");
    let secret_b = format!("{}{}", "ya", "29.two");
    let b = Bundle::from_input(
        input(
            0,
            vec![(secret_a, ConfigValue::Str("plain".into()))],
            vec![secret_b],
        ),
        Limits::default(),
    );
    assert_eq!(b.redactions, 2);
}

#[test]
fn redactions_inside_object_keys_are_counted() {
    let mut b = input(0, vec![], vec![]);
    b.functions.events =
        vec![serde_json::json!({ format!("{}{}", "Author", "ization: k"): 1, "plain": 2 })];
    let bundle = Bundle::from_input(b, Limits::default());
    assert_eq!(bundle.redactions, 1);
}

#[test]
fn true_booleans_round_trip_as_true() {
    let mut b = input(0, vec![], vec![]);
    b.rules.history_enabled = true;
    b.functions.log_gaps = true;
    let bundle = Bundle::from_input(b, Limits::default());
    let back = from_value(&to_value(&bundle)).expect("round trip");
    assert!(back.rules.history_enabled);
    assert!(back.functions.log_gaps);
    assert_eq!(back, bundle);
}

#[test]
fn every_configuration_value_kind_and_scalar_round_trips_through_from_value() {
    let config = vec![
        ("a".to_owned(), ConfigValue::Null),
        ("b".to_owned(), ConfigValue::Bool(true)),
        ("c".to_owned(), ConfigValue::Bool(false)),
        ("d".to_owned(), ConfigValue::Int(-3)),
        ("e".to_owned(), ConfigValue::Str("text".into())),
    ];
    let b = Bundle::from_input(input(1, config, vec![]), Limits::default());
    let back = from_value(&to_value(&b)).expect("round trip");
    assert_eq!(back, b);
    assert_eq!(back.rules.retention, 7);
    assert!(!back.rules.history_enabled);
    assert_eq!(back.rules.dropped, 3);
}

#[test]
fn a_wrong_scalar_type_is_refused_by_name() {
    let mut value = to_value(&Bundle::from_input(
        input(0, vec![], vec![]),
        Limits::default(),
    ));
    value["rules"]["retention"] = serde_json::json!("seven");
    assert!(from_value(&value).unwrap_err().contains("integer"));
}

#[test]
fn credential_scan_accepts_underscore_and_hyphen_in_each_position() {
    let bearer = format!("{}{}", "use Bear", "er abc_de-f");
    assert_eq!(scrub(&bearer).1, 1);
    let dashed = format!("{}{}", "use Bear", "er -x1");
    assert_eq!(scrub(&dashed).1, 1);
    let jwt = format!(
        "{}.{}.{}",
        "eyJ_".to_owned() + &"a".repeat(8),
        "b-".repeat(5),
        "c".repeat(10)
    );
    assert_eq!(scrub(&jwt).1, 1, "jwt with _ and - segments");
    let key = format!("{} {}{}", "x".repeat(20), "AIza", "a".repeat(35));
    assert_eq!(scrub(&key).1, 1, "key after a long prefix");
}

#[test]
fn string_budget_cuts_on_character_boundaries_and_html_escapes() {
    let long = "a".repeat(10_000);
    let boundary = format!("{}😀<", "a".repeat(4095));
    let escaped = format!("<{}", "b".repeat(10_000));
    let bundle = Bundle::from_input(
        input(0, vec![], vec![long, boundary, escaped]),
        Limits::default(),
    );
    assert_eq!(bundle.logs.lines[0].len(), 4096);
    assert_eq!(bundle.logs.lines[1], "a".repeat(4095));
    assert_eq!(bundle.logs.lines[2].len(), 4096);
    assert!(fireemu_adapter_support::diagnostics::to_html(&bundle).contains("&lt;"));
    let cuts: Vec<_> = bundle
        .truncations
        .iter()
        .filter(|t| t.section == "strings")
        .collect();
    assert_eq!(cuts.len(), 3);
    assert_eq!((cuts[0].kept, cuts[0].dropped), (4096, 5904));
    assert_eq!((cuts[1].kept, cuts[1].dropped), (4096, 5));
    assert_eq!((cuts[2].kept, cuts[2].dropped), (4096, 5905));
}
