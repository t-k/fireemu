//! The `timestamp` / `duration` / `latlng` / `math` / `hashing` namespaces, `map.diff()`,
//! `getAfter()` and the `firestore` namespace, and the set-valued proof values (`in`,
//! `!=`, `not-in` constraints).

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request, evaluate_request_with, Decision, DenyReason, DocumentAccess, Method,
    RequestContext, RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;

const DOC: &str = "/databases/(default)/documents/notes/n1";
// 2026-08-30T01:02:03.5Z
const NOW_NANOS: i128 = 1_788_051_723_i128 * 1_000_000_000 + 500_000_000;

fn ctx(data: &[(&str, RulesValue)]) -> RequestContext {
    let mut resource = BTreeMap::new();
    resource.insert(
        "data".to_owned(),
        RulesValue::Map(
            data.iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ),
    );
    resource.insert("id".to_owned(), RulesValue::String("n1".into()));
    RequestContext {
        service: RulesService::Firestore,
        method: Method::Update,
        path: DOC.to_owned(),
        auth: None,
        resource: Some(RulesValue::Map(resource.clone())),
        request_resource: Some(RulesValue::Map(resource)),
        time_unix_nanos: NOW_NANOS,
        abstract_path: false,
        request_query: None,
    }
}

fn rules(cond: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{database}}/documents {{ match /notes/{{id}} {{ allow write: if {cond}; }} }} }}"
    )
}

fn decide(cond: &str, ctx: &RequestContext) -> Decision {
    evaluate_request(&parse_ruleset(&rules(cond)).unwrap(), ctx).decision
}

fn holds(cond: &str) -> bool {
    matches!(decide(cond, &ctx(&[])), Decision::Allow)
}

#[test]
fn timestamp_namespace_and_methods() {
    for cond in [
        "request.time.year() == 2026",
        "request.time.month() == 8",
        "request.time.day() == 30",
        "request.time.hours() == 1",
        "request.time.minutes() == 2",
        "request.time.seconds() == 1788051723",
        "request.time.nanos() == 500000000",
        "request.time.dayOfWeek() == 7",
        "request.time.dayOfYear() == 242",
        "request.time.toMillis() == 1788051723500",
        "request.time.date() == timestamp.date(2026, 8, 30)",
        "request.time.time() == duration.time(1, 2, 3, 500000000)",
        "timestamp.value(1788051723500) == request.time",
        "timestamp.date(1970, 1, 1).toMillis() == 0",
        "timestamp.date(2000, 2, 29).dayOfYear() == 60",
        "request.time - duration.value(1, 'd') < request.time",
        "request.time + duration.value(2, 'h') > request.time",
        "(request.time - timestamp.date(2026, 8, 30)) == duration.time(1, 2, 3, 500000000)",
        "request.time - timestamp.date(2026, 8, 29) > duration.value(1, 'd')",
        "duration.value(1, 'w') == duration.value(7, 'd')",
        "duration.value(90, 'm') == duration.value(1, 'h') + duration.value(30, 'm')",
        "duration.value(1500, 'ms').seconds() == 1",
        "duration.value(1500, 'ms').nanos() == 500000000",
        "duration.abs(duration.value(-3, 's')) == duration.value(3, 's')",
        "duration.value(-3, 's') < duration.value(0, 'ns')",
        "request.time is timestamp",
        "duration.value(1, 's') is duration",
        "!(duration.value(1, 's') is timestamp)",
    ] {
        assert!(holds(cond), "{cond}");
    }
    for cond in [
        "timestamp.date(2023, 2, 29) == request.time",
        "duration.value(1, 'fortnight') == duration.value(1, 'd')",
        "request.time.year() == 2025",
    ] {
        assert!(!holds(cond), "{cond}");
    }
}

#[test]
fn latlng_math_and_hashing_namespaces() {
    for cond in [
        "latlng.value(35.6812, 139.7671).latitude() == 35.6812",
        "latlng.value(35.6812, 139.7671).longitude() == 139.7671",
        // Tokyo Station to Shin-Osaka: about 400 km.
        "latlng.value(35.6812, 139.7671).distance(latlng.value(34.7334, 135.5002)) > 395.0",
        "latlng.value(35.6812, 139.7671).distance(latlng.value(34.7334, 135.5002)) < 405.0",
        "latlng.value(0, 0).distance(latlng.value(0, 0)) == 0.0",
        "latlng.value(1, 2) is latlng",
        "math.abs(-3) == 3",
        "math.abs(-2.5) == 2.5",
        "math.ceil(1.2) == 2.0",
        "math.floor(1.8) == 1.0",
        "math.round(2.5) == 3.0",
        "math.sqrt(16.0) == 4.0",
        "math.pow(2.0, 10.0) == 1024.0",
        "math.isNaN(0.0 / 0.0)",
        "math.isInfinite(1.0 / 0.0)",
        "!math.isNaN(1.0)",
        "hashing.md5('abc').toHexString() == '900150983cd24fb0d6963f7d28e17f72'",
        "hashing.sha256('abc').toHexString() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'",
        "hashing.crc32('123456789').toHexString() == 'cbf43926'",
        "hashing.crc32c('123456789').toHexString() == 'e3069283'",
        "hashing.sha256('abc') == hashing.sha256('abc'.toUtf8())",
        "hashing.sha256('abc').size() == 32",
        "hashing.md5('foobar'.toUtf8()).toBase64() == 'OFj2IjCsPJFfMAxmQxLGPw=='",
        "'foobar'.toUtf8().toBase64() == 'Zm9vYmFy'",
        "'foobar'.toUtf8() is bytes",
    ] {
        assert!(holds(cond), "{cond}");
    }
    assert!(!holds("latlng.value(91, 0).latitude() == 91.0"));
    assert!(!holds("math.abs('x') == 1"));
}

#[test]
fn map_diff_reports_added_removed_changed_and_unchanged_keys() {
    let c = ctx(&[]);
    let mut before = BTreeMap::new();
    before.insert(
        "data".to_owned(),
        RulesValue::Map(BTreeMap::from([
            ("title".to_owned(), RulesValue::String("old".into())),
            ("owner".to_owned(), RulesValue::String("u1".into())),
            ("gone".to_owned(), RulesValue::Int(1)),
        ])),
    );
    let mut after = BTreeMap::new();
    after.insert(
        "data".to_owned(),
        RulesValue::Map(BTreeMap::from([
            ("title".to_owned(), RulesValue::String("new".into())),
            ("owner".to_owned(), RulesValue::String("u1".into())),
            ("added".to_owned(), RulesValue::Bool(true)),
        ])),
    );
    let c = RequestContext {
        resource: Some(RulesValue::Map(before)),
        request_resource: Some(RulesValue::Map(after)),
        ..c
    };
    let diff = "request.resource.data.diff(resource.data)";
    for cond in [
        format!("{diff}.addedKeys().hasOnly(['added'])"),
        format!("{diff}.removedKeys() == ['gone']"),
        format!("{diff}.changedKeys().hasAll(['title']) && {diff}.changedKeys().size() == 1"),
        format!("{diff}.unchangedKeys() == ['owner']"),
        format!("{diff}.affectedKeys().hasOnly(['added', 'gone', 'title'])"),
        format!("!{diff}.affectedKeys().hasAny(['owner'])"),
        format!("'title' in {diff}.affectedKeys()"),
    ] {
        assert!(matches!(decide(&cond, &c), Decision::Allow), "{cond}");
    }
    assert!(!matches!(
        decide(&format!("{diff}.affectedKeys().hasOnly(['title'])"), &c),
        Decision::Allow
    ));
}

struct Access {
    before: BTreeMap<String, RulesValue>,
    after: Option<BTreeMap<String, RulesValue>>,
}

fn doc(fields: &[(&str, RulesValue)]) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "data".to_owned(),
        RulesValue::Map(
            fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ),
    );
    RulesValue::Map(m)
}

impl DocumentAccess for Access {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        self.before.get(&segments.join("/")).cloned()
    }
    fn get_after(&self, segments: &[String]) -> Option<Option<RulesValue>> {
        self.after
            .as_ref()
            .map(|after| after.get(&segments.join("/")).cloned())
    }
}

#[test]
fn get_after_reads_the_state_after_the_write_and_fails_closed_elsewhere() {
    let n1 = "databases/(default)/documents/notes/n1";
    let counter = "databases/(default)/documents/counters/c";
    let access = Access {
        before: BTreeMap::from([
            (n1.to_owned(), doc(&[("v", RulesValue::Int(1))])),
            (counter.to_owned(), doc(&[("n", RulesValue::Int(1))])),
        ]),
        after: Some(BTreeMap::from([
            (n1.to_owned(), doc(&[("v", RulesValue::Int(2))])),
            (counter.to_owned(), doc(&[("n", RulesValue::Int(2))])),
        ])),
    };
    let c = ctx(&[]);
    let eval = |cond: &str, access: &Access| {
        evaluate_request_with(&parse_ruleset(&rules(cond)).unwrap(), &c, Some(access)).decision
    };
    let counter_path = "/databases/$(database)/documents/counters/c";
    for cond in [
        format!("getAfter({counter_path}).data.n == get({counter_path}).data.n + 1"),
        format!("getAfter({counter_path}).data.n == 2 && get({counter_path}).data.n == 1"),
        format!("exists({counter_path}) && !exists(/databases/$(database)/documents/counters/x)"),
        format!("firestore.get({counter_path}).data.n == 1"),
        format!("firestore.exists({counter_path})"),
    ] {
        assert!(matches!(eval(&cond, &access), Decision::Allow), "{cond}");
    }
    // A missing document after the write.
    let deleted = Access {
        after: Some(BTreeMap::new()),
        ..Access {
            before: access.before.clone(),
            after: None,
        }
    };
    assert!(matches!(
        eval(&format!("!exists(/databases/$(database)/documents/nothing) && getAfter({counter_path}).data.n == 2"), &deleted),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    // Reads (no after-state) fail closed with an explicit reason.
    let read_only = Access {
        before: access.before.clone(),
        after: None,
    };
    assert!(matches!(
        eval(&format!("getAfter({counter_path}).data.n == 2"), &read_only),
        Decision::Deny(DenyReason::Unsupported(_))
    ));
    // Budget: get and getAfter of one path are two accesses.
    let mut terms: Vec<String> = (0..5)
        .map(|i| {
            format!(
                "get(/databases/$(database)/documents/d/{i}) != null && getAfter(/databases/$(database)/documents/d/{i}) != null"
            )
        })
        .collect();
    terms.push("exists(/databases/$(database)/documents/d/extra)".to_owned());
    let many = terms.join(" && ");
    let docs: BTreeMap<String, RulesValue> = (0..5)
        .map(|i| {
            (
                format!("databases/(default)/documents/d/{i}"),
                doc(&[("x", RulesValue::Int(i))]),
            )
        })
        .collect();
    let full = Access {
        before: docs.clone(),
        after: Some(docs),
    };
    assert!(matches!(
        eval(&many, &full),
        Decision::Deny(DenyReason::BudgetExceeded {
            limit_id: "RULES-DOC-ACCESS-SINGLE",
            current: 11,
            maximum: 10
        })
    ));
}

#[test]
fn set_valued_fields_prove_equality_membership_and_types() {
    let one_of = |members: &[RulesValue]| ctx(&[("status", RulesValue::OneOf(members.to_vec()))]);
    let not_one_of =
        |members: &[RulesValue]| ctx(&[("status", RulesValue::NotOneOf(members.to_vec()))]);
    let s = |v: &str| RulesValue::String(v.into());
    let allow = |cond: &str, c: &RequestContext| matches!(decide(cond, c), Decision::Allow);
    // `status in ['a', 'b']`
    let c = one_of(&[s("a"), s("b")]);
    assert!(allow("resource.data.status in ['a', 'b', 'c']", &c));
    assert!(allow("resource.data.status != 'z'", &c));
    assert!(allow("resource.data.status is string", &c));
    assert!(allow("!(resource.data.status == 'z')", &c));
    assert!(!allow("resource.data.status == 'a'", &c)); // undetermined: a or b
    assert!(!allow("resource.data.status in ['a']", &c));
    assert!(allow("resource.data.status == 'a'", &one_of(&[s("a")])));
    assert!(!allow(
        "resource.data.status is string",
        &one_of(&[s("a"), RulesValue::Int(1)])
    ));
    assert!(allow(
        "resource.data.status < 10",
        &one_of(&[RulesValue::Int(1), RulesValue::Int(2)])
    ));
    assert!(!allow(
        "resource.data.status < 2",
        &one_of(&[RulesValue::Int(1), RulesValue::Int(2)])
    ));
    // `status != 'deleted'` / `status not-in ['deleted', 'hidden']`
    let c = not_one_of(&[s("deleted"), s("hidden")]);
    assert!(allow("resource.data.status != 'deleted'", &c));
    assert!(allow("!(resource.data.status == 'hidden')", &c));
    assert!(allow(
        "!(resource.data.status in ['deleted', 'hidden'])",
        &c
    ));
    assert!(!allow("resource.data.status != 'other'", &c));
    assert!(!allow("resource.data.status == 'public'", &c));
    assert!(!allow("resource.data.status is string", &c));
    assert!(!allow("resource.data.status in ['public', 'deleted']", &c));
}

#[test]
fn array_contains_any_proves_only_what_every_candidate_satisfies() {
    let s = |v: &str| RulesValue::String(v.into());
    let field =
        |members: &[RulesValue]| ctx(&[("tags", RulesValue::PartialListAny(members.to_vec()))]);
    let allow = |cond: &str, c: &RequestContext| matches!(decide(cond, c), Decision::Allow);
    // The array holds a or b (not necessarily both).
    let c = field(&[s("a"), s("b")]);
    assert!(allow("resource.data.tags.hasAny(['a', 'b'])", &c));
    assert!(allow("resource.data.tags.hasAny(['a', 'b', 'c'])", &c));
    assert!(allow("resource.data.tags is list", &c));
    assert!(
        !allow("resource.data.tags.hasAny(['a'])", &c),
        "may hold only b"
    );
    assert!(!allow("resource.data.tags.hasAll(['a', 'b'])", &c));
    assert!(!allow("'a' in resource.data.tags", &c));
    assert!(!allow("resource.data.tags.size() == 2", &c));
    // A single candidate is certain.
    let one = field(&[s("a")]);
    assert!(allow("'a' in resource.data.tags", &one));
    assert!(allow("resource.data.tags.hasAny(['a'])", &one));
}
