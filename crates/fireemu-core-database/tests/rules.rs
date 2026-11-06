//! Realtime Database rules against what the official emulator (firebase-database-emulator
//! v4.11.2) answered. `fixtures/rules-expressions-*official-emulator-4.11.2.json` hold, for
//! each `.read` expression at `/t` (with the `.indexOn` beside it, if any), whether loading
//! the rules failed (and with which text), and otherwise whether a read of `/t` by user `u1`,
//! with the REST query parameters recorded, was allowed.

#![allow(
    clippy::field_reassign_with_default,
    clippy::option_option,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

mod support;

use fireemu_core_database::rules::{Requester, RuleSource, RuleSpec, Rules, SourceExpr};
use fireemu_core_database::{Json, Limit, OrderBy, Path, QueryParams};
use support::{j, p, tree_with};

/// The rules file the official emulator was given: `{"rules":{"t":{".read":<expr>}}}`,
/// with the expression written as `JSON.stringify` writes it.
fn read_rule_at_t(expr: &str) -> RuleSpec {
    let prefix = r#"{"rules":{"t":{".read":""#;
    let mut column = prefix.chars().count() + 1;
    let mut positions = Vec::new();
    for c in expr.chars() {
        // As JSON.stringify writes it, in UTF-16 units; an escaped character is placed where
        // its escape ends, as the rules file reader places it.
        let width = match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if u32::from(c) < 0x20 => 6,
            c => c.len_utf16(),
        };
        let escaped = matches!(c, '"' | '\\') || u32::from(c) < 0x20;
        positions.push((1, if escaped { column + width - 1 } else { column }));
        column += width;
    }
    positions.push((1, column));
    let mut t = RuleSpec::default();
    t.read = Some(RuleSource::Expr(SourceExpr {
        text: expr.to_owned(),
        positions,
        second_units: Vec::new(),
    }));
    let mut root = RuleSpec::default();
    root.children.insert("t".to_owned(), t);
    root
}

fn seed() -> fireemu_core_database::Tree {
    tree_with(serde_json::json!({
        "t": {"s": "Hello", "n": 5, "d": 2.5, "b": true, "z": 0, "o": {"k": "v", "m": 1},
              "arr": {"0": "a", "1": "b"}, ".priority": 7},
        "u": "u1"
    }))
}

/// `auth` as the official emulator showed it for the token the corpus used: the custom
/// claims are members too.
fn auth() -> Json {
    j(serde_json::json!({
        "uid": "u1",
        "provider": "anonymous",
        "email": "A@b.co", "admin": true, "n": 3, "roles": ["x"],
        "token": {"sub": "u1", "uid": "u1", "iat": 1, "exp": 9_999_999_999_i64,
                  "email": "A@b.co", "admin": true, "n": 3, "roles": ["x"]}
    }))
}

/// The query a fixture's REST parameters ask for; `None` for a query the REST layer
/// refuses before rules (an order without its index).
fn query(params: &str, index_on: &[String]) -> Option<Option<QueryParams>> {
    if params.is_empty() {
        return Some(None);
    }
    let mut q = QueryParams::default();
    for pair in params.trim_start_matches('&').split('&') {
        let (name, value) = pair.split_once('=').unwrap();
        let value = value
            .replace("%22", "\"")
            .replace("%24", "$")
            .replace("%2F", "/");
        let json = || j(serde_json::from_str(&value).unwrap());
        match name {
            "orderBy" => {
                let order = value.trim_matches('"');
                let indexed = |name: &str| index_on.iter().any(|i| i == name);
                q.order_by = match order {
                    "$key" => OrderBy::Key,
                    "$priority" => OrderBy::Priority,
                    "$value" if indexed(".value") => OrderBy::Value,
                    child if indexed(child) => OrderBy::Child(p(child)),
                    _ => return None,
                }
            }
            "limitToFirst" => q = q.limit_to_first(value.parse().unwrap()),
            "limitToLast" => q = q.limit_to_last(value.parse().unwrap()),
            "equalTo" => q = q.equal_to(json(), None),
            "startAt" => q = q.start_at(json(), None),
            "startAfter" => q = q.start_after(json(), None),
            "endAt" => q = q.end_at(json(), None),
            "endBefore" => q = q.end_before(json(), None),
            other => panic!("{other}"),
        }
    }
    Some(Some(q))
}

fn differences(fixture: &str) -> Vec<String> {
    differences_with(fixture, false)
}

/// [`differences`] with the emulator profile's regular-expression dialect on or off.
fn differences_with(fixture: &str, jar_dialect: bool) -> Vec<String> {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(fixture).unwrap();
    let tree = seed();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 1_792_464_733_000,
    };
    let mut failures = Vec::new();
    for entry in &corpus {
        let expr = entry["expr"].as_str().unwrap();
        let params = entry["query"].as_str().unwrap();
        let index_on: Vec<String> = entry["indexOn"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .map(|n| n.as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let compiled =
            Rules::compile(&read_rule_at_t(expr)).map(|r| r.with_jar_dialect(jar_dialect));
        let got = match (&compiled, entry["load"].as_u64().unwrap()) {
            (Err(error), 400) => {
                let expected = entry["error"].as_str().unwrap().trim_end_matches('\n');
                (error.to_string() != expected).then(|| format!("error {error} vs {expected}"))
            }
            (Err(error), _) => Some(format!("refused: {error}")),
            (Ok(_), 400) => Some(format!("loaded, expected {}", entry["error"])),
            (Ok(rules), _) => {
                let Some(query) = query(params, &index_on) else {
                    continue;
                };
                let allowed = rules.can_read(tree.root(), &p("/t"), query.as_ref(), &requester);
                let expected = entry["read"].as_u64() == Some(200);
                (allowed != expected).then(|| format!("read {allowed}, expected {expected}"))
            }
        };
        if let Some(problem) = got {
            failures.push(format!("{expr:?} {params}: {problem}"));
        }
    }
    failures
}

/// The regular-expression rows of the r6 differential fuzz (and the review rows), recorded on
/// the official emulator. A row marked `"fireemu": "denies"` uses a construct whose meaning
/// there fireemu does not reproduce (RTDB-03c): it is a rule error here, so the read is
/// denied where the official emulator allows it. No row is the other way round: fireemu never
/// allows a read the official emulator denies, and loads every rule it loads.
#[test]
fn every_recorded_pattern_decides_as_the_official_emulator_or_denies() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/rules-expressions-3-official-emulator-4.11.2.json"
    ))
    .unwrap();
    fn marked(mark: &'static str) -> impl Fn(&serde_json::Value) -> bool {
        move |entry| entry.get("fireemu").is_some_and(|f| f == mark)
    }
    // Refused at load here, and by the official emulator with another text: a statement keyword such as `return`, an
    // E4X `<`, a character outside the Basic Multilingual Plane or U+0085 inside a name (a lone escaped
    // surrogate is held as UTF-16 units since 2026-11-06, and its rows are in the agreeing set).
    // The illegal characters, escaped names, line offsets and Rhino's error texts and places agree
    // since the rules-load fix of 2026-11-04 and are in the agreeing rows.
    let (refused, corpus): (Vec<serde_json::Value>, Vec<serde_json::Value>) =
        corpus.into_iter().partition(marked("refuses"));
    assert!(refused.len() >= 8);
    for entry in &refused {
        let expr = entry["expr"].as_str().unwrap();
        assert!(Rules::compile(&read_rule_at_t(expr)).is_err(), "{entry}");
    }
    let (denied, agreeing): (Vec<serde_json::Value>, Vec<serde_json::Value>) =
        corpus.into_iter().partition(|entry| {
            entry.get("fireemu").is_some() && entry["fireemu_current"] != "official"
        });
    assert!(agreeing.len() > 1200 && denied.len() > 200);
    // (An expression that spans a line break has its syntax errors placed as the official
    // emulator places them, by their offset in the line, since the rules-load fix.)
    let failures = differences(&serde_json::to_string(&agreeing).unwrap());
    assert!(failures.is_empty(), "{failures:#?}");
    let denied: Vec<serde_json::Value> = denied
        .into_iter()
        .map(|mut entry| {
            assert_eq!(entry["fireemu"], "denies");
            assert_eq!(entry["read"], 200, "{entry}");
            entry["read"] = 401.into();
            entry
        })
        .collect();
    let failures = differences(&serde_json::to_string(&denied).unwrap());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Strings that hold a lone surrogate (an escape such as `'\uD83D'`, which Java holds as one UTF-16 unit), probed on the official
/// emulator jar 4.11.2 (docs.local/runs/rtdb-lone-surrogate): length, `+`, equality, ordering and the string methods. Production
/// has not answered these, so both profiles follow the jar.
#[test]
fn lone_surrogate_strings_load_and_decide_as_the_official_emulator() {
    let failures = differences(include_str!(
        "fixtures/rules-lone-surrogates-official-emulator-4.11.2.json"
    ));
    assert!(
        failures.is_empty(),
        "{} rows differ: {failures:#?}",
        failures.len()
    );
}

/// `query.orderBy` (documented by production) loads in both profiles and decides as the official
/// emulator does (owner 2276): it is an ordering, equal to `query.orderByChild` when the read orders by a
/// child, otherwise only to itself. The 81 rows were recorded with the jar (reads under each query kind
/// and the load refusals of the other operators).
#[test]
fn query_order_by_loads_and_decides_as_the_official_emulator() {
    let failures = differences(include_str!(
        "fixtures/rules-query-orderby-official-emulator-4.11.2.json"
    ));
    assert!(
        failures.is_empty(),
        "{} rows differ: {failures:#?}",
        failures.len()
    );
}

/// The emulator profile reads `\W` and `\D` as the complement of a language of strings, and an escaped
/// letter or digit as that character, as the official emulator does (owner 2276): 500 jar rows over
/// bare, anchored, quantified, grouped and class forms, with and without `i`, and the `[\uD800-\uDFFF]` class,
/// which there is the characters u, D, 8, 0 and the range 0-u, D, F. The strict profile keeps an error for
/// them (production has not answered): every one of these rows that mentions one is denied there.
#[test]
fn the_emulator_profile_reads_complement_classes_and_escaped_letters_as_the_official_emulator() {
    let fixture = include_str!("fixtures/rules-regex-dialect-official-emulator-4.11.2.json");
    let failures = differences_with(fixture, true);
    assert!(
        failures.is_empty(),
        "{} rows differ: {failures:#?}",
        failures.len()
    );
    // Under the strict profile none of them reads 200 where the jar answers 401, and the rows that use
    // one of the constructs read false, negated or not.
    let strict = differences_with(fixture, false);
    assert!(strict.len() > 60, "{}", strict.len());
    assert!(
        strict
            .iter()
            .all(|f| f.ends_with("read false, expected true")),
        "{strict:#?}"
    );
}

/// The 14k-row differential corpus of the regular-expression dialect, run with the emulator profile's dialect on:
/// no row moves the wrong way (an allow where the official emulator denies, or a load that differs), and of the 323
/// rows fireemu denied where the official emulator allows, 252 now decide as it does. The 71 others stay errors,
/// hence denied: each uses the `i` flag with non-ASCII text, which needs a Java 21 case-folding table (a declared
/// difference, owner ledger line 2288).
#[test]
fn the_emulator_profile_moves_no_corpus_row_the_wrong_way() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/rules-expressions-3-official-emulator-4.11.2.json"
    ))
    .unwrap();
    let rows: Vec<serde_json::Value> = corpus
        .into_iter()
        .filter(|e| e.get("fireemu") != Some(&serde_json::Value::from("refuses")))
        .collect();
    let denied = rows
        .iter()
        .filter(|e| e.get("fireemu").is_some_and(|f| f == "denies"))
        .count();
    let failures = differences_with(&serde_json::to_string(&rows).unwrap(), true);
    let wrong_way: Vec<&String> = failures
        .iter()
        .filter(|f| !f.ends_with("read false, expected true"))
        .collect();
    assert!(wrong_way.is_empty(), "{wrong_way:#?}");
    assert_eq!(denied, 323);
    assert_eq!(failures.len(), 71, "{failures:#?}");
}

#[test]
fn every_recorded_expression_loads_and_decides_as_the_official_emulator() {
    let mut failures = differences(include_str!(
        "fixtures/rules-expressions-official-emulator-4.11.2.json"
    ));
    failures.extend(differences(include_str!(
        "fixtures/rules-expressions-2-official-emulator-4.11.2.json"
    )));
    // The official emulator's regular expressions are a dialect of their own (RTDB-03c).
    // Until it is followed, a pattern fireemu does not read as it does is an error in the
    // rule, so the rule is false negated or not: these recorded rows are allowed there and
    // denied here, and no row is the other way round.
    let known: std::collections::BTreeSet<&str> = [
        r#""'?:a'.matches(/(?:a)/)" : read false, expected true"#,
        r#""'a]'.matches(/[[:alpha:]]/)" : read false, expected true"#,
        r#""'[]'.matches(/[[:alpha:]]/)" : read false, expected true"#,
        r#""'?ia'.matches(/(?i)a/)" : read false, expected true"#,
        r#""'?=a'.matches(/(?=a)/)" : read false, expected true"#,
        r#""'x?:a'.matches(/x(?:a)/)" : read false, expected true"#,
        r#""'?'.matches(/^(?)$/)" : read false, expected true"#,
        r#""'1'.matches(/^\\1$/)" : read false, expected true"#,
        r#""!'\\n'.matches(/^\\n$/)" : read false, expected true"#,
        r#""'n'.matches(/^\\n$/)" : read false, expected true"#,
        r#""'r'.matches(/^\\r$/)" : read false, expected true"#,
        r#""'t'.matches(/^\\t$/)" : read false, expected true"#,
        r#""'b'.matches(/^\\b$/)" : read false, expected true"#,
        r#""'q'.matches(/^\\q$/)" : read false, expected true"#,
        r#""'x'.matches(/^\\x$/)" : read false, expected true"#,
        r#""!'aa'.matches(/^(a)\\1$/)" : read false, expected true"#,
        // Ranges whose endpoints are surrogates of one character are, read by UTF-16 unit,
        // reversed or not ranges at all: an error here, false and true there.
        // `\u` and `\x` in a pattern are escaped letters of the dialect: an error.
        r#""!('\u{e000}'.matches(/^[\u{e000}-😀]$/))" : read false, expected true"#,
        r#""!('😀'.matches(/^[😀-😁]$/))" : read false, expected true"#,
        r#""!('😀'.matches(/^[😀-😁]+$/))" : read false, expected true"#,
        r#""!('A'.matches(/\\u0041/))" : read false, expected true"#,
        r#""!('A'.matches(/\\x41/))" : read false, expected true"#,
        // `\W` and `\D` complement a language there; `i` is read only for ASCII patterns.
        r#""'a'.matches(/^\\D$/)" : read false, expected true"#,
        r#""'-'.matches(/^\\W$/)" : read false, expected true"#,
        r#""'ａ'.matches(/^Ａ$/i)" : read false, expected true"#,
        r#""'Ａ'.matches(/^ａ$/i)" : read false, expected true"#,
        r#""'Ｃ'.matches(/^[ａ-ｚ]$/i)" : read false, expected true"#,
        r#""'ｃ'.matches(/^[Ａ-Ｚ]$/i)" : read false, expected true"#,
        r#""'ä'.matches(/^Ä$/i)" : read false, expected true"#,
        r#""'-＄'.matches(/^\\W＄$/i)" : read false, expected true"#,
        r#""'a＄'.matches(/^\\D＄$/i)" : read false, expected true"#,
        r#""'A＄'.matches(/^a＄$/i)" : read false, expected true"#,
    ]
    .into_iter()
    .collect();
    let gone: Vec<&&str> = known
        .iter()
        .filter(|k| !failures.iter().any(|f| f == **k))
        .collect();
    assert!(
        gone.is_empty(),
        "known differences that no longer differ: {gone:?}"
    );
    let failures: Vec<&String> = failures
        .iter()
        .filter(|f| !known.contains(f.as_str()))
        .collect();
    assert!(
        failures.is_empty(),
        "{} differ:\n{}",
        failures.len(),
        failures
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn reads_cascade_and_wildcards_bind() {
    let mut users = RuleSpec::default();
    let mut uid = RuleSpec::default();
    uid.read = Some(expr("auth.uid == $uid"));
    users.children.insert("$uid".to_owned(), uid);
    let mut open = RuleSpec::default();
    open.read = Some(RuleSource::Bool(true));
    let mut closed_below = RuleSpec::default();
    closed_below.read = Some(RuleSource::Bool(false));
    open.children.insert("inner".to_owned(), closed_below);
    let mut root = RuleSpec::default();
    root.children.insert("users".to_owned(), users);
    root.children.insert("open".to_owned(), open);
    let rules = Rules::compile(&root).unwrap();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 0,
    };
    let tree = tree_with(serde_json::json!({"users": {"u1": 1, "u2": 2}}));
    let read = |path: &str| rules.can_read(tree.root(), &p(path), None, &requester);
    assert!(read("/users/u1"));
    assert!(read("/users/u1/deeper"));
    assert!(!read("/users/u2"));
    assert!(!read("/users"));
    // A grant above cannot be taken back below.
    assert!(read("/open/inner"));
    assert!(!read("/"));
}

fn expr(text: &str) -> RuleSource {
    RuleSource::Expr(SourceExpr {
        text: text.to_owned(),
        positions: (0..=text.chars().count()).map(|i| (1, i + 1)).collect(),
        second_units: Vec::new(),
    })
}

#[test]
fn writes_cascade_and_validate_every_node_left_non_null() {
    // The rules of the recorded probe validate-1.txt (jar v4.11.2).
    let mut age = RuleSpec::default();
    age.validate = Some(expr("newData.isNumber()"));
    let mut uid = RuleSpec::default();
    uid.validate = Some(expr("newData.hasChildren(['name'])"));
    uid.children.insert("age".to_owned(), age);
    let mut users = RuleSpec::default();
    users.children.insert("$uid".to_owned(), uid);
    let mut leaf = RuleSpec::default();
    leaf.validate = Some(expr("newData.val() < 5"));
    let mut root = RuleSpec::default();
    root.write = Some(RuleSource::Bool(true));
    root.children.insert("users".to_owned(), users);
    root.children.insert("leaf".to_owned(), leaf);
    let rules = Rules::compile(&root).unwrap();
    let auth = Json::Null;
    let requester = Requester {
        auth: &auth,
        now: 0,
    };
    let mut tree = tree_with(serde_json::json!({}));
    let mut write = |method: &str, path: &str, body: serde_json::Value| -> bool {
        let mut after = tree.clone();
        let path_p = p(path);
        let written: Vec<Path> = if method == "PATCH" {
            let entries: Vec<(String, Json)> = body
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), j(v.clone())))
                .collect();
            after.update(&path_p, &entries, support::NOW).unwrap();
            entries.iter().map(|(k, _)| path_p.join(&p(k))).collect()
        } else {
            after.set(&path_p, &j(body), support::NOW).unwrap();
            vec![path_p]
        };
        let allowed = rules.can_write(tree.root(), after.root(), &written, &requester);
        if allowed {
            tree = after;
        }
        allowed
    };
    use serde_json::json;
    assert!(!write("PUT", "/users/u1/age", json!(1)));
    assert!(write("PUT", "/users/u2", json!({"name": "a"})));
    assert!(write("PUT", "/users/u2/age", json!(2)));
    assert!(!write("PUT", "/users/u2/age", json!("x")));
    assert!(!write("PUT", "/users/u2/name", json!(null)));
    assert!(write("PUT", "/leaf", json!(3)));
    assert!(!write("PUT", "/leaf", json!(9)));
    assert!(!write("PUT", "/", json!({"leaf": 9})));
    assert!(!write("PATCH", "/users/u3", json!({"age": 1})));
    assert!(!write("PATCH", "/users/u2", json!({"name": null})));
    assert!(write(
        "PUT",
        "/users/u4",
        json!({"name": 1, "extra": {"deep": 1}})
    ));
    assert!(!write("PUT", "/users/u5", json!({"name": 1, "age": "x"})));
    assert_eq!(
        support::s(&tree.get_json(&Path::root(), fireemu_core_database::Format::Plain)),
        json!({"leaf": 3, "users": {"u2": {"age": 2, "name": "a"}, "u4": {"extra": {"deep": 1}, "name": 1}}})
    );
}

#[test]
fn index_on_is_read_per_location() {
    let mut q = RuleSpec::default();
    q.index_on = vec!["n".to_owned()];
    let mut root = RuleSpec::default();
    root.children.insert("q".to_owned(), q);
    let rules = Rules::compile(&root).unwrap();
    assert_eq!(rules.index_on(&p("/q")), vec!["n".to_owned()]);
    assert!(rules.index_on(&p("/r")).is_empty());
    let _ = Limit::First(1);
}

/// A rules object of the write fixture as a [`RuleSpec`] (expressions without positions).
fn spec(value: &serde_json::Value) -> RuleSpec {
    let mut spec = RuleSpec::default();
    for (key, child) in value.as_object().unwrap() {
        let rule = || match child {
            serde_json::Value::Bool(b) => RuleSource::Bool(*b),
            serde_json::Value::String(s) => expr(s),
            other => panic!("{other}"),
        };
        match key.as_str() {
            ".read" => spec.read = Some(rule()),
            ".write" => spec.write = Some(rule()),
            ".validate" => spec.validate = Some(rule()),
            _ => {
                spec.children.insert(key.clone(), self::spec(child));
            }
        }
    }
    spec
}

#[test]
fn every_recorded_write_and_expression_error_matches_the_official_emulator() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/rules-writes-official-emulator-4.11.2.json"
    ))
    .unwrap();
    let token = j(serde_json::json!({
        "uid": "u1", "provider": "anonymous",
        "token": {"sub": "u1", "uid": "u1", "iat": 1, "exp": 9_999_999_999_i64, "admin": true}
    }));
    let mut failures = Vec::new();
    let (mut expression_errors, mut writes) = (0, 0);
    for entry in &corpus {
        let text = entry["rulesText"].as_str().unwrap();
        if entry["method"].is_null() {
            // `{"rules":{".read":"<expression>"}}`: an expression error, placed in the file.
            let Some(inner) = text
                .strip_prefix(r#"{"rules":{".read":""#)
                .and_then(|rest| rest.strip_suffix(r#""}}"#))
            else {
                continue;
            };
            let expr_text = inner.replace("\\'", "'");
            let mut root = RuleSpec::default();
            root.read = Some(RuleSource::Expr(SourceExpr {
                positions: (0..=expr_text.chars().count())
                    .map(|i| (1, 20 + i))
                    .collect(),
                text: expr_text.clone(),
                second_units: Vec::new(),
            }));
            let got = Rules::compile(&root).map_err(|e| e.to_string());
            let expected = entry["error"]
                .as_str()
                .map(|e| e.trim_end_matches('\n').to_owned());
            match (&got, &expected) {
                (Err(g), Some(e)) if g == e => {}
                (Ok(_), None) => {}
                _ => failures.push(format!("{text}: {got:?} vs {expected:?}")),
            }
            expression_errors += 1;
            continue;
        }
        let rules_value: serde_json::Value = serde_json::from_str(text).unwrap();
        let compiled = Rules::compile(&spec(&rules_value["rules"]));
        if entry["load"] == 400 {
            let expected = entry["error"].as_str().unwrap();
            let message = expected.split_once(": ").unwrap().1.trim_end_matches('\n');
            match compiled {
                Err(e) if e.message == message => {}
                other => failures.push(format!("{text}: {other:?} vs {expected}")),
            }
            continue;
        }
        let rules = compiled.unwrap();
        let before =
            tree_with(serde_json::json!({"t": {"x": {"name": "a", "n": 1}, "y": 5}, "u": "u1"}));
        let mut after = before.clone();
        let path = p(entry["path"].as_str().unwrap());
        let body = j(entry["body"].clone());
        let written: Vec<Path> = match entry["method"].as_str().unwrap() {
            "PATCH" => {
                let entries: Vec<(String, Json)> = entry["body"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), j(v.clone())))
                    .collect();
                after.update(&path, &entries, support::NOW).unwrap();
                entries.iter().map(|(k, _)| path.join(&p(k))).collect()
            }
            "DELETE" => {
                after.set(&path, &Json::Null, support::NOW).unwrap();
                vec![path]
            }
            _ => {
                after.set(&path, &body, support::NOW).unwrap();
                vec![path]
            }
        };
        let auth = if entry["auth"] == false {
            Json::Null
        } else {
            token.clone()
        };
        let requester = Requester {
            auth: &auth,
            now: 1_792_464_733_000,
        };
        let allowed = rules.can_write(before.root(), after.root(), &written, &requester);
        let expected = entry["status"] == 200;
        writes += 1;
        if allowed != expected {
            failures.push(format!(
                "{text} {} {}: {allowed} vs {expected}",
                entry["method"], entry["path"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        (expression_errors, writes),
        (13, 34),
        "the fixture was read whole"
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;
    use std::fmt::Write as _;

    /// A string made of units a Rules literal can spell: ASCII, an astral character, and the surrogates alone or together.
    fn unit_text() -> impl Strategy<Value = Vec<u16>> {
        prop::collection::vec(
            prop::sample::select(vec![
                0x61_u16, 0x62, 0xD83D, 0xDE00, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0x20AC,
            ]),
            0..5,
        )
    }

    /// The literal that spells `units`: every unit as a `\u` escape, so a pair is two escapes.
    fn literal(units: &[u16]) -> String {
        let mut escapes = String::new();
        for unit in units {
            write!(escapes, "\\u{unit:04X}").unwrap();
        }
        format!("'{escapes}'")
    }

    fn holds(expr: &str) -> Option<bool> {
        let rules = Rules::compile(&read_rule_at_t(expr)).ok()?;
        let tree = seed();
        let auth = auth();
        let requester = Requester {
            auth: &auth,
            now: 1_792_464_733_000,
        };
        Some(rules.can_read(tree.root(), &p("/t"), None, &requester))
    }

    /// One atom of a pattern in the official emulator's dialect, with the language it stands for as a predicate on a
    /// run of characters (the automaton's view): `\W` and `\D` are complements of languages of strings.
    #[derive(Debug, Clone, Copy)]
    enum Atom {
        Lit(char, bool),
        Dot,
        Word,
        Digit,
        ComplementWord,
        ComplementDigit,
        ClassComplementWord,
        ClassComplementWordOrA,
        ClassComplementDigitOrA,
        NegatedClassComplementWord,
        NegatedClassComplementDigit,
        PlainClass,
        NegatedPlainClass,
        EscapedLetterClass,
        NegatedEscapedLetterClass,
        BracketFirstClass,
    }

    #[derive(Debug, Clone, Copy)]
    enum Times {
        Once,
        Optional,
        Star,
        Plus,
    }

    fn is_word(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }

    impl Atom {
        fn text(self) -> String {
            match self {
                Self::Lit(c, escaped) if escaped && c.is_ascii_alphanumeric() => format!("\\{c}"),
                Self::Lit(c, _) => c.to_string(),
                Self::Dot => ".".to_owned(),
                Self::Word => "\\w".to_owned(),
                Self::Digit => "\\d".to_owned(),
                Self::ComplementWord => "\\W".to_owned(),
                Self::ComplementDigit => "\\D".to_owned(),
                Self::ClassComplementWord => "[\\W]".to_owned(),
                Self::ClassComplementWordOrA => "[\\Wa]".to_owned(),
                Self::ClassComplementDigitOrA => "[a\\D]".to_owned(),
                Self::NegatedClassComplementWord => "[^\\W]".to_owned(),
                Self::NegatedClassComplementDigit => "[^\\D]".to_owned(),
                Self::PlainClass => "[ab]".to_owned(),
                Self::NegatedPlainClass => "[^ab]".to_owned(),
                Self::EscapedLetterClass => "[\\ub]".to_owned(),
                Self::NegatedEscapedLetterClass => "[^\\ub]".to_owned(),
                Self::BracketFirstClass => "[]a]".to_owned(),
            }
        }

        fn accepts(self, run: &[char]) -> bool {
            let one = |test: &dyn Fn(char) -> bool| run.len() == 1 && test(run[0]);
            match self {
                Self::Lit(c, _) => one(&|x| x == c),
                Self::Dot => run.len() == 1,
                Self::Word | Self::NegatedClassComplementWord => one(&is_word),
                Self::Digit | Self::NegatedClassComplementDigit => one(&|x| x.is_ascii_digit()),
                Self::ComplementWord | Self::ClassComplementWord => !one(&is_word),
                Self::ComplementDigit => !one(&|x| x.is_ascii_digit()),
                Self::ClassComplementWordOrA => !one(&|x| is_word(x) && x != 'a'),
                // `a` is no digit, so the union with `\D` is `\D`.
                Self::ClassComplementDigitOrA => !one(&|x| x.is_ascii_digit()),
                Self::PlainClass => one(&|x| matches!(x, 'a' | 'b')),
                Self::NegatedPlainClass => one(&|x| !matches!(x, 'a' | 'b')),
                Self::EscapedLetterClass => one(&|x| matches!(x, 'u' | 'b')),
                Self::NegatedEscapedLetterClass => one(&|x| !matches!(x, 'u' | 'b')),
                Self::BracketFirstClass => one(&|x| matches!(x, ']' | 'a')),
            }
        }
    }

    /// Whether `^atoms$` matches all of `subject`, by the positions each atom can reach.
    fn oracle(atoms: &[(Atom, Times)], subject: &[char]) -> bool {
        let n = subject.len();
        let mut reach = vec![false; n + 1];
        reach[0] = true;
        for &(atom, times) in atoms {
            let step = |from: &[bool]| {
                let mut to = vec![false; n + 1];
                for i in (0..=n).filter(|&i| from[i]) {
                    for j in i..=n {
                        if atom.accepts(&subject[i..j]) {
                            to[j] = true;
                        }
                    }
                }
                to
            };
            let closure = |mut set: Vec<bool>| loop {
                let next = step(&set);
                let merged: Vec<bool> = set.iter().zip(&next).map(|(a, b)| *a || *b).collect();
                if merged == set {
                    return set;
                }
                set = merged;
            };
            reach = match times {
                Times::Once => step(&reach),
                Times::Optional => {
                    let once = step(&reach);
                    reach.iter().zip(&once).map(|(a, b)| *a || *b).collect()
                }
                Times::Star => closure(reach),
                Times::Plus => closure(step(&reach)),
            };
        }
        reach[n]
    }

    fn atom() -> impl Strategy<Value = Atom> {
        prop_oneof![
            (
                prop::sample::select(vec!['a', 'b', '1', '_', '!', 'u']),
                any::<bool>()
            )
                .prop_map(|(c, e)| Atom::Lit(c, e)),
            Just(Atom::Dot),
            Just(Atom::Word),
            Just(Atom::Digit),
            Just(Atom::ComplementWord),
            Just(Atom::ComplementDigit),
            Just(Atom::ClassComplementWord),
            Just(Atom::ClassComplementWordOrA),
            Just(Atom::ClassComplementDigitOrA),
            Just(Atom::NegatedClassComplementWord),
            Just(Atom::NegatedClassComplementDigit),
            Just(Atom::PlainClass),
            Just(Atom::NegatedPlainClass),
            Just(Atom::EscapedLetterClass),
            Just(Atom::NegatedEscapedLetterClass),
            Just(Atom::BracketFirstClass),
        ]
    }

    fn times() -> impl Strategy<Value = Times> {
        prop::sample::select(vec![
            Times::Once,
            Times::Once,
            Times::Optional,
            Times::Star,
            Times::Plus,
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig {cases: 600, rng_seed: proptest::test_runner::RngSeed::Fixed(0x10_5f), ..ProptestConfig::default()})]

        /// The emulator profile's `\W`, `\D`, classes holding them and escaped letters match as the language they stand for
        /// (the official emulator's automaton), over patterns of up to four atoms with every quantifier and subjects of up to
        /// four characters; the strict profile never allows what the emulator profile denies, and denies each pattern
        /// that uses the dialect.
        #[test]
        fn the_emulator_profile_matches_the_language_the_pattern_stands_for(
            atoms in prop::collection::vec((atom(), times()), 1..5),
            subject in prop::collection::vec(prop::sample::select(vec!['a', 'b', '1', '_', '!', 'é', 'u', '[', ']', '^']), 0..5),
        ) {
            let mut text = String::from("^");
            for &(atom, times) in &atoms {
                text.push_str(&atom.text());
                text.push_str(match times {
                    Times::Once => "",
                    Times::Optional => "?",
                    Times::Star => "*",
                    Times::Plus => "+",
                });
            }
            text.push('$');
            let subject_text: String = subject.iter().collect();
            let expr = format!("'{subject_text}'.matches(/{text}/)");
            let rules = Rules::compile(&read_rule_at_t(&expr)).unwrap();
            let tree = seed();
            let auth = auth();
            let requester = Requester { auth: &auth, now: 0 };
            let read = |rules: &Rules| rules.can_read(tree.root(), &p("/t"), None, &requester);
            let emulator = read(&rules.clone().with_jar_dialect(true));
            prop_assert_eq!(emulator, oracle(&atoms, &subject), "{}", expr);
            let strict = read(&rules);
            prop_assert!(!strict || emulator, "{}", expr);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {cases: 400, rng_seed: proptest::test_runner::RngSeed::Fixed(0x10_5e), ..ProptestConfig::default()})]

        /// Strings with lone surrogates behave as Java's UTF-16 strings: length counts units, `+` joins them (and a pair spelled
        /// by two escapes is the character), `==` and the order compare unit by unit, and the searches are unit searches.
        #[test]
        fn strings_of_utf16_units_behave_as_java_strings(a in unit_text(), b in unit_text()) {
            let (la, lb) = (literal(&a), literal(&b));
            let joined: Vec<u16> = a.iter().chain(&b).copied().collect();
            prop_assert_eq!(holds(&format!("{la}.length == {}", a.len())), Some(true));
            prop_assert_eq!(holds(&format!("{la}.length == {}", a.len() + 1)), Some(false));
            prop_assert_eq!(holds(&format!("{la} + {lb} == {}", literal(&joined))), Some(true));
            prop_assert_eq!(holds(&format!("({la} + {lb}).length == {}", joined.len())), Some(true));
            prop_assert_eq!(holds(&format!("{la} == {lb}")), Some(a == b));
            prop_assert_eq!(holds(&format!("{la} != {lb}")), Some(a != b));
            prop_assert_eq!(holds(&format!("{la} < {lb}")), Some(a < b));
            prop_assert_eq!(holds(&format!("{la} >= {lb}")), Some(a >= b));
            prop_assert_eq!(holds(&format!("{la}.beginsWith({lb})")), Some(a.starts_with(&b)));
            prop_assert_eq!(holds(&format!("{la}.endsWith({lb})")), Some(a.ends_with(&b)));
            let found = b.is_empty() || a.windows(b.len()).any(|window| window == b.as_slice());
            prop_assert_eq!(holds(&format!("{la}.contains({lb})")), Some(found));
            // A string that is valid UTF-16 equals the character it spells.
            if let Ok(text) = String::from_utf16(&a) {
                prop_assert_eq!(holds(&format!("{la} == '{text}'")), Some(!text.contains(['\'', '\\'])));
            }
        }
    }

    /// Small expressions over the whole grammar, well-formed or not.
    fn expression() -> impl Strategy<Value = String> {
        let leaf = prop::sample::select(vec![
            "true",
            "false",
            "null",
            "1",
            "2.5",
            "'a'",
            "\"b\"",
            "auth",
            "auth.uid",
            "now",
            "data",
            "root",
            "newData",
            "query.limitToFirst",
            "$k",
            "data.val()",
            "data.child('s')",
            "data.child('s').val()",
            "/a+/i",
            "['a']",
            "auth.token.x",
        ])
        .prop_map(str::to_owned);
        leaf.prop_recursive(4, 32, 3, |inner| {
            prop_oneof![
                (
                    inner.clone(),
                    prop::sample::select(vec![
                        "+", "-", "*", "/", "%", "==", "===", "!=", "<", "<=", ">", ">=", "&&",
                        "||",
                    ]),
                    inner.clone()
                )
                    .prop_map(|(a, op, b)| format!("{a} {op} {b}")),
                inner.clone().prop_map(|a| format!("!{a}")),
                inner.clone().prop_map(|a| format!("-{a}")),
                inner.clone().prop_map(|a| format!("({a})")),
                (inner.clone(), inner.clone(), inner.clone())
                    .prop_map(|(a, b, c)| format!("{a} ? {b} : {c}")),
                (
                    inner.clone(),
                    prop::sample::select(vec![
                        "val()",
                        "exists()",
                        "length",
                        "child('o')",
                        "parent()",
                        "hasChildren()",
                        "contains('e')",
                        "matches(/e/)",
                        "toLowerCase()",
                        "isString()",
                        "foo",
                    ])
                )
                    .prop_map(|(a, m)| format!("{a}.{m}")),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {cases: 256, rng_seed: proptest::test_runner::RngSeed::Fixed(0xc012), ..ProptestConfig::default()})]

        #[test]
        fn coverage_trace_preserves_read_and_write_decisions(text in expression(), authenticated in any::<bool>()) {
            let mut spec = read_rule_at_t(&text);
            let at_t = spec.children.get_mut("t").unwrap();
            at_t.write = at_t.read.clone();
            if let Ok(rules) = Rules::compile(&spec) {
                let before = seed();
                let after = tree_with(serde_json::json!({"t":"changed"}));
                let auth = if authenticated {auth()} else {Json::Null};
                let requester = Requester {auth:&auth,now:123 };
                rules.set_coverage_enabled(false);
                let read = rules.can_read(before.root(), &p("t"), None, &requester);
                let write = rules.can_write(before.root(), after.root(), &[p("t")], &requester);
                let empty = rules.coverage_report();
                rules.set_coverage_enabled(true);
                prop_assert_eq!(rules.can_read(before.root(), &p("t"), None, &requester),read);
                prop_assert_eq!(rules.can_write(before.root(), after.root(), &[p("t")], &requester),write);
                rules.set_coverage_enabled(false);
                let recorded = rules.coverage_report();
                rules.can_read(before.root(), &p("t"), None, &requester);
                prop_assert_eq!(rules.coverage_report(),recorded);
                prop_assert_ne!(empty, rules.coverage_report());
            }
        }

        #[test]
        fn coverage_decoded_utf16_ranges_select_their_text(parts in prop::collection::vec(prop::sample::select(vec!["a","é","😀"]),0..8)) {
            let subject=parts.concat();
            let text=format!("  '{subject}'.length >= 0 && (\ntrue || data.child('x').exists()) ");
            assert_coverage_ranges(&text);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Loading and running any expression ends with a decision or a load error, never a
        /// panic, for every kind of rule.
        #[test]
        fn any_expression_loads_or_is_refused_and_never_panics(text in expression()) {
            let tree = seed();
            let auth = auth();
            let requester = Requester { auth: &auth, now: 1 };
            for kind in [".read", ".write", ".validate"] {
                let mut k = RuleSpec::default();
                let rule = Some(expr(&text));
                match kind {
                    ".read" => k.read = rule,
                    ".write" => k.write = rule,
                    _ => k.validate = rule,
                }
                let mut t = RuleSpec::default();
                t.children.insert("$k".to_owned(), k);
                let mut root = RuleSpec::default();
                root.children.insert("t".to_owned(), t);
                if let Ok(rules) = Rules::compile(&root) {
                    let _ = rules.can_read(tree.root(), &p("/t/s"), None, &requester);
                    let _ = rules.can_write(tree.root(), tree.root(), &[p("/t/s")], &requester);
                } else {
                    let error = Rules::compile(&root).unwrap_err();
                    prop_assert!(error.column >= 1 && error.column <= text.chars().count() + 1);
                }
            }
        }

        /// Arbitrary text never panics the parser.
        #[test]
        fn arbitrary_text_is_parsed_or_refused(text in "[ -~]{0,40}") {
            let mut root = RuleSpec::default();
            root.read = Some(expr(&text));
            let _ = Rules::compile(&root);
        }

        /// A read is allowed exactly when some `.read` on the way to the location is true.
        #[test]
        fn reads_cascade_from_any_level(grants in prop::collection::vec(prop::option::of(any::<bool>()), 1..5)) {
            let keys = ["a", "b", "c", "d", "e"];
            let mut spec = RuleSpec::default();
            for (depth, grant) in grants.iter().enumerate().rev() {
                let mut level = RuleSpec::default();
                level.read = grant.map(RuleSource::Bool);
                if depth + 1 < grants.len() {
                    level.children.insert(keys[depth + 1].to_owned(), spec);
                }
                spec = level;
            }
            let mut root = RuleSpec::default();
            root.children.insert("a".to_owned(), spec);
            let rules = Rules::compile(&root).unwrap();
            let path = Path::from_keys(keys[..grants.len()].iter().copied());
            let auth = Json::Null;
            let requester = Requester { auth: &auth, now: 0 };
            let expected = grants.contains(&Some(true));
            prop_assert_eq!(rules.can_read(None, &path, None, &requester), expected);
        }

        /// A rule and its negation are never both true, and a pattern fireemu does not read as
        /// the official emulator does (`(?`, `[[:`, an escaped letter or digit other than
        /// `\d \D \w \W`) makes both false.
        #[test]
        fn a_match_and_its_negation_never_both_pass(
            parts in prop::collection::vec(
                prop::sample::select(vec![
                    "a", "b", ".", "*", "+", "?", "(", ")", "[", "]", "^", "$", "(?", "[[:",
                    "\\d", "\\w", "\\n", "\\1", "\\b", "\\.", "{2}", "|", ":",
                ]),
                1..6,
            ),
            subject in "[ab?:(\\[\\].n1]{0,4}",
        ) {
            let pattern = parts.concat();
            let tree = seed();
            let auth = auth();
            let requester = Requester { auth: &auth, now: 0 };
            let decide = |text: String| {
                Rules::compile(&read_rule_at_t(&text))
                    .ok()
                    .map(|rules| rules.can_read(tree.root(), &p("/t"), None, &requester))
            };
            let subject = subject.replace(['\\', '\''], "");
            let plain = decide(format!("'{subject}'.matches(/{pattern}/)"));
            let negated = decide(format!("!'{subject}'.matches(/{pattern}/)"));
            if let (Some(plain), Some(negated)) = (plain, negated) {
                prop_assert!(!(plain && negated), "{pattern} {subject}");
                let unread = pattern.contains("(?")
                    || pattern.contains("[[:")
                    || ["\\n", "\\1", "\\b"].iter().any(|e| pattern.contains(e));
                if unread {
                    prop_assert!(!plain && !negated, "{pattern} {subject}");
                }
            }
        }

        /// A write is allowed exactly when some `.write` at or above the location it is judged
        /// at is true: rules below that location never allow it, and a priority is judged at its
        /// node, a `$wildcard` below the node included.
        #[test]
        fn writes_are_judged_at_or_above_their_node(
            grants in prop::collection::vec(
                (prop::option::of(any::<bool>()), prop::option::of(any::<bool>())),
                1..5,
            ),
            depth in 1usize..5,
            priority in any::<bool>(),
        ) {
            // Level i holds key keys[i] with a `.write` of grants[i].0, and a `$w` wildcard
            // beside it with grants[i].1.
            let keys = ["a", "b", "c", "d", "e"];
            let mut spec = RuleSpec::default();
            for (level_at, (exact, wildcard)) in grants.iter().enumerate().rev() {
                let mut level = RuleSpec::default();
                level.write = exact.map(RuleSource::Bool);
                // The next level's key and wildcard sit inside this one.
                level.children = std::mem::take(&mut spec.children);
                let mut wild = RuleSpec::default();
                wild.write = wildcard.map(RuleSource::Bool);
                let mut holder = RuleSpec::default();
                holder.children.insert(keys[level_at].to_owned(), level);
                holder.children.insert("$w".to_owned(), wild);
                spec = holder;
            }
            // `spec` is the root's level: the root holds keys[0] and `$w`.
            let rules = Rules::compile(&spec).unwrap();
            let node = Path::from_keys(keys[..depth].iter().copied());
            let written = if priority { node.child(".priority") } else { node.clone() };
            let auth = Json::Null;
            let requester = Requester { auth: &auth, now: 0 };
            // The levels the walk to `node` visits: keys[0..depth] exactly while they exist.
            let expected = (0..depth.min(grants.len())).any(|i| grants[i].0 == Some(true));
            prop_assert_eq!(
                rules.can_write(None, None, std::slice::from_ref(&written), &requester),
                expected
            );
        }
    }
}

/// The stack of the daemon's server workers, where rules are evaluated
/// (`RUNTIME_THREAD_STACK_BYTES` in fireemu's daemon).
const WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

fn on_stack<T: Send + 'static>(bytes: usize, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// Loads `.read: <text>` at `/t` where the adapter loads it: on a thread with room for the
/// bound.
fn load_deep(text: String) -> Result<Rules, String> {
    on_stack(256 * 1024 * 1024, move || {
        Rules::compile(&read_rule_at_t(&text)).map_err(|error| error.message)
    })
}

/// An expression of a shape, nested `n` deep.
type Shape = fn(usize) -> String;

#[test]
fn every_level_counts_and_a_rule_at_the_bound_is_evaluated_on_a_worker_stack() {
    // Each shape, and the deepest `n` that loads: one level per group, `!`, conditional or
    // `-`, two per `.child()` or `.parent()` call (the member and the call), one per index.
    let shapes: Vec<(&str, Shape, usize)> = vec![
        (
            "groups",
            |n| format!("{}true{}", "(".repeat(n), ")".repeat(n)),
            599,
        ),
        ("not", |n| format!("{}true", "!".repeat(n)), 599),
        (
            "child",
            |n| format!("root{}.val() == null", ".child('a')".repeat(n)),
            298,
        ),
        (
            "parent",
            |n| format!("data{}.val() == null", ".parent()".repeat(n)),
            298,
        ),
        (
            "index",
            |n| format!("auth{} == null", "['a']".repeat(n)),
            598,
        ),
        (
            "ternary then",
            |n| format!("{}true{}", "true ? ".repeat(n), " : false".repeat(n)),
            599,
        ),
        (
            "ternary otherwise",
            |n| format!("{}true", "false ? false : ".repeat(n)),
            599,
        ),
        ("minus", |n| format!("1{} < 0", " - 1".repeat(n)), 598),
    ];
    let tree = seed();
    for (name, shape, expected) in shapes {
        // The deepest that loads, found by bisection, is within the bound.
        let (mut ok, mut refused) = (1usize, 2_000usize);
        assert!(load_deep(shape(ok)).is_ok(), "{name}");
        while refused - ok > 1 {
            let mid = usize::midpoint(ok, refused);
            if load_deep(shape(mid)).is_ok() {
                ok = mid;
            } else {
                refused = mid;
            }
        }
        // 600 levels: the levels each shape adds, and the ones around it, fill the bound.
        assert_eq!(ok, expected, "{name}");
        for deeper in [ok + 1, 10_000] {
            assert_eq!(
                load_deep(shape(deeper)).unwrap_err(),
                "Rule expression may not be empty.",
                "{name} {deeper}"
            );
        }
        // The deepest is evaluated on a worker's stack without running out of it.
        let rules = load_deep(shape(ok)).unwrap();
        let root = tree.root().cloned();
        on_stack(WORKER_STACK_BYTES, move || {
            let auth = auth();
            let requester = Requester {
                auth: &auth,
                now: 0,
            };
            let _ = rules.can_read(root.as_ref(), &p("/t"), None, &requester);
        });
    }
}

/// `1 - (inner) - 0 - 0 …`: the inner expression lands `tail` levels below the outermost
/// operator although it is read first.
fn left_nested(inner: &str, tail: usize) -> String {
    format!("1 - ({inner}){}", " - 0".repeat(tail))
}

#[test]
fn shallow_pieces_composed_deep_are_refused_at_load() {
    // Each piece is within the bound alone; composed they are thousands of levels deep
    // (review r3 M6c), and are refused however they nest.
    let nest = |piece: &dyn Fn(&str) -> String, seed: &str, times: usize| {
        (0..times).fold(seed.to_owned(), |inner, _| piece(&inner))
    };
    let sub = nest(&|inner| left_nested(inner, 590), "1", 6);
    let parents = nest(
        &|inner| format!("root.child({inner}.val() + 'a'){}", ".parent()".repeat(590)),
        "root.child('a')",
        6,
    );
    let index = nest(
        &|inner| format!("auth[{inner} == null ? 'a' : 'b']{}", ".y".repeat(590)),
        "auth",
        6,
    );
    for text in [
        format!("{sub} < 0"),
        format!("{parents}.val() == null"),
        format!("{index} == null"),
        format!("({sub} < 0) ? true : false"),
        format!("true ? ({sub} < 0) : false"),
    ] {
        assert_eq!(
            load_deep(text.clone()).unwrap_err(),
            "Rule expression may not be empty.",
            "{}",
            &text[..40]
        );
    }
    // Composed within the bound, they load and are evaluated on a worker's stack.
    let tree = seed();
    for text in [
        format!("{} < 0", nest(&|inner| left_nested(inner, 90), "1", 6)),
        format!(
            "{}.val() == null",
            nest(
                &|inner| format!("root.child({inner}.val() + 'a'){}", ".parent()".repeat(40)),
                "root.child('a')",
                5,
            )
        ),
    ] {
        let rules = load_deep(text).unwrap();
        let root = tree.root().cloned();
        on_stack(WORKER_STACK_BYTES, move || {
            let auth = auth();
            let requester = Requester {
                auth: &auth,
                now: 0,
            };
            let _ = rules.can_read(root.as_ref(), &p("/t"), None, &requester);
        });
    }
}

#[test]
fn a_bare_postfix_chain_is_bounded_by_its_nodes() {
    // `!`, the receiver, 298 `.parent()` calls (two nodes each) and `.exists()`: 600 nodes,
    // and as many levels for the parser.
    let chain = |n: usize| format!("!root{}.exists()", ".parent()".repeat(n));
    assert!(load_deep(chain(298)).is_ok());
    assert_eq!(
        load_deep(chain(299)).unwrap_err(),
        "Rule expression may not be empty."
    );
}

#[test]
fn compiling_needs_no_stack_from_the_caller() {
    // Rules::compile parses on a thread of its own: 100,000 nested groups are refused on a
    // worker's stack without running out of it.
    let text = format!("{}true{}", "(".repeat(100_000), ")".repeat(100_000));
    let refused = on_stack(WORKER_STACK_BYTES, move || {
        Rules::compile(&read_rule_at_t(&text))
            .map(|_| ())
            .unwrap_err()
            .message
    });
    assert_eq!(refused, "Rule expression may not be empty.");
}

#[test]
fn levels_are_given_back_when_an_operand_ends() {
    // 700 operands side by side, each nested a few levels in every way, load: the levels of
    // one operand do not add to the next one's.
    for operand in [
        "data.child('a').val() == null",
        "(true ? true : false)",
        "(1 - 1 < 1)",
        "!(!true)",
        "auth['a']['b'] == null",
    ] {
        let text = vec![operand; 700].join(" && ");
        assert!(load_deep(text).is_ok(), "{operand}");
    }
}

#[test]
fn chains_of_one_associative_operator_have_no_depth() {
    let tree = seed();
    for (text, allowed) in [
        (vec!["false"; 5_000].join(" || ") + " || true", true),
        (vec!["true"; 5_000].join(" && "), true),
        (vec!["true"; 5_000].join(" && ") + " && false", false),
        (format!("{} != ''", vec!["'a'"; 5_000].join(" + ")), true),
        (format!("{} == 5000", vec!["1"; 5_000].join(" + ")), true),
    ] {
        let rules = load_deep(text).unwrap();
        let root = tree.root().cloned();
        let decided = on_stack(WORKER_STACK_BYTES, move || {
            let auth = auth();
            let requester = Requester {
                auth: &auth,
                now: 0,
            };
            rules.can_read(root.as_ref(), &p("/t"), None, &requester)
        });
        assert_eq!(decided, allowed);
    }
    // A chain reads left to right: a string met first makes the rest text.
    let rules = load_deep("1 + 2 + 'a' + 1 + 2 == '3a12'".to_owned()).unwrap();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 0,
    };
    assert!(rules.can_read(tree.root(), &p("/t"), None, &requester));
}

#[test]
fn coverage_observation_can_be_disabled_without_changing_authorization() {
    let expressions = [
        "true",
        "false",
        "true || data.val().contains('x')",
        "data.val().contains('x')",
        "'é😀'.length == 3",
        "auth != null && auth.uid == 'u1'",
    ];
    for expression in expressions {
        let rules = Rules::compile(&read_rule_at_t(expression)).unwrap();
        rules.set_coverage_enabled(false);
        let tree = seed();
        let auth = auth();
        let requester = Requester {
            auth: &auth,
            now: 123,
        };
        let expected = rules.can_read(tree.root(), &p("t"), None, &requester);
        let empty = rules.coverage_report();
        rules.set_coverage_enabled(true);
        assert_eq!(
            rules.can_read(tree.root(), &p("t"), None, &requester),
            expected,
            "{expression}"
        );
        assert_ne!(rules.coverage_report(), empty, "{expression}");
    }
}

fn assert_coverage_ranges(text: &str) {
    let spec = read_rule_at_t(text);
    let rules = Rules::compile(&spec).unwrap();
    let RuleSource::Expr(source) = spec.children["t"].read.as_ref().unwrap() else {
        panic!("expression")
    };
    let (row, column) = source.positions[0];
    let mut at = (row - 1, column - 1);
    let mut positions = std::collections::BTreeMap::new();
    let mut index = 0;
    for character in text.chars() {
        for unit in 0..character.len_utf16() {
            positions.insert(format!("{}:{}", at.0, at.1 + unit), index + unit);
        }
        index += character.len_utf16();
        if character == '\n' {
            at = (at.0 + 1, 0);
        } else {
            at.1 += character.len_utf16();
        }
    }
    let encoded: Vec<_> = text.encode_utf16().collect();
    let report = rules.coverage_report();
    let Json::Object(report) = report else {
        panic!("object")
    };
    let Json::Object(level) = &report["t"] else {
        panic!("object")
    };
    let mut pending = vec![&level[".read"]];
    while let Some(node) = pending.pop() {
        let Json::Object(node) = node else {
            panic!("expression")
        };
        let Json::String(start) = &node["location-start"] else {
            panic!("start")
        };
        let Json::String(end) = &node["location-end"] else {
            panic!("end")
        };
        let Json::String(actual) = &node["text"] else {
            panic!("text")
        };
        let first = positions[start];
        let last = positions[end];
        assert_eq!(String::from_utf16(&encoded[first..=last]).unwrap(), *actual);
        if let Some(Json::Array(children)) = node.get("children") {
            pending.extend(children);
        }
    }
}

#[test]
fn coverage_keeps_local_escaped_literal_and_multiline_spans() {
    for text in [
        r"'a\\b'.length > 0",
        r"'a\'b'.length > 0",
        "('é😀'.length > 0) &&\n true",
        "true && true && false || true",
        "auth['uid'] == 'u1'",
        "query.orderByChild == 'a/b'",
    ] {
        assert_coverage_ranges(text);
    }
}

/// Review M1 (2026-10-25): coverage is collected for every evaluation of a long-lived daemon,
/// so it must stay bounded. Opaque snapshot identities are fresh on every evaluation and `now`
/// differs on every request; neither may grow a histogram past its cap, and every recording
/// is still counted, either under a kept value or as omitted.
#[test]
#[allow(clippy::cast_possible_truncation)]
fn coverage_histograms_stay_bounded_over_many_evaluations() {
    const EVALUATIONS: i64 = 5_000;
    let rules = Rules::compile(&read_rule_at_t("data.child('x').exists() || now > 0")).unwrap();
    let tree = seed();
    let auth = auth();
    for now in 1..=EVALUATIONS {
        let requester = Requester { auth: &auth, now };
        assert!(rules.can_read(tree.root(), &p("t"), None, &requester));
    }
    let report = rules.coverage_report();
    let Json::Object(report) = &report else {
        panic!("object")
    };
    let Json::Object(level) = &report["t"] else {
        panic!("object")
    };
    let mut pending = vec![(&level[".read"], true)];
    let mut largest = 0;
    while let Some((node, top)) = pending.pop() {
        let Json::Object(node) = node else {
            panic!("expression")
        };
        let Json::Array(values) = &node["values"] else {
            panic!("values")
        };
        largest = largest.max(values.len());
        assert!(
            values.len() <= fireemu_core_database::rules::COVERAGE_VALUES_PER_EXPRESSION,
            "{} kept values for {:?}",
            values.len(),
            node["text"]
        );
        let kept: i64 = values
            .iter()
            .map(|value| match value {
                Json::Object(entry) => match &entry["count"] {
                    Json::Number(count) => count.as_f64() as i64,
                    other => panic!("count {other:?}"),
                },
                other => panic!("entry {other:?}"),
            })
            .sum();
        let omitted = match node.get("values-omitted") {
            Some(Json::Number(count)) => count.as_f64() as i64,
            None => 0,
            Some(other) => panic!("omitted {other:?}"),
        };
        assert!(
            !matches!(node.get("values-omitted"), Some(Json::Number(count)) if count.as_f64() == 0.0),
            "an empty omitted count is left out, as the official report has no such field"
        );
        // `now` is evaluated every time (the first operand is false) with a new value.
        if top || node["text"] == Json::string("now") {
            assert_eq!(kept + omitted, EVALUATIONS, "{:?}", node["text"]);
        }
        if node["text"] == Json::string("now") {
            assert_eq!(
                omitted,
                EVALUATIONS
                    - i64::try_from(fireemu_core_database::rules::COVERAGE_VALUES_PER_EXPRESSION)
                        .unwrap()
            );
        }
        if let Some(Json::Array(children)) = node.get("children") {
            pending.extend(children.iter().map(|child| (child, false)));
        }
    }
    assert_eq!(
        largest,
        fireemu_core_database::rules::COVERAGE_VALUES_PER_EXPRESSION
    );
}

#[test]
fn auth_root_identity_matches_the_recorded_read() {
    let tree = seed();
    let auth = j(serde_json::json!({"uid": "synthetic-user"}));
    let requester = Requester {
        auth: &auth,
        now: 1_792_464_733_000,
    };
    let rules = Rules::compile(&read_rule_at_t(
        "auth != null && auth.uid == 'synthetic-user' && auth == auth",
    ))
    .unwrap();
    assert!(rules.can_read(tree.root(), &p("/t"), None, &requester));
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]

    #[test]
    fn root_auth_identity_through_rules_for_varied_claims(
        uid in "[a-zA-Z0-9]{1,20}",
        score in proptest::prelude::any::<i32>(),
        enabled in proptest::prelude::any::<bool>(),
    ) {
        let tree = seed();
        let auth = j(serde_json::json!({"uid": uid, "score": score, "enabled": enabled}));
        let requester = Requester { auth: &auth, now: 0 };
        let guard = Rules::compile(&read_rule_at_t("auth != null && auth == auth")).unwrap();
        let negated = Rules::compile(&read_rule_at_t("auth != null && !(auth == auth)")).unwrap();
        proptest::prop_assert!(guard.can_read(tree.root(), &p("/t"), None, &requester));
        proptest::prop_assert!(!negated.can_read(tree.root(), &p("/t"), None, &requester));

        let anonymous = Json::Null;
        let requester = Requester { auth: &anonymous, now: 0 };
        let null_control = Rules::compile(&read_rule_at_t("auth == null && auth == auth")).unwrap();
        proptest::prop_assert!(null_control.can_read(tree.root(), &p("/t"), None, &requester));
        proptest::prop_assert!(!guard.can_read(tree.root(), &p("/t"), None, &requester));
    }
}

/// A snapshot in a `.write` rule at `/t`: `root`, `data` or `newData`, then `child` and
/// `parent` steps.
#[derive(Debug, Clone)]
struct SnapshotExpr {
    base: usize,
    steps: Vec<Option<&'static str>>,
}

impl SnapshotExpr {
    const BASES: [&'static str; 3] = ["root", "data", "newData"];

    fn text(&self) -> String {
        let mut text = Self::BASES[self.base].to_owned();
        for step in &self.steps {
            match step {
                Some(key) => {
                    text.push_str(".child('");
                    text.push_str(key);
                    text.push_str("')");
                }
                None => text.push_str(".parent()"),
            }
        }
        text
    }

    /// The version it reads (`newData`'s or the tree before the write) and its keys, or
    /// `None` when a `parent()` of the root makes it an error.
    fn identity(&self) -> Option<(bool, Vec<&'static str>)> {
        let mut keys = if self.base == 0 {
            Vec::new()
        } else {
            vec!["t"]
        };
        for step in &self.steps {
            match step {
                Some(key) => keys.push(key),
                None => {
                    keys.pop()?;
                }
            }
        }
        Some((self.base == 2, keys))
    }
}

fn snapshot_expr() -> impl proptest::strategy::Strategy<Value = SnapshotExpr> {
    use proptest::prelude::*;
    let step = prop_oneof![
        Just(Some("t")),
        Just(Some("o")),
        Just(Some("k")),
        Just(None::<&'static str>),
    ];
    (0..3usize, proptest::collection::vec(step, 0..4))
        .prop_map(|(base, steps)| SnapshotExpr { base, steps })
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(256))]

    /// Two snapshots are equal when they read the same version of the tree at the same
    /// location, as the official emulator compares them (review r9 M25, option (a)); a
    /// ternary lets the comparison past the static check.
    #[test]
    fn snapshots_are_equal_when_they_read_one_version_at_one_location(
        left in snapshot_expr(),
        right in snapshot_expr(),
        signed_in in proptest::prelude::any::<bool>(),
    ) {
        let before = seed();
        let mut after = before.clone();
        after.set(&p("/t/o/k"), &j(serde_json::json!("w")), support::NOW).unwrap();
        let auth = if signed_in { auth() } else { Json::Null };
        let requester = Requester { auth: &auth, now: 0 };
        let expected = match (left.identity(), right.identity()) {
            (Some(l), Some(r)) => Some(l == r),
            _ => None,
        };
        for (op, holds) in [("==", expected), ("!=", expected.map(|equal| !equal))] {
            let text = format!(
                "(auth != null ? {} : 'a') {op} (auth != null ? {} : 'a')",
                left.text(),
                right.text()
            );
            let mut t = RuleSpec::default();
            t.write = Some(expr(&text));
            let mut root = RuleSpec::default();
            root.children.insert("t".to_owned(), t);
            let rules = Rules::compile(&root).unwrap();
            let allowed =
                rules.can_write(before.root(), after.root(), &[p("/t/o/k")], &requester);
            // Anonymously both sides are 'a'.
            let holds = if signed_in { holds == Some(true) } else { op == "==" };
            proptest::prop_assert_eq!(allowed, holds, "{}", text);
        }
    }
}

#[test]
fn query_equals_itself_through_a_ternary() {
    let tree = seed();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 0,
    };
    for (text, allowed) in [
        ("(true ? query : 'a') == (true ? query : 'a')", true),
        ("(true ? query : 'a') != (true ? query : 'a')", false),
        ("(true ? query : 'a') == (true ? data : 'a')", false),
        (
            "(true ? data : 'a') == (true ? root.child('t') : 'a')",
            true,
        ),
        (
            "(true ? data.val() : 'a') == (true ? data.val() : 'a')",
            false,
        ),
        (
            "(true ? auth.token : 'a') == (true ? auth.token : 'a')",
            false,
        ),
    ] {
        let rules = Rules::compile(&read_rule_at_t(text)).unwrap();
        assert_eq!(
            rules.can_read(tree.root(), &p("/t"), None, &requester),
            allowed,
            "{text}"
        );
    }
}

/// An astral string with the empty string replaced: Java puts the replacement between the halves of a
/// pair, which is a string with lone surrogates, so the answer is the jar's (owner 2270 (2)).
#[test]
fn replacing_the_empty_string_in_an_astral_string_splits_its_pair() {
    for (expr, expected) in [
        ("'😀'.replace('', 'x').length == 5", true),
        ("!('😀'.replace('', 'x').length == 5)", false),
        ("'\\uD83D\\uDE00'.replace('', 'y').length == 5", true),
        ("'😀'.replace('', 'x') == 'x\\uD83Dx\\uDE00x'", true),
        ("'😀a'.replace('', '').length == 3", true),
    ] {
        assert_eq!(reads(expr), expected, "{expr}");
    }
}

/// Reads `/t` as user `u1` with `expr` as the rule.
fn reads(expr: &str) -> bool {
    let rules = Rules::compile(&read_rule_at_t(expr)).unwrap();
    let tree = seed();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 123,
    };
    rules.can_read(tree.root(), &p("t"), None, &requester)
}

/// A string a Rules operation builds is bounded before it is allocated (Codex r2 Must): ten chained
/// `replace('', '0123456789')` would reach 5e10 units. Up to the bound the answer is the jar's (seven
/// chained replaces, 3.9e7 units, answer there under a 512 MB heap; eight, 4.3e8, are a 500, negated or
/// not); past it the operation is an error, so the rule is false negated or not, for lone-surrogate
/// strings and ordinary ones alike.
#[test]
fn a_string_grown_past_the_bound_is_an_error_negated_or_not() {
    for base in ["'\\uD83D'", "'a'"] {
        let chain = |n: usize| format!("{base}{}", ".replace('', '0123456789')".repeat(n));
        assert!(
            reads(&format!("{}.length == 38974341", chain(7))),
            "{base} seven"
        );
        assert!(
            reads(&format!("!({}.length == 0)", chain(7))),
            "{base} seven negated"
        );
        for n in [8, 9, 10] {
            assert!(!reads(&format!("{}.length == 0", chain(n))), "{base} {n}");
            assert!(
                !reads(&format!("!({}.length == 0)", chain(n))),
                "{base} {n} negated"
            );
        }
        // `+` is bounded on the same terms: 2 x 3.5e6 is within it, 2 x 3.9e7 is not.
        assert!(reads(&format!(
            "({} + {}).length == 7086242",
            chain(6),
            chain(6)
        )));
        assert!(!reads(&format!(
            "({} + {}).length == 0",
            chain(7),
            chain(7)
        )));
        assert!(!reads(&format!(
            "!(({} + {}).length == 0)",
            chain(7),
            chain(7)
        )));
    }
    // A target that is not empty grows as fast: every `a` becomes a hundred.
    let hundred = "a".repeat(100);
    for start in ["'a'", "'a\\uD83D'"] {
        let grow = |n: usize| format!("{start}{}", format!(".replace('a', '{hundred}')").repeat(n));
        assert!(reads(&format!("{}.length >= 1000000", grow(3))), "{start}");
        assert!(!reads(&format!("{}.length == 0", grow(4))), "{start}");
        assert!(!reads(&format!("!({}.length == 0)", grow(4))), "{start}");
    }
}

/// The Rules coverage report names a value by a JSON string, which cannot hold a lone surrogate: a literal that holds one
/// is shown with U+FFFD for each (the character the report would otherwise lose). Decisions are not affected.
#[test]
fn the_coverage_report_shows_a_lone_surrogate_literal_with_the_replacement_character() {
    let spec = read_rule_at_t(r"'\uD83D'.length == 1");
    let rules = Rules::compile(&spec).unwrap();
    rules.set_coverage_enabled(true);
    let tree = seed();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 123,
    };
    assert!(rules.can_read(tree.root(), &p("t"), None, &requester));
    let report = format!("{:?}", rules.coverage_report());
    assert!(
        report.contains(&format!(
            r#"String("'\\uD83D'"), "values": Array([Object({{"count": Number(Int(1)), "value": String("{}")}})])"#,
            '\u{fffd}'
        )),
        "{report}"
    );
}

/// Reads `/t` with the data `tree` and `expr` as the rule.
fn reads_in(tree: &fireemu_core_database::Tree, expr: &str) -> bool {
    let rules = Rules::compile(&read_rule_at_t(expr)).unwrap();
    let auth = auth();
    let requester = Requester {
        auth: &auth,
        now: 123,
    };
    rules.can_read(tree.root(), &p("t"), None, &requester)
}

/// Case conversion is measured before it allocates, in both string paths: a string just under the size bound that
/// grows past it when converted (`ﬃ` is `FFI`, `ΐ` is three characters, six bytes for two) is an error, negated or
/// not (Astra review of 985528f1c).
#[test]
fn case_conversion_past_the_size_bound_is_an_error_before_it_allocates() {
    // The units path: 2^25 - 1 units of `ﬃ`, which become 3 units each.
    let doubled = |start: &str, to: &str, n: usize| {
        format!("{start}{}", format!(".replace('', '{to}')").repeat(n))
    };
    let units = doubled("'\\uD83D'", "\\uFB03", 24);
    assert!(reads(&format!("{units}.length == 33554431")));
    for expr in [
        format!("{units}.toUpperCase().length > 67108864"),
        format!("!({units}.toUpperCase().length > 67108864)"),
    ] {
        assert!(!reads(&expr), "units path");
    }
    // The Str path: 2^24 - 1 characters of `ΐ`, 2 bytes each, become 6 bytes each.
    let text = doubled("'\u{390}'", "\u{390}", 23);
    assert!(reads(&format!("{text}.length == 16777215")));
    for expr in [
        format!("{text}.toUpperCase().length > 0"),
        format!("!({text}.toUpperCase().length > 0)"),
    ] {
        assert!(!reads(&expr), "str path");
    }
    // Within the bound the same conversion answers.
    assert!(reads(&format!(
        "{}.toUpperCase().length == 7",
        doubled("'\\uD83D'", "\\uFB03", 1)
    )));
}

/// Evaluation work is bounded, not only the size of one result: a long stored string joined again and again, each
/// time below the size bound, stops; a search is linear, so a long string and a long needle that almost matches
/// answer at once (Astra review of 985528f1c).
#[test]
fn repeated_work_on_long_strings_stops_and_a_search_is_linear() {
    let long = "a".repeat(8 * 1024 * 1024);
    let tree = tree_with(serde_json::json!({"t": {"h": long}}));
    // Eight MiB read a few times is ordinary; read two hundred times it is past the bound (2^30).
    let join = |times: usize| {
        format!(
            "(root.child('t').child('h').val(){}).length > 0",
            " + ''".repeat(times)
        )
    };
    assert!(reads_in(&tree, &join(10)));
    for times in [200, 1000] {
        assert!(!reads_in(&tree, &join(times)), "{times}");
        assert!(
            !reads_in(&tree, &format!("!({})", join(times))),
            "{times} negated"
        );
    }
    // The quadratic search of the review: 1 MiB of `a` and an almost matching needle of 512 KiB.
    let haystack = "a".repeat(1024 * 1024);
    let needle = format!("{}b", "a".repeat(512 * 1024));
    let tree = tree_with(serde_json::json!({"t": {"h": haystack, "n": needle}}));
    let started = std::time::Instant::now();
    let found = reads_in(
        &tree,
        "(root.child('t').child('h').val() + '\\uD83D').contains(root.child('t').child('n').val())",
    );
    assert!(!found);
    assert!(
        reads_in(
            &tree,
            "!((root.child('t').child('h').val() + '\\uD83D').contains(root.child('t').child('n').val()))"
        ),
        "the search answers false, not an error"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
}

/// The bound is sized on purpose: a maximum-size stored string (10 MiB) is read and searched thirteen times by an
/// honest rule without being denied (the case Astra's review of 2258af58e named), and is denied, negated or not, when
/// a rule does it a hundred and twenty times.
#[test]
fn honest_large_rules_are_not_denied_and_runaway_ones_are() {
    let tree = tree_with(serde_json::json!({"t": {"h": "a".repeat(10 * 1024 * 1024)}}));
    let search = "root.child('t').child('h').val().contains('a')";
    let rule = |times: usize| vec![search; times].join(" && ");
    assert!(reads_in(&tree, &rule(13)));
    assert!(reads_in(&tree, &rule(40)));
    for times in [120, 400] {
        assert!(!reads_in(&tree, &rule(times)), "{times}");
        assert!(
            !reads_in(&tree, &format!("!({})", rule(times))),
            "{times} negated"
        );
    }
}

/// Building a location from a long path string costs its keys once, charged: Astra's quadratic example (a 50,000-key
/// path read from the data, through `child`, `hasChild` and `hasChildren`) finishes at once, and a rule that does it
/// again and again stops at the evaluation bound.
#[test]
fn a_location_built_from_a_long_path_is_neither_quadratic_nor_free() {
    let long = "a/".repeat(50_000);
    let tree = tree_with(serde_json::json!({"t": {"p": long}}));
    let started = std::time::Instant::now();
    assert!(reads_in(
        &tree,
        "!root.child(root.child('t').child('p').val()).exists()"
    ));
    assert!(reads_in(
        &tree,
        "!root.hasChild(root.child('t').child('p').val())"
    ));
    assert!(reads_in(
        &tree,
        "!root.child(root.child('t').child('p').val()).hasChildren()"
    ));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    // Each use copies the 100,000-byte string and builds 50,000 keys: ten thousand of them pass the bound.
    let once = "!root.hasChild(root.child('t').child('p').val())";
    let many = vec![once; 12_000].join(" && ");
    assert!(!reads_in(&tree, &many));
    assert!(!reads_in(&tree, &format!("!({many})")));
}

/// Copying the claims is work by their size: a rule that uses a large `auth` many times stops at the bound, whether
/// or not it is negated, while a few uses are allowed.
#[test]
fn copies_of_the_claims_are_charged() {
    let big = j(serde_json::json!({"uid": "u1", "token": {"blob": "x".repeat(1024 * 1024)}}));
    let tree = tree_with(serde_json::json!({"t": {"s": 1}}));
    let reads = |expr: &str| {
        Rules::compile(&read_rule_at_t(expr)).unwrap().can_read(
            tree.root(),
            &p("t"),
            None,
            &Requester { auth: &big, now: 0 },
        )
    };
    let rule = |times: usize| vec!["auth != null"; times].join(" && ");
    assert!(reads(&rule(10)));
    assert!(reads(&rule(500)));
    assert!(!reads(&rule(2000)));
    assert!(!reads(&format!("!({})", rule(2000))));
    // The items of an array are copied with it.
    let listed =
        j(serde_json::json!({"uid": "u1", "token": {"list": ["x".repeat(1024 * 1024), 1]}}));
    let reads_listed = |expr: &str| {
        Rules::compile(&read_rule_at_t(expr)).unwrap().can_read(
            tree.root(),
            &p("t"),
            None,
            &Requester {
                auth: &listed,
                now: 0,
            },
        )
    };
    let list = |times: usize| vec!["auth.token.list != null"; times].join(" && ");
    assert!(reads_listed(&list(10)));
    assert!(!reads_listed(&list(2000)));
    // A nested value read from the claims is copied too.
    let nested = |times: usize| vec!["auth.token != null"; times].join(" && ");
    assert!(reads(&nested(10)));
    assert!(!reads(&nested(2000)));
}

/// The ordinary rules of the Rules corpora use a tiny fraction of the evaluation work bound (2^30): the most any
/// one evaluation does stays under 2^18, a thousandth of it.
#[test]
fn ordinary_rules_stay_far_below_the_evaluation_work_bound() {
    fireemu_core_database::rules::reset_evaluation_work_high_water();
    for fixture in [
        include_str!("fixtures/rules-expressions-official-emulator-4.11.2.json"),
        include_str!("fixtures/rules-expressions-2-official-emulator-4.11.2.json"),
        include_str!("fixtures/rules-expressions-3-official-emulator-4.11.2.json"),
        include_str!("fixtures/rules-lone-surrogates-official-emulator-4.11.2.json"),
        include_str!("fixtures/rules-query-orderby-official-emulator-4.11.2.json"),
        include_str!("fixtures/rules-regex-dialect-official-emulator-4.11.2.json"),
    ] {
        let _ = differences_with(fixture, true);
    }
    let high = fireemu_core_database::rules::evaluation_work_high_water();
    assert!(high < 1 << 18, "the most work one evaluation did: {high}");
    assert!(high > 0);
}

/// The high-water mark follows the most work one evaluation did, keeps it across smaller ones, and starts again
/// from zero when it is reset.
#[test]
fn the_high_water_mark_follows_the_most_work_one_evaluation_did() {
    use fireemu_core_database::rules::{
        evaluation_work_high_water, reset_evaluation_work_high_water,
    };
    reset_evaluation_work_high_water();
    assert_eq!(evaluation_work_high_water(), 0);
    assert!(reads("data.child('s').val().contains('ell')"));
    let large = evaluation_work_high_water();
    assert!(large >= 5, "{large}");
    assert!(reads("data.child('n').val() == 5"));
    assert_eq!(
        evaluation_work_high_water(),
        large,
        "a smaller one keeps the mark"
    );
    reset_evaluation_work_high_water();
    assert_eq!(evaluation_work_high_water(), 0);
    assert!(reads("data.child('s').val().length == 5"));
    let small = evaluation_work_high_water();
    assert!(small > 0 && small < large + 100, "{small}");
}

/// The emulator profile reads a pattern by UTF-16 unit and a backslash before a line terminator or a character beyond
/// ASCII as the official emulator does: 289 rows of the jar (a character beyond the Basic Multilingual Plane is two
/// class members and two units for `.`; after a backslash CR, CR LF, U+2028 and U+2029 are a line feed, and U+FEFF and
/// U+0085 are themselves).
#[test]
fn the_emulator_profile_reads_utf16_units_and_escaped_line_characters_as_the_official_emulator() {
    let fixture =
        include_str!("fixtures/rules-regex-escapes-and-units-official-emulator-4.11.2.json");
    let failures = differences_with(fixture, true);
    assert!(
        failures.is_empty(),
        "{} rows differ: {failures:#?}",
        failures.len()
    );
}

/// The edges of the emulator profile's class grammar: an end at U+FFFF is a character like another, a class that
/// holds nothing matches nothing and its negation any one character, and a range whose end is an astral character
/// ends at its high surrogate (its low surrogate is a member of its own).
#[test]
fn the_class_grammar_of_the_emulator_profile_at_the_edges_of_the_basic_plane() {
    let jar = |expr: &str| {
        Rules::compile(&read_rule_at_t(expr))
            .unwrap()
            .with_jar_dialect(true)
            .can_read(
                seed().root(),
                &p("t"),
                None,
                &Requester {
                    auth: &auth(),
                    now: 123,
                },
            )
    };
    assert!(jar("'b'.matches(/^[a-\u{FFFF}]$/)"));
    assert!(jar("'\u{FFFF}'.matches(/^[a-\u{FFFF}]$/)"));
    assert!(jar("'\u{FFFF}'.matches(/^[\u{FFFF}-\u{FFFF}]$/)"));
    assert!(jar("'\u{FFFF}'.matches(/^[\u{FFFF}-]$/)"));
    assert!(jar("'-'.matches(/^[\u{FFFF}-]$/)"));
    // `[a-😀]` is `a` to the high surrogate and the low surrogate: `b` is in it, the pair is two units.
    assert!(jar("'b'.matches(/^[a-\u{1F600}]$/)"));
    assert!(jar("'\\uDE00'.matches(/^[a-\u{1F600}]$/)"));
    assert!(!jar("'\u{1F600}'.matches(/^[a-\u{1F600}]$/)"));
    assert!(jar("'\u{1F600}'.matches(/^[a-\u{1F600}]{2}$/)"));
    assert!(jar("'a'.matches(/^[a\u{1F600}]$/)"));
    assert!(jar("!('\u{1F600}'.matches(/^[\u{1F600}]$/))"));
    assert!(jar("'zx'.matches(/^[^b-a]x$/)"));
    assert!(!jar("'x'.matches(/^[b-a]x$/)"));
    // A `\W` in the pattern is read by the same grammar.
    assert!(jar("'b!'.matches(/^[a-\u{FFFF}]\\W$/)"));
    assert!(jar("'\u{FFFF}!'.matches(/^[\u{FFFF}-\u{FFFF}]\\W$/)"));
    assert!(jar("'-!'.matches(/^[\u{FFFF}-]\\W$/)"));
}
