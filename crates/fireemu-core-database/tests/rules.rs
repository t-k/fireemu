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
        positions.push((1, column));
        column += if c == '"' || c == '\\' { 2 } else { 1 };
    }
    positions.push((1, column));
    let mut t = RuleSpec::default();
    t.read = Some(RuleSource::Expr(SourceExpr {
        text: expr.to_owned(),
        positions,
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
        let compiled = Rules::compile(&read_rule_at_t(expr));
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
        r#""'a'.matches(/^a**$/)" : read false, expected true"#,
        r#""'aaa'.matches(/^a**$/)" : read false, expected true"#,
        r#""''.matches(/^a**$/)" : read false, expected true"#,
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
        r#""'a'.matches(/a**/)" : read false, expected true"#,
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
        ("minus", |n| format!("1{} < 0", " - 1".repeat(n)), 599),
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
