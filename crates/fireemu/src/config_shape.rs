//! The shape of a canonical configuration document, checked against the embedded JSON schema.
//!
//! The loader in `config.rs` reads each key by hand, and a hand-written reader that asks for
//! a string and receives a number would quietly fall back to the default. This pass runs over
//! the whole document first, so that a misspelt key, or a value of the wrong type, is refused
//! with the key's path and what it should have been, for `fireemu.toml` and `fireemu.json`
//! alike (the CLI turns TOML into the same JSON value before it gets here).
//!
//! Only the structure is checked here: `type`, `properties`, `additionalProperties`, `items`,
//! `required`, `$ref`, `enum`, `const`, `minimum`, `maximum` and the alternatives of `oneOf`
//! and `anyOf`. Patterns, formats, lengths and the cross-field rules stay with the loader,
//! which reports them in its own words.

use serde_json::Value;

use crate::config::ConfigError;

/// The embedded schema, parsed once.
fn schema() -> &'static Value {
    static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!("../../../spec/config/fireemu.schema.json"))
            .expect("embedded configuration schema")
    })
}

/// Checks `document` against the shape the embedded schema describes, then against the
/// cross-field rules the schema cannot express.
pub(crate) fn check(document: &Value) -> Result<(), ConfigError> {
    let root = schema();
    check_node(root, root, document, "").map_err(ConfigError)?;
    cross_field(document)
}

/// How a path reads in a diagnostic: the root has none.
fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// The schema a `$ref` such as `#/$defs/passwordPolicy` names.
fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    let mut node = node;
    // A reference chain ends at a definition; the bound keeps a cyclic schema from looping.
    for _ in 0..16 {
        let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
            return node;
        };
        let target = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer));
        node = target.expect("a schema $ref names a definition in the same schema");
    }
    node
}

/// A value's kind as a diagnostic says it.
fn found(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "an integer",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The schema type name of a value.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn expected(kind: &str) -> &'static str {
    match kind {
        "null" => "null",
        "boolean" => "a boolean",
        "integer" => "an integer",
        "number" => "a number",
        "string" => "a string",
        "array" => "an array",
        "object" => "an object",
        _ => "a value of another type",
    }
}

fn is_kind(value: &Value, kind: &str) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => true,
    }
}

fn at(path: &str) -> &str {
    if path.is_empty() {
        "the configuration"
    } else {
        path
    }
}

/// The constraints that concern one value alone: `type`, `const`, `enum`, `minimum`, `maximum`.
fn check_constraints(node: &Value, value: &Value, path: &str) -> Result<(), String> {
    if let Some(kinds) = node.get("type") {
        let kinds: Vec<&str> = match kinds {
            Value::String(kind) => vec![kind.as_str()],
            Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !kinds.is_empty() && !kinds.iter().any(|kind| is_kind(value, kind)) {
            let wanted: Vec<&str> = kinds.iter().map(|kind| expected(kind)).collect();
            return Err(format!(
                "{} must be {}, found {}",
                at(path),
                wanted.join(" or "),
                found(value)
            ));
        }
    }
    if let Some(constant) = node.get("const") {
        if value != constant {
            return Err(format!("{} must be {constant}", at(path)));
        }
    }
    if let Some(allowed) = node.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            let list: Vec<String> = allowed.iter().map(ToString::to_string).collect();
            let list = list.join(", ");
            // A value of another kind than the choices is named by what it should have been.
            let kind = allowed.first().map(kind_of);
            return Err(match kind {
                Some(kind)
                    if allowed.iter().all(|choice| kind_of(choice) == kind)
                        && kind_of(value) != kind =>
                {
                    format!(
                        "{} must be {} (one of {list}), found {}",
                        at(path),
                        expected(kind),
                        found(value)
                    )
                }
                _ => format!("{} must be one of {list}", at(path)),
            });
        }
    }
    if let Some(number) = value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
    {
        let bound = |keyword: &str| {
            node.get(keyword).and_then(|bound| {
                bound
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| bound.as_u64().map(i128::from))
            })
        };
        if let Some(minimum) = bound("minimum").filter(|minimum| number < *minimum) {
            return Err(format!("{} must be at least {minimum}", at(path)));
        }
        if let Some(maximum) = bound("maximum").filter(|maximum| number > *maximum) {
            return Err(format!("{} must be at most {maximum}", at(path)));
        }
    }
    Ok(())
}

/// One node of the schema against one value; the error names the first offending path.
fn check_node(root: &Value, node: &Value, value: &Value, path: &str) -> Result<(), String> {
    let node = resolve(root, node);
    check_constraints(node, value, path)?;
    for keyword in ["oneOf", "anyOf"] {
        if let Some(alternatives) = node.get(keyword).and_then(Value::as_array) {
            let mut first = None;
            let mut matched = false;
            for alternative in alternatives {
                match check_node(root, alternative, value, path) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(error) => {
                        first.get_or_insert(error);
                    }
                }
            }
            if !matched {
                // `null or a string` reads better than the first alternative's complaint.
                let kinds: Option<Vec<&str>> = alternatives
                    .iter()
                    .map(|alternative| resolve(root, alternative).get("type")?.as_str())
                    .collect();
                return Err(match kinds {
                    Some(kinds) if !kinds.is_empty() => format!(
                        "{} must be {}, found {}",
                        at(path),
                        kinds
                            .iter()
                            .map(|kind| expected(kind))
                            .collect::<Vec<_>>()
                            .join(" or "),
                        found(value)
                    ),
                    _ => first.unwrap_or_else(|| format!("{} matches no allowed shape", at(path))),
                });
            }
        }
    }
    if let Some(alternatives) = node.get("allOf").and_then(Value::as_array) {
        for alternative in alternatives {
            check_node(root, alternative, value, path)?;
        }
    }
    match value {
        Value::Object(members) => check_object(root, node, members, path),
        Value::Array(items) => {
            if let Some(item) = node.get("items") {
                for (index, element) in items.iter().enumerate() {
                    check_node(root, item, element, &format!("{path}[{index}]"))?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_object(
    root: &Value,
    node: &Value,
    members: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), String> {
    if let Some(required) = node.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !members.contains_key(key) {
                return Err(format!("{} is required", join(path, key)));
            }
        }
    }
    let properties = node.get("properties").and_then(Value::as_object);
    let additional = node.get("additionalProperties");
    for (key, member) in members {
        let child = join(path, key);
        if let Some(schema) = properties.and_then(|properties| properties.get(key)) {
            check_node(root, schema, member, &child)?;
        } else {
            match additional {
                Some(Value::Bool(false)) => {
                    return Err(if path.is_empty() {
                        format!("unknown config key {key:?}")
                    } else {
                        format!("unknown config key {child}")
                    });
                }
                Some(schema @ Value::Object(_)) => check_node(root, schema, member, &child)?,
                _ => {}
            }
        }
    }
    Ok(())
}

/// The rules between keys that `spec/config` states and `config-schema-check` applies to the
/// examples. They concern only keys the daemon accepts without acting on, and only a pair the
/// document sets both of: the default edition without a `limits` block stays valid.
fn cross_field(document: &Value) -> Result<(), ConfigError> {
    let text = |pointer: &str| document.pointer(pointer).and_then(Value::as_str);
    let refuse = |message: String| Err(ConfigError(message));
    let edition = text("/firestore/edition");
    if let (Some(edition), Some(catalog)) = (edition, text("/limits/catalog")) {
        let prefix = match edition {
            "standard" => "firestore-standard-",
            "enterprise" => "firestore-enterprise-native-",
            _ => "",
        };
        if !catalog.starts_with(prefix) {
            return refuse(format!(
                "limits.catalog {catalog:?} does not belong to firestore.edition {edition:?}"
            ));
        }
    }
    match (edition, document.pointer("/limits/queryCatalog")) {
        (Some("standard"), Some(Value::Null)) => {
            return refuse(
                "firestore.edition \"standard\" needs a limits.queryCatalog; remove the key to leave it unset"
                    .to_owned(),
            );
        }
        (Some("enterprise"), Some(Value::String(catalog))) => {
            return refuse(format!(
                "firestore.edition \"enterprise\" cannot use the Standard query catalog {catalog:?}; use null"
            ));
        }
        _ => {}
    }
    if text("/firestore/pipeline/executionMode") == Some("proxy") {
        return refuse(
            "firestore.pipeline.executionMode \"proxy\" forwards to a real Firestore backend, which fireemu never does"
                .to_owned(),
        );
    }
    if text("/firestore/textSearch/fidelity") == Some("upstream-proxy") {
        return refuse(
            "firestore.textSearch.fidelity \"upstream-proxy\" forwards to a real Firestore backend, which fireemu never does"
                .to_owned(),
        );
    }
    if text("/firestore/textSearch/visibilityPolicy") == Some("virtual-lag")
        && document
            .pointer("/firestore/textSearch/visibilityLag")
            .is_none_or(Value::is_null)
    {
        return refuse(
            "firestore.textSearch.visibilityPolicy \"virtual-lag\" needs firestore.textSearch.visibilityLag"
                .to_owned(),
        );
    }
    if text("/firestore/textSearch/fidelity") == Some("strict-validation-only")
        && text("/firestore/textSearch/scorePrecision") == Some("exact")
    {
        return refuse(
            "firestore.textSearch.fidelity \"strict-validation-only\" cannot use scorePrecision \"exact\""
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use proptest::strategy::Strategy as _;

    use super::*;
    use crate::config::RuntimeConfig;

    fn load(extra: Value) -> Result<RuntimeConfig, ConfigError> {
        let Value::Object(members) = extra else {
            panic!("a configuration is an object");
        };
        let mut document = json!({"schemaVersion": 1});
        for (key, value) in members {
            document[key] = value;
        }
        RuntimeConfig::from_json(&document)
    }

    /// The refusal for `extra`, failing the test when the loader accepts it.
    fn refusal(extra: Value) -> String {
        let shown = extra.to_string();
        match load(extra) {
            Err(error) => error.0,
            Ok(_) => panic!("{shown} must be refused"),
        }
    }

    #[test]
    fn a_misspelt_key_in_any_section_is_refused_with_its_path() {
        for section in [
            "firestore",
            "projects",
            "storage",
            "rules",
            "trace",
            "network",
            "daemon",
            "events",
            "pubsub",
            "scheduler",
            "functions",
            "appCheck",
            "auth",
            "eventarc",
            "limits",
        ] {
            let error = ConfigError(refusal(json!({ section: {"prot": 8080} })));
            assert!(
                error
                    .0
                    .contains(&format!("unknown config key {section}.prot")),
                "{section}: {}",
                error.0
            );
        }
        for (path, document) in [
            (
                "firestore.history.maxByte",
                json!({"firestore": {"history": {"maxByte": 1}}}),
            ),
            (
                "rules.compiledSize.mod",
                json!({"rules": {"compiledSize": {"mod": "off"}}}),
            ),
            (
                "functions.clock.dates",
                json!({"functions": {"clock": {"dates": "real"}}}),
            ),
        ] {
            let error = ConfigError(refusal(document));
            assert!(
                error.0.contains(&format!("unknown config key {path}")),
                "{path}: {}",
                error.0
            );
        }
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_with_its_path_and_the_expected_type() {
        for (path, document, expected) in [
            (
                "daemon.firestorePort",
                json!({"daemon": {"firestorePort": "8080"}}),
                "an integer",
            ),
            (
                "daemon.authProject",
                json!({"daemon": {"authProject": 5}}),
                "a string",
            ),
            (
                "daemon.seed",
                json!({"daemon": {"seed": "1"}}),
                "an integer",
            ),
            (
                "projects.requireDemoPrefix",
                json!({"projects": {"requireDemoPrefix": "yes"}}),
                "a boolean",
            ),
            (
                "rules.source",
                json!({"rules": {"source": true}}),
                "a string",
            ),
            (
                "storage.rules",
                json!({"storage": {"rules": 5}}),
                "a string",
            ),
            (
                "firestore.enforceLimits",
                json!({"firestore": {"enforceLimits": "false"}}),
                "a boolean",
            ),
            (
                "firestore.indexFile",
                json!({"firestore": {"indexFile": 1}}),
                "a string",
            ),
            (
                "firestore.edition",
                json!({"firestore": {"edition": 5}}),
                "a string",
            ),
            (
                "events.maxAttempts",
                json!({"events": {"maxAttempts": "3"}}),
                "an integer",
            ),
            (
                "functions.maxGlobalConcurrency",
                json!({"functions": {"maxGlobalConcurrency": 2.5}}),
                "an integer",
            ),
            ("firebaseJson", json!({"firebaseJson": 5}), "a string"),
            ("bind", json!({"bind": 5}), "a string"),
            (
                "trace.enabled",
                json!({"trace": {"enabled": "on"}}),
                "a boolean",
            ),
        ] {
            let error = ConfigError(refusal(document));
            assert!(
                error.0.contains(path) && error.0.contains(expected),
                "{path}: {}",
                error.0
            );
        }
    }

    #[test]
    fn the_alternatives_of_a_nullable_key_are_named_together() {
        let error = check(&json!({
            "schemaVersion": 1,
            "firestore": {"textSearch": {"visibilityLag": 5}}
        }))
        .unwrap_err();
        assert_eq!(
            error.0,
            "firestore.textSearch.visibilityLag must be null or an object, found an integer"
        );
        check(&json!({"schemaVersion": 1, "firestore": {"textSearch": {"visibilityLag": null}}}))
            .unwrap();
    }

    #[test]
    fn a_number_below_the_schema_s_minimum_is_refused_not_raised_to_it() {
        // `events.maxAttempts` used to be raised to 1 without a word.
        let error = refusal(json!({"events": {"maxAttempts": 0}}));
        assert!(
            error.contains("events.maxAttempts must be at least 1"),
            "{error}"
        );
        load(json!({"events": {"maxAttempts": 1}})).unwrap();
        assert!(load(json!({"daemon": {"seed": -1}})).is_err());
    }

    #[test]
    fn a_port_above_the_range_is_refused() {
        for key in [
            "firestorePort",
            "httpPort",
            "storagePort",
            "functionsPort",
            "hubPort",
            "uiPort",
        ] {
            let error = ConfigError(refusal(json!({"daemon": {key: 65536}})));
            assert!(
                error.0.contains(&format!("daemon.{key}")),
                "{key}: {}",
                error.0
            );
            load(json!({"daemon": {key: 65535}})).unwrap();
        }
        assert!(load(json!({"daemon": {"firestorePort": -1}})).is_err());
    }

    /// The JSON files in a `spec/config` directory, by file name.
    fn corpus(directory: &str) -> Vec<(String, Value)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/config")
            .join(directory);
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&root).expect("the corpus directory is readable") {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let document = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            files.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                document,
            ));
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        files
    }

    #[test]
    fn every_valid_example_loads_and_every_invalid_example_is_refused() {
        let valid = corpus("examples");
        let invalid = corpus("invalid-examples");
        assert!(
            valid.len() >= 20 && invalid.len() >= 40,
            "the corpus must not shrink"
        );
        let mut wrong = Vec::new();
        for (name, document) in &valid {
            if let Err(error) = RuntimeConfig::from_json(document) {
                wrong.push(format!("examples/{name} must load: {}", error.0));
            }
        }
        for (name, document) in &invalid {
            if RuntimeConfig::from_json(document).is_ok() {
                wrong.push(format!("invalid-examples/{name} must be refused"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Every property name a schema file declares, at any depth.
    fn property_names(schema: &Value) -> std::collections::BTreeSet<String> {
        let mut names = std::collections::BTreeSet::new();
        let mut pending = vec![schema];
        while let Some(node) = pending.pop() {
            match node {
                Value::Object(members) => {
                    if let Some(Value::Object(properties)) = members.get("properties") {
                        names.extend(properties.keys().cloned());
                    }
                    pending.extend(members.values());
                }
                Value::Array(items) => pending.extend(items),
                _ => {}
            }
        }
        names
    }

    #[test]
    fn every_key_the_loader_reads_is_a_property_in_the_schema() {
        let source = include_str!("config.rs");
        let loader = &source[..source
            .find("#[cfg(test)]\nmod tests {")
            .expect("the loader precedes its tests")];
        let mut named = property_names(schema());
        // The keys of a firebase.json are read by the same file.
        let firebase_json: Value = serde_json::from_str(include_str!(
            "../../../spec/config/firebase-json.schema.json"
        ))
        .unwrap();
        named.extend(property_names(&firebase_json));
        // Not keys of a configuration file: the schema walk's own, `.firebaserc`'s, and the
        // key that is only read to be refused.
        named.extend(
            ["default", "properties", "targets", "indexValidationPolicy"]
                .into_iter()
                .map(str::to_owned),
        );
        let mut missing = std::collections::BTreeSet::new();
        for part in loader.split(".get(\"").skip(1) {
            if let Some((key, rest)) = part.split_once("\")") {
                if !key.contains('"') && !named.contains(key) && !rest.is_empty() {
                    missing.insert(key.to_owned());
                }
            }
        }
        assert!(
            missing.is_empty(),
            "the loader reads keys the schema does not declare: {missing:?}"
        );
    }

    #[test]
    fn the_loader_s_key_lists_are_the_schema_s_properties() {
        use crate::config::{
            AUTH_KEYS, DAEMON_KEYS, EVENTS_KEYS, FUNCTIONS_KEYS, KNOWN_TOP_LEVEL, PUBSUB_KEYS,
            SCHEDULER_KEYS,
        };
        let schema = schema();
        let declared = |pointer: &str| -> std::collections::BTreeSet<String> {
            schema
                .pointer(pointer)
                .and_then(|node| node.get("properties"))
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{pointer} has properties"))
                .keys()
                .cloned()
                .collect()
        };
        let listed = |keys: &[&str]| -> std::collections::BTreeSet<String> {
            keys.iter().map(|key| (*key).to_owned()).collect()
        };
        assert_eq!(listed(KNOWN_TOP_LEVEL), declared(""), "top level");
        for (name, keys) in [
            ("auth", &AUTH_KEYS[..]),
            ("daemon", &DAEMON_KEYS[..]),
            ("events", &EVENTS_KEYS[..]),
            ("functions", &FUNCTIONS_KEYS[..]),
            ("pubsub", &PUBSUB_KEYS[..]),
            ("scheduler", &SCHEDULER_KEYS[..]),
        ] {
            assert_eq!(
                listed(keys),
                declared(&format!("/properties/{name}")),
                "{name}"
            );
        }
    }

    /// Every object in `document` that the schema closes to unknown keys, as a JSON pointer.
    fn closed_objects(document: &Value) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![(String::new(), document)];
        while let Some((pointer, value)) = pending.pop() {
            if let Value::Object(members) = value {
                // The pointer's schema node is the one the checker itself walks; ask it by
                // planting a key and seeing whether the shape alone refuses.
                let mut probe = document.clone();
                let target = if pointer.is_empty() {
                    Some(&mut probe)
                } else {
                    probe.pointer_mut(&pointer)
                };
                if let Some(Value::Object(object)) = target {
                    object.insert("zzNotAKey".to_owned(), json!(1));
                }
                if check(&probe).is_err_and(|error| error.0.contains("unknown config key")) {
                    found.push(pointer.clone());
                }
                for (key, member) in members {
                    pending.push((
                        format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                        member,
                    ));
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn a_key_added_to_any_closed_object_of_any_example_is_refused() {
        let mut planted = 0;
        for (name, document) in corpus("examples") {
            for pointer in closed_objects(&document) {
                let mut changed = document.clone();
                let object = if pointer.is_empty() {
                    &mut changed
                } else {
                    changed.pointer_mut(&pointer).unwrap()
                };
                object
                    .as_object_mut()
                    .unwrap()
                    .insert("misspelt".to_owned(), json!(true));
                let message = refusal_of(&changed);
                // A section another validator reads (`auth.mfa`, `eventarc.oauthCredentials`) refuses
                // in its own words, but still names the section.
                let section = pointer
                    .trim_start_matches('/')
                    .split('/')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(".");
                assert!(
                    message.contains("misspelt") || message.contains(&section),
                    "examples/{name} {pointer:?}: {message}"
                );
                planted += 1;
            }
        }
        assert!(
            planted > 40,
            "the examples must close many objects: {planted}"
        );
    }

    /// The refusal for a whole document, failing when the loader accepts it.
    fn refusal_of(document: &Value) -> String {
        match RuntimeConfig::from_json(document) {
            Err(error) => error.0,
            Ok(_) => panic!("{document} must be refused"),
        }
    }

    /// A value of another kind than any scalar's, for the leaves of the examples.
    fn of_another_kind(value: &Value) -> Option<Value> {
        match value {
            Value::Bool(_) | Value::Number(_) | Value::String(_) => Some(json!([])),
            _ => None,
        }
    }

    /// Whether the schema gives the value at `pointer` a `type`, `enum` or `const` of its own: a
    /// tenant document, for one, is free-form here and read by the Admin API's code.
    fn is_typed(document: &Value, pointer: &str) -> bool {
        let root = schema();
        let mut node = root;
        let mut here = document;
        for segment in pointer.split('/').skip(1) {
            let segment = segment.replace("~1", "/").replace("~0", "~");
            node = resolve(root, node);
            let next = match here {
                Value::Array(items) => {
                    here = &items[segment.parse::<usize>().unwrap()];
                    node.get("items")
                }
                Value::Object(members) => {
                    here = &members[&segment];
                    node.get("properties")
                        .and_then(|properties| properties.get(&segment))
                        .or_else(|| node.get("additionalProperties").filter(|a| a.is_object()))
                }
                _ => None,
            };
            let Some(next) = next else { return false };
            node = next;
        }
        let node = resolve(root, node);
        node.get("type").is_some() || node.get("enum").is_some() || node.get("const").is_some()
    }

    #[test]
    fn a_scalar_replaced_by_one_of_another_kind_in_any_example_is_refused() {
        let mut replaced = 0;
        for (name, document) in corpus("examples") {
            let mut pending = vec![(String::new(), &document)];
            while let Some((pointer, value)) = pending.pop() {
                match value {
                    Value::Object(members) => {
                        pending.extend(members.iter().map(|(key, member)| {
                            (
                                format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                                member,
                            )
                        }));
                    }
                    Value::Array(items) => pending.extend(
                        items
                            .iter()
                            .enumerate()
                            .map(|(i, item)| (format!("{pointer}/{i}"), item)),
                    ),
                    scalar => {
                        let Some(other) = of_another_kind(scalar) else {
                            continue;
                        };
                        if !is_typed(&document, &pointer) {
                            continue;
                        }
                        let mut changed = document.clone();
                        *changed.pointer_mut(&pointer).unwrap() = other;
                        assert!(
                            RuntimeConfig::from_json(&changed).is_err(),
                            "examples/{name}: {pointer} changed kind and was still accepted"
                        );
                        replaced += 1;
                    }
                }
            }
        }
        assert!(
            replaced > 100,
            "the examples must hold many scalars: {replaced}"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn the_shape_check_accepts_exactly_the_ports_in_range(port in -70_000_i64..140_000) {
            let accepted = load(json!({"daemon": {"hubPort": port}})).is_ok();
            proptest::prop_assert_eq!(accepted, (0..=65_535).contains(&port));
        }

        #[test]
        fn any_other_kind_of_value_for_a_string_key_is_refused(
            value in proptest::prop_oneof![
                proptest::prelude::any::<bool>().prop_map(|b| json!(b)),
                proptest::prelude::any::<i64>().prop_map(|n| json!(n)),
                proptest::prelude::any::<f64>().prop_filter("finite", |f| f.is_finite()).prop_map(|f| json!(f)),
                proptest::strategy::Just(json!(null)),
                proptest::strategy::Just(json!([])),
                proptest::strategy::Just(json!({})),
            ]
        ) {
            for (section, key) in [("rules", "source"), ("storage", "rules"), ("firestore", "indexFile"), ("daemon", "authProject")] {
                let refused = load(json!({ (section): { (key): value.clone() } })).is_err();
                proptest::prop_assert!(refused, "{section}.{key} accepted {value}");
            }
        }
    }
}
