//! `functions.isolation = "function"`: one dedicated runner process per function of a codebase.
//!
//! Production runs every function in its own instance. The instance starts with the function's
//! identity (`FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE`, `K_SERVICE`) and the secrets that
//! function declares already in its environment, loads the whole codebase into its own module
//! graph, and serves `concurrency` calls of that one function at a time. The codebase runner
//! cannot be that: it rewrites the identity per call and serializes calls that use local secrets.
//!
//! A function-isolated codebase is started in two steps. The ordinary codebase runner discovers
//! the manifest (it needs no identity: it only describes the exports). Then one runner per served
//! function is spawned with that function's environment and `--function <name>`, and the
//! discovery runner is retired. The runtime holds one unit per function; a crash, a restart and a
//! reload of one unit never involve another.

use std::sync::Arc;

use fireemu_adapter_functions::runner::{
    remove_local_secrets, Runner, SpawnSpec, LOCAL_SECRET_NAMES_VARIABLE,
};
use fireemu_adapter_functions::runtime::CodebaseSpec;
use fireemu_core_functions::manifest::{
    FunctionGeneration, FunctionManifest, FunctionSpec, Trigger,
};

use super::{check_started_runner, EmulatorHosts};
use crate::config::RuntimeConfig;

/// The variable the daemon uses to hand a codebase runner every local secret at once.
const LOCAL_SECRETS_VARIABLE: &str = "FIREEMU_LOCAL_SECRETS_JSON";

/// The most dedicated runners one run starts. Each is a full Node or Python process that loads the
/// whole codebase, so the count is bounded the way the codebase count is: a project with more
/// functions than this keeps `functions.isolation = "codebase"`.
pub(super) const MAX_ISOLATED_FUNCTIONS: usize = 64;

/// What `FUNCTION_SIGNATURE_TYPE` says for a function: how the Functions Framework is asked to speak
/// for it. HTTP, task-queue and Auth blocking functions all enter through the HTTP wrapper; a
/// schedule does too from the second generation; every other first-generation trigger is an
/// `event`, and every other second-generation trigger a `cloudevent`.
pub(super) fn signature_type(function: &FunctionSpec) -> &'static str {
    let first = function.generation == FunctionGeneration::First;
    match function.trigger {
        Trigger::Http { .. } | Trigger::TaskQueue { .. } | Trigger::BlockingAuth { .. } => "http",
        Trigger::Schedule { .. } if !first => "http",
        _ if first => "event",
        _ => "cloudevent",
    }
}

/// The three variables of the Cloud Run identity of one function.
pub(super) fn identity_environment(function: &FunctionSpec) -> [(String, String); 3] {
    [
        ("FUNCTION_TARGET".to_owned(), function.entry_point.clone()),
        (
            "FUNCTION_SIGNATURE_TYPE".to_owned(),
            signature_type(function).to_owned(),
        ),
        ("K_SERVICE".to_owned(), function.name.clone()),
    ]
}

/// How to start (and restart) the dedicated runner of `function`, derived from how the codebase
/// runner is started: the same command and environment, plus `--function`, the function's identity,
/// and the local secrets that function declares as ordinary environment variables. No other
/// function's secret reaches the process, and the all-secrets channel is not passed on.
pub(super) fn function_spawn_spec(base: &SpawnSpec, function: &FunctionSpec) -> SpawnSpec {
    let secrets: serde_json::Map<String, serde_json::Value> = base
        .env
        .iter()
        .rev()
        .find(|(name, _)| name == LOCAL_SECRETS_VARIABLE)
        .and_then(|(_, text)| serde_json::from_str(text).ok())
        .unwrap_or_default();
    let identity = identity_environment(function);
    let declared = &function.platform_options.secrets;
    let secret_names: Vec<String> = secrets.keys().chain(declared.iter()).cloned().collect();
    let mut env: Vec<(String, String)> = base
        .env
        .iter()
        .filter(|(name, _)| {
            name != LOCAL_SECRETS_VARIABLE
                && name != LOCAL_SECRET_NAMES_VARIABLE
                && !identity.iter().any(|(fixed, _)| fixed == name)
        })
        .cloned()
        .collect();
    remove_local_secrets(&mut env, &secret_names);
    env.extend(identity);
    for name in declared {
        if let Some(value) = secrets.get(name).and_then(serde_json::Value::as_str) {
            env.push((name.clone(), value.to_owned()));
        }
    }
    env.push((
        LOCAL_SECRET_NAMES_VARIABLE.to_owned(),
        serde_json::to_string(&secret_names).expect("secret names serialize"),
    ));
    let mut command = base.command.clone();
    command.push("--function".to_owned());
    command.push(function.name.clone());
    SpawnSpec {
        command,
        cwd: base.cwd.clone(),
        env,
        hello_timeout: base.hello_timeout,
    }
}

/// Whether a function's runner is started with the codebase rather than on its first trigger.
///
/// Production starts an instance on the first request, so a function's runner does too: its process
/// does not exist until the first call, event or task for it needs one, and the work waits meanwhile.
/// Two kinds start at launch. With a debugger requested, every runner does, because the developer
/// attaches before the first call and each process reports its own port. A Blocking Auth function
/// does, because it answers a sign-up inside a short deadline and a sign-up must not be the call that
/// pays for a cold start.
pub(super) fn starts_at_launch(function: &FunctionSpec, inspecting: bool) -> bool {
    inspecting || matches!(function.trigger, Trigger::BlockingAuth { .. })
}

/// The manifest of one unit: its function, and the codebase's ignored exports on the first unit so
/// the union the runtime builds lists each of them once.
pub(super) fn unit_manifest(manifest: &FunctionManifest, index: usize) -> FunctionManifest {
    FunctionManifest {
        functions: vec![manifest.functions[index].clone()],
        ignored: if index == 0 {
            manifest.ignored.clone()
        } else {
            Vec::new()
        },
    }
}

/// Replaces the codebase runner `discovery` by one dedicated runner per function it discovered.
///
/// All of them are started together, checked like any started runner, and either every one is
/// kept or every one is stopped and the codebase fails to start. The discovery runner is retired
/// last, so a failure leaves nothing running.
pub(super) async fn isolate_functions(
    cfg: &RuntimeConfig,
    hosts: &EmulatorHosts,
    python: bool,
    discovery: CodebaseSpec,
    clock_snapshot: fireemu_core_session::clock::ClockSnapshot,
) -> Result<Vec<CodebaseSpec>, String> {
    let label = discovery.name.clone();
    let Some(base) = discovery.spawn.clone() else {
        return Ok(vec![discovery]);
    };
    let count = discovery.manifest.functions.len();
    if count > MAX_ISOLATED_FUNCTIONS {
        discovery.runner.kill_now();
        return Err(format!(
            "the Functions codebase {label:?}: functions.isolation \"function\" starts one runner process per function, and this codebase serves {count} (the limit is {MAX_ISOLATED_FUNCTIONS}); set functions.isolation to \"codebase\" (the default) to serve this codebase from one process"
        ));
    }
    let specs: Vec<SpawnSpec> = discovery
        .manifest
        .functions
        .iter()
        .map(|function| function_spawn_spec(&base, function))
        .collect();
    let inspecting = cfg.functions_inspect_dynamic || cfg.functions_inspect_port.is_some();
    let mut starts = tokio::task::JoinSet::new();
    for (index, spec) in specs.iter().cloned().enumerate() {
        if !starts_at_launch(&discovery.manifest.functions[index], inspecting) {
            continue;
        }
        let admin = hosts.admin_app_check.clone();
        starts.spawn(async move { (index, Runner::spawn_spec_with(&spec, admin).await) });
    }
    let mut runners: Vec<Option<Arc<Runner>>> = vec![None; count];
    let mut failure = None;
    while let Some(joined) = starts.join_next().await {
        match joined {
            Ok((index, Ok(runner))) => runners[index] = Some(Arc::new(runner)),
            Ok((index, Err(error))) => {
                let name = &discovery.manifest.functions[index].name;
                failure.get_or_insert(format!(
                    "the Functions codebase {label:?}: function {name:?}: {error}"
                ));
            }
            Err(error) => {
                failure.get_or_insert(format!(
                    "the Functions codebase {label:?}: a function runner start task failed: {error}"
                ));
            }
        }
    }
    let stop_all = |runners: &[Option<Arc<Runner>>]| {
        for runner in runners.iter().flatten() {
            runner.kill_now();
        }
    };
    if let Some(error) = failure {
        stop_all(&runners);
        discovery.runner.kill_now();
        return Err(error);
    }
    for runner in runners.iter().flatten() {
        if let Err(error) = check_started_runner(cfg, &label, python, runner, clock_snapshot).await
        {
            stop_all(&runners);
            discovery.runner.kill_now();
            return Err(error);
        }
    }
    discovery.runner.shutdown().await;
    Ok(specs
        .into_iter()
        .zip(runners)
        .enumerate()
        .map(|(index, (spec, runner))| CodebaseSpec {
            name: label.clone(),
            function: Some(discovery.manifest.functions[index].name.clone()),
            manifest: unit_manifest(&discovery.manifest, index),
            // A function whose runner starts on its first trigger holds a placeholder until then.
            runner: runner.unwrap_or_else(|| {
                Arc::new(Runner::unstarted(&format!(
                    "[functions:{label}/{}]",
                    discovery.manifest.functions[index].name
                )))
            }),
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    fn functions(document: &serde_json::Value) -> Vec<FunctionSpec> {
        parse_manifest(document).unwrap().functions
    }

    fn base(secrets: &serde_json::Value) -> SpawnSpec {
        SpawnSpec {
            command: vec![
                "node".to_owned(),
                "runner.mjs".to_owned(),
                "--source".to_owned(),
                "/src".to_owned(),
                "--codebase".to_owned(),
                "default".to_owned(),
            ],
            cwd: Some("/src".to_owned()),
            env: vec![
                ("GCLOUD_PROJECT".to_owned(), "demo-iso".to_owned()),
                ("K_SERVICE".to_owned(), "inherited".to_owned()),
                (LOCAL_SECRETS_VARIABLE.to_owned(), secrets.to_string()),
                ("FIREEMU_RUNNER".to_owned(), "1".to_owned()),
            ],
            hello_timeout: std::time::Duration::from_secs(60),
        }
    }

    fn env_of<'a>(spec: &'a SpawnSpec, name: &str) -> Vec<&'a str> {
        spec.env
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    #[tokio::test]
    async fn isolation_accepts_64_functions_and_refuses_65() {
        let hosts = EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        let mut cfg = RuntimeConfig::default();
        let clock = fireemu_core_session::clock::ClockSnapshot {
            instant: cfg.clock_start,
            elapsed_nanos: 0,
            revision: 0,
        };
        for count in [64, 65] {
            let entries: Vec<_> = (0..count)
                .map(|index| json!({"name": format!("f{index}"), "generation": 2, "trigger": {"type": "http"}}))
                .collect();
            let discovery = CodebaseSpec {
                name: "default".to_owned(),
                function: None,
                manifest: parse_manifest(&json!({"functions": entries})).unwrap(),
                runner: Arc::new(Runner::unstarted("discovery")),
                spawn: Some(base(&json!({}))),
                cleanup_dir: None,
            };
            let result = isolate_functions(&cfg, &hosts, false, discovery, clock).await;
            if count == 64 {
                assert_eq!(result.unwrap().len(), 64);
            } else {
                assert!(result.err().unwrap().contains("the limit is 64"));
            }
        }
        for fixed in [false, true] {
            cfg.functions_inspect_dynamic = !fixed;
            cfg.functions_inspect_port = fixed.then_some(9229);
            let mut spawn = base(&json!({}));
            spawn.command = vec!["fireemu-nonexistent-isolation-test-runner".to_owned()];
            let discovery = CodebaseSpec {
                name: "default".to_owned(),
                function: None,
                manifest: parse_manifest(&json!({"functions": [
                    {"name": "f", "generation": 2, "trigger": {"type": "http"}}
                ]}))
                .unwrap(),
                runner: Arc::new(Runner::unstarted("discovery")),
                spawn: Some(spawn),
                cleanup_dir: None,
            };
            assert!(isolate_functions(&cfg, &hosts, false, discovery, clock)
                .await
                .is_err());
        }
    }

    #[test]
    fn the_signature_type_follows_the_trigger_and_the_generation() {
        let all = functions(&json!({"functions": [
            {"name": "web1", "generation": 1, "trigger": {"type": "http"}},
            {"name": "web2", "generation": 2, "trigger": {"type": "http"}},
            {"name": "queue", "generation": 2, "trigger": {"type": "tasks"}},
            {"name": "block", "generation": 2, "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"}},
            {"name": "cron1", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            {"name": "cron2", "generation": 2, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            {"name": "doc1", "generation": 1, "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}},
            {"name": "doc2", "generation": 2, "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}},
            {"name": "topic1", "generation": 1, "trigger": {"type": "pubsub", "topic": "t"}},
            {"name": "topic2", "generation": 2, "trigger": {"type": "pubsub", "topic": "t"}},
        ]}));
        let table: Vec<(&str, &str)> = all
            .iter()
            .map(|f| (f.name.as_str(), signature_type(f)))
            .collect();
        assert_eq!(
            table,
            vec![
                ("web1", "http"),
                ("web2", "http"),
                ("queue", "http"),
                ("block", "http"),
                ("cron1", "event"),
                ("cron2", "http"),
                ("doc1", "event"),
                ("doc2", "cloudevent"),
                ("topic1", "event"),
                ("topic2", "cloudevent"),
            ]
        );
    }

    #[test]
    fn a_function_runner_starts_with_its_identity_secrets_and_name() {
        let all = functions(&json!({"functions": [
            {"name": "alpha", "entryPoint": "group.alpha", "generation": 2, "trigger": {"type": "http"},
             "platformOptions": {"secrets": ["ALPHA_KEY"]}},
            {"name": "beta", "generation": 2, "trigger": {"type": "pubsub", "topic": "t"}},
        ]}));
        let secrets = json!({"ALPHA_KEY": "a-value", "BETA_KEY": "b-value"});
        let spec = function_spawn_spec(&base(&secrets), &all[0]);
        assert_eq!(
            &spec.command[spec.command.len() - 2..],
            ["--function", "alpha"]
        );
        assert_eq!(spec.command[..6], base(&secrets).command[..]);
        assert_eq!(spec.cwd.as_deref(), Some("/src"));
        assert_eq!(env_of(&spec, "K_SERVICE"), vec!["alpha"]);
        assert_eq!(env_of(&spec, "FUNCTION_TARGET"), vec!["group.alpha"]);
        assert_eq!(env_of(&spec, "FUNCTION_SIGNATURE_TYPE"), vec!["http"]);
        assert_eq!(env_of(&spec, "ALPHA_KEY"), vec!["a-value"]);
        assert!(
            env_of(&spec, "BETA_KEY").is_empty(),
            "another function's secret"
        );
        assert!(
            env_of(&spec, LOCAL_SECRETS_VARIABLE).is_empty(),
            "the all-secrets channel"
        );
        assert_eq!(env_of(&spec, "GCLOUD_PROJECT"), vec!["demo-iso"]);
        assert_eq!(env_of(&spec, "FIREEMU_RUNNER"), vec!["1"]);
        // A function that declares nothing sees no secret at all.
        let plain = function_spawn_spec(&base(&secrets), &all[1]);
        assert!(env_of(&plain, "ALPHA_KEY").is_empty());
        assert!(env_of(&plain, "BETA_KEY").is_empty());
        assert_eq!(
            env_of(&plain, "FUNCTION_SIGNATURE_TYPE"),
            vec!["cloudevent"]
        );
        assert_eq!(env_of(&plain, "FUNCTION_TARGET"), vec!["beta"]);
    }

    #[test]
    fn a_declared_secret_without_a_local_value_is_not_invented() {
        let all = functions(&json!({"functions": [
            {"name": "alpha", "generation": 2, "trigger": {"type": "http"},
             "platformOptions": {"secrets": ["MISSING_KEY"]}},
        ]}));
        let spec = function_spawn_spec(&base(&json!({})), &all[0]);
        assert!(env_of(&spec, "MISSING_KEY").is_empty());
        // No secrets channel at all is the same as an empty one.
        let mut without = base(&json!({}));
        without
            .env
            .retain(|(name, _)| name != LOCAL_SECRETS_VARIABLE);
        assert!(env_of(&function_spawn_spec(&without, &all[0]), "MISSING_KEY").is_empty());
    }

    #[test]
    fn a_declared_secret_replaces_a_plain_variable_of_the_same_name() {
        let all = functions(&json!({"functions": [
            {"name": "alpha", "generation": 2, "trigger": {"type": "http"},
             "platformOptions": {"secrets": ["API_KEY"]}},
        ]}));
        let mut codebase = base(&json!({"API_KEY": "secret-value"}));
        codebase
            .env
            .push(("API_KEY".to_owned(), "dotenv-value".to_owned()));
        assert_eq!(
            env_of(&function_spawn_spec(&codebase, &all[0]), "API_KEY"),
            vec!["secret-value"]
        );
    }

    #[test]
    fn inherited_local_secrets_are_removed_from_other_functions() {
        let all = functions(&json!({"functions": [
            {"name": "alpha", "generation": 2, "trigger": {"type": "http"},
             "platformOptions": {"secrets": ["ALPHA_KEY", "MISSING_KEY"]}},
            {"name": "beta", "generation": 2, "trigger": {"type": "http"},
             "platformOptions": {"secrets": ["BETA_KEY"]}},
        ]}));
        let mut codebase = base(&json!({"ALPHA_KEY": "local-alpha", "BETA_KEY": "local-beta"}));
        codebase.env.extend([
            ("ALPHA_KEY".to_owned(), "inherited-alpha".to_owned()),
            ("BETA_KEY".to_owned(), "inherited-beta".to_owned()),
            ("MISSING_KEY".to_owned(), "inherited-missing".to_owned()),
            ("UNRELATED".to_owned(), "retained".to_owned()),
        ]);
        let alpha = function_spawn_spec(&codebase, &all[0]);
        let excluded: Vec<String> =
            serde_json::from_str(env_of(&alpha, LOCAL_SECRET_NAMES_VARIABLE)[0]).unwrap();
        assert!(excluded.contains(&"BETA_KEY".to_owned()));
        assert!(excluded.contains(&"MISSING_KEY".to_owned()));
        assert_eq!(env_of(&alpha, "ALPHA_KEY"), vec!["local-alpha"]);
        assert!(env_of(&alpha, "BETA_KEY").is_empty());
        assert!(env_of(&alpha, "MISSING_KEY").is_empty());
        assert_eq!(env_of(&alpha, "UNRELATED"), vec!["retained"]);
        let beta = function_spawn_spec(&codebase, &all[1]);
        assert!(env_of(&beta, "ALPHA_KEY").is_empty());
        assert_eq!(env_of(&beta, "BETA_KEY"), vec!["local-beta"]);
    }

    #[test]
    fn a_runner_starts_on_its_first_trigger_except_for_blocking_auth_and_under_a_debugger() {
        let all = functions(&json!({"functions": [
            {"name": "web", "generation": 2, "trigger": {"type": "http"}},
            {"name": "doc", "generation": 2, "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}},
            {"name": "cron", "generation": 2, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            {"name": "queue", "generation": 2, "trigger": {"type": "tasks"}},
            {"name": "block", "generation": 2, "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"}},
        ]}));
        let at_launch = |inspecting| -> Vec<&str> {
            all.iter()
                .filter(|f| starts_at_launch(f, inspecting))
                .map(|f| f.name.as_str())
                .collect()
        };
        assert_eq!(at_launch(false), vec!["block"]);
        assert_eq!(
            at_launch(true),
            vec!["web", "doc", "cron", "queue", "block"]
        );
    }

    #[test]
    fn only_the_first_unit_carries_the_ignored_exports() {
        let document = json!({"functions": [
            {"name": "a", "generation": 2, "trigger": {"type": "http"}},
            {"name": "b", "generation": 2, "trigger": {"type": "http"}},
        ], "ignored": [
            {"name": "gone", "region": "us-central1", "triggerType": "testLab", "scope": "unsupported", "reason": "x"},
        ]});
        let manifest = parse_manifest(&document).unwrap();
        assert_eq!(manifest.ignored.len(), 1, "fixture");
        let units: Vec<_> = (0..2)
            .map(|index| unit_manifest(&manifest, index))
            .collect();
        assert_eq!(units[0].ignored.len(), 1);
        assert!(units[1].ignored.is_empty());
        let names: Vec<&str> = units
            .iter()
            .flat_map(|unit| unit.functions.iter().map(|f| f.name.as_str()))
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    proptest! {
        // For any declared set and any local secrets, a function's process receives exactly the
        // intersection, once each, with the value the secrets file gave, and nothing else secret.
        #[test]
        fn a_function_runner_receives_exactly_the_secrets_it_declares(
            declared in proptest::collection::btree_set("[A-Z][A-Z0-9_]{0,8}", 0..5),
            local in proptest::collection::btree_map("[A-Z][A-Z0-9_]{0,8}", "[a-z0-9]{1,12}", 0..8),
        ) {
            let reserved = ["GCLOUD_PROJECT", "K_SERVICE", "FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "FIREEMU_RUNNER", LOCAL_SECRETS_VARIABLE];
            prop_assume!(declared.iter().chain(local.keys()).all(|name| !reserved.contains(&name.as_str())));
            let document = json!({"functions": [{
                "name": "f", "generation": 2, "trigger": {"type": "http"},
                "platformOptions": {"secrets": declared.iter().collect::<Vec<_>>()},
            }]});
            let function = &functions(&document)[0];
            let secrets = serde_json::to_value(&local).unwrap();
            let spec = function_spawn_spec(&base(&secrets), function);
            let received: BTreeSet<&str> = spec
                .env
                .iter()
                .map(|(name, _)| name.as_str())
                .filter(|name| local.contains_key(*name))
                .collect();
            let expected: BTreeSet<&str> = declared
                .iter()
                .filter(|name| local.contains_key(*name))
                .map(String::as_str)
                .collect();
            prop_assert_eq!(&received, &expected);
            for name in &expected {
                prop_assert_eq!(env_of(&spec, name), vec![local[*name].as_str()]);
            }
            prop_assert!(env_of(&spec, LOCAL_SECRETS_VARIABLE).is_empty());
            for fixed in ["K_SERVICE", "FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE"] {
                prop_assert_eq!(env_of(&spec, fixed).len(), 1, "{} appears once", fixed);
            }
        }
    }
}
