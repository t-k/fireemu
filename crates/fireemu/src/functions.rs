//! Functions runtime wiring: runner process, event subscriptions, control hooks.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::FunctionsHook;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::ids::SessionId;

use crate::config::RuntimeConfig;

/// The debug feature the callable trusted protocol turns on, and nothing else.
///
/// `firebase-functions` reads `FIREBASE_DEBUG_MODE` once when it is first required and
/// re-reads `FIREBASE_DEBUG_FEATURES` per lookup. `skipTokenVerification` makes the callable
/// wrapper decode the App Check and Auth credentials locally instead of calling out to Google,
/// which is only safe because the daemon has already verified and re-inserted both
/// (specification section 13.4). No other feature is enabled: `enableCors`, in particular,
/// would change what the functions themselves answer.
const DEBUG_FEATURES: &str = r#"{"skipTokenVerification":true}"#;

/// Addresses the runner's functions need to reach the daemon.
pub struct EmulatorHosts {
    /// Firestore gRPC / REST.
    pub firestore: String,
    /// Auth REST.
    pub auth: String,
    /// Storage.
    pub storage: String,
}

/// The bundled Node runner (overridable with `FIREEMU_RUNNER_NODE`).
fn default_runner() -> Vec<String> {
    let script = std::env::var("FIREEMU_RUNNER_NODE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/runner-node/index.mjs"
        )
        .to_owned()
    });
    vec!["node".to_owned(), script]
}

/// Starts the runner and the runtime for `cfg.functions_source` and installs it as the
/// backend's synchronous commit observer (Storage events are wired by the caller through
/// [`storage_sink`]).
#[allow(clippy::too_many_lines)]
pub async fn start(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    backend: &Arc<LocalBackend>,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) -> Result<Arc<FunctionsRuntime>, String> {
    let source = cfg
        .functions_source
        .clone()
        .ok_or_else(|| "functions.source is not configured".to_owned())?;
    if !Path::new(&source).is_dir() {
        return Err(format!("functions.source {source:?} is not a directory"));
    }
    let mut command = cfg.functions_runner.clone().unwrap_or_else(default_runner);
    command.push("--source".to_owned());
    command.push(source.clone());
    let default_bucket = format!("{}.appspot.com", cfg.auth_project);
    let env = vec![
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("FUNCTIONS_EMULATOR".to_owned(), "true".to_owned()),
        (
            "FIRESTORE_EMULATOR_HOST".to_owned(),
            hosts.firestore.clone(),
        ),
        ("FIREBASE_AUTH_EMULATOR_HOST".to_owned(), hosts.auth.clone()),
        (
            "FIREBASE_STORAGE_EMULATOR_HOST".to_owned(),
            hosts.storage.clone(),
        ),
        (
            "STORAGE_EMULATOR_HOST".to_owned(),
            format!("http://{}", hosts.storage),
        ),
        (
            "FIREBASE_CONFIG".to_owned(),
            serde_json::json!({"projectId": cfg.auth_project, "storageBucket": default_bucket})
                .to_string(),
        ),
        ("FIREEMU_RUNNER".to_owned(), "1".to_owned()),
        ("FIREEMU_RUNNER_SECRET".to_owned(), runner_secret.to_owned()),
    ];
    // Debug mode is granted only when the daemon is the sole source of both callable
    // credentials. The runner inherits an allowlist that does not contain these names, and
    // `SpawnSpec::env` is applied last, so neither can be shadowed from the host environment.
    let mut env = env;
    if callable_trusted_protocol {
        env.push(("FIREBASE_DEBUG_MODE".to_owned(), "true".to_owned()));
        env.push((
            "FIREBASE_DEBUG_FEATURES".to_owned(),
            DEBUG_FEATURES.to_owned(),
        ));
    }
    let spec = SpawnSpec {
        command,
        cwd: None,
        env,
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec).await?;
    let manifest_json = match &cfg.functions_manifest {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("functions manifest {path}: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("functions manifest {path}: {e}"))?
        }
        None => runner
            .hello()
            .manifest
            .clone()
            .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?,
    };
    let mut manifest_json = manifest_json;
    if let Some(tz) = &cfg.scheduler_default_time_zone {
        // Schedules without a zone use the configured default.
        if let Some(functions) = manifest_json
            .get_mut("functions")
            .and_then(serde_json::Value::as_array_mut)
        {
            for f in functions {
                if let Some(trigger) = f.get_mut("trigger") {
                    if trigger.get("type").and_then(serde_json::Value::as_str) == Some("schedule")
                        && trigger
                            .get("timeZone")
                            .is_none_or(serde_json::Value::is_null)
                    {
                        trigger["timeZone"] = serde_json::Value::String(tz.clone());
                    }
                }
            }
        }
    }
    let manifest = parse_manifest(&manifest_json)?;
    if callable_trusted_protocol && cfg.functions_manifest.is_some() {
        // A configured manifest replaces discovery outright, and the callable flag is what
        // decides whether a request goes through the trust boundary at all: a file that calls
        // a real `onCall` an `onRequest` would have the proxy forward the raw `Authorization`
        // and App Check fields to a runner that decodes them without verifying
        // (`INV-APPCHECK-010`). The runner still discovered the truth, so the two are
        // reconciled instead of trusted blindly.
        let discovered = runner
            .hello()
            .manifest
            .clone()
            .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?;
        check_manifest_agrees_on_callables(&manifest, &parse_manifest(&discovered)?)?;
    }
    check_callable_app_check(
        &manifest,
        runner.hello().app_check.as_ref(),
        callable_trusted_protocol,
    )?;
    let config = FunctionsConfig {
        project: cfg.auth_project.clone(),
        default_bucket,
        location: "nam5".to_owned(),
        session: SessionId::new(u128::from(cfg.seed)),
        max_running: cfg.functions_max_running,
        retry_attempts: cfg.events_max_attempts,
        max_catch_up_runs: cfg.scheduler_max_catch_up_runs,
        runner_secret: runner_secret.to_owned(),
        overlap: fireemu_adapter_functions::runtime::OverlapPolicy::parse(&cfg.scheduler_overlap)
            .unwrap_or_default(),
        catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::parse(&cfg.scheduler_catch_up)
            .unwrap_or_default(),
    };
    let runtime = FunctionsRuntime::new(
        manifest,
        config,
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    // Commits reach the runtime inside the database critical section: in order, never
    // dropped, and enqueued before the write returns to its caller.
    let sink_runtime = runtime.clone();
    backend.set_change_sink(Arc::new(move |event| sink_runtime.on_commit(event)));
    Ok(runtime)
}

/// Refuses a configured manifest that disagrees with discovery about which HTTP functions are
/// callable.
///
/// Only the callable flag is reconciled. Everything else a manifest file overrides -- regions,
/// timeouts, schedules -- is deployment shape, but the callable flag decides which side of the
/// trust boundary a request lands on, and the runner is the only thing that actually knows.
fn check_manifest_agrees_on_callables(
    configured: &fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::Trigger;
    let callable_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| matches!(f.trigger, Trigger::Http { callable: true, .. }))
    };
    // The App Check options of a callable are what the runner observed in the code; a
    // manifest may not weaken them (a `consumeAppCheckToken: true` callable written as
    // disabled would run without replay protection, an `enforceAppCheck: true` one as open).
    let app_check_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| match &f.trigger {
                Trigger::Http {
                    callable: true,
                    enforce_app_check,
                    consume_app_check_token,
                } => Some((*enforce_app_check, *consume_app_check_token)),
                _ => None,
            })
    };
    for f in &configured.functions {
        if !matches!(f.trigger, Trigger::Http { .. }) {
            continue;
        }
        if let (Some(configured_options), Some(discovered_options)) = (
            app_check_in(configured, &f.name),
            app_check_in(discovered, &f.name),
        ) {
            if configured_options != discovered_options {
                return Err(format!(
                    "the configured functions manifest gives callable {:?} App Check options \
                     (enforceAppCheck / consumeAppCheckToken) that differ from what the \
                     codebase declares; the manifest cannot override them",
                    f.name
                ));
            }
        }
        match callable_in(discovered, &f.name) {
            Some(discovered_callable)
                if discovered_callable
                    == matches!(f.trigger, Trigger::Http { callable: true, .. }) => {}
            Some(_) => {
                return Err(format!(
                    "the configured functions manifest calls {:?} {}, but the codebase declares \
                     the opposite; App Check for callables cannot trust a manifest that \
                     disagrees with the code",
                    f.name,
                    if matches!(f.trigger, Trigger::Http { callable: true, .. }) {
                        "callable"
                    } else {
                        "an onRequest function"
                    }
                ))
            }
            None => {
                return Err(format!(
                    "the configured functions manifest declares the HTTP function {:?}, which \
                     the codebase does not export",
                    f.name
                ))
            }
        }
    }
    Ok(())
}

/// Fails startup when the callable App Check contract cannot be honoured (specification
/// section 13.4).
///
/// Three separate things have to hold, and each of them is fatal in its own way:
///
/// - a callable that declares `consumeAppCheckToken: true` fails discovery outright, whatever
///   else is configured, because replay protection is unimplemented and running such a callable
///   would hand it `alreadyConsumed: false` -- a silently wrong answer;
/// - with App Check enabled, a callable whose value could not be observed fails startup. The
///   value is never guessed as `false`;
/// - with App Check enabled, the runner must have proved that the installed
///   `firebase-functions` reads the debug switches the way the trusted protocol relies on. The
///   daemon turns `skipTokenVerification` on; if that flag does not mean what it is expected to
///   mean, the runner is decoding credentials under rules nobody checked.
fn check_callable_app_check(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    report: Option<&serde_json::Value>,
    callable_trusted_protocol: bool,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    let mut undetermined: Vec<&str> = Vec::new();
    for f in &manifest.functions {
        let Trigger::Http {
            callable: true,
            consume_app_check_token,
            ..
        } = &f.trigger
        else {
            continue;
        };
        match consume_app_check_token {
            ConsumeAppCheckToken::Enabled => {
                return Err(format!(
                    "callable {:?} declares consumeAppCheckToken: true, which needs limited-use \
                     token consumption (APP_CHECK_REPLAY_UNSUPPORTED); it is not implemented",
                    f.name
                ))
            }
            ConsumeAppCheckToken::Undetermined => undetermined.push(&f.name),
            ConsumeAppCheckToken::Disabled => {}
        }
    }
    if !callable_trusted_protocol {
        return Ok(());
    }
    let report = report.ok_or_else(|| {
        "the functions runner did not report its callable App Check support; App Check cannot \
         be enabled for callables"
            .to_owned()
    })?;
    let text = |key: &str| {
        report
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_owned()
    };
    let instrumentation = text("instrumentation");
    if instrumentation != "ok" {
        return Err(format!(
            "the functions runner could not read the callable App Check options: {instrumentation}"
        ));
    }
    let debug_features = text("debugFeatures");
    if debug_features != "verified" {
        return Err(format!(
            "the installed firebase-functions debug-feature semantics differ from what the \
             trusted callable protocol requires: {debug_features}"
        ));
    }
    // The auth-override fields by their actual values. The proxy strips them by name, so a
    // renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    // context (`INV-APPCHECK-010`). Refusing to start is the only safe answer: the names are
    // not something the daemon can discover at request time.
    let honoured = report
        .get("authHeaders")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            "the functions runner did not report which auth-override headers the installed \
             firebase-functions honours"
                .to_owned()
        })?;
    for field in honoured {
        let name = field.as_str().unwrap_or_default();
        if name.is_empty()
            || !fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                .iter()
                .any(|stripped| stripped.eq_ignore_ascii_case(name))
        {
            return Err(format!(
                "the installed firebase-functions honours the auth-override header {name:?}, \
                 which the callable proxy does not strip"
            ));
        }
    }
    if !undetermined.is_empty() {
        return Err(format!(
            "consumeAppCheckToken could not be determined for callable(s) {}; App Check for \
             callables fails closed rather than assuming false",
            undetermined.join(", ")
        ));
    }
    Ok(())
}

/// The Storage event observer for `runtime` (called inside the store's critical section).
pub fn storage_sink(
    runtime: &Arc<FunctionsRuntime>,
    tenancy: &fireemu_core_session::tenancy::SharedTenancy,
) -> Arc<dyn Fn(&fireemu_core_storage::store::StorageEvent) + Send + Sync> {
    let runtime = runtime.clone();
    let tenancy = tenancy.clone();
    Arc::new(move |event| {
        use fireemu_core_storage::store::StorageEvent;
        let bucket = match event {
            StorageEvent::Finalized(m)
            | StorageEvent::Deleted(m)
            | StorageEvent::MetadataUpdated(m) => m.bucket.as_str(),
        };
        // The runtime belongs to the default session: other sessions' buckets do not
        // trigger its functions.
        let owned = tenancy
            .read()
            .is_ok_and(|t| t.project_of_bucket(bucket) == runtime.project());
        if owned {
            runtime.on_storage_event(event);
        }
    })
}

/// The Auth user event observer for `runtime` (called after each Auth request).
pub fn auth_sink(
    runtime: &Arc<FunctionsRuntime>,
) -> fireemu_adapter_http::identity_toolkit::AuthEventSink {
    let runtime = runtime.clone();
    Arc::new(move |event| runtime.on_user_event(event))
}

/// The runtime as the control API's hook.
pub struct Hook(pub Arc<FunctionsRuntime>);

impl FunctionsHook for Hook {
    fn on_clock_changed(&self) {
        self.0.on_clock_changed();
    }

    fn run_schedule(&self, function: &str) -> Result<(), String> {
        self.0.run_schedule(function)
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }

    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.idle_notify()
    }

    fn status(&self) -> serde_json::Value {
        self.0.status()
    }

    fn publish(&self, topic: &str, messages: &[serde_json::Value]) -> Result<Vec<String>, String> {
        if topic.is_empty() || topic.len() > 255 {
            return Err("topic must be 1..=255 characters".to_owned());
        }
        Ok(self.0.publish(topic, messages))
    }

    fn project(&self) -> String {
        self.0.project().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::check_callable_app_check;
    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use serde_json::json;

    /// One callable with the given `consumeAppCheckToken` spelling, or none at all when
    /// `consume` is `None` (an older manifest that does not mention the field).
    fn manifest(consume: Option<&str>) -> fireemu_core_functions::manifest::FunctionManifest {
        let mut trigger = json!({"type": "http", "callable": true, "enforceAppCheck": true});
        if let Some(consume) = consume {
            trigger["consumeAppCheckToken"] = json!(consume);
        }
        parse_manifest(&json!({"functions": [{"name": "guarded", "trigger": trigger}]}))
            .expect("the fixture manifest parses")
    }

    fn report(instrumentation: &str, debug_features: &str) -> serde_json::Value {
        report_with(
            instrumentation,
            debug_features,
            &["x-callable-context-auth", "x-original-auth"],
        )
    }

    fn report_with(
        instrumentation: &str,
        debug_features: &str,
        auth_headers: &[&str],
    ) -> serde_json::Value {
        json!({
            "firebaseFunctionsVersion": "7.3.2",
            "instrumentation": instrumentation,
            "debugFeatures": debug_features,
            "debugMode": true,
            "authHeaders": auth_headers,
        })
    }

    /// Functions scenario 6: `consumeAppCheckToken: true` fails discovery outright, whether or
    /// not App Check is enabled -- replay protection is unimplemented, and the callable would
    /// otherwise run with `alreadyConsumed: false`.
    #[test]
    fn consume_app_check_token_fails_function_discovery_while_replay_support_is_unavailable() {
        for trusted in [true, false] {
            let e = check_callable_app_check(
                &manifest(Some("enabled")),
                Some(&report("ok", "verified")),
                trusted,
            )
            .expect_err("a callable that consumes tokens cannot be served");
            assert!(e.contains("APP_CHECK_REPLAY_UNSUPPORTED"), "{e}");
            assert!(e.contains("guarded"), "{e}");
        }
    }

    /// An undeterminable value is never guessed as `false`: it fails startup, but only when
    /// App Check is actually enabled for callables.
    #[test]
    fn an_undeterminable_consume_app_check_token_fails_only_with_app_check_enabled() {
        for absent in [None, Some("undetermined")] {
            let e =
                check_callable_app_check(&manifest(absent), Some(&report("ok", "verified")), true)
                    .expect_err("an unobserved option fails closed");
            assert!(e.contains("could not be determined"), "{e}");
            check_callable_app_check(&manifest(absent), None, false)
                .expect("without App Check the callable protocol is inactive");
        }
    }

    /// A configured manifest cannot weaken what the runner observed: writing a token-consuming
    /// callable as disabled would run it without replay protection.
    #[test]
    fn a_manifest_cannot_override_the_app_check_options_the_runner_observed() {
        let e = super::check_manifest_agrees_on_callables(
            &manifest(Some("disabled")),
            &manifest(Some("enabled")),
        )
        .expect_err("the manifest disagrees with the code");
        assert!(e.contains("cannot override"), "{e}");
        super::check_manifest_agrees_on_callables(
            &manifest(Some("enabled")),
            &manifest(Some("enabled")),
        )
        .expect("agreeing manifests reconcile");
    }

    #[test]
    fn a_runner_that_could_not_instrument_the_sdk_fails_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "firebase-functions 9.0.0 is outside the supported range",
                "verified",
            )),
            true,
        )
        .expect_err("the callable options cannot be trusted");
        assert!(e.contains("outside the supported range"), "{e}");
    }

    /// The daemon turns `skipTokenVerification` on. If that flag does not mean what it is
    /// expected to mean, the runner would be decoding credentials under rules nobody checked.
    #[test]
    fn unexpected_debug_feature_semantics_fail_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "ok",
                "the installed firebase-functions reads skipTokenVerification differently",
            )),
            true,
        )
        .expect_err("the debug switch semantics are part of the trust boundary");
        assert!(e.contains("debug-feature semantics differ"), "{e}");
    }

    /// The proxy strips the auth-override fields by name. A supported minor release that
    /// renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    /// context, so the mismatch has to be fatal rather than silent (`INV-APPCHECK-010`).
    #[test]
    fn an_auth_override_header_the_proxy_does_not_strip_fails_startup() {
        for honoured in [
            vec!["x-callable-context-auth", "x-firebase-callable-auth"],
            vec!["x-callable-context-auth"],
            vec![],
        ] {
            let e = check_callable_app_check(
                &manifest(Some("disabled")),
                Some(&report_with("ok", "verified", &honoured)),
                true,
            );
            if honoured.iter().all(|h| {
                fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(h))
            }) {
                // A shorter list is not a mismatch: everything it names is stripped.
                e.expect("every honoured field is stripped");
            } else {
                let e = e.expect_err("an unstripped auth-override field is fatal");
                assert!(e.contains("auth-override header"), "{e}");
            }
        }
    }

    #[test]
    fn a_runner_that_does_not_report_its_auth_override_headers_fails_startup() {
        let mut report = report("ok", "verified");
        report
            .as_object_mut()
            .expect("an object")
            .remove("authHeaders");
        let e = check_callable_app_check(&manifest(Some("disabled")), Some(&report), true)
            .expect_err("no report is no evidence");
        assert!(e.contains("auth-override headers"), "{e}");
    }

    #[test]
    fn a_runner_without_an_app_check_report_fails_startup() {
        let e = check_callable_app_check(&manifest(Some("disabled")), None, true)
            .expect_err("no report is no evidence");
        assert!(e.contains("did not report"), "{e}");
    }

    /// A configured manifest replaces discovery outright, and the callable flag decides which
    /// side of the trust boundary a request lands on. A file that calls a real `onCall` an
    /// `onRequest` would have the proxy forward the raw credentials to a runner that decodes
    /// them without verifying.
    #[test]
    fn a_configured_manifest_that_hides_a_callable_fails_startup() {
        let discovered = manifest(Some("disabled"));
        let hidden = parse_manifest(&json!({
            "functions": [{"name": "guarded", "trigger": {"type": "http", "callable": false}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&hidden, &discovered)
            .expect_err("a manifest may not reclassify a callable");
        assert!(e.contains("guarded"), "{e}");
        assert!(e.contains("disagrees with the code"), "{e}");

        let invented = parse_manifest(&json!({
            "functions": [{"name": "ghost", "trigger": {"type": "http", "callable": true}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&invented, &discovered)
            .expect_err("a manifest may not invent an HTTP function");
        assert!(e.contains("does not export"), "{e}");

        super::check_manifest_agrees_on_callables(&discovered, &discovered)
            .expect("an agreeing manifest starts");
    }

    #[test]
    fn a_fully_reported_disabled_callable_starts() {
        check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report("ok", "verified")),
            true,
        )
        .expect("a callable that does not consume tokens is servable");
    }
}
