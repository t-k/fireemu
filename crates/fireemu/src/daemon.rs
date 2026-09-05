//! Runtime assembly and lifecycle for `up` and `exec`.

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_adapter_grpc::serve::serve_multiplexed;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_adapter_http::identity_toolkit::{AuthState, AuthWallClock};
use fireemu_core_auth::jwt::IdTokenSigner;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, PlanningContext};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

use super::{
    app_check_state, bind_listeners, child_environment, clock_millis, control, control_state,
    exit_code, functions, hub, hub_emulators, import_export, load_rules, load_storage_rules,
    logical_system_time, print_banner, print_rules_status, random_secret, runtime_thread_counts,
    service_admission, session_rsa_cache, spawn_child, start_firestore_config_reload_supervisors,
    stop_child, storage_state, terminate_signal, ui, wait_child, BoundAddrs, ExecPlan, Exporter,
    Listeners, Options, RedactedRuntimeConfig, RuntimeConfig, Selection, Verbosity,
};

struct BoundStartup {
    cfg: RuntimeConfig,
    only: Selection,
    verbosity: Verbosity,
    import: Option<PathBuf>,
    export_on_exit: Option<PathBuf>,
    quiet: bool,
    auth_wall_clock: Option<AuthWallClock>,
    clock: Arc<Mutex<VirtualClock>>,
    gateway: Gateway,
    backend: Arc<LocalBackend>,
    text_indexes: Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>>,
    faults: fireemu_core_session::fault::SharedFaultRegistry,
    tenancy: fireemu_core_session::tenancy::SharedTenancy,
    auth_store: Arc<Mutex<AuthStore>>,
    registry: Arc<fireemu_core_auth::store::AuthRegistry>,
    rules: Arc<RulesetSlot>,
    database_rules: std::collections::BTreeMap<String, Arc<RulesetSlot>>,
    storage_rules: super::LoadedStorageRules,
    barrier: Arc<fireemu_core_session::barrier::AdmissionBarrier>,
    listeners: Listeners,
    ui_listener: Option<tokio::net::TcpListener>,
    ui_note: Option<String>,
    addrs: BoundAddrs,
    control_token: String,
    storage_admin_capability: String,
    app_check: Option<Arc<fireemu_adapter_http::app_check::AppCheckState>>,
    app_check_gate: Option<fireemu_core_app_check::AppCheckGate>,
    callable_trusted_protocol: bool,
    functions_runtime: Option<Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>>,
}

struct ServiceAssembly {
    cfg: RuntimeConfig,
    only: Selection,
    verbosity: Verbosity,
    import: Option<PathBuf>,
    export_on_exit: Option<PathBuf>,
    quiet: bool,
    clock: Arc<Mutex<VirtualClock>>,
    gateway: Gateway,
    backend: Arc<LocalBackend>,
    auth_store: Arc<Mutex<AuthStore>>,
    registry: Arc<fireemu_core_auth::store::AuthRegistry>,
    rules: Arc<RulesetSlot>,
    database_rules: std::collections::BTreeMap<String, Arc<RulesetSlot>>,
    listeners: Listeners,
    ui_listener: Option<tokio::net::TcpListener>,
    ui_note: Option<String>,
    addrs: BoundAddrs,
    control_token: String,
    storage_admin_capability: String,
    app_check: Option<Arc<fireemu_adapter_http::app_check::AppCheckState>>,
    callable_trusted_protocol: bool,
    functions_runtime: Option<Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>>,
    firestore_policy: Option<Arc<fireemu_core_app_check::ServiceAdmission>>,
    auth: Arc<AuthState>,
    storage: Arc<fireemu_adapter_http::storage::StorageState>,
    control: Arc<fireemu_adapter_http::control::ControlState>,
    pubsub: fireemu_adapter_pubsub::PubSubHandle,
}

fn function_log_input(
    level: &str,
    message: &str,
    function: Option<&str>,
    user: bool,
    fields: serde_json::Map<String, serde_json::Value>,
    timestamp_ms: i64,
) -> fireemu_adapter_logging::LogInput {
    let mut input = fireemu_adapter_logging::LogInput::plain(level, message, timestamp_ms)
        .for_emulator("functions");
    if let Some(function) = function {
        input = input.for_function(function);
    }
    input.user = user;
    input.fields = fields;
    input
}

fn assemble_adapters(bound: BoundStartup) -> Result<ServiceAssembly, String> {
    let BoundStartup {
        cfg,
        only,
        verbosity,
        import,
        export_on_exit,
        quiet,
        auth_wall_clock,
        clock,
        gateway,
        backend,
        text_indexes,
        faults,
        tenancy,
        auth_store,
        registry,
        rules,
        database_rules,
        storage_rules,
        barrier,
        listeners,
        ui_listener,
        ui_note,
        addrs,
        control_token,
        storage_admin_capability,
        app_check,
        app_check_gate,
        callable_trusted_protocol,
        functions_runtime,
    } = bound;
    let Listeners {
        firestore: grpc_listener,
        control: http_listener,
        auth_selected,
        storage: storage_listener,
        functions: functions_listener,
        eventarc: eventarc_listener,
        tasks: tasks_listener,
        pubsub: pubsub_listener,
        hub: hub_listener,
        logging: logging_listener,
    } = listeners;
    // The Pub/Sub broker: real topic/subscription state served over gRPC. Its seed is the
    // daemon seed with a fixed tag so its message and ack ids never coincide with another
    // subsystem's stream. A published message also reaches subscribed Cloud Functions
    // through the bridge (EVTINFRA-02), when a functions runtime is loaded.
    let pubsub_state = Arc::new(Mutex::new(fireemu_core_pubsub::PubSubState::new(
        cfg.seed ^ 0x5053_5542,
    )));
    let pubsub_resources = if pubsub_listener.is_some() {
        if let Some(runtime) = &functions_runtime {
            let resources =
                functions::function_pubsub_resources(runtime.project(), runtime.manifest())?;
            let mut state = pubsub_state
                .lock()
                .map_err(|_| "the Pub/Sub state lock is poisoned".to_owned())?;
            functions::provision_function_pubsub_resources(&mut state, &resources)?;
            resources
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let pubsub_bridge: Option<Arc<dyn fireemu_adapter_pubsub::TopicDelivery>> =
        functions_runtime.as_ref().map(|r| {
            Arc::new(functions::PubSubBridge::new(r.clone()))
                as Arc<dyn fireemu_adapter_pubsub::TopicDelivery>
        });
    let pubsub_handle = fireemu_adapter_pubsub::PubSubHandle::new(
        pubsub_state.clone(),
        clock.clone(),
        pubsub_bridge,
    );
    let auth_policy = service_admission(
        app_check_gate.as_ref(),
        "auth",
        only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Auth),
    );
    let firestore_policy = service_admission(
        app_check_gate.as_ref(),
        "firestore",
        only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Firestore),
    );
    let storage_policy = service_admission(
        app_check_gate.as_ref(),
        "storage",
        only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Storage),
    );
    // Auth user events reach the functions runtime after each Auth request.
    let auth = Arc::new(AuthState {
        store: auth_store.clone(),
        clock: clock.clone(),
        wall_clock: auth_wall_clock,
        totp_extension_enabled: cfg.auth_totp.is_some(),
        barrier: Some(barrier.clone()),
        events: functions_runtime.as_ref().map(functions::auth_sink),
        blocking: functions_runtime.as_ref().map(|runtime| {
            Arc::new(
                functions::BlockingAuthBridge::new_with_forward_inbound_credentials(
                    runtime.clone(),
                    cfg.auth_forward_inbound_credentials,
                ),
            ) as Arc<dyn fireemu_adapter_http::identity_toolkit::AuthBlockingHook>
        }),
        operation_gate: Arc::new(Mutex::new(())),
        control_token: Some(control_token.clone()),
        registry: Some(registry.clone()),
        allow_routed_projects: cfg.profile == crate::config::CompatibilityProfile::Firebase,
        stateless_refresh_tokens: cfg.profile == crate::config::CompatibilityProfile::Firebase,
        query_limits: match cfg.profile {
            crate::config::CompatibilityProfile::Firebase => {
                fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded
            }
            crate::config::CompatibilityProfile::Strict => {
                fireemu_adapter_http::identity_toolkit::AuthQueryLimits::ProductionBounded
            }
        },
        fake_custom_token_expiry: match cfg.profile {
            crate::config::CompatibilityProfile::Firebase => {
                fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore
            }
            crate::config::CompatibilityProfile::Strict => {
                fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject
            }
        },
        tenancy: Some(tenancy.clone()),
        app_check: app_check.clone(),
        app_check_policy: auth_policy,
    });
    // A fault plan that moves the clock wakes the functions runtime like the clock
    // route does.
    let clock_observer: Option<Arc<dyn Fn() + Send + Sync>> = functions_runtime.as_ref().map(|r| {
        let r = r.clone();
        Arc::new(move || r.on_clock_changed()) as Arc<dyn Fn() + Send + Sync>
    });
    if let Some(observer) = &clock_observer {
        backend.set_clock_observer(observer.clone());
    }
    let storage = storage_state(
        &cfg,
        &clock,
        &registry,
        &tenancy,
        &storage_rules.registry,
        functions_runtime
            .as_ref()
            .map(|r| functions::storage_sink(r, &tenancy)),
        &backend,
        &faults,
        clock_observer,
        storage_policy,
        storage_admin_capability.clone(),
    )?;
    if let Some(runtime) = &functions_runtime {
        runtime.set_faults(faults.for_project(runtime.project()));
        if let Some(gate) = &app_check_gate {
            // The callable baseline is `unenforced`: the daemon classifies and records
            // every callable token, and the callable's own `enforceAppCheck` decides
            // (specification section 13.4). The Auth verifier is a dedicated enforcer that
            // never evaluates a rule: it exists to verify the ID token against the target
            // project's users on the virtual clock, which is required whether or not
            // Security Rules are enforced at all.
            // The service label is the core's own constant: counters group callable
            // observations by function name for exactly this label (section 15).
            let policy = service_admission(
                Some(gate),
                fireemu_core_app_check::observe::FUNCTIONS_SERVICE,
                fireemu_core_app_check::verify::BaselineMode::Unenforced,
            )
            .ok_or_else(|| "the callable App Check policy is unavailable".to_owned())?;
            let verifier = Arc::new(
                RulesEnforcer::new(
                    Arc::new(RulesetSlot::default()),
                    auth_store.clone(),
                    clock.clone(),
                )
                .with_registry(registry.clone()),
            );
            runtime.set_callable_trust(Arc::new(
                fireemu_adapter_functions::callable::CallableTrust::new(
                    policy,
                    verifier,
                    runtime.project(),
                ),
            ));
        }
    }
    let control = Arc::new(control_state(
        &cfg,
        &clock,
        &rules,
        &database_rules,
        &storage_rules.registry,
        &backend,
        &auth_store,
        &storage,
        functions_runtime.as_ref(),
        control_token.clone(),
        faults.clone(),
        text_indexes.clone(),
        &registry,
        tenancy.clone(),
        app_check_gate.clone(),
        &pubsub_state,
        &pubsub_handle,
        &pubsub_resources,
    ));
    Ok(ServiceAssembly {
        cfg,
        only,
        verbosity,
        import,
        export_on_exit,
        quiet,
        clock,
        gateway,
        backend,
        auth_store,
        registry,
        rules,
        database_rules,
        listeners: Listeners {
            firestore: grpc_listener,
            control: http_listener,
            auth_selected,
            storage: storage_listener,
            functions: functions_listener,
            eventarc: eventarc_listener,
            tasks: tasks_listener,
            pubsub: pubsub_listener,
            hub: hub_listener,
            logging: logging_listener,
        },
        ui_listener,
        ui_note,
        addrs,
        control_token,
        storage_admin_capability,
        app_check,
        callable_trusted_protocol,
        functions_runtime,
        firestore_policy,
        auth,
        storage,
        control,
        pubsub: pubsub_handle,
    })
}

fn assemble_suite(assembly: ServiceAssembly, exec_mode: bool) -> Result<ReadySuite, String> {
    let ServiceAssembly {
        cfg,
        only,
        verbosity,
        import,
        export_on_exit,
        quiet,
        clock,
        gateway,
        backend,
        auth_store,
        registry,
        rules,
        database_rules,
        listeners,
        ui_listener,
        ui_note,
        addrs,
        control_token,
        storage_admin_capability,
        app_check,
        callable_trusted_protocol,
        functions_runtime,
        firestore_policy,
        auth,
        storage,
        control,
        pubsub,
    } = assembly;
    let http_addr = addrs.control;
    let hub_addr = addrs.hub;
    let ui_addr = addrs.ui;

    // The Emulator Hub's locator file lives as long as this scope: dropping it removes
    // the file, so a clean exit on either signal path leaves no stale discovery behind.
    // The export seam: one object that owns everything an export reads, shared by the
    // Hub's route, `emulators:export` and `--export-on-exit`.
    let exporter = Arc::new(Exporter {
        backend: backend.clone(),
        auth: registry.clone(),
        storage: storage.clone(),
        clock: clock.clone(),
        project: cfg.auth_project.clone(),
        products: import_export::Products::from(&only),
    });
    // The import happens before the command starts and before the banner claims the
    // suite is ready: a run that cannot install its fixture must not run at all.
    if let Some(dir) = &import {
        let prepared = import_export::prepare(dir, exporter.products, &cfg.auth_project)
            .map_err(|e| format!("--import {}: {e}", dir.display()))?;
        if !quiet {
            for notice in &prepared.notices {
                eprintln!("note: --import {}: {notice}", dir.display());
            }
        }
        let summary = prepared.summary();
        import_export::apply(prepared, &exporter.endpoints())
            .map_err(|e| format!("--import {}: {e}", dir.display()))?;
        if !quiet {
            println!("  imported: {} ({summary})", dir.display());
        }
    }
    let hub_state = Arc::new(hub::HubState {
        project: cfg.auth_project.clone(),
        addr: hub_addr.unwrap_or(http_addr),
        emulators: hub_emulators(&addrs),
        functions: functions_runtime.clone(),
        export: Some(exporter.clone() as Arc<dyn hub::ExportRunner>),
        control_token: control_token.clone(),
    });
    let locator = hub_addr.map(|_| {
        let (locator, note) = hub::Locator::write(&hub_state);
        if let (Some(note), false) = (note, quiet) {
            eprintln!("note: {note}");
        }
        locator
    });
    if !quiet {
        print_banner(
            &cfg,
            if exec_mode { "exec" } else { "up" },
            &addrs,
            functions_runtime.as_deref(),
        );
        if let Some(state) = &app_check {
            println!(
            "  app check:        {} app(s)   FIREEMU_APP_CHECK_EMULATOR_HOST={http_addr}   JWKS: http://{http_addr}/v1/jwks (kid {})",
            cfg.app_check.apps.len(),
            state.signer.kid()
        );
            println!(
            "  app check modes:  auth={} firestore={} storage={}   (Firestore covers unary gRPC, REST, Write/Listen streams and WebChannel; Storage covers resumable uploads too){}",
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Auth),
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Firestore),
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Storage),
            if callable_trusted_protocol {
                "\n  app check callables: the trusted callable protocol is active; enforceAppCheck is honoured per function"
            } else {
                ""
            },
        );
        }
        if let Some(addr) = ui_addr {
            println!("  ui:               http://{addr}/ui");
        }
        if let Some(note) = ui_note {
            println!("{note}");
        }
        print_rules_status(&cfg, rules.snapshot().is_ok_and(|r| r.is_loaded()));
        if let Some(runtime) = &functions_runtime {
            let names: Vec<&str> = runtime
                .manifest()
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect();
            println!("  functions loaded: {}", names.join(", "));
        }
        if verbosity == Verbosity::Debug {
            println!("  resolved config:  {:?}", RedactedRuntimeConfig(&cfg));
            println!("  selection:        {only:?}");
        }
    }

    let enforcer = cfg.rules_enforced.then(|| {
        Arc::new(
            RulesEnforcer::new(rules.clone(), auth_store.clone(), clock.clone())
                .with_registry(registry.clone())
                .with_database_rules(database_rules.clone())
                .with_token_acceptance(cfg.token_acceptance),
        )
    });
    let mut service = GatewayService::local(gateway.clone(), backend.clone());
    if let Some(e) = &enforcer {
        service = service.with_rules(e.clone());
    }
    if let Some(policy) = &firestore_policy {
        service = service.with_app_check(policy.clone());
    }
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway),
        rules: enforcer,
        app_check: firestore_policy,
    });
    Ok(ReadySuite {
        cfg,
        only,
        quiet,
        export_on_exit,
        clock,
        backend,
        auth,
        storage,
        control,
        app_check,
        functions_runtime,
        exporter,
        hub_state,
        locator,
        addrs,
        control_token,
        storage_admin_capability,
        listeners,
        ui_listener,
        firestore_service: service,
        rest,
        pubsub,
    })
}

struct ReadySuite {
    cfg: RuntimeConfig,
    only: Selection,
    quiet: bool,
    export_on_exit: Option<PathBuf>,
    clock: Arc<Mutex<VirtualClock>>,
    backend: Arc<LocalBackend>,
    auth: Arc<AuthState>,
    storage: Arc<fireemu_adapter_http::storage::StorageState>,
    control: Arc<fireemu_adapter_http::control::ControlState>,
    app_check: Option<Arc<fireemu_adapter_http::app_check::AppCheckState>>,
    functions_runtime: Option<Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>>,
    exporter: Arc<Exporter>,
    hub_state: Arc<hub::HubState>,
    locator: Option<hub::Locator>,
    addrs: BoundAddrs,
    control_token: String,
    storage_admin_capability: String,
    listeners: Listeners,
    ui_listener: Option<tokio::net::TcpListener>,
    firestore_service: GatewayService,
    rest: Arc<RestState>,
    pubsub: fireemu_adapter_pubsub::PubSubHandle,
}

async fn serve_suite(ready: ReadySuite, exec: Option<ExecPlan>) -> Result<i32, String> {
    let ReadySuite {
        cfg,
        only,
        quiet,
        export_on_exit,
        clock,
        backend,
        auth,
        storage,
        control,
        app_check,
        functions_runtime,
        exporter,
        hub_state,
        locator: _locator,
        addrs,
        control_token,
        storage_admin_capability,
        listeners,
        ui_listener,
        firestore_service,
        rest,
        pubsub,
    } = ready;
    let Listeners {
        firestore: grpc_listener,
        control: http_listener,
        auth_selected: _,
        storage: storage_listener,
        functions: functions_listener,
        eventarc: eventarc_listener,
        tasks: tasks_listener,
        pubsub: pubsub_listener,
        hub: hub_listener,
        logging: logging_listener,
    } = listeners;
    let mut servers = tokio::task::JoinSet::<(&'static str, String)>::new();
    macro_rules! spawn_server {
        ($name:literal, $future:expr) => {
            let future = $future;
            servers.spawn(async move { ($name, format!("{:?}", future.await)) });
        };
    }
    if let Some(listener) = grpc_listener {
        spawn_server!(
            "gRPC",
            serve_multiplexed(
                listener,
                FirestoreServer::new(firestore_service)
                    .max_decoding_message_size(10 * 1024 * 1024)
                    .max_encoding_message_size(10 * 1024 * 1024),
                rest.clone(),
            )
        );
    }
    spawn_server!(
        "HTTP",
        fireemu_adapter_http::server::serve_with_control(
            http_listener,
            auth.clone(),
            control.clone(),
        )
    );
    if let Some(listener) = storage_listener {
        spawn_server!(
            "Storage",
            fireemu_adapter_http::storage_server::serve_storage(listener, storage.clone())
        );
    }
    if let Some(listener) = hub_listener {
        spawn_server!("Emulator Hub", hub::serve(listener, hub_state.clone()));
    }
    let functions_http_admission = fireemu_adapter_functions::http::HttpAdmission::new();
    if let (Some(listener), Some(runtime)) = (functions_listener, functions_runtime.clone()) {
        spawn_server!(
            "Functions",
            fireemu_adapter_functions::http::serve_functions(
                listener,
                runtime,
                functions_http_admission.clone(),
            )
        );
    }
    if let (Some(listener), Some(runtime)) = (eventarc_listener, functions_runtime.clone()) {
        spawn_server!(
            "Eventarc",
            fireemu_adapter_functions::http::serve_eventarc(
                listener,
                runtime,
                functions_http_admission.clone(),
            )
        );
    }
    if let (Some(listener), Some(runtime)) = (tasks_listener, functions_runtime.clone()) {
        spawn_server!(
            "Cloud Tasks",
            fireemu_adapter_functions::http::serve_tasks(
                listener,
                runtime,
                functions_http_admission,
            )
        );
    }
    if let Some(listener) = pubsub_listener {
        spawn_server!(
            "Pub/Sub",
            fireemu_adapter_pubsub::serve_pubsub(listener, pubsub)
        );
    }
    let log_bus = fireemu_adapter_logging::LogBus::new();
    for (name, addr) in [
        ("firestore", addrs.firestore),
        ("auth", addrs.auth),
        ("storage", addrs.storage),
        ("functions", addrs.functions),
        ("eventarc", addrs.eventarc),
        ("tasks", addrs.tasks),
        ("pubsub", addrs.pubsub),
    ] {
        if let Some(addr) = addr {
            log_bus.publish(
                &fireemu_adapter_logging::LogInput::plain(
                    "info",
                    format!("{name} emulator started on {addr}"),
                    clock_millis(&clock),
                )
                .for_emulator(name),
            );
        }
    }
    let functions_log_pump = functions_runtime.clone().map(|runtime| {
        let bus = log_bus.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            let mut cursors: std::collections::BTreeMap<
                String,
                (Arc<fireemu_adapter_functions::runner::Runner>, Option<u64>),
            > = std::collections::BTreeMap::new();
            let mut poll = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                poll.tick().await;
                let runners = runtime.current_runners();
                cursors.retain(|name, _| runners.iter().any(|(current, _)| current == name));
                for (codebase, runner) in runners {
                    let state = cursors
                        .entry(codebase.clone())
                        .or_insert_with(|| (runner.clone(), None));
                    if !Arc::ptr_eq(&state.0, &runner) {
                        *state = (runner.clone(), None);
                    }
                    let slice = runner.logs_since(state.1);
                    state.1 = Some(slice.next_seq);
                    if slice.truncated {
                        bus.publish(
                            &fireemu_adapter_logging::LogInput::plain(
                                "warning",
                                format!(
                                    "earlier function logs were truncated for codebase {codebase}"
                                ),
                                clock_millis(&clock),
                            )
                            .for_emulator("functions"),
                        );
                    }
                    for line in slice.lines {
                        bus.publish(&function_log_input(
                            line.level(),
                            line.message(),
                            line.function(),
                            line.is_user(),
                            line.fields().clone(),
                            clock_millis(&clock),
                        ));
                    }
                }
            }
        })
    });
    if let Some(listener) = logging_listener {
        spawn_server!(
            "Logging emulator",
            fireemu_adapter_logging::serve_logging(listener, log_bus.clone())
        );
    }
    if let (Some(listener), Some(addr)) = (ui_listener, addrs.ui) {
        let state = ui::state(ui::Parts {
            cfg: &cfg,
            only: &only,
            control_token: control_token.clone(),
            rest: rest.clone(),
            backend: backend.clone(),
            auth: auth.clone(),
            storage: storage.clone(),
            control: control.clone(),
            functions: functions_runtime.clone(),
            app_check,
            addrs: (
                addrs.firestore.unwrap_or(addrs.control),
                addrs.control,
                addrs.storage.unwrap_or(addrs.control),
                addrs.functions,
                addr,
            ),
        });
        spawn_server!("UI", fireemu_adapter_ui::server::serve_ui(listener, state));
    }
    // Every listener is now served, so an exec child can safely use all advertised endpoints.
    let mut child = match &exec {
        Some(plan) => {
            let env = child_environment(
                &cfg,
                &only,
                &addrs,
                &control_token,
                &storage_admin_capability,
            );
            if !quiet {
                println!("  running command");
            }
            Some(spawn_child(plan, &env)?)
        }
        None => None,
    };
    let child_pid = child.as_ref().and_then(super::child_id);
    let mut terminated = false;
    let outcome = tokio::select! {
        result = servers.join_next() => match result {
            Some(Ok((name, result))) => Err(format!("{name} server stopped: {result}")),
            Some(Err(error)) => Err(format!("server task stopped: {error}")),
            None => Err("all server tasks stopped".to_owned()),
        },
        status = wait_child(child.as_mut()) => match status {
            Ok(status) => Ok(Some(exit_code(status))),
            Err(e) => Err(format!("waiting for the command: {e}")),
        },
        _ = tokio::signal::ctrl_c() => {
            if !quiet {
                println!("shutting down");
            }
            Ok::<Option<i32>, String>(None)
        }
        () = terminate_signal() => {
            if !quiet {
                println!("shutting down (SIGTERM)");
            }
            terminated = true;
            Ok::<Option<i32>, String>(None)
        }
    };
    // Keep services and the Hub locator alive through child cleanup, export, and Functions
    // shutdown. Every remaining server is then aborted and joined before its listener can leave
    // this function.
    if let Some(pump) = &functions_log_pump {
        pump.abort();
    }
    let code = match (&outcome, child.as_mut(), child_pid) {
        (Ok(Some(code)), Some(child), Some(pid)) => {
            #[cfg(not(windows))]
            super::sweep_child_tree(child, pid);
            #[cfg(windows)]
            super::sweep_child_tree(child, pid).await;
            *code
        }
        (Ok(Some(code)), _, None) => *code,
        (_, Some(child), Some(pid)) => {
            stop_child(child, pid, if terminated { "-TERM" } else { "-INT" }).await
        }
        _ => 0,
    };
    if let Some(dir) = &export_on_exit {
        use hub::ExportRunner as _;
        match exporter.export(dir, "exit") {
            Ok(()) => {
                if !quiet {
                    println!("exported to {}", dir.display());
                }
            }
            Err(e) => eprintln!("error: --export-on-exit {}: {e}", dir.display()),
        }
    }
    if let Some(runtime) = functions_runtime {
        runtime.shutdown().await;
    }
    servers.abort_all();
    while servers.join_next().await.is_some() {}
    outcome.map(|_| code)
}

fn build_runtime() -> Result<tokio::runtime::Runtime, String> {
    let worker_override = std::env::var("FIREEMU_WORKER_THREADS").ok();
    let blocking_override = std::env::var("FIREEMU_MAX_BLOCKING_THREADS").ok();
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let (workers, blocking) = runtime_thread_counts(
        available,
        worker_override.as_deref(),
        blocking_override.as_deref(),
    )?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(blocking)
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start runtime: {e}"))
}

pub(super) fn run(options: Options, exec: Option<ExecPlan>) -> ExitCode {
    let Options {
        mut cfg,
        only,
        verbosity,
        import,
        export_on_exit,
    } = options;
    let quiet = verbosity == Verbosity::Quiet;
    let auth_wall_clock = if cfg.clock_start_pinned {
        None
    } else {
        // Unpinned: start at the precise wall-clock instant so a credential mutation around
        // a second boundary cannot lag the caller by the subsecond part discarded at startup.
        // Token claims are still serialized at second precision; daemon.clockStart pins the
        // logical clock for reproducible runs.
        let monotonic_start = std::time::Instant::now();
        cfg.clock_start = logical_system_time(std::time::SystemTime::now());
        Some(AuthWallClock::from_anchor(cfg.clock_start, monotonic_start))
    };
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
        let gateway = Gateway {
            enforce_limits: cfg.enforce_limits,
            ctx: PlanningContext {
                edition: cfg.edition,
                api_mode: cfg.api_mode,
                policy: cfg.index_policy,
            },
            indexes: match &cfg.index_file {
                Some(path) => control::load_indexes(path)?,
                None => IndexSet::default(),
            },
        };
        let backend = Arc::new(if cfg.clock_start_pinned {
            LocalBackend::new(gateway.clone(), clock.clone(), cfg.seed)
        } else {
            LocalBackend::new(gateway.clone(), clock.clone(), cfg.seed)
                .with_wall_clock_write_time()
        });
        for (database, files) in &cfg.firestore_databases {
            if database != fireemu_core_types::ids::DatabaseId::DEFAULT {
                if let Some(path) = &files.indexes {
                    backend.replace_database_indexes(database, control::load_indexes(path)?);
                }
            }
        }
        // Text Index definitions (FS-TEXT-VAL-1): validated at start, never executed.
        let text_indexes = Arc::new(Mutex::new(control::load_text_indexes(&cfg)?));
        // The sessions' fault plans (spec 18), shared by every adapter; empty until PUT.
        let faults: fireemu_core_session::fault::SharedFaultRegistry =
            Arc::new(fireemu_core_session::fault::FaultRegistry::new());
        backend.set_faults(faults.clone());
        // Which session owns which project, bucket and API key.
        let tenancy: fireemu_core_session::tenancy::SharedTenancy = Arc::new(RwLock::new(
            fireemu_core_session::tenancy::Tenancy::new(&cfg.auth_project),
        ));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            &cfg.auth_project,
            SplitMix64::new(cfg.seed ^ 0xA0),
            cfg.auth_totp.unwrap_or_default(),
        )));
        // Both keys are 2048-bit RSA and slow to generate in a debug build; when both are
        // wanted they are generated concurrently on blocking tasks. They are always separate
        // keys: the Auth key is derived from the session seed, the App Check key is drawn from
        // the operating system CSPRNG once per daemon instance (spec 7.2).
        let want_auth_key = only.uses_auth_identity()
            && cfg.id_token_signing == fireemu_core_auth::jwt::SigningMode::SessionRsa;
        let want_app_check = only.app_check_available(&cfg.app_check);
        if (want_auth_key || want_app_check) && !quiet {
            println!("  generating the RSA signing keys ...");
        }
        let auth_key = want_auth_key.then(|| {
            let seed = cfg.seed ^ 0x2256;
            tokio::task::spawn_blocking(move || session_rsa_cache::load_or_generate(seed))
        });
        let app_check_key = want_app_check.then(|| {
            tokio::task::spawn_blocking(|| {
                fireemu_adapter_http::signing::AppCheckRsaSigner::generate(
                    fireemu_adapter_http::signing::AppCheckKeySource::OperatingSystem,
                )
            })
        });
        let app_check_signer = match app_check_key {
            Some(task) => Some(task.await.map_err(|e| format!("App Check RSA key: {e}"))??),
            None => None,
        };
        let barrier = backend.barrier();
        // Session projects other than the default get their own Auth store (same signer).
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            &cfg.auth_project,
            auth_store.clone(),
        ));
        let rules = Arc::new(RulesetSlot::new(load_rules(&cfg)?));
        let mut database_rules = std::collections::BTreeMap::new();
        for (database, files) in &cfg.firestore_databases {
            if database == fireemu_core_types::ids::DatabaseId::DEFAULT {
                continue;
            }
            let loaded = match &files.rules {
                Some(path) => {
                    let source = std::fs::read_to_string(path)
                        .map_err(|error| format!("rules source {path}: {error}"))?;
                    LoadedRules::from_source(&source)
                        .map_err(|error| format!("rules source {path} does not parse: {error}"))?
                }
                None => LoadedRules::default(),
            };
            database_rules.insert(database.clone(), Arc::new(RulesetSlot::new(loaded)));
        }
        let storage_rules = load_storage_rules(&cfg)?;
        start_firestore_config_reload_supervisors(
            &cfg,
            &backend,
            &rules,
            &database_rules,
            &storage_rules,
            &barrier,
        );
        let Listeners {
            firestore: grpc_listener,
            control: http_listener,
            auth_selected,
            storage: storage_listener,
            functions: functions_listener,
            eventarc: eventarc_listener,
            tasks: tasks_listener,
            pubsub: pubsub_listener,
            hub: hub_listener,
            logging: logging_listener,
        } = bind_listeners(&cfg, &only).await?;
        let grpc_addr = match grpc_listener.as_ref() {
            Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?),
            None => None,
        };
        let http_addr = http_listener.local_addr().map_err(|e| e.to_string())?;
        let storage_addr = match storage_listener.as_ref() {
            Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?),
            None => None,
        };
        let functions_addr = functions_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok());
        let eventarc_addr = eventarc_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok());
        let tasks_addr = tasks_listener.as_ref().and_then(|l| l.local_addr().ok());
        let pubsub_addr = pubsub_listener.as_ref().and_then(|l| l.local_addr().ok());
        let hub_addr = hub_listener.as_ref().and_then(|l| l.local_addr().ok());
        let logging_addr = logging_listener.as_ref().and_then(|l| l.local_addr().ok());
        let (ui_listener, ui_note) = match ui::bind().await? {
            ui::Ui::Bound(listener) => (Some(listener), None),
            ui::Ui::Disabled => (None, None),
            ui::Ui::Unavailable(note) => (None, Some(note)),
        };
        let ui_addr = ui_listener.as_ref().and_then(|l| l.local_addr().ok());
        let addrs = BoundAddrs {
            firestore: grpc_addr,
            auth: auth_selected.then_some(http_addr),
            storage: storage_addr,
            functions: functions_addr,
            eventarc: eventarc_addr,
            tasks: tasks_addr,
            pubsub: pubsub_addr,
            hub: hub_addr,
            ui: ui_addr,
            logging: logging_addr,
            control: http_addr,
        };
        // Random secrets: the control token browsers must present, and the secret that ties
        // the runner's HTTP server to this daemon's proxy.
        let control_token = random_secret()?;
        let runner_secret = random_secret()?;
        let storage_admin_capability = random_secret()?;
        let app_check = match app_check_signer {
            Some(signer) => Some(app_check_state(
                &cfg,
                &clock,
                &barrier,
                &control_token,
                signer,
            )?),
            None => None,
        };
        // One gate for the whole daemon; one policy per product from appCheck.services.* and
        // the --only selection (the activation table of specification section 8).
        let app_check_gate = app_check.as_ref().map(|s| s.gate());
        // Row 4 of the activation table: selecting Functions selects its App Check dependency,
        // and the callable trusted protocol is then active for every callable -- including the
        // ones that do not enforce, so valid app context is available to them. The runner is
        // started only after this is known, because it decides whether the runner may run with
        // the `skipTokenVerification` debug feature at all.
        let callable_trusted_protocol = app_check_gate.is_some() && functions_listener.is_some();
        // The runner's functions see exactly the services this run selected: an unselected
        // one leaves its variable unset there too, so a handler cannot reach a product the
        // suite is not running.
        let functions_runtime = match functions_listener.as_ref() {
            Some(_) => Some(
                functions::start(
                    &cfg,
                    &clock,
                    &backend,
                    &functions::EmulatorHosts {
                        firestore: grpc_addr.map(|a| a.to_string()),
                        auth: addrs.auth.map(|a| a.to_string()),
                        storage: storage_addr.map(|a| a.to_string()),
                        functions: functions_addr.map(|a| a.to_string()),
                        eventarc: eventarc_addr.map(|a| a.to_string()),
                        tasks: tasks_addr.map(|a| a.to_string()),
                        logging: logging_addr.map(|a| a.to_string()),
                    },
                    &runner_secret,
                    callable_trusted_protocol,
                )
                .await?,
            ),
            None => None,
        };
        // Auth signing is independent of rules, listener binding and Functions discovery.
        // Await it only after those startup tasks have had the whole key-generation window
        // to make progress; no Auth listener is served until the tasks below are spawned.
        if let Some(task) = auth_key {
            let signer = task.await.map_err(|e| format!("session RSA key: {e}"))??;
            if !quiet {
                println!(
                    "  id tokens:        RS256 (kid {})   JWKS: http://{}/.well-known/jwks.json",
                    signer.kid(),
                    cfg.http_addr
                );
                println!("  note: the Firebase Admin SDK verifies only unsigned tokens while FIREBASE_AUTH_EMULATOR_HOST is set; keep auth.idTokenSigning = \"unsigned-emulator\" when the Admin SDK calls verifyIdToken");
            }
            if let Ok(mut store) = auth_store.lock() {
                store.set_signer(signer);
            }
        }
        let assembly = assemble_adapters(BoundStartup {
                cfg,
                only,
                verbosity,
                import,
                export_on_exit,
                quiet,
                auth_wall_clock,
                clock,
                gateway,
                backend,
                text_indexes,
                faults,
                tenancy,
                auth_store,
                registry,
                rules,
                database_rules,
                storage_rules,
                barrier,
                listeners: Listeners {
                    firestore: grpc_listener,
                    control: http_listener,
                    auth_selected,
                    storage: storage_listener,
                    functions: functions_listener,
                    eventarc: eventarc_listener,
                    tasks: tasks_listener,
                    pubsub: pubsub_listener,
                    hub: hub_listener,
                    logging: logging_listener,
                },
                ui_listener,
                ui_note,
                addrs,
                control_token,
                storage_admin_capability,
                app_check,
                app_check_gate,
                callable_trusted_protocol,
                functions_runtime,
            })?;
        let ready = assemble_suite(assembly, exec.is_some())?;
        serve_suite(ready, exec).await
    });
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::function_log_input;
    use fireemu_adapter_logging::wire::build_bundle;

    #[test]
    fn function_user_logs_keep_the_official_logging_metadata() {
        let fields = serde_json::Map::from_iter([
            (
                "trace".to_owned(),
                serde_json::json!("projects/demo/traces/abc"),
            ),
            ("metadata".to_owned(), serde_json::json!({"spoofed": true})),
        ]);
        let bundle = build_bundle(&function_log_input(
            "warning",
            "payment delayed",
            Some("settlePayment"),
            true,
            fields,
            123,
        ));

        assert_eq!(bundle["level"], "warning");
        assert_eq!(bundle["message"], "payment delayed");
        assert_eq!(bundle["data"]["metadata"]["emulator"]["name"], "functions");
        assert_eq!(
            bundle["data"]["metadata"]["function"]["name"],
            "settlePayment"
        );
        assert_eq!(bundle["data"]["metadata"]["type"], "USER");
        assert_eq!(bundle["data"]["trace"], "projects/demo/traces/abc");
        assert_eq!(bundle["data"]["metadata"]["user"]["spoofed"], true);
    }
}
