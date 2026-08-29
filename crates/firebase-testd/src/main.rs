//! `firebase-testd` command-line entry point.
//!
//! ```text
//! firebase-testd up [--config firebase-testd.json] [--firestore-port 8080] [--http-port 9099]
//! firebase-testd doctor
//! firebase-testd capabilities
//! ```
//!
//! `up` serves the Firestore v1 gRPC API (local execution behind the strict gateway), the
//! Identity Toolkit REST subset and the control API on loopback until Ctrl-C.

mod config;
mod control;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::service::GatewayService;
use ftd_adapter_http::identity_toolkit::AuthState;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::index::{IndexSet, PlanningContext};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

use crate::config::RuntimeConfig;

fn usage() -> ExitCode {
    eprintln!("usage: firebase-testd up [--config <file>] [--firestore-port <n>] [--http-port <n>]\n       firebase-testd doctor\n       firebase-testd capabilities");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => match parse_up(&args[1..]) {
            Ok(cfg) => run_up(cfg),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Some("doctor") => {
            println!("firebase-testd {}", env!("CARGO_PKG_VERSION"));
            println!(
                "vendored googleapis commit: {}",
                ftd_proto_firestore::UPSTREAM_COMMIT.trim()
            );
            println!(
                "limit catalogs: {}",
                ftd_core_limits::catalogs::ALL_CATALOGS
                    .iter()
                    .map(|c| c.meta.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            ExitCode::SUCCESS
        }
        Some("capabilities") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&control::capabilities_manifest()).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn parse_up(args: &[String]) -> Result<RuntimeConfig, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut firestore_port: Option<u16> = None;
    let mut http_port: Option<u16> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--config needs a value")?,
                ));
                i += 2;
            }
            "--firestore-port" => {
                firestore_port = Some(
                    args.get(i + 1)
                        .ok_or("--firestore-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--firestore-port: {e}"))?,
                );
                i += 2;
            }
            "--http-port" => {
                http_port = Some(
                    args.get(i + 1)
                        .ok_or("--http-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--http-port: {e}"))?,
                );
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let mut cfg = match config_path {
        Some(p) => RuntimeConfig::from_file(&p).map_err(|e| e.to_string())?,
        None => RuntimeConfig::default(),
    };
    if let Some(p) = firestore_port {
        cfg.firestore_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = http_port {
        cfg.http_addr = format!("127.0.0.1:{p}");
    }
    Ok(cfg)
}

fn run_up(cfg: RuntimeConfig) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
        let gateway = Gateway {
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
        let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), cfg.seed));
        let auth = Arc::new(AuthState {
            store: Mutex::new(AuthStore::new(
                &cfg.auth_project,
                SplitMix64::new(cfg.seed ^ 0xA0),
                TotpPolicy::default(),
            )),
            clock: clock.clone(),
        });
        let control = Arc::new(ftd_adapter_http::control::ControlState {
            clock: clock.clone(),
            require_demo_prefix: cfg.require_demo_prefix,
            edition: cfg.edition,
            capabilities: control::capabilities_manifest(),
        });

        let grpc_listener = tokio::net::TcpListener::bind(&cfg.firestore_addr)
            .await
            .map_err(|e| format!("bind {}: {e}", cfg.firestore_addr))?;
        let http_listener = tokio::net::TcpListener::bind(&cfg.http_addr)
            .await
            .map_err(|e| format!("bind {}: {e}", cfg.http_addr))?;
        let grpc_addr = grpc_listener.local_addr().map_err(|e| e.to_string())?;
        let http_addr = http_listener.local_addr().map_err(|e| e.to_string())?;
        println!("firebase-testd up");
        println!("  firestore (gRPC): {grpc_addr}   FIRESTORE_EMULATOR_HOST={grpc_addr}");
        println!("  auth (REST):      {http_addr}   FIREBASE_AUTH_EMULATOR_HOST={http_addr}");
        println!("  control API:      http://{http_addr}/v1/  (health: /health/live)");
        println!("  edition: {}   clock: {}", cfg.edition, cfg.clock_start);

        let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
        let grpc = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(
                    tonic::codegen::tokio_stream::wrappers::TcpListenerStream::new(grpc_listener),
                )
                .await
        });
        let http = tokio::spawn(ftd_adapter_http::server::serve_with_control(
            http_listener,
            auth,
            control,
        ));
        tokio::select! {
            r = grpc => Err(format!("gRPC server stopped: {r:?}")),
            r = http => Err(format!("HTTP server stopped: {r:?}")),
            _ = tokio::signal::ctrl_c() => {
                println!("shutting down");
                Ok::<(), String>(())
            }
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
