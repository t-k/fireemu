//! The runner child process: spawn, handshake, invocations with real-time timeouts, logs.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::protocol::{read_frame, write_frame};

/// What the runner announced in its `hello`.
#[derive(Debug, Clone, Default)]
pub struct Hello {
    /// Runner name (`node`).
    pub runner: String,
    /// Port of the runner's HTTP server (HTTP / callable functions), if any.
    pub http_port: Option<u16>,
    /// Discovered manifest (canonical JSON), if the runner performed discovery.
    pub manifest: Option<Value>,
}

/// Outcome of one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeOutcome {
    /// The handler completed.
    Ok,
    /// The handler failed (message from the runner).
    Failed(String),
    /// No result within the timeout.
    TimedOut,
    /// The runner died or the protocol broke.
    RunnerGone(String),
}

/// Environment variables a runner inherits from the daemon (everything else, credentials
/// such as `GOOGLE_APPLICATION_CREDENTIALS`, `FIREBASE_TOKEN` or `CLOUDSDK_*` included, is
/// withheld; the emulator variables are added explicitly). `HOME` stays: Node version
/// managers (Volta, nvm, mise, asdf, fnm) resolve `node` through it and their own
/// variables, which are inherited by prefix ([`INHERITED_ENV_PREFIXES`]).
pub const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "NODE_PATH",
    "NODE_OPTIONS",
    "NODE_EXTRA_CA_CERTS",
    "NVM_DIR",
    "NVM_BIN",
];

/// Variable prefixes inherited by a runner (tool managers, XDG directories).
pub const INHERITED_ENV_PREFIXES: &[&str] = &["VOLTA_", "MISE_", "ASDF_", "FNM_", "XDG_"];

/// A running runner.
pub struct Runner {
    child: AsyncMutex<Option<Child>>,
    stdin: AsyncMutex<Option<ChildStdin>>,
    hello: Hello,
    waiters: Arc<Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>>,
    logs: Arc<Mutex<Vec<String>>>,
    label: String,
    alive: Arc<AtomicBool>,
}

/// The environment of a runner child: the inherited allowlist, then `extra` (emulator
/// endpoints and project settings).
#[must_use]
pub fn child_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            INHERITED_ENV.contains(&k.as_str())
                || INHERITED_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
        })
        .collect();
    env.extend(extra.iter().cloned());
    env
}

impl Runner {
    /// Spawns `command` (program + args) with `env`, in `cwd`, and waits for its `hello`.
    #[allow(clippy::too_many_lines)]
    pub async fn spawn(
        command: &[String],
        cwd: Option<&str>,
        env: &[(String, String)],
        hello_timeout: Duration,
    ) -> Result<Self, String> {
        let (program, args) = command
            .split_first()
            .ok_or_else(|| "functions runner: empty command".to_owned())?;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        for (k, v) in child_env(env) {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("functions runner: cannot start {program}: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "functions runner: no stdin".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "functions runner: no stdout".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "functions runner: no stderr".to_owned())?;
        let label = format!(
            "[functions:{}]",
            program.rsplit('/').next().unwrap_or(program)
        );
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let label = label.clone();
            let logs = logs.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    eprintln!("{label} {line}");
                    if let Ok(mut l) = logs.lock() {
                        l.push(line);
                        if l.len() > 1000 {
                            l.remove(0);
                        }
                    }
                }
            });
        }
        let waiters: Arc<Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let (hello_tx, hello_rx) = oneshot::channel::<Hello>();
        {
            let waiters = waiters.clone();
            let label = label.clone();
            let logs = logs.clone();
            let alive = alive.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout);
                let mut hello_tx = Some(hello_tx);
                loop {
                    let frame = match read_frame(&mut reader).await {
                        Ok(Some(f)) => f,
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("{label} protocol error: {e}");
                            break;
                        }
                    };
                    match frame.get("type").and_then(Value::as_str) {
                        Some("hello") => {
                            let hello = Hello {
                                runner: frame
                                    .get("runner")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                                    .to_owned(),
                                http_port: frame
                                    .get("httpPort")
                                    .and_then(Value::as_u64)
                                    .and_then(|p| u16::try_from(p).ok()),
                                manifest: frame.get("manifest").cloned(),
                            };
                            if let Some(tx) = hello_tx.take() {
                                let _ = tx.send(hello);
                            }
                        }
                        Some("result") => {
                            let id = frame
                                .get("invocationId")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let outcome = if frame.get("ok").and_then(Value::as_bool) == Some(true)
                            {
                                InvokeOutcome::Ok
                            } else {
                                InvokeOutcome::Failed(
                                    frame
                                        .get("error")
                                        .and_then(Value::as_str)
                                        .unwrap_or("function failed")
                                        .to_owned(),
                                )
                            };
                            if let Some(tx) = waiters.lock().ok().and_then(|mut w| w.remove(&id)) {
                                let _ = tx.send(outcome);
                            }
                        }
                        Some("log") => {
                            let level =
                                frame.get("level").and_then(Value::as_str).unwrap_or("info");
                            let message =
                                frame.get("message").and_then(Value::as_str).unwrap_or("");
                            let line = match frame.get("invocationId").and_then(Value::as_str) {
                                Some(id) => format!("{level} {id} {message}"),
                                None => format!("{level} {message}"),
                            };
                            eprintln!("{label} {line}");
                            if let Ok(mut l) = logs.lock() {
                                l.push(line);
                                if l.len() > 1000 {
                                    l.remove(0);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // The runner is gone: every waiter learns it and the runtime stops
                // dispatching.
                alive.store(false, Ordering::SeqCst);
                eprintln!(
                    "{label} runner exited; functions are unavailable until the daemon restarts"
                );
                if let Ok(mut w) = waiters.lock() {
                    for (_, tx) in w.drain() {
                        let _ = tx.send(InvokeOutcome::RunnerGone("runner exited".into()));
                    }
                }
            });
        }
        let hello = match tokio::time::timeout(hello_timeout, hello_rx).await {
            Ok(Ok(h)) => h,
            Ok(Err(_)) => {
                let _ = child.kill().await;
                return Err("functions runner exited before its hello".to_owned());
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(format!(
                    "functions runner sent no hello within {}s",
                    hello_timeout.as_secs()
                ));
            }
        };
        Ok(Self {
            child: AsyncMutex::new(Some(child)),
            stdin: AsyncMutex::new(Some(stdin)),
            hello,
            waiters,
            logs,
            label,
            alive,
        })
    }

    /// Whether the runner process is still alive.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// The runner's `hello`.
    #[must_use]
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Log lines seen so far (stderr and `log` frames), oldest first.
    #[must_use]
    pub fn logs(&self) -> Vec<String> {
        self.logs.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Sends an `invoke` and waits for its result. One deadline covers the stdin lock, the
    /// frame write (a runner that stopped reading its stdin cannot block others forever) and
    /// the result; a timed-out invocation's late result is discarded (the `invocationId` is
    /// unique per attempt).
    pub async fn invoke(&self, request: Value, timeout: Duration) -> InvokeOutcome {
        if !self.is_alive() {
            return InvokeOutcome::RunnerGone("runner exited".into());
        }
        let id = request
            .get("invocationId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let (tx, rx) = oneshot::channel();
        if let Ok(mut w) = self.waiters.lock() {
            w.insert(id.clone(), tx);
        }
        let send_and_wait = async {
            {
                let mut stdin = self.stdin.lock().await;
                let Some(stdin) = stdin.as_mut() else {
                    return InvokeOutcome::RunnerGone("runner stdin closed".into());
                };
                let mut frame = request;
                frame["type"] = Value::String("invoke".into());
                if let Err(e) = write_frame(stdin, &frame).await {
                    return InvokeOutcome::RunnerGone(format!("cannot write to runner: {e}"));
                }
            }
            match rx.await {
                Ok(outcome) => outcome,
                Err(_) => InvokeOutcome::RunnerGone("runner exited".into()),
            }
        };
        let outcome = match tokio::time::timeout(timeout, send_and_wait).await {
            Ok(outcome) => outcome,
            Err(_) => InvokeOutcome::TimedOut,
        };
        if let Ok(mut w) = self.waiters.lock() {
            w.remove(&id);
        }
        outcome
    }

    /// Asks the runner to exit, then kills it.
    pub async fn shutdown(&self) {
        if let Some(stdin) = self.stdin.lock().await.as_mut() {
            let _ = write_frame(stdin, &json!({"type": "shutdown"})).await;
        }
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            let _ = child.kill().await;
        }
        eprintln!("{} stopped", self.label);
    }
}
