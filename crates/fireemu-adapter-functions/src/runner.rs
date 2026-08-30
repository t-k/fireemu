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
    /// The runner's callable App Check report: the installed `firebase-functions` version,
    /// whether the loader instrumentation could be installed, and whether the debug switches
    /// behave the way the trusted callable protocol relies on (specification section 13.4).
    pub app_check: Option<Value>,
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
    "NODE_EXTRA_CA_CERTS",
    "NVM_DIR",
    "NVM_BIN",
];

/// Variable prefixes inherited by a runner (Node version managers only).
pub const INHERITED_ENV_PREFIXES: &[&str] = &["VOLTA_", "MISE_", "ASDF_", "FNM_"];

/// How to start (and restart) a runner.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// Program and arguments.
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// Extra environment (emulator endpoints, project settings).
    pub env: Vec<(String, String)>,
    /// How long to wait for the `hello`.
    pub hello_timeout: Duration,
}

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
    // `HOME` has to stay (the version-manager shims need it), so Application Default
    // Credentials are blocked explicitly: the well-known file lookup goes through
    // `CLOUDSDK_CONFIG` (an empty directory) and `GOOGLE_APPLICATION_CREDENTIALS` names a
    // file that does not exist.
    let isolated = std::env::temp_dir().join("fireemu-runner");
    let _ = std::fs::create_dir_all(isolated.join("gcloud-empty"));
    env.push((
        "CLOUDSDK_CONFIG".to_owned(),
        isolated.join("gcloud-empty").to_string_lossy().into_owned(),
    ));
    env.push((
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        isolated
            .join("no-credentials.json")
            .to_string_lossy()
            .into_owned(),
    ));
    env.extend(extra.iter().cloned());
    env
}

/// Result of an invocation plus, after a timeout, the channel on which the handler's late
/// result (or the runner's death) will still arrive.
pub struct Invocation {
    /// Outcome within the deadline.
    pub outcome: InvokeOutcome,
    /// Present only for `TimedOut`: resolves when the handler actually finishes.
    pub late: Option<oneshot::Receiver<InvokeOutcome>>,
}

impl Runner {
    /// Spawns a runner from its spec.
    pub async fn spawn_spec(spec: &SpawnSpec) -> Result<Self, String> {
        Self::spawn(
            &spec.command,
            spec.cwd.as_deref(),
            &spec.env,
            spec.hello_timeout,
        )
        .await
    }

    /// Kills the process immediately (session reset: handlers still running must not write
    /// into the reset state). Waiters learn it through the reader task's exit.
    pub fn kill_now(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(mut slot) = self.child.try_lock() {
            if let Some(mut child) = slot.take() {
                let _ = child.start_kill();
                kill_process_group(child.id());
                // Reaped in the background: a killed runner must not linger as a zombie.
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let _ = child.wait().await;
                    });
                }
            }
        }
        if let Ok(mut stdin) = self.stdin.try_lock() {
            *stdin = None;
        }
    }

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
            // Its own process group, so a reset or shutdown takes the handlers' own
            // subprocesses down with it.
            .process_group(0)
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
        // The codebase, when the command names one, so a multi-codebase project can tell
        // which runner a line came from.
        let codebase = command
            .iter()
            .position(|a| a == "--codebase")
            .and_then(|i| command.get(i + 1))
            .filter(|name| name.as_str() != "default");
        let label = match codebase {
            Some(name) => format!("[functions:{name}]"),
            None => format!(
                "[functions:{}]",
                program.rsplit('/').next().unwrap_or(program)
            ),
        };
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
                                app_check: frame.get("appCheck").cloned(),
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
                kill_process_group(child.id());
                let _ = child.kill().await;
                return Err("functions runner exited before its hello".to_owned());
            }
            Err(_) => {
                kill_process_group(child.id());
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
    /// frame write and the result. A frame that cannot be written in full within the
    /// deadline means the runner stopped reading its stdin: the stream is closed and the
    /// runner retired rather than left with a half frame. A timed-out invocation keeps its
    /// waiter: the late result (or the runner's death) arrives on [`Invocation::late`].
    pub async fn invoke(&self, request: Value, timeout: Duration) -> Invocation {
        let done = |outcome| Invocation {
            outcome,
            late: None,
        };
        if !self.is_alive() {
            return done(InvokeOutcome::RunnerGone("runner exited".into()));
        }
        let id = request
            .get("invocationId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let (tx, mut rx) = oneshot::channel();
        if let Ok(mut w) = self.waiters.lock() {
            w.insert(id.clone(), tx);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let forget = |waiters: &Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>| {
            if let Ok(mut w) = waiters.lock() {
                w.remove(&id);
            }
        };
        // 1. The stdin lock (waiting here is harmless: nothing was written yet).
        let Ok(mut stdin) = tokio::time::timeout_at(deadline, self.stdin.lock()).await else {
            forget(&self.waiters);
            return done(InvokeOutcome::TimedOut);
        };
        let Some(pipe) = stdin.as_mut() else {
            forget(&self.waiters);
            return done(InvokeOutcome::RunnerGone("runner stdin closed".into()));
        };
        // 2. The frame: a partial write would desynchronize the protocol, so a stalled or
        //    failed write retires the runner.
        let mut frame = request;
        frame["type"] = Value::String("invoke".into());
        let written = tokio::time::timeout_at(deadline, write_frame(pipe, &frame)).await;
        if !matches!(written, Ok(Ok(()))) {
            *stdin = None;
            self.alive.store(false, Ordering::SeqCst);
            eprintln!(
                "{} runner stopped reading its stdin; functions are unavailable until the daemon restarts",
                self.label
            );
            forget(&self.waiters);
            return done(InvokeOutcome::RunnerGone(
                "runner stopped reading its stdin".into(),
            ));
        }
        drop(stdin);
        // 3. The result.
        match tokio::time::timeout_at(deadline, &mut rx).await {
            Ok(Ok(outcome)) => {
                forget(&self.waiters);
                done(outcome)
            }
            Ok(Err(_)) => {
                forget(&self.waiters);
                done(InvokeOutcome::RunnerGone("runner exited".into()))
            }
            Err(_) => Invocation {
                outcome: InvokeOutcome::TimedOut,
                late: Some(rx),
            },
        }
    }

    /// Asks the runner to exit, then kills it.
    pub async fn shutdown(&self) {
        // The polite part is bounded: a stalled runner or a full pipe must not keep the
        // daemon alive.
        let polite = async {
            if let Some(stdin) = self.stdin.lock().await.as_mut() {
                let _ = write_frame(stdin, &json!({"type": "shutdown"})).await;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), polite).await;
        let child = tokio::time::timeout(Duration::from_secs(2), self.child.lock())
            .await
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(mut child) = child {
            let pid = child.id();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            let _ = child.kill().await;
            kill_process_group(pid);
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
        eprintln!("{} stopped", self.label);
    }
}

/// Kills the process group the runner leads (`process_group(0)`: its id is the runner's
/// pid), taking the subprocesses of handlers with it. Best effort, through `kill(1)` (the
/// core forbids unsafe code, so no direct `killpg`).
fn kill_process_group(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
