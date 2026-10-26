//! The runner child process: spawn, handshake, invocations with real-time timeouts, logs.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(not(windows))]
use tokio::process::Child;
use tokio::process::{ChildStdin, Command};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

#[cfg(windows)]
use process_wrap::tokio::{JobObject, KillOnDrop, TokioChildWrapper, TokioCommandWrap};

use crate::admin_app_check::{
    answer, malformed_frame, parse_request, reply_frame, AdminAppCheckVerifier, Reply,
    MAX_IN_FLIGHT,
};
use crate::protocol::{read_frame, write_frame};

/// What the runner announced in its `hello`.
#[derive(Debug, Clone, Default)]
pub struct Hello {
    /// Runner name (`node`).
    pub runner: String,
    /// Active Node inspector port, if the runner was started in debug mode.
    pub inspector_port: Option<u16>,
    /// Port of the runner's HTTP server (HTTP / callable functions), if any.
    pub http_port: Option<u16>,
    /// Discovered manifest (canonical JSON), if the runner performed discovery.
    pub manifest: Option<Value>,
    /// What the runner found out about the codebase's declared parameters (`defineString`,
    /// `defineInt`, ...): `missing` lists each `{name, type}` that has neither a value in the
    /// dotenv chain nor a declared default, `defaulted` each one a default filled in.
    pub params: Option<Value>,
    /// The runner's callable App Check report: the installed `firebase-functions` version,
    /// whether the loader instrumentation could be installed, and whether the debug switches
    /// behave the way the trusted callable protocol relies on (specification section 13.4).
    pub app_check: Option<Value>,
    /// Clock protocol capabilities advertised by this runner.
    pub clock: Option<Value>,
    /// The runner's Admin SDK App Check report: whether `firebase-admin`'s `verifyToken` was
    /// instrumented to ask the daemon, and why not when it was not.
    pub admin_app_check: Option<Value>,
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

const LOG_CAPACITY: usize = 1_000;
const LOG_ENTRY_BYTE_LIMIT: usize = 1024 * 1024;
const LOG_BUFFER_BYTE_LIMIT: usize = 8 * 1024 * 1024;
const STDERR_LINE_BYTE_LIMIT: usize = 256 * 1024;
const STDERR_TRUNCATION_MARKER: &str = "...[truncated]";
static RUNNER_SANDBOX_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static RUNNER_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Converts canonical Windows drive/UNC paths to paths accepted by Node's loaders.
/// Call only at the Windows Node boundary; other device namespaces stay unchanged.
#[must_use]
pub fn node_path(path: &str) -> std::borrow::Cow<'_, str> {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{unc}").into();
    }
    if let Some(drive) = path.strip_prefix(r"\\?\") {
        let bytes = drive.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\" {
            return drive.into();
        }
    }
    path.into()
}

/// One retained runner line with the metadata needed by the official Logging stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerLog {
    display: String,
    level: String,
    message: String,
    function: Option<String>,
    invocation_id: Option<String>,
    truncated: bool,
    user: bool,
    fields: Map<String, Value>,
}

impl RunnerLog {
    #[cfg(test)]
    fn raw(message: impl Into<String>) -> Self {
        Self::raw_with_truncation(message, false)
    }

    fn raw_with_truncation(message: impl Into<String>, truncated: bool) -> Self {
        let message = message.into();
        Self {
            display: message.clone(),
            level: "info".to_owned(),
            message,
            function: None,
            invocation_id: None,
            truncated,
            user: false,
            fields: Map::new(),
        }
        .bounded()
    }

    fn structured(
        level: impl Into<String>,
        message: impl Into<String>,
        invocation_id: Option<&str>,
        function: Option<&str>,
        user: bool,
        fields: Map<String, Value>,
    ) -> Self {
        let level = level.into();
        let message = message.into();
        let display = invocation_id.map_or_else(
            || format!("{level} {message}"),
            |id| format!("{level} {id} {message}"),
        );
        Self {
            display,
            level,
            message,
            function: function.map(str::to_owned),
            invocation_id: invocation_id.map(str::to_owned),
            truncated: false,
            user,
            fields,
        }
        .bounded()
    }

    fn retained_bytes(&self) -> usize {
        self.display
            .len()
            .saturating_add(self.level.len())
            .saturating_add(self.message.len())
            .saturating_add(self.function.as_ref().map_or(0, String::len))
            .saturating_add(self.invocation_id.as_ref().map_or(0, String::len))
            .saturating_add(
                serde_json::to_vec(&self.fields).map_or(usize::MAX, |fields| fields.len()),
            )
    }

    fn bounded(mut self) -> Self {
        if self.retained_bytes() > LOG_ENTRY_BYTE_LIMIT {
            let marker = "[runner log truncated: byte limit]".to_owned();
            self.display = marker.clone();
            "warning".clone_into(&mut self.level);
            self.message = marker;
            self.function = None;
            self.invocation_id = None;
            self.truncated = true;
            self.user = false;
            self.fields.clear();
        }
        self
    }

    /// Existing text form consumed by the fireemu UI and stderr diagnostics.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Severity reported by the runner.
    #[must_use]
    pub fn level(&self) -> &str {
        &self.level
    }

    /// Message without the display-only level and invocation prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Function that owned the invocation, when the runner could attribute it.
    #[must_use]
    pub fn function(&self) -> Option<&str> {
        self.function.as_deref()
    }

    /// Invocation ID supplied by the runner frame, never by user fields or display text.
    #[must_use]
    pub fn invocation_id(&self) -> Option<&str> {
        self.invocation_id.as_deref()
    }

    /// Whether the runner retained only a truncation marker or bounded stderr prefix.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether this is function user output rather than a runner diagnostic.
    #[must_use]
    pub const fn is_user(&self) -> bool {
        self.user
    }

    /// Arbitrary structured fields emitted by the Firebase Functions logger SDK.
    #[must_use]
    pub fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }
}

/// A cursor-based view of the runner log buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSlice {
    /// Retained lines newer than the requested cursor.
    pub lines: Vec<RunnerLog>,
    /// Cursor to pass to the next call.
    pub next_seq: u64,
    /// Whether lines preceding this slice have been evicted.
    pub truncated: bool,
}

#[derive(Debug, Default)]
struct LogBuffer {
    lines: VecDeque<(RunnerLog, usize)>,
    bytes: usize,
    first_seq: u64,
    next_seq: u64,
}

impl LogBuffer {
    fn push(&mut self, line: RunnerLog) {
        let bytes = line.retained_bytes();
        self.lines.push_back((line, bytes));
        self.bytes = self.bytes.saturating_add(bytes);
        self.next_seq = self.next_seq.saturating_add(1);
        while self.lines.len() > LOG_CAPACITY || self.bytes > LOG_BUFFER_BYTE_LIMIT {
            let (_, bytes) = self
                .lines
                .pop_front()
                .expect("the log buffer is over a limit");
            self.bytes -= bytes;
            self.first_seq = self.first_seq.saturating_add(1);
        }
    }

    fn since(&self, cursor: Option<u64>) -> LogSlice {
        let requested = cursor.unwrap_or(self.first_seq);
        let truncated = requested < self.first_seq || (cursor.is_none() && self.first_seq > 0);
        let start = requested
            .max(self.first_seq)
            .min(self.next_seq)
            .saturating_sub(self.first_seq);
        let start = usize::try_from(start).unwrap_or(usize::MAX);
        LogSlice {
            lines: self
                .lines
                .iter()
                .skip(start)
                .map(|(line, _)| line.clone())
                .collect(),
            next_seq: self.next_seq,
            truncated,
        }
    }
}

async fn read_bounded_stderr_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<(String, bool)>> {
    let keep = STDERR_LINE_BYTE_LIMIT - STDERR_TRUNCATION_MARKER.len();
    let mut bytes = Vec::new();
    let mut saw_input = false;
    let mut truncated = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if !saw_input {
                return Ok(None);
            }
            break;
        }
        saw_input = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content = &available[..newline.unwrap_or(consumed)];
        let copy = content.len().min(keep.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&content[..copy]);
        truncated |= copy < content.len();
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if !truncated && bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let mut line = String::from_utf8_lossy(&bytes).into_owned();
    if line.len() > keep {
        let end = (0..=keep)
            .rev()
            .find(|end| line.is_char_boundary(*end))
            .unwrap_or(0);
        line.truncate(end);
        truncated = true;
    }
    if truncated {
        line.push_str(STDERR_TRUNCATION_MARKER);
    }
    Ok(Some((line, truncated)))
}

/// How a verdict gets back to one runner, and how many may be pending for it.
struct AdminReplyChannel {
    stdin: Arc<AsyncMutex<Option<ChildStdin>>>,
    alive: Arc<AtomicBool>,
    in_flight: Arc<AtomicUsize>,
    label: String,
}

/// How long a verdict may wait for the runner's stdin before it is dropped: a runner that stopped
/// reading cannot hold up the daemon, and one that never gets its verdict fails the call itself.
const ADMIN_REPLY_DEADLINE: Duration = Duration::from_secs(10);

impl AdminReplyChannel {
    async fn send(self, frame: Value) {
        let Ok(mut stdin) = tokio::time::timeout(ADMIN_REPLY_DEADLINE, self.stdin.lock()).await
        else {
            return;
        };
        let Some(pipe) = stdin.as_mut() else {
            return;
        };
        let written = matches!(
            tokio::time::timeout(ADMIN_REPLY_DEADLINE, write_frame(pipe, &frame)).await,
            Ok(Ok(()))
        );
        if !written {
            // A frame that could not be written in full would desynchronize the protocol.
            *stdin = None;
            self.alive.store(false, Ordering::SeqCst);
            eprintln!("{} runner stopped reading its stdin", self.label);
        }
    }
}

/// Answers one `appCheck:verify` frame from the runner without blocking the reader: the
/// verification itself may wait for a session reset to finish, so it runs on a blocking
/// thread and the reply is written when it completes.
fn dispatch_admin_verify(
    frame: &Value,
    verifier: Option<Arc<dyn AdminAppCheckVerifier>>,
    channel: AdminReplyChannel,
) {
    let request = match parse_request(frame) {
        Ok(request) => request,
        Err(Some(id)) => {
            tokio::spawn(channel.send(malformed_frame(&id)));
            return;
        }
        Err(None) => return,
    };
    if channel.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
        channel.in_flight.fetch_sub(1, Ordering::SeqCst);
        tokio::spawn(channel.send(reply_frame(&request.request_id, Reply::Unavailable)));
        return;
    }
    tokio::spawn(async move {
        let reply = match verifier {
            Some(verifier) => {
                let request = request.clone();
                tokio::task::spawn_blocking(move || answer(&request, Some(&*verifier)))
                    .await
                    .unwrap_or(Reply::Unavailable)
            }
            None => answer(&request, None),
        };
        channel.in_flight.fetch_sub(1, Ordering::SeqCst);
        let frame = reply_frame(&request.request_id, reply);
        channel.send(frame).await;
    });
}

/// How to start (and restart) a runner.
#[derive(Clone)]
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

impl std::fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnSpec")
            .field("command", &"[redacted]")
            .field("cwd", &self.cwd)
            .field("env", &"[redacted]")
            .field("hello_timeout", &self.hello_timeout)
            .finish()
    }
}

/// A running runner.
pub struct Runner {
    diagnostic_id: u64,
    child: AsyncMutex<Option<RunnerChild>>,
    #[cfg(unix)]
    _lifetime_guard: RunnerLifetimeGuard,
    stdin: Arc<AsyncMutex<Option<ChildStdin>>>,
    hello: Hello,
    waiters: Arc<Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>>,
    logs: Arc<Mutex<LogBuffer>>,
    label: String,
    alive: Arc<AtomicBool>,
    credential_sandbox: Mutex<Option<PathBuf>>,
    clock_revision: AsyncMutex<Option<u64>>,
    clock_sequence: AtomicU64,
    clock_status: Arc<Mutex<Value>>,
}

#[cfg(not(windows))]
type RunnerChild = Child;

#[cfg(windows)]
type RunnerChild = Box<dyn TokioChildWrapper>;

#[cfg(not(windows))]
async fn wait_child(child: &mut RunnerChild) -> std::io::Result<std::process::ExitStatus> {
    child.wait().await
}

#[cfg(windows)]
async fn wait_child(child: &mut RunnerChild) -> std::io::Result<std::process::ExitStatus> {
    Box::into_pin(child.wait()).await
}

#[cfg(not(windows))]
async fn kill_child(child: &mut RunnerChild) -> std::io::Result<()> {
    child.kill().await
}

#[cfg(windows)]
async fn kill_child(child: &mut RunnerChild) -> std::io::Result<()> {
    Box::into_pin(child.kill()).await
}

/// Creates an exclusive directory used to block the standard gcloud credential lookup.
fn create_credential_sandbox() -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    for _ in 0..32 {
        let sequence = RUNNER_SANDBOX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!("fireemu-runner-{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&root) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| {
                            let _ = std::fs::remove_dir_all(&root);
                            format!("cannot protect Functions runner credential sandbox: {error}")
                        })?;
                }
                let config = root.join("gcloud-empty");
                std::fs::create_dir(&config).map_err(|error| {
                    let _ = std::fs::remove_dir_all(&root);
                    format!("cannot create Functions runner gcloud sandbox: {error}")
                })?;
                return Ok(root);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create Functions runner credential sandbox: {error}"
                ));
            }
        }
    }
    Err("cannot allocate an exclusive Functions runner credential sandbox".to_owned())
}

/// The environment of a runner child: the inherited allowlist, then `extra` (emulator
/// endpoints and project settings).
fn child_env(extra: &[(String, String)]) -> Result<(Vec<(String, String)>, PathBuf), String> {
    let mut env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(k, _)| {
            #[cfg(windows)]
            let k = &k.to_ascii_uppercase();
            INHERITED_ENV.contains(&k.as_str())
                || INHERITED_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
        })
        .collect();
    let isolated = create_credential_sandbox()?;
    // `HOME` has to stay (the version-manager shims need it), so Application Default
    // Credentials are blocked explicitly: the well-known file lookup goes through
    // `CLOUDSDK_CONFIG` (an exclusive empty directory) and `GOOGLE_APPLICATION_CREDENTIALS`
    // names a file that does not exist. Caller-provided credential paths are discarded below.
    env.extend(
        extra
            .iter()
            .filter(|(key, _)| {
                key != "FIREBASE_TOKEN"
                    && key != "GOOGLE_APPLICATION_CREDENTIALS"
                    && !key.starts_with("CLOUDSDK_")
            })
            .cloned(),
    );
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
    Ok((env, isolated))
}

fn remove_credential_sandbox(sandbox: &Mutex<Option<PathBuf>>) {
    if let Ok(mut sandbox) = sandbox.lock() {
        if let Some(path) = sandbox.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
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
        Self::spawn_spec_with(spec, None).await
    }

    /// Spawns a runner from its spec, answering its Admin SDK App Check questions with
    /// `admin_app_check`. A runner without one answers every such question as unavailable
    /// (never as an acceptance).
    pub async fn spawn_spec_with(
        spec: &SpawnSpec,
        admin_app_check: Option<Arc<dyn AdminAppCheckVerifier>>,
    ) -> Result<Self, String> {
        Self::spawn_with(
            &spec.command,
            spec.cwd.as_deref(),
            &spec.env,
            spec.hello_timeout,
            admin_app_check,
        )
        .await
    }

    /// Kills the process immediately (session reset: handlers still running must not write
    /// into the reset state). Waiters learn it through the reader task's exit.
    pub fn kill_now(&self) {
        self.alive.store(false, Ordering::SeqCst);
        remove_credential_sandbox(&self.credential_sandbox);
        if let Ok(mut slot) = self.child.try_lock() {
            if let Some(mut child) = slot.take() {
                let _ = child.start_kill();
                #[cfg(unix)]
                kill_process_group(child.id());
                // Reaped in the background: a killed runner must not linger as a zombie.
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let _ = wait_child(&mut child).await;
                    });
                }
            }
        }
        if let Ok(mut stdin) = self.stdin.try_lock() {
            *stdin = None;
        }
    }

    /// Spawns `command` (program + args) with `env`, in `cwd`, and waits for its `hello`.
    pub async fn spawn(
        command: &[String],
        cwd: Option<&str>,
        env: &[(String, String)],
        hello_timeout: Duration,
    ) -> Result<Self, String> {
        Self::spawn_with(command, cwd, env, hello_timeout, None).await
    }

    /// [`Self::spawn`] with the verifier that answers the runner's Admin SDK App Check
    /// questions.
    #[allow(clippy::too_many_lines)]
    pub async fn spawn_with(
        command: &[String],
        cwd: Option<&str>,
        env: &[(String, String)],
        hello_timeout: Duration,
        admin_app_check: Option<Arc<dyn AdminAppCheckVerifier>>,
    ) -> Result<Self, String> {
        let (program, args) = command
            .split_first()
            .ok_or_else(|| "functions runner: empty command".to_owned())?;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group, so a reset or shutdown takes the handlers' own
        // subprocesses down with it.
        #[cfg(unix)]
        cmd.process_group(0);
        cmd.kill_on_drop(true);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let (child_environment, credential_sandbox) = child_env(env)?;
        let credential_sandbox_guard = CredentialSandboxGuard(Some(credential_sandbox));
        for (k, v) in child_environment {
            cmd.env(k, v);
        }
        #[cfg(not(windows))]
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("functions runner: cannot start {program}: {e}"))?;
        #[cfg(unix)]
        let mut process_group_guard = ProcessGroupGuard::new(child.id());
        #[cfg(unix)]
        let lifetime_guard = RunnerLifetimeGuard::spawn(child.id())?;
        #[cfg(windows)]
        let mut child = {
            let mut wrapped = TokioCommandWrap::from(cmd);
            wrapped.wrap(JobObject).wrap(KillOnDrop);
            wrapped
                .spawn()
                .map_err(|e| format!("functions runner: cannot start {program}: {e}"))?
        };
        #[cfg(not(windows))]
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "functions runner: no stdin".to_owned())?;
        #[cfg(windows)]
        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| "functions runner: no stdin".to_owned())?;
        let stdin_shared = Arc::new(AsyncMutex::new(Some(stdin)));
        #[cfg(not(windows))]
        let stdout_source = child
            .stdout
            .take()
            .ok_or_else(|| "functions runner: no stdout".to_owned())?;
        #[cfg(windows)]
        let stdout_source = child
            .stdout()
            .take()
            .ok_or_else(|| "functions runner: no stdout".to_owned())?;
        #[cfg(not(windows))]
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "functions runner: no stderr".to_owned())?;
        #[cfg(windows)]
        let stderr = child
            .stderr()
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
        let logs = Arc::new(Mutex::new(LogBuffer::default()));
        let mut stderr_task = {
            let label = label.clone();
            let logs = logs.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                while let Ok(Some((line, truncated))) = read_bounded_stderr_line(&mut reader).await
                {
                    eprintln!("{label} {line}");
                    if let Ok(mut l) = logs.lock() {
                        l.push(RunnerLog::raw_with_truncation(line, truncated));
                    }
                }
            })
        };
        // Retain the actual wire bytes, including malformed/partial frames, without
        // changing the protocol parser. Both the pipe and the diagnostic tail are bounded.
        let stdout_tail = Arc::new(Mutex::new(VecDeque::new()));
        let (mut captured_stdout, stdout) = tokio::io::duplex(4096);
        let stdout_capture = stdout_tail.clone();
        tokio::spawn(async move {
            let mut source = stdout_source;
            let mut chunk = [0_u8; 4096];
            while let Ok(count) = source.read(&mut chunk).await {
                if count == 0 {
                    break;
                }
                if let Ok(mut tail) = stdout_capture.lock() {
                    tail.extend(&chunk[..count]);
                    let excess = tail.len().saturating_sub(4096);
                    tail.drain(..excess);
                }
                if captured_stdout.write_all(&chunk[..count]).await.is_err() {
                    break;
                }
            }
        });
        let waiters: Arc<Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let clock_status = Arc::new(Mutex::new(Value::Null));
        let alive = Arc::new(AtomicBool::new(true));
        let (hello_tx, hello_rx) = oneshot::channel::<Hello>();
        {
            let waiters = waiters.clone();
            let label = label.clone();
            let logs = logs.clone();
            let alive = alive.clone();
            let clock_status = clock_status.clone();
            let stdin_shared = stdin_shared.clone();
            let in_flight = Arc::new(AtomicUsize::new(0));
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
                                inspector_port: frame
                                    .get("inspectorPort")
                                    .and_then(Value::as_u64)
                                    .and_then(|p| u16::try_from(p).ok()),
                                http_port: frame
                                    .get("httpPort")
                                    .and_then(Value::as_u64)
                                    .and_then(|p| u16::try_from(p).ok()),
                                manifest: frame.get("manifest").cloned(),
                                params: frame.get("params").cloned(),
                                app_check: frame.get("appCheck").cloned(),
                                clock: frame.get("clock").cloned(),
                                admin_app_check: frame.get("adminAppCheck").cloned(),
                            };
                            if let Some(tx) = hello_tx.take() {
                                let _ = tx.send(hello);
                            }
                        }
                        Some("result") => {
                            if let Some(status) = frame.get("timers") {
                                if let Ok(mut current) = clock_status.lock() {
                                    *current = status.clone();
                                }
                            }
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
                        Some("appCheck:verify") => dispatch_admin_verify(
                            &frame,
                            admin_app_check.clone(),
                            AdminReplyChannel {
                                stdin: stdin_shared.clone(),
                                alive: alive.clone(),
                                in_flight: in_flight.clone(),
                                label: label.clone(),
                            },
                        ),
                        Some("log") => {
                            let level =
                                frame.get("level").and_then(Value::as_str).unwrap_or("info");
                            let message =
                                frame.get("message").and_then(Value::as_str).unwrap_or("");
                            let log = RunnerLog::structured(
                                level,
                                message,
                                frame.get("invocationId").and_then(Value::as_str),
                                frame.get("functionName").and_then(Value::as_str),
                                frame.get("user").and_then(Value::as_bool) == Some(true),
                                frame
                                    .get("fields")
                                    .and_then(Value::as_object)
                                    .cloned()
                                    .unwrap_or_default(),
                            );
                            eprintln!("{label} {}", log.display());
                            if let Ok(mut l) = logs.lock() {
                                l.push(log);
                            }
                        }
                        _ => {}
                    }
                }
                // The runner is gone: every waiter learns it and the runtime stops
                // dispatching.
                alive.store(false, Ordering::SeqCst);
                eprintln!("{label} runner exited");
                if let Ok(mut w) = waiters.lock() {
                    for (_, tx) in w.drain() {
                        let _ = tx.send(InvokeOutcome::RunnerGone("runner exited".into()));
                    }
                }
            });
        }
        let hello = match tokio::time::timeout(hello_timeout, hello_rx).await {
            Ok(Ok(h)) => Ok(h),
            Ok(Err(_)) => Err("functions runner exited before its hello".to_owned()),
            Err(_) => Err(format!(
                "functions runner sent no hello within {}s",
                hello_timeout.as_secs()
            )),
        };
        let hello = match hello {
            Ok(hello) => hello,
            Err(reason) => {
                #[cfg(unix)]
                let process_group = child.id();
                // stdout can close just before process termination, or while the
                // process remains alive. Preserve a natural exit status before cleanup.
                #[cfg(not(windows))]
                let exited = tokio::time::timeout(Duration::from_millis(250), child.wait()).await;
                #[cfg(windows)]
                let exited =
                    tokio::time::timeout(Duration::from_millis(250), child.inner_mut().wait())
                        .await;
                let status = match exited {
                    Ok(Ok(status)) => status
                        .code()
                        .map_or_else(|| status.to_string(), |code| code.to_string()),
                    Ok(Err(error)) => format!("unavailable: {error}"),
                    Err(_) => "still running; terminated after handshake failure".to_owned(),
                };
                #[cfg(unix)]
                kill_process_group(process_group);
                let _ = kill_child(&mut child).await;
                if tokio::time::timeout(Duration::from_millis(250), &mut stderr_task)
                    .await
                    .is_err()
                {
                    stderr_task.abort();
                }
                let stderr = logs
                    .lock()
                    .map(|logs| {
                        logs.since(None)
                            .lines
                            .iter()
                            .map(RunnerLog::display)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                let stdout = stdout_tail
                    .lock()
                    .map(|tail| {
                        String::from_utf8_lossy(&tail.iter().copied().collect::<Vec<_>>())
                            .into_owned()
                    })
                    .unwrap_or_default();
                return Err(format!(
                    "{reason}; exit status: {status}; captured stderr: {stderr:?}; last stdout bytes: {stdout:?}"
                ));
            }
        };
        #[cfg(unix)]
        process_group_guard.disarm();
        let credential_sandbox = credential_sandbox_guard.into_path();
        Ok(Self {
            diagnostic_id: RUNNER_DIAGNOSTIC_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            child: AsyncMutex::new(Some(child)),
            #[cfg(unix)]
            _lifetime_guard: lifetime_guard,
            stdin: stdin_shared,
            hello,
            waiters,
            logs,
            label,
            alive,
            credential_sandbox: Mutex::new(Some(credential_sandbox)),
            clock_revision: AsyncMutex::new(None),
            clock_sequence: AtomicU64::new(0),
            clock_status,
        })
    }

    /// Process-local identity for diagnostic cursors; a replacement never reuses its predecessor's cursor.
    #[must_use]
    pub const fn diagnostic_id(&self) -> u64 {
        self.diagnostic_id
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

    /// Returns retained log lines newer than `cursor` without cloning older entries.
    #[must_use]
    pub fn logs_since(&self, cursor: Option<u64>) -> LogSlice {
        self.logs.lock().map_or_else(
            |_| LogSlice {
                lines: Vec::new(),
                next_seq: cursor.unwrap_or_default(),
                truncated: false,
            },
            |logs| logs.since(cursor),
        )
    }

    /// Sends an `invoke` and waits for its result. One deadline covers the stdin lock, the
    /// frame write and the result. A frame that cannot be written in full within the
    /// deadline means the runner stopped reading its stdin: the stream is closed and the
    /// runner retired rather than left with a half frame. A timed-out invocation keeps its
    /// waiter: the late result (or the runner's death) arrives on [`Invocation::late`].
    pub async fn invoke(&self, request: impl std::fmt::Display, timeout: Duration) -> Invocation {
        self.invoke_inner(request, Some(timeout), "invoke").await
    }

    /// Sends an `invoke` without a handler deadline. The debugger uses this path so time
    /// stopped at a breakpoint does not expire the invocation. Shutdown still closes the
    /// runner and resolves the waiter as `RunnerGone`.
    pub async fn invoke_unbounded(&self, request: impl std::fmt::Display) -> Invocation {
        self.invoke_inner(request, None, "invoke").await
    }

    async fn invoke_inner(
        &self,
        request: impl std::fmt::Display,
        timeout: Option<Duration>,
        kind: &str,
    ) -> Invocation {
        let done = |outcome| Invocation {
            outcome,
            late: None,
        };
        if !self.is_alive() {
            return done(InvokeOutcome::RunnerGone("runner exited".into()));
        }
        let Ok(request) = serde_json::from_str::<BTreeMap<String, Box<serde_json::value::RawValue>>>(
            &request.to_string(),
        ) else {
            return done(InvokeOutcome::RunnerGone("invalid invocation JSON".into()));
        };
        let id = request
            .get("invocationId")
            .and_then(|value| serde_json::from_str::<String>(value.get()).ok())
            .unwrap_or_default();
        let (tx, mut rx) = oneshot::channel();
        if let Ok(mut w) = self.waiters.lock() {
            w.insert(id.clone(), tx);
        }
        let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
        let forget = |waiters: &Mutex<HashMap<String, oneshot::Sender<InvokeOutcome>>>| {
            if let Ok(mut w) = waiters.lock() {
                w.remove(&id);
            }
        };
        // 1. The stdin lock (waiting here is harmless: nothing was written yet).
        let mut stdin = match deadline {
            Some(deadline) => {
                let Ok(stdin) = tokio::time::timeout_at(deadline, self.stdin.lock()).await else {
                    forget(&self.waiters);
                    return done(InvokeOutcome::TimedOut);
                };
                stdin
            }
            None => self.stdin.lock().await,
        };
        let Some(pipe) = stdin.as_mut() else {
            forget(&self.waiters);
            return done(InvokeOutcome::RunnerGone("runner stdin closed".into()));
        };
        // 2. The frame: a partial write would desynchronize the protocol, so a stalled or
        //    failed write retires the runner.
        let mut frame = request;
        frame.insert(
            "type".to_owned(),
            serde_json::value::to_raw_value(kind).expect("JSON string serializes"),
        );
        let frame = serde_json::value::to_raw_value(&frame).expect("raw invocation serializes");
        let written = match deadline {
            Some(deadline) => matches!(
                tokio::time::timeout_at(deadline, write_frame(pipe, &frame)).await,
                Ok(Ok(()))
            ),
            None => write_frame(pipe, &frame).await.is_ok(),
        };
        if !written {
            *stdin = None;
            self.alive.store(false, Ordering::SeqCst);
            eprintln!("{} runner stopped reading its stdin", self.label);
            forget(&self.waiters);
            return done(InvokeOutcome::RunnerGone(
                "runner stopped reading its stdin".into(),
            ));
        }
        drop(stdin);
        // 3. The result.
        if let Some(deadline) = deadline {
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
        } else {
            let outcome = rx
                .await
                .unwrap_or_else(|_| InvokeOutcome::RunnerGone("runner exited".into()));
            forget(&self.waiters);
            done(outcome)
        }
    }

    /// Install a clock revision without waiting for application callbacks.
    pub async fn sync_clock(
        &self,
        snapshot: fireemu_core_session::clock::ClockSnapshot,
    ) -> Result<(), String> {
        let mut revision = self.clock_revision.lock().await;
        if revision.is_some_and(|previous| previous >= snapshot.revision) {
            return Ok(());
        }
        let id = format!(
            "clock-{}",
            self.clock_sequence.fetch_add(1, Ordering::Relaxed)
        );
        let result = self
            .invoke_inner(
                json!({"invocationId":id,
            "instantNanos":snapshot.instant.as_nanos().to_string(),
            "elapsedNanos":snapshot.elapsed_nanos.to_string(),
            "revision":snapshot.revision.to_string()}),
                Some(Duration::from_secs(5)),
                "clock:set",
            )
            .await;
        match result.outcome {
            InvokeOutcome::Ok => {
                *revision = Some(snapshot.revision);
                Ok(())
            }
            other => Err(format!("runner clock synchronization failed: {other:?}")),
        }
    }

    /// Drain one bounded batch of application timers using native protocol deadlines.
    pub async fn run_due(&self, budget: usize) -> Result<Value, String> {
        let _revision = self.clock_revision.lock().await;
        let id = format!(
            "clock-{}",
            self.clock_sequence.fetch_add(1, Ordering::Relaxed)
        );
        let result = self
            .invoke_inner(
                json!({"invocationId":id,"budget":budget}),
                Some(Duration::from_secs(5)),
                "clock:runDue",
            )
            .await;
        match result.outcome {
            InvokeOutcome::Ok => self
                .clock_status
                .lock()
                .map(|s| s.clone())
                .map_err(|_| "runner clock status poisoned".into()),
            other => Err(format!("runner timer batch failed: {other:?}")),
        }
    }

    /// Asks the runner to exit, then kills it.
    pub async fn shutdown(&self) {
        // Retire the runner synchronously with the shutdown request. The stdout reader also
        // clears this flag on EOF, but waiting for that independent task would make the
        // postcondition scheduler-dependent and briefly admit work into a retiring process.
        self.alive.store(false, Ordering::SeqCst);
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
            #[cfg(unix)]
            let pid = child.id();
            let _ = tokio::time::timeout(Duration::from_secs(2), wait_child(&mut child)).await;
            let _ = kill_child(&mut child).await;
            #[cfg(unix)]
            kill_process_group(pid);
            let _ = tokio::time::timeout(Duration::from_secs(2), wait_child(&mut child)).await;
        }
        eprintln!("{} stopped", self.label);
        remove_credential_sandbox(&self.credential_sandbox);
    }
}

struct CredentialSandboxGuard(Option<PathBuf>);

impl CredentialSandboxGuard {
    fn into_path(mut self) -> PathBuf {
        self.0.take().expect("credential sandbox is present")
    }
}

impl Drop for CredentialSandboxGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        remove_credential_sandbox(&self.credential_sandbox);
    }
}

/// An independent group member observes daemon lifetime, even during blocked user code.
/// Its inherited output handles also keep a supervised daemon's close pending until cleanup.
#[cfg(unix)]
struct RunnerLifetimeGuard(std::process::Child);

#[cfg(unix)]
impl RunnerLifetimeGuard {
    fn spawn(pid: Option<u32>) -> Result<Self, String> {
        use std::os::unix::process::CommandExt;
        let group = pid
            .filter(|value| *value > 1)
            .ok_or("runner group is unavailable")?;
        let script = r#"
trap '' TERM
own=$(/bin/ps -o pgid= -p $$)
[ "$own" -eq "$1" ] && [ "$1" -gt 1 ] || exit 1
IFS= read -r lifetime || :
/bin/kill -s TERM -- "-$1" 2>/dev/null || :
/bin/sleep 0.5
/bin/kill -s KILL -- "-$1" 2>/dev/null || :
"#;
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", script, "fireemu-runner-lifetime", &group.to_string()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(i32::try_from(group).map_err(|_| "runner group exceeds pid range")?);
        command
            .spawn()
            .map(Self)
            .map_err(|error| format!("functions lifetime guard: {error}"))
    }
}

#[cfg(unix)]
impl Drop for RunnerLifetimeGuard {
    fn drop(&mut self) {
        // Closing the lease triggers the independent guard; reap only the child we own.
        self.0.stdin.take();
        let child = &mut self.0;
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        // The guard sends KILL after its bounded native grace period.
        let pid = child.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("[functions] lifetime guard {pid} exceeded cleanup grace");
    }
}

/// Cancellation guard for discovery and respawn. Dropping a Tokio child kills only the direct
/// process; user code may already have created descendants in the runner's process group before
/// sending its hello.
#[cfg(unix)]
struct ProcessGroupGuard {
    pid: Option<u32>,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }

    fn disarm(&mut self) {
        self.pid = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        kill_process_group(self.pid);
    }
}

/// Kills the process group the runner leads (`process_group(0)`: its id is the runner's
/// pid), taking the subprocesses of handlers with it.
#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) else {
        return;
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return;
    };
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
}

#[cfg(test)]
mod tests {
    /// How long a test waits for a real Node child's hello: the daemon's own wait. A cold Node
    /// start on a loaded Windows CI runner takes longer than 5 s, and every failure seen there
    /// was a child that had not run a line of JS yet.
    const NODE_HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    use super::{child_env, LogBuffer, RunnerLog, LOG_CAPACITY};

    #[test]
    fn node_paths_preserve_drive_unc_and_non_verbatim_paths() {
        for (input, expected) in [
            (r"\\?\C:\functions\index.mjs", r"C:\functions\index.mjs"),
            (r"\\?\z:\space # %\index.mjs", r"z:\space # %\index.mjs"),
            (
                r"\\?\UNC\server\share\index.mjs",
                r"\\server\share\index.mjs",
            ),
            (r"C:\functions\index.mjs", r"C:\functions\index.mjs"),
            (r"\\server\share\index.mjs", r"\\server\share\index.mjs"),
            ("/tmp/functions/index.mjs", "/tmp/functions/index.mjs"),
            (
                r"\\?\Volume{example}\index.mjs",
                r"\\?\Volume{example}\index.mjs",
            ),
        ] {
            assert_eq!(super::node_path(input), expected);
        }
    }

    #[tokio::test]
    async fn early_runner_exit_reports_status_stderr_and_stdout_tail() {
        for output in ["", "partial", "3\n{", "9".repeat(8192).as_str()] {
            let script = format!(
                "require('node:fs').writeSync(1, {}); require('node:fs').writeSync(2, 'startup failed\\r\\n'); process.exit(23);",
                serde_json::to_string(output).unwrap()
            );
            let result = super::Runner::spawn(
                &["node".to_owned(), "-e".to_owned(), script],
                None,
                &[],
                NODE_HELLO_TIMEOUT,
            )
            .await;
            let error = match result {
                Ok(runner) => {
                    runner.shutdown().await;
                    panic!("runner must fail before hello");
                }
                Err(error) => error,
            };
            assert!(error.contains("exited before its hello"), "{error}");
            assert!(
                error.contains("exit status: 23; captured stderr:"),
                "{error}"
            );
            assert!(
                error.contains("captured stderr: \"startup failed\""),
                "{error}"
            );
            let tail = &output[output.len().saturating_sub(4096)..];
            assert!(
                error.contains(&format!("last stdout bytes: {tail:?}")),
                "{error}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn child_env_inherits_windows_variable_names_case_insensitively() {
        const PROBE: &str = "FIREEMU_WINDOWS_ENV_PROBE";
        if std::env::var(PROBE).as_deref() == Ok("1") {
            let (environment, sandbox) = child_env(&[]).unwrap();
            for name in ["PATH", "SYSTEMROOT", "VOLTA_FIREEMU_VALID"] {
                assert!(
                    environment
                        .iter()
                        .any(|(key, _)| key.eq_ignore_ascii_case(name)),
                    "missing {name}"
                );
            }
            std::fs::remove_dir_all(sandbox).unwrap();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runner::tests::child_env_inherits_windows_variable_names_case_insensitively",
            ])
            .env(PROBE, "1")
            .env("Path", std::env::var_os("PATH").unwrap())
            .env("SystemRoot", std::env::var_os("SYSTEMROOT").unwrap())
            .env("Volta_FIREEMU_VALID", "retained")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn bundled_runner_installs_dates_before_import_and_drains_timers() {
        use super::{InvokeOutcome, Runner};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
        let dir = trusted_temp::TrustedTempDir::new("application-clock");
        std::fs::write(dir.join("package.json"), r#"{"main":"index.cjs"}"#).unwrap();
        std::fs::write(dir.join("index.cjs"), r"
            const fs=require('node:fs'); const imported=Date.now();
            const fn=async()=>{fs.writeFileSync('observed.json',JSON.stringify([imported,Date.now(),+new Date()])); await new Promise(r=>setTimeout(r,5)); fs.writeFileSync('timer.json',JSON.stringify(Date.now()));};
            fn.run=fn; fn.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};
            module.exports={clock:fn};
        ").unwrap();
        let mut clock = VirtualClock::new(LogicalInstant::from_nanos(1_000_000_000));
        let policy = crate::application_clock::ApplicationClockPolicy {
            date_virtual: true,
            timers_virtual: true,
            tasks_virtual: false,
        };
        let trace_path = dir.join("fireemu-runner-trace.log");
        let runner = std::sync::Arc::new(
            Runner::spawn(
                &[
                    "node".into(),
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../tools/runner-node/index.mjs"
                    )
                    .into(),
                    "--source".into(),
                    dir.to_string_lossy().into_owned(),
                ],
                Some(&dir.to_string_lossy()),
                &[
                    ("GCLOUD_PROJECT".into(), "demo-clock".into()),
                    ("FIREEMU_RUNNER_TRACE".into(), "1".into()),
                    (
                        "FIREEMU_CLOCK_JSON".into(),
                        policy.runner_options(clock.snapshot()).to_string(),
                    ),
                ],
                NODE_HELLO_TIMEOUT,
            )
            .await
            .unwrap_or_else(|error| {
                let trace = std::fs::read_to_string(&trace_path);
                panic!("{error}; startup trace file: {trace:?}");
            }),
        );
        assert_eq!(runner.hello().clock.as_ref().unwrap()["version"], 1);
        clock.advance(LogicalDuration::from_millis(1000)).unwrap();
        runner.sync_clock(clock.snapshot()).await.unwrap();
        let active = runner.clone();
        let invocation = tokio::spawn(async move {
            active.invoke(serde_json::json!({"invocationId":"test-clock","function":"clock","trigger":"schedule","event":{}}), std::time::Duration::from_secs(3)).await
        });
        for _ in 0..100 {
            if dir.join("observed.json").exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("observed.json")).unwrap(),
            "[1000,2000,2000]"
        );
        assert!(!dir.join("timer.json").exists());
        clock.advance(LogicalDuration::from_millis(5)).unwrap();
        runner.sync_clock(clock.snapshot()).await.unwrap();
        runner.run_due(1000).await.unwrap();
        assert_eq!(invocation.await.unwrap().outcome, InvokeOutcome::Ok);
        assert_eq!(
            std::fs::read_to_string(dir.join("timer.json")).unwrap(),
            "2005"
        );
        runner.shutdown().await;
        assert!(!runner.is_alive());
        let trace = std::fs::read_to_string(&trace_path).unwrap();
        for (index, line) in trace.lines().enumerate() {
            assert!(
                line.starts_with(&format!("[runner trace {}] ", index + 1)),
                "{trace}"
            );
        }
        for step in [
            "process start",
            "runner imports complete",
            "argv parsed",
            "source resolved",
            "clock preamble installed",
            "stdin frame reader installed",
            "user module import start",
            "user module import end",
            "hello about to be written",
            "hello written",
        ] {
            assert!(trace.contains(&format!("] {step}\n")), "{trace}");
        }
    }

    #[tokio::test]
    async fn bundled_runner_serves_an_http_function_without_the_sdk() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = trusted_temp::TrustedTempDir::new("runner-http");
        let source = root.join("source # % unicode-\u{65e5}");
        std::fs::create_dir_all(source.join("node_modules/express")).unwrap();
        std::fs::write(source.join("package.json"), r#"{"main":"index.cjs"}"#).unwrap();
        std::fs::write(
            source.join("index.cjs"),
            r"
            function hello(req, res) { res.end('hello:' + req.url); }
            hello.__endpoint = {platform:'gcfv2',httpsTrigger:{}};
            module.exports = {hello};
        ",
        )
        .unwrap();
        std::fs::write(
            source.join("node_modules/express/package.json"),
            r#"{"name":"express","version":"5.0.0","main":"index.cjs"}"#,
        )
        .unwrap();
        // Exercise the real runner and HTTP socket without installing Express or the SDK.
        std::fs::write(source.join("node_modules/express/index.cjs"), r"
            module.exports = function() {
                let route;
                const app = (req, res) => {
                    const parts = req.url.split('/');
                    req.params = {project:parts[1],region:parts[2],name:parts[3]};
                    route(req, res);
                };
                app.use = () => {};
                app.all = (_, handler) => {route = handler;};
                return app;
            };
            for (const parser of ['json','text','urlencoded','raw']) module.exports[parser] = () => () => {};
        ").unwrap();
        let source = std::fs::canonicalize(&source)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let script = std::fs::canonicalize(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/runner-node/index.mjs"
        ))
        .unwrap()
        .to_string_lossy()
        .into_owned();
        #[cfg(windows)]
        let (source, script) = (
            super::node_path(&source).into_owned(),
            super::node_path(&script).into_owned(),
        );
        let trace_path = std::path::Path::new(&source).join("fireemu-runner-trace.log");
        let runner = super::Runner::spawn(
            &["node".into(), script, "--source".into(), source.clone()],
            Some(&source),
            &[
                ("GCLOUD_PROJECT".into(), "demo-http".into()),
                ("FIREEMU_RUNNER_TRACE".into(), "1".into()),
                ("FIREEMU_RUNNER_SECRET".into(), "test-http-secret".into()),
            ],
            NODE_HELLO_TIMEOUT,
        )
        .await
        .unwrap_or_else(|error| {
            let trace = std::fs::read_to_string(&trace_path);
            panic!("{error}; startup trace file: {trace:?}");
        });
        let port = runner
            .hello()
            .http_port
            .expect("HTTP server announced in hello");
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            socket.write_all(b"GET /demo-http/us-central1/hello/world HTTP/1.1\r\nHost: localhost\r\nx-fireemu-runner-secret: test-http-secret\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            response
        }).await;
        runner.shutdown().await;
        let response = response.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("hello:/world"), "{response}");
        assert!(!runner.is_alive());
        let trace = std::fs::read_to_string(&trace_path).unwrap();
        assert!(
            trace.starts_with("[runner trace 1] process start\n"),
            "{trace}"
        );
        assert!(trace.contains("hello written\n"), "{trace}");
        assert!(trace.contains("HTTP server ready\n"), "{trace}");
    }

    #[cfg(unix)]
    mod trusted_temp {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/support/trusted_temp.rs"
        ));
    }

    #[cfg(not(unix))]
    mod trusted_temp {
        use std::ops::Deref;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(0);

        pub struct TrustedTempDir(PathBuf);

        impl TrustedTempDir {
            pub fn new(label: &str) -> Self {
                loop {
                    let nonce = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
                    let path = std::env::temp_dir()
                        .join(format!("fireemu-{label}-{}-{nonce}", std::process::id()));
                    match std::fs::create_dir(&path) {
                        Ok(()) => return Self(path),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => panic!("create owned test directory: {error}"),
                    }
                }
            }
        }

        impl Deref for TrustedTempDir {
            type Target = Path;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Drop for TrustedTempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    struct OwnedTestDirectory(std::path::PathBuf);

    impl OwnedTestDirectory {
        fn create(path: std::path::PathBuf) -> Self {
            std::fs::create_dir(&path).expect("create owned test directory");
            Self(path)
        }
    }

    impl Drop for OwnedTestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn credential_sandbox_fixture_cleanup_keeps_a_sibling_sentinel() {
        let owned_root = trusted_temp::TrustedTempDir::new("runner-sandbox-fixture");
        let sentinel_path = owned_root
            .parent()
            .expect("trusted test namespace parent")
            .join(format!(
                "{}-sentinel",
                owned_root
                    .file_name()
                    .expect("trusted test namespace basename")
                    .to_string_lossy()
            ));
        let sentinel = OwnedTestDirectory::create(sentinel_path);

        drop(owned_root);

        assert!(
            sentinel.0.exists(),
            "fixture cleanup must not remove a sibling it did not create"
        );
    }

    fn environment_value<'a>(environment: &'a [(String, String)], name: &str) -> &'a str {
        environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .expect("environment variable")
    }

    #[test]
    fn child_env_uses_an_exclusive_adc_sandbox_and_ignores_credential_overrides() {
        let first = child_env(&[
            (
                "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
                "/attacker/credentials.json".to_owned(),
            ),
            ("CLOUDSDK_CONFIG".to_owned(), "/attacker/gcloud".to_owned()),
            ("FIREBASE_TOKEN".to_owned(), "secret-token".to_owned()),
        ])
        .expect("runner credential sandbox");
        let second = child_env(&[]).expect("runner credential sandbox");

        let first_config = environment_value(&first.0, "CLOUDSDK_CONFIG");
        let second_config = environment_value(&second.0, "CLOUDSDK_CONFIG");
        let first_credentials = environment_value(&first.0, "GOOGLE_APPLICATION_CREDENTIALS");

        assert_ne!(first_config, second_config);
        assert!(std::path::Path::new(first_config).is_dir());
        assert!(std::path::Path::new(first_credentials)
            .parent()
            .is_some_and(std::path::Path::is_dir));
        assert_ne!(
            first_credentials, "/attacker/credentials.json",
            "a caller-supplied credential path must not replace the sandbox"
        );
        assert_ne!(first_config, "/attacker/gcloud");
        assert!(first.0.iter().all(|(key, value)| {
            !(key == "FIREBASE_TOKEN" || key == "GOOGLE_APPLICATION_CREDENTIALS")
                || value != "secret-token"
        }));

        std::fs::remove_dir_all(first.1).expect("first sandbox cleanup");
        std::fs::remove_dir_all(second.1).expect("second sandbox cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn child_env_skips_non_utf8_inherited_values_without_panicking() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::process::Command;

        const PROBE: &str = "FIREEMU_RUNNER_NON_UTF8_CHILD_TEST";
        if std::env::var(PROBE).as_deref() == Ok("1") {
            let (environment, sandbox) = child_env(&[]).expect("runner environment");
            assert_eq!(
                environment_value(&environment, "VOLTA_FIREEMU_VALID"),
                "retained"
            );
            assert!(environment
                .iter()
                .all(|(key, _)| key != "VOLTA_FIREEMU_INVALID"));
            std::fs::remove_dir_all(sandbox).expect("sandbox cleanup");
            println!("non-UTF-8 environment probe ran");
            return;
        }

        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "runner::tests::child_env_skips_non_utf8_inherited_values_without_panicking",
                "--nocapture",
            ])
            .env(PROBE, "1")
            .env("VOLTA_FIREEMU_VALID", "retained")
            .env("VOLTA_FIREEMU_INVALID", OsString::from_vec(vec![0xff]))
            .output()
            .expect("test subprocess");
        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("non-UTF-8 environment probe ran"),
            "the subprocess did not run the probe"
        );
    }

    #[test]
    fn spawn_setup_guard_removes_its_owned_sandbox_on_error_and_unwind() {
        let on_error = super::create_credential_sandbox().unwrap();
        let on_error_path = on_error.clone();
        drop(super::CredentialSandboxGuard(Some(on_error)));
        assert!(!on_error_path.exists());

        let on_unwind = super::create_credential_sandbox().unwrap();
        let on_unwind_path = on_unwind.clone();
        let result = std::panic::catch_unwind(|| {
            let _guard = super::CredentialSandboxGuard(Some(on_unwind));
            panic!("simulated spawn unwind");
        });
        assert!(result.is_err());
        assert!(!on_unwind_path.exists());
    }

    #[cfg(unix)]
    async fn assert_failed_hello_removes_credential_sandbox(script: &str, expected: &str) {
        use std::time::Duration;

        let root = trusted_temp::TrustedTempDir::new("runner-failed-hello");
        let probe = root.join("config-path");
        let result = super::Runner::spawn(
            &[
                "python3".to_owned(),
                "-c".to_owned(),
                script.to_owned(),
                probe.display().to_string(),
            ],
            None,
            &[],
            Duration::from_secs(5),
        )
        .await;
        let error = match result {
            Ok(runner) => {
                runner.shutdown().await;
                panic!("runner must fail before hello");
            }
            Err(error) => error,
        };
        assert!(error.contains(expected), "{error}");
        let config = std::fs::read_to_string(&probe).expect("runner reported its config path");
        let sandbox = std::path::Path::new(config.trim())
            .parent()
            .expect("gcloud config has a sandbox parent");
        assert!(!sandbox.exists(), "failed runner sandbox remains");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_and_early_exit_remove_their_credential_sandboxes() {
        assert_failed_hello_removes_credential_sandbox(
            "import os,sys,time; open(sys.argv[1], 'w').write(os.environ['CLOUDSDK_CONFIG']); time.sleep(10)",
            "sent no hello",
        )
        .await;
        assert_failed_hello_removes_credential_sandbox(
            "import os,sys; open(sys.argv[1], 'w').write(os.environ['CLOUDSDK_CONFIG'])",
            "exited before its hello",
        )
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_runner_start_kills_its_whole_process_group() {
        use std::process::Command;
        use std::time::Duration;

        let root = trusted_temp::TrustedTempDir::new("runner-cancel");
        let descendant_pid = root.join("descendant.pid");
        let script = format!(
            "sleep 30 & echo $! > '{}'; sleep 30",
            descendant_pid.display()
        );
        let spawning = tokio::spawn(async move {
            super::Runner::spawn(
                &["/bin/sh".to_owned(), "-c".to_owned(), script],
                None,
                &[],
                Duration::from_secs(60),
            )
            .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !descendant_pid.is_file() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the runner fixture did not create its descendant"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = std::fs::read_to_string(&descendant_pid).unwrap();

        spawning.abort();
        let _ = spawning.await;
        let gone = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if !Command::new("/bin/kill")
                .args(["-0", pid.trim()])
                .status()
                .unwrap()
                .success()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < gone,
                "cancelling discovery left descendant process {} alive",
                pid.trim()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn shutting_down_a_runner_removes_its_credential_sandbox() {
        use std::time::Duration;

        let root = trusted_temp::TrustedTempDir::new("runner-sandbox-probe");
        let probe = root.join("config-path");
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
        let runner = super::Runner::spawn(
            &["python3".to_owned(), script.to_owned()],
            None,
            &[(
                "FIREEMU_SANDBOX_PROBE".to_owned(),
                probe.display().to_string(),
            )],
            Duration::from_secs(60),
        )
        .await
        .expect("runner starts");
        let config = std::fs::read_to_string(&probe).expect("runner reported its config path");
        let sandbox = std::path::Path::new(config.trim())
            .parent()
            .expect("gcloud config has a sandbox parent")
            .to_owned();
        assert!(sandbox.is_dir());

        runner.shutdown().await;

        assert!(!sandbox.exists(), "runner credential sandbox remains");
    }

    #[test]
    fn log_buffer_evicts_old_lines_and_keeps_a_monotonic_cursor() {
        let mut logs = LogBuffer::default();
        for index in 0..LOG_CAPACITY + 2 {
            logs.push(RunnerLog::raw(format!("line-{index}")));
        }

        let snapshot = logs.since(None);
        assert!(snapshot.truncated);
        assert_eq!(snapshot.lines.len(), LOG_CAPACITY);
        assert_eq!(
            snapshot.lines.first().map(RunnerLog::display),
            Some("line-2")
        );
        assert_eq!(snapshot.next_seq, (LOG_CAPACITY + 2) as u64);

        let cursor = snapshot.next_seq;
        logs.push(RunnerLog::raw("later"));
        let delta = logs.since(Some(cursor));
        assert!(!delta.truncated);
        assert_eq!(delta.lines[0].display(), "later");
        assert_eq!(delta.next_seq, cursor + 1);
    }

    #[test]
    fn stale_log_cursor_returns_retained_lines_with_a_truncation_marker() {
        let mut logs = LogBuffer::default();
        assert!(!logs.since(None).truncated);
        for index in 0..=LOG_CAPACITY {
            logs.push(RunnerLog::raw(format!("line-{index}")));
        }

        assert!(!logs.since(Some(1)).truncated);
        let delta = logs.since(Some(0));
        assert!(delta.truncated);
        assert_eq!(delta.lines.first().map(RunnerLog::display), Some("line-1"));
        assert_eq!(delta.next_seq, (LOG_CAPACITY + 1) as u64);
    }

    #[test]
    fn log_buffer_limits_a_single_raw_or_structured_entry() {
        let mut logs = LogBuffer::default();
        logs.push(RunnerLog::raw("x".repeat(10 * 1024 * 1024)));
        let raw = logs.since(None);
        assert_eq!(raw.lines.len(), 1);
        assert!(raw.lines[0].display().len() <= 1024 * 1024);

        let fields = serde_json::Map::from_iter([(
            "payload".to_owned(),
            serde_json::json!("x".repeat(2 * 1024 * 1024)),
        )]);
        logs.push(RunnerLog::structured(
            "info",
            "large fields",
            None,
            None,
            true,
            fields,
        ));
        let structured = logs.since(Some(1));
        assert_eq!(structured.lines.len(), 1);
        assert!(
            serde_json::to_vec(structured.lines[0].fields())
                .unwrap()
                .len()
                <= 1024 * 1024
        );
    }

    #[test]
    fn log_buffer_evicts_by_total_bytes_as_well_as_line_count() {
        let mut logs = LogBuffer::default();
        for _ in 0..100 {
            logs.push(RunnerLog::raw("x".repeat(100_000)));
        }
        let slice = logs.since(None);
        let retained: usize = slice
            .lines
            .iter()
            .map(|line| line.display().len() + line.message().len())
            .sum();
        assert!(retained <= 8 * 1024 * 1024);
        assert!(slice.truncated);
        assert_eq!(slice.next_seq, 100);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_stderr_line_is_truncated_and_the_next_line_survives() {
        let script = r#"import sys
payload = b'{"type":"hello","runner":"node"}'
sys.stdout.buffer.write(str(len(payload)).encode() + b'\n' + payload)
sys.stdout.buffer.flush()
sys.stderr.write('x' * 280000 + '\nshort\n')
sys.stderr.flush()
sys.stdin.readline()
"#;
        let runner = super::Runner::spawn(
            &["python3".to_owned(), "-c".to_owned(), script.to_owned()],
            None,
            &[],
            NODE_HELLO_TIMEOUT,
        )
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let logs = loop {
            let logs = runner.logs_since(None);
            if logs.lines.len() >= 2 || tokio::time::Instant::now() >= deadline {
                break logs;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        runner.shutdown().await;
        assert_eq!(logs.lines.len(), 2);
        assert_eq!(logs.lines[1].display(), "short");
        assert!(logs.lines[0].display().len() <= 256 * 1024);
        assert!(logs.lines[0].display().contains("[truncated]"));
    }

    #[test]
    fn invocation_attribution_cannot_be_forged_by_user_fields_or_raw_text() {
        let fields =
            serde_json::Map::from_iter([("invocationId".to_owned(), serde_json::json!("forged"))]);
        let log = RunnerLog::structured(
            "info",
            "info forged text",
            Some("real-2"),
            Some("consume"),
            true,
            fields,
        );
        assert_eq!(log.invocation_id(), Some("real-2"));
        assert_eq!(RunnerLog::raw("info real-2 forged").invocation_id(), None);
        let oversized = RunnerLog::structured(
            "info",
            "x".repeat(super::LOG_ENTRY_BYTE_LIMIT),
            Some("real-2"),
            Some("consume"),
            true,
            serde_json::Map::new(),
        );
        assert_eq!(oversized.invocation_id(), None);
        assert_eq!(oversized.function(), None);
        assert!(oversized.is_truncated());
        // The retained trusted ID has its own allocation in addition to the display prefix.
        let large_id = "x".repeat(super::LOG_ENTRY_BYTE_LIMIT / 2);
        let metadata_limit = RunnerLog::structured(
            "info",
            "short",
            Some(&large_id),
            Some("consume"),
            true,
            serde_json::Map::new(),
        );
        assert!(metadata_limit.is_truncated());
        assert_eq!(metadata_limit.invocation_id(), None);
    }

    proptest::proptest! {
        #[test]
        fn trusted_log_attribution_is_independent_of_arbitrary_user_fields(id in "[a-z0-9-]{1,32}", forged in ".{0,64}", message in ".{0,64}") {
            let fields = serde_json::Map::from_iter([("invocationId".to_owned(), serde_json::json!(forged))]);
            let log = RunnerLog::structured("info", message, Some(&id), Some("consume"), true, fields);
            proptest::prop_assert_eq!(log.invocation_id(), Some(id.as_str()));
            let raw = RunnerLog::raw(log.display());
            proptest::prop_assert_eq!(raw.invocation_id(), None);
        }

        #[test]
        fn log_cursor_slices_match_the_bounded_sequence_model(count in 0usize..1200, cursor in 0u64..1500) {
            let mut buffer = LogBuffer::default();
            for index in 0..count { buffer.push(RunnerLog::raw(format!("line-{index}"))); }
            let first = count.saturating_sub(LOG_CAPACITY);
            let result = buffer.since(Some(cursor));
            let start = usize::try_from(cursor).unwrap().clamp(first, count);
            let expected: Vec<_> = (start..count).map(|index| format!("line-{index}")).collect();
            proptest::prop_assert_eq!(result.next_seq, count as u64);
            proptest::prop_assert_eq!(result.truncated, cursor < first as u64);
            proptest::prop_assert_eq!(result.lines.iter().map(|line| line.display().to_owned()).collect::<Vec<_>>(), expected);
        }
    }

    #[test]
    fn structured_runner_logs_keep_wire_metadata_separate_from_the_ui_line() {
        let fields = serde_json::Map::from_iter([("code".to_owned(), serde_json::json!(47))]);
        let log = RunnerLog::structured(
            "warning",
            "payment delayed",
            Some("inv-7"),
            Some("settlePayment"),
            true,
            fields.clone(),
        );

        assert_eq!(log.display(), "warning inv-7 payment delayed");
        assert_eq!(log.level(), "warning");
        assert_eq!(log.message(), "payment delayed");
        assert_eq!(log.function(), Some("settlePayment"));
        assert_eq!(log.invocation_id(), Some("inv-7"));
        assert!(log.is_user());
        assert_eq!(log.fields(), &fields);
    }
}
