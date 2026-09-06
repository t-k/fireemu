//! Private lifecycle for the Apalache backend used by one verification command.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
#[cfg(any(target_os = "linux", test))]
use std::net::Ipv6Addr;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{kill_process, Signal};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::process::{validate_apalache_distribution, OwnedApalacheServer, APALACHE_JAR_SHA256};

const READINESS_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const LOOPBACK_AGENT_SOURCE: &[u8] =
    include_bytes!("../java/io/fireemu/verification/LoopbackServerProviderAgent.java");

pub(crate) struct RunningApalacheServer {
    endpoint: Option<OwnedApalacheServer>,
    child: Child,
    _owner_pipe: ChildStdin,
    _temporary: TempDir,
    stderr: PathBuf,
    closed: bool,
}

impl RunningApalacheServer {
    pub(crate) fn start() -> Result<Self, String> {
        let temporary = tempfile::Builder::new()
            .prefix("fireemu-quint-apalache-")
            .tempdir()
            .map_err(|error| format!("cannot create Apalache private directory: {error}"))?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect Apalache private directory: {error}"))?;
        let RuntimeArtifacts {
            java,
            private_jar,
            agent_jar,
        } = prepare_runtime(&temporary)?;

        let stdout_path = temporary.path().join("stdout.log");
        let stderr_path = temporary.path().join("stderr.log");
        let stdout = File::create(&stdout_path)
            .map_err(|error| format!("cannot create Apalache stdout: {error}"))?;
        let stderr = File::create(&stderr_path)
            .map_err(|error| format!("cannot create Apalache stderr: {error}"))?;
        let mut command = clean_command(&java, temporary.path());
        command
            .arg(format!("-javaagent:{}", agent_jar.display()))
            .arg("-Xmx4096m")
            .args([
                "-XX:+UseG1GC",
                "-XX:G1PeriodicGCInterval=600000",
                "-XX:+G1PeriodicGCInvokesConcurrent",
            ])
            .arg(format!("-Djava.io.tmpdir={}", temporary.path().display()))
            .arg("-jar")
            .arg(&private_jar)
            .args(["server", "--port=0"])
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .stdin(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot launch owned Apalache server: {error}"))?;
        let owner_pipe = child
            .stdin
            .take()
            .ok_or_else(|| "owned Apalache server has no owner pipe".to_owned())?;
        let mut running = Self {
            endpoint: None,
            child,
            _owner_pipe: owner_pipe,
            _temporary: temporary,
            stderr: stderr_path,
            closed: false,
        };
        let address = running.wait_until_ready()?;
        running.endpoint = Some(OwnedApalacheServer::from_validated_child(
            address,
            running.child.id(),
        ));
        Ok(running)
    }

    pub(crate) fn endpoint(&self) -> &OwnedApalacheServer {
        self.endpoint
            .as_ref()
            .expect("a running server has a validated endpoint")
    }

    pub(crate) fn ensure_running(&mut self) -> Result<(), String> {
        match self.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(format!(
                "owned Apalache server exited prematurely ({status}): {}",
                self.diagnostic()
            )),
            Err(error) => Err(format!("cannot inspect owned Apalache server: {error}")),
        }
    }

    pub(crate) fn close(mut self) -> Result<(), String> {
        let result = self.stop();
        self.closed = true;
        result
    }

    fn wait_until_ready(&mut self) -> Result<SocketAddr, String> {
        let deadline = Instant::now() + READINESS_TIMEOUT;
        while Instant::now() < deadline {
            self.ensure_running()?;
            let endpoints = listener_endpoints(self.child.id())?;
            if let Some(address) = validated_listener(&endpoints)? {
                if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                    return Ok(address);
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(format!(
            "owned Apalache server did not become ready within {}s: {}",
            READINESS_TIMEOUT.as_secs(),
            self.diagnostic()
        ))
    }

    fn diagnostic(&self) -> String {
        let mut file = match File::open(&self.stderr) {
            Ok(file) => file,
            Err(error) => return format!("cannot read server diagnostic: {error}"),
        };
        let mut bytes = Vec::new();
        if let Err(error) = file
            .by_ref()
            .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
        {
            return format!("cannot read server diagnostic: {error}");
        }
        bounded(&bytes)
    }

    fn stop(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        if self
            .child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        let raw_pid = i32::try_from(self.child.id())
            .map_err(|_| "owned Apalache server PID exceeds i32".to_owned())?;
        let pid = rustix::process::Pid::from_raw(raw_pid)
            .ok_or_else(|| "owned Apalache server has invalid PID".to_owned())?;
        let _ = kill_process(pid, Signal::TERM);
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        while Instant::now() < deadline {
            if self
                .child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = kill_process(pid, Signal::KILL);
        self.child
            .wait()
            .map_err(|error| format!("cannot reap owned Apalache server: {error}"))?;
        Ok(())
    }
}

struct RuntimeArtifacts {
    java: PathBuf,
    private_jar: PathBuf,
    agent_jar: PathBuf,
}

fn prepare_runtime(temporary: &TempDir) -> Result<RuntimeArtifacts, String> {
    let source_jar = validate_apalache_distribution()?;
    let jar_bytes = fs::read(&source_jar).map_err(|error| {
        format!(
            "cannot read pinned Apalache JAR {}: {error}",
            source_jar.display()
        )
    })?;
    let digest = format!("{:x}", Sha256::digest(&jar_bytes));
    if digest != APALACHE_JAR_SHA256 {
        return Err(format!(
            "Apalache JAR changed before private copy: expected {APALACHE_JAR_SHA256}, found {digest}"
        ));
    }
    let private_jar = temporary.path().join("apalache.jar");
    fs::write(&private_jar, jar_bytes)
        .map_err(|error| format!("cannot create private Apalache JAR: {error}"))?;
    fs::set_permissions(&private_jar, fs::Permissions::from_mode(0o400))
        .map_err(|error| format!("cannot protect private Apalache JAR: {error}"))?;

    let java = trusted_executable("java")?;
    let jdk_bin = java
        .parent()
        .ok_or_else(|| format!("Java executable has no parent: {}", java.display()))?;
    let javac = trusted_sibling(jdk_bin, "javac")?;
    let jar = trusted_sibling(jdk_bin, "jar")?;
    let source = temporary.path().join("LoopbackServerProviderAgent.java");
    fs::write(&source, LOOPBACK_AGENT_SOURCE)
        .map_err(|error| format!("cannot create private loopback provider source: {error}"))?;
    let classes = temporary.path().join("classes");
    fs::create_dir(&classes)
        .map_err(|error| format!("cannot create private Java classes directory: {error}"))?;
    let compile = clean_command(&javac, temporary.path())
        .args(["-cp"])
        .arg(&private_jar)
        .args(["-d"])
        .arg(&classes)
        .arg(&source)
        .output()
        .map_err(|error| format!("cannot launch trusted javac: {error}"))?;
    if !compile.status.success() {
        return Err(format!(
            "cannot compile loopback provider: {}",
            bounded(&compile.stderr)
        ));
    }

    let manifest = temporary.path().join("MANIFEST.MF");
    fs::write(
        &manifest,
        b"Manifest-Version: 1.0\r\nPremain-Class: io.fireemu.verification.LoopbackServerProviderAgent\r\n\r\n",
    )
    .map_err(|error| format!("cannot create Java agent manifest: {error}"))?;
    let agent_jar = temporary.path().join("loopback-agent.jar");
    let package = clean_command(&jar, temporary.path())
        .args(["cfm"])
        .arg(&agent_jar)
        .arg(&manifest)
        .args(["-C"])
        .arg(&classes)
        .arg(".")
        .output()
        .map_err(|error| format!("cannot launch trusted jar tool: {error}"))?;
    if !package.status.success() {
        return Err(format!(
            "cannot package loopback provider: {}",
            bounded(&package.stderr)
        ));
    }
    fs::set_permissions(&agent_jar, fs::Permissions::from_mode(0o400))
        .map_err(|error| format!("cannot protect loopback provider JAR: {error}"))?;
    Ok(RuntimeArtifacts {
        java,
        private_jar,
        agent_jar,
    })
}

fn validated_listener(endpoints: &BTreeSet<SocketAddr>) -> Result<Option<SocketAddr>, String> {
    if endpoints.len() > 1 {
        return Err(format!(
            "owned Apalache process has multiple listeners: {endpoints:?}"
        ));
    }
    let Some(address) = endpoints.iter().next().copied() else {
        return Ok(None);
    };
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(format!(
            "owned Apalache process is not IPv4 loopback-bound: {address}"
        ));
    }
    Ok(Some(address))
}

impl Drop for RunningApalacheServer {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.stop();
        }
    }
}

fn clean_command(executable: &Path, temporary: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .current_dir(temporary)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TMPDIR", temporary);
    command
}

fn trusted_executable(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH")
        .and_then(|value| {
            std::env::split_paths(&value)
                .map(|directory| directory.join(name))
                .find(|candidate| candidate.is_file())
        })
        .ok_or_else(|| format!("required executable is unavailable: {name}"))?;
    trusted_path(&path)
}

fn trusted_sibling(directory: &Path, name: &str) -> Result<PathBuf, String> {
    trusted_path(&directory.join(name))
}

fn trusted_path(path: &Path) -> Result<PathBuf, String> {
    let path = path.canonicalize().map_err(|error| {
        format!(
            "cannot resolve trusted executable {}: {error}",
            path.display()
        )
    })?;
    let groups = rustix::process::getgroups()
        .map_err(|error| format!("cannot inspect caller groups: {error}"))?
        .into_iter()
        .map(rustix::fs::Gid::as_raw)
        .chain(std::iter::once(rustix::process::getgid().as_raw()))
        .collect::<BTreeSet<_>>();
    for candidate in std::iter::once(path.as_path()).chain(path.ancestors().skip(1)) {
        let metadata = candidate.metadata().map_err(|error| {
            format!(
                "cannot inspect trusted path {}: {error}",
                candidate.display()
            )
        })?;
        let caller_writable = metadata.mode() & 0o002 != 0
            || (groups.contains(&metadata.gid()) && metadata.mode() & 0o020 != 0);
        if metadata.uid() != 0 || caller_writable {
            return Err(format!(
                "required executable path is not trusted: {}",
                candidate.display()
            ));
        }
    }
    if !path.is_file()
        || path
            .metadata()
            .is_ok_and(|metadata| metadata.mode() & 0o111 == 0)
    {
        return Err(format!(
            "required executable is not executable: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn bounded(bytes: &[u8]) -> String {
    let bytes = if bytes.len() > MAX_DIAGNOSTIC_BYTES {
        &bytes[..MAX_DIAGNOSTIC_BYTES]
    } else {
        bytes
    };
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(target_os = "macos")]
fn listener_endpoints(pid: u32) -> Result<BTreeSet<SocketAddr>, String> {
    let output = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fn",
        ])
        .env_clear()
        .output()
        .map_err(|error| format!("cannot inspect owned server listeners: {error}"))?;
    if output.status.code() == Some(1) && output.stderr.is_empty() {
        return Ok(BTreeSet::new());
    }
    if !output.status.success() {
        return Err(format!(
            "listener inspection failed with {}: {}",
            output.status,
            bounded(&output.stderr)
        ));
    }
    parse_lsof_listener_output(&output.stdout)
}

#[cfg(any(target_os = "macos", test))]
fn parse_lsof_listener_output(output: &[u8]) -> Result<BTreeSet<SocketAddr>, String> {
    let mut endpoints = BTreeSet::new();
    for line in output.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(b"n") else {
            continue;
        };
        let value = std::str::from_utf8(value)
            .map_err(|error| format!("listener address is not UTF-8: {error}"))?;
        let address = value
            .parse::<SocketAddr>()
            .map_err(|error| format!("unrecognized listener address {value:?}: {error}"))?;
        endpoints.insert(address);
    }
    Ok(endpoints)
}

#[cfg(target_os = "linux")]
fn listener_endpoints(pid: u32) -> Result<BTreeSet<SocketAddr>, String> {
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| format!("cannot inspect Apalache descriptors: {error}"))?;
    let socket_inodes = descriptors
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let mut endpoints = BTreeSet::new();
    for table_name in ["tcp", "tcp6"] {
        let path = format!("/proc/{pid}/net/{table_name}");
        let table = fs::read_to_string(&path)
            .map_err(|error| format!("cannot inspect Apalache {table_name} listeners: {error}"))?;
        parse_linux_listener_table(table_name, &table, &socket_inodes, &mut endpoints)?;
    }
    Ok(endpoints)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_listener_table(
    table_name: &str,
    table: &str,
    socket_inodes: &BTreeSet<String>,
    endpoints: &mut BTreeSet<SocketAddr>,
) -> Result<(), String> {
    for line in table.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            return Err(format!("malformed /proc listener row: {line:?}"));
        }
        if fields[3] != "0A" || !socket_inodes.contains(fields[9]) {
            continue;
        }
        let Some((address, port)) = fields[1].rsplit_once(':') else {
            return Err(format!("malformed /proc listener address: {:?}", fields[1]));
        };
        let port = u16::from_str_radix(port, 16)
            .map_err(|error| format!("invalid listener port: {error}"))?;
        let endpoint = match table_name {
            "tcp" if address.len() == 8 => {
                let raw = u32::from_str_radix(address, 16)
                    .map_err(|error| format!("invalid IPv4 listener address: {error}"))?;
                SocketAddr::from((Ipv4Addr::from(raw.to_le_bytes()), port))
            }
            "tcp6" if address.len() == 32 => {
                let mut bytes = [0_u8; 16];
                for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
                    let chunk = std::str::from_utf8(chunk)
                        .map_err(|error| format!("invalid IPv6 listener address: {error}"))?;
                    let raw = u32::from_str_radix(chunk, 16)
                        .map_err(|error| format!("invalid IPv6 listener address: {error}"))?;
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
                }
                SocketAddr::from((Ipv6Addr::from(bytes), port))
            }
            _ => {
                return Err(format!(
                    "unexpected {table_name} listener address {address:?}"
                ));
            }
        };
        endpoints.insert(endpoint);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn listener_endpoints(_pid: u32) -> Result<BTreeSet<SocketAddr>, String> {
    Err("owned Apalache servers are supported only on Linux and macOS".to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    use super::{parse_linux_listener_table, parse_lsof_listener_output, validated_listener};

    #[test]
    fn listener_validation_requires_one_nonzero_ipv4_loopback_socket() {
        assert_eq!(
            validated_listener(&BTreeSet::new()).expect("no listener is not yet an error"),
            None
        );
        let loopback = "127.0.0.1:43123".parse::<SocketAddr>().unwrap();
        assert_eq!(
            validated_listener(&BTreeSet::from([loopback])).unwrap(),
            Some(loopback)
        );

        for rejected in ["0.0.0.0:43123", "[::1]:43123", "127.0.0.1:0"] {
            let diagnostic =
                validated_listener(&BTreeSet::from([rejected.parse::<SocketAddr>().unwrap()]))
                    .expect_err("non-loopback or zero listeners must fail closed");
            assert!(diagnostic.contains("not IPv4 loopback-bound"));
        }

        let diagnostic = validated_listener(&BTreeSet::from([
            loopback,
            "127.0.0.1:43124".parse().unwrap(),
        ]))
        .expect_err("multiple listeners must fail closed");
        assert!(diagnostic.contains("multiple listeners"));
    }

    #[test]
    fn lsof_listener_parser_preserves_ipv6_and_rejects_unknown_addresses() {
        let endpoints = parse_lsof_listener_output(b"p42\nn127.0.0.1:43123\nn[::1]:43124\n")
            .expect("recognized IPv4 and IPv6 listeners must parse");
        assert_eq!(endpoints.len(), 2);
        assert!(validated_listener(&endpoints).is_err());

        for malformed in [b"p42\nn*:43123\n".as_slice(), b"p42\nn\xff\n".as_slice()] {
            assert!(
                parse_lsof_listener_output(malformed).is_err(),
                "unrecognized lsof listener output must fail closed"
            );
        }
    }

    #[test]
    fn proc_listener_parser_preserves_ipv6_and_fails_closed() {
        let inodes = BTreeSet::from(["12345".to_owned(), "12346".to_owned()]);
        let mut endpoints = BTreeSet::new();
        parse_linux_listener_table(
            "tcp",
            "header\n0: 0100007F:A86B 00000000:0000 0A 0:0 00:0 0 1000 0 12345\n",
            &inodes,
            &mut endpoints,
        )
        .unwrap();
        parse_linux_listener_table(
            "tcp6",
            "header\n0: 00000000000000000000000001000000:A86C 00000000000000000000000000000000:0000 0A 0:0 00:0 0 1000 0 12346\n",
            &inodes,
            &mut endpoints,
        )
        .unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(validated_listener(&endpoints).is_err());

        let error = parse_linux_listener_table(
            "tcp6",
            "header\n0: malformed:A86C 0000:0000 0A 0:0 00:0 0 1000 0 12346\n",
            &inodes,
            &mut BTreeSet::new(),
        )
        .expect_err("malformed owned listeners must fail closed");
        assert!(error.contains("unexpected tcp6 listener address"));
    }
}
