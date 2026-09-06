//! Process census for tests that start daemons, shells or background jobs.
//!
//! Nextest's leak detection only sees processes that still hold the test's captured stdout or
//! stderr. A child that closed or redirected those handles is invisible to it, so a test that
//! owns processes checks the census as well: `assert_no_owned_descendants` fails with the PID,
//! parent PID, process group and command of everything that survived.
//!
//! Any test file in this crate can use it with `mod census;`. Each test binary that does so
//! compiles its own copy and uses only part of it, hence the module-wide `dead_code` allowance.

#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One line of `ps -eo pid,ppid,pgid,command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    /// Process ID.
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// Process group ID.
    pub pgid: i32,
    /// Full command line.
    pub command: String,
}

impl Proc {
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let pid = fields.next()?.parse().ok()?;
        let parent = fields.next()?.parse().ok()?;
        let group = fields.next()?.parse().ok()?;
        let rest: Vec<&str> = fields.collect();
        Some(Self {
            pid,
            ppid: parent,
            pgid: group,
            command: rest.join(" "),
        })
    }
}

const PS_COMMAND: &str = "ps -eo pid,ppid,pgid,command";

/// Every process visible to this user, in the order `ps` reports them.
///
/// The `ps` process the census itself starts is filtered out: it is a child of the test and
/// would otherwise count as a survivor of it.
#[must_use]
pub fn snapshot() -> Vec<Proc> {
    let output = Command::new("ps")
        .args(["-eo", "pid,ppid,pgid,command"])
        .stdin(Stdio::null())
        .output()
        .expect("ps must be available for the process census");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter_map(Proc::parse)
        .filter(|p| !p.command.starts_with(PS_COMMAND))
        .collect()
}

/// Transitive descendants of `pid`, excluding `pid` itself.
#[must_use]
pub fn descendants_of(pid: i32) -> Vec<Proc> {
    let all = snapshot();
    let mut owned = vec![pid];
    let mut found: Vec<Proc> = Vec::new();
    // The parent of a process always has a lower PID than the process only in the common case,
    // so iterate to a fixed point instead of relying on the order.
    loop {
        let before = found.len();
        for p in &all {
            if owned.contains(&p.ppid) && !owned.contains(&p.pid) {
                owned.push(p.pid);
                found.push(p.clone());
            }
        }
        if found.len() == before {
            return found;
        }
    }
}

/// Every process in group `pgid`.
#[must_use]
pub fn process_group(pgid: i32) -> Vec<Proc> {
    snapshot().into_iter().filter(|p| p.pgid == pgid).collect()
}

/// The census entry for `pid`, if it is still running.
#[must_use]
pub fn find(pid: i32) -> Option<Proc> {
    snapshot().into_iter().find(|p| p.pid == pid)
}

/// The process group this test process belongs to.
#[must_use]
pub fn own_process_group() -> Option<i32> {
    let me = i32::try_from(std::process::id()).ok()?;
    find(me).map(|p| p.pgid)
}

/// Waits until `pid` has no descendants left, up to `timeout`. Returns the survivors.
#[must_use]
pub fn wait_for_no_descendants(pid: i32, timeout: Duration) -> Vec<Proc> {
    let deadline = Instant::now() + timeout;
    loop {
        let survivors = descendants_of(pid);
        if survivors.is_empty() || Instant::now() >= deadline {
            return survivors;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Waits until `pgid` has no members left, up to `timeout`. Returns the survivors.
#[must_use]
pub fn wait_for_empty_process_group(pgid: i32, timeout: Duration) -> Vec<Proc> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_alive(pgid) {
            return Vec::new();
        }
        if Instant::now() >= deadline {
            return process_group(pgid);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Renders a census table for a failure message.
#[must_use]
pub fn table(procs: &[Proc]) -> String {
    use std::fmt::Write;

    let mut out = format!("{:>8} {:>8} {:>8} COMMAND\n", "PID", "PPID", "PGID");
    for p in procs {
        let _ = writeln!(
            out,
            "{:>8} {:>8} {:>8} {}",
            p.pid, p.ppid, p.pgid, p.command
        );
    }
    out
}

/// Fails with a census table when any descendant of this test process survives `grace`.
///
/// Call it at the end of a test that starts processes, after its own cleanup: it covers the
/// descendants nextest cannot see because they no longer hold the captured output handles.
pub fn assert_no_owned_descendants(context: &str, grace: Duration) {
    let me = i32::try_from(std::process::id()).expect("pid fits in i32");
    let survivors = wait_for_no_descendants(me, grace);
    assert!(
        survivors.is_empty(),
        "{context}: {} owned descendant(s) survived after {grace:?}\n{}",
        survivors.len(),
        table(&survivors)
    );
}

/// Fails with a census table when a command's dedicated process group survives `grace`.
pub fn assert_process_group_empty(pgid: i32, context: &str, grace: Duration) {
    let survivors = wait_for_empty_process_group(pgid, grace);
    assert!(
        survivors.is_empty(),
        "{context}: {} process-group member(s) survived after {grace:?}\n{}",
        survivors.len(),
        table(&survivors)
    );
}

/// Terminates a whole process group and reaps it, first politely and then not.
///
/// Killing the group (rather than a single PID) is what catches the shells, daemons and
/// background jobs a command leaves behind.
pub fn kill_process_group(pgid: i32) {
    kill_process_group_with_grace(pgid, Duration::from_secs(2));
}

/// Terminates a whole process group using a caller-selected per-signal grace interval.
pub fn kill_process_group_with_grace(pgid: i32, grace: Duration) {
    for signal in ["-TERM", "-KILL"] {
        let _ = Command::new("kill")
            .args([signal, &format!("-{pgid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !process_group_alive(pgid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn process_group_alive(pgid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &format!("-{pgid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Kills `pid` unconditionally; used to clean up a fixture's recorded child.
pub fn kill_pid(pid: i32) {
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Terminates exactly the process observed by a prior census, without signaling a process
/// group or a different process that later reused the numeric PID.
pub fn terminate_exact_process(expected: &Proc, grace: Duration) {
    for signal in [rustix::process::Signal::TERM, rustix::process::Signal::KILL] {
        if find(expected.pid).as_ref() != Some(expected) {
            return;
        }
        let Some(pid) = rustix::process::Pid::from_raw(expected.pid) else {
            return;
        };
        let _ = rustix::process::kill_process(pid, signal);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !alive(expected.pid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Whether `pid` is alive.
#[must_use]
pub fn alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
