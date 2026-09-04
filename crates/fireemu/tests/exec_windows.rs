//! Native Windows lifecycle and quoting coverage for `emulators:exec`.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn daemon() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args([
            "emulators:exec",
            "--only",
            "auth",
            "--http-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fireemu exec windows {name} {}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn powershell_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

fn process_exists(pid: u32) -> bool {
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

struct ProcessGuard(Option<u32>);

impl ProcessGuard {
    fn new(pid: u32) -> Self {
        Self(Some(pid))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[test]
fn leader_exit_sweeps_a_background_grandchild() {
    let dir = scratch("job object");
    let pid_file = dir.join("grandchild.pid");
    let script = format!(
        "powershell.exe -NoProfile -NonInteractive -Command \"$p=Start-Process ping.exe -ArgumentList '-n','301','127.0.0.1' -PassThru; [IO.File]::WriteAllText('{}',[string]$p.Id)\"",
        powershell_path(&pid_file)
    );

    let output = daemon().arg(script).output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
    let mut guard = ProcessGuard::new(pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !process_exists(pid),
        "the background process survived fireemu"
    );
    guard.disarm();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn positional_cmd_script_preserves_quoted_metacharacters_and_exit_code() {
    let dir = scratch("cmd quoting");
    let batch = dir.join("command fixture.cmd");
    let output_file = dir.join("output value.txt");
    std::fs::write(
        &batch,
        "@echo off\r\n>\"%~2\" <nul set /p \"=%~1\"\r\nexit /b 23\r\n",
    )
    .unwrap();
    let expected = "value with spaces & pipe | parens ()";
    let script = format!(
        "\"{}\" \"{expected}\" \"{}\"",
        batch.display(),
        output_file.display()
    );

    let output = daemon().arg(script).output().unwrap();

    assert_eq!(output.status.code(), Some(23));
    assert_eq!(std::fs::read_to_string(&output_file).unwrap(), expected);
    let _ = std::fs::remove_dir_all(dir);
}
