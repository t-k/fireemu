//! Best-effort evidence for a test that finds an emulator port still accepting connections:
//! which processes hold a listening socket on it. On Linux the holders are read from `/proc`
//! (`/proc/net/tcp{,6}` maps the port to socket inodes, `/proc/<pid>/fd` maps an inode to its
//! holders). Elsewhere, or when `/proc` cannot be read, the text says why no owner is shown.
//!
//! The text only lists the holders; it does not say whether they belong to the test.

/// The processes holding a listening socket on `port`, or the reason none can be named.
#[must_use]
pub fn owners(port: u16) -> String {
    #[cfg(target_os = "linux")]
    {
        owners_linux(port)
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!(
            "owners unavailable: {} has no /proc to read them from (port {port})",
            std::env::consts::OS
        )
    }
}

#[cfg(target_os = "linux")]
fn owners_linux(port: u16) -> String {
    let inodes = match listening_inodes(port) {
        Ok(inodes) => inodes,
        Err(reason) => return format!("owners unavailable: {reason}"),
    };
    if inodes.is_empty() {
        return format!("owners: no listening socket on port {port} in /proc/net/tcp{{,6}}");
    }
    let holders = holders(&inodes);
    if holders.is_empty() {
        return format!(
            "owners unavailable: {} listening socket(s) on port {port} have no readable holder \
             (another user's process, or one that exited)",
            inodes.len()
        );
    }
    format!("owners of port {port}: {}", holders.join(" "))
}

/// The inodes of the sockets in LISTEN state on `port`, over IPv4 and IPv6.
#[cfg(target_os = "linux")]
fn listening_inodes(port: u16) -> Result<Vec<u64>, String> {
    /// `st` of a socket in the LISTEN state.
    const LISTEN: &str = "0A";
    let mut inodes = Vec::new();
    let mut readable = false;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        readable = true;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(state), Some(inode)) =
                (fields.get(1), fields.get(3), fields.get(9))
            else {
                continue;
            };
            let local_port = local
                .rsplit_once(':')
                .and_then(|(_, hex)| u16::from_str_radix(hex, 16).ok());
            if local_port == Some(port) && *state == LISTEN {
                if let Ok(inode) = inode.parse() {
                    inodes.push(inode);
                }
            }
        }
    }
    if readable {
        Ok(inodes)
    } else {
        Err("/proc/net/tcp is not readable".to_owned())
    }
}

/// `[pid N `command`]` for each process that holds one of `inodes`. Processes this user may not
/// inspect are skipped.
#[cfg(target_os = "linux")]
fn holders(inodes: &[u64]) -> Vec<String> {
    let targets: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    let mut holders = Vec::new();
    let Ok(processes) = std::fs::read_dir("/proc") else {
        return holders;
    };
    for entry in processes.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let holds = fds.flatten().any(|fd| {
            std::fs::read_link(fd.path())
                .is_ok_and(|link| targets.iter().any(|t| link.as_os_str() == t.as_str()))
        });
        if holds {
            let command = std::fs::read(entry.path().join("cmdline"))
                .map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .split('\0')
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            holders.push(format!("[pid {pid} `{command}`]"));
        }
    }
    holders
}
