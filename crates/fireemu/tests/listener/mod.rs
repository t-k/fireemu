//! Who owns a TCP listener: evidence for a test that finds an emulator port still open.
//!
//! A listener that survives a daemon's shutdown is either the daemon's own socket (a shutdown
//! defect) or another process that bound the released ephemeral port afterwards (not a defect of
//! the daemon). A bare "still listens" cannot tell the two apart. On Linux the owners are read
//! from `/proc`: `/proc/net/tcp` and `/proc/net/tcp6` map a listening port to socket inodes, and
//! `/proc/<pid>/fd` maps an inode to the processes holding it. Other platforms report the
//! evidence as unavailable.
//!
//! Each test binary that uses this module compiles its own copy and uses only part of it,
//! hence the module-wide `dead_code` allowance.

#![allow(dead_code)]

/// One process holding a listening socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// Process ID.
    pub pid: i32,
    /// Command line, NUL separators replaced by spaces; empty when it could not be read.
    pub command: String,
}

/// What the owner evidence says about a port that still accepts connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// No listening socket on the port was found.
    NoListener,
    /// Every owner belongs to the process family under test: a listener it should have closed.
    OwnedSurvivor(Vec<Owner>),
    /// No owner belongs to that family: another process claimed the released port.
    Foreign(Vec<Owner>),
    /// Owners from both sides (a socket shared across a fork, for example).
    Mixed(Vec<Owner>),
    /// A listening socket exists but no readable process holds it (another user's process,
    /// or one that exited between the two reads), or `/proc` is unavailable.
    Unknown(String),
}

impl std::fmt::Display for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let owners = |f: &mut std::fmt::Formatter<'_>, label: &str, owners: &[Owner]| {
            write!(f, "{label}:")?;
            for owner in owners {
                write!(f, " [pid {} `{}`]", owner.pid, owner.command)?;
            }
            Ok(())
        };
        match self {
            Self::NoListener => write!(f, "no listening socket found on the port"),
            Self::OwnedSurvivor(list) => {
                owners(f, "listener owned by the process family under test", list)
            }
            Self::Foreign(list) => owners(f, "listener owned by an unrelated process", list),
            Self::Mixed(list) => owners(
                f,
                "listener shared by related and unrelated processes",
                list,
            ),
            Self::Unknown(reason) => write!(f, "listener owner unknown: {reason}"),
        }
    }
}

/// Classifies `owners` of a port against `family`, the PIDs the test is responsible for (the
/// child it started and every descendant the census found).
#[must_use]
pub fn classify(listening: bool, owners: &[Owner], family: &[i32]) -> Ownership {
    if !listening {
        return Ownership::NoListener;
    }
    if owners.is_empty() {
        return Ownership::Unknown("a listening socket has no readable owner".to_owned());
    }
    let related = owners.iter().filter(|o| family.contains(&o.pid)).count();
    if related == owners.len() {
        Ownership::OwnedSurvivor(owners.to_vec())
    } else if related == 0 {
        Ownership::Foreign(owners.to_vec())
    } else {
        Ownership::Mixed(owners.to_vec())
    }
}

/// Classifies whoever holds a listening socket on `port`.
#[must_use]
pub fn ownership(port: u16, family: &[i32]) -> Ownership {
    match listening_inodes(port) {
        Ok(inodes) if inodes.is_empty() => Ownership::NoListener,
        Ok(inodes) => classify(true, &owners_of(&inodes), family),
        Err(reason) => Ownership::Unknown(reason),
    }
}

/// The socket inodes listening on `port` (any local address), from `/proc/net/tcp{,6}`.
#[cfg(target_os = "linux")]
pub fn listening_inodes(port: u16) -> Result<Vec<u64>, String> {
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

#[cfg(not(target_os = "linux"))]
pub fn listening_inodes(_port: u16) -> Result<Vec<u64>, String> {
    Err("listener owners are read from /proc, which this platform does not have".to_owned())
}

/// The processes holding any of `inodes` open, from `/proc/<pid>/fd`. Processes this user may not
/// inspect are skipped.
#[cfg(target_os = "linux")]
#[must_use]
pub fn owners_of(inodes: &[u64]) -> Vec<Owner> {
    let targets: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    let mut owners = Vec::new();
    let Ok(processes) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in processes.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
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
            owners.push(Owner { pid, command });
        }
    }
    owners
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn owners_of(_inodes: &[u64]) -> Vec<Owner> {
    Vec::new()
}
