#!/usr/bin/env python3
"""
portctl: a tiny cooperative local TCP port registry for AI agents and dev tools.

- Uses SQLite transactions for atomic claims.
- Avoids ports already reserved in the registry.
- Avoids ports currently bound by non-cooperating processes.
- Supports TTL-based cleanup and release-on-exit via the `run` subcommand.

Python 3.9+, stdlib only. Non-interactive CLI suitable for agents.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

SCHEMA_VERSION = 1
DEFAULT_RANGE = "3000-3999"
DEFAULT_TTL = "4h"


class PortCtlError(Exception):
    pass


@dataclass(frozen=True)
class Claim:
    port: int
    host: str
    project: str
    service: str
    agent_id: str
    token: str
    created_at: int
    expires_at: Optional[int]
    db: str

    def as_dict(self) -> dict:
        return {
            "port": self.port,
            "host": self.host,
            "project": self.project,
            "service": self.service,
            "agent_id": self.agent_id,
            "token": self.token,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "db": self.db,
        }


def now() -> int:
    return int(time.time())


def run_git_rev_parse(
    args: Sequence[str], start: Optional[Path] = None
) -> Optional[str]:
    """Run a small git rev-parse query. Return None outside a git worktree."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", *args],
            cwd=str((start or Path.cwd()).resolve()),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )
        return proc.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def git_common_dir(start: Optional[Path] = None) -> Optional[Path]:
    """Return the common .git directory shared by all linked worktrees."""
    cwd = (start or Path.cwd()).resolve()
    value = run_git_rev_parse(["--path-format=absolute", "--git-common-dir"], cwd)
    if value:
        return Path(value).expanduser().resolve()

    # Fallback for older Git versions that do not support --path-format.
    value = run_git_rev_parse(["--git-common-dir"], cwd)
    if not value:
        return None
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = cwd / p
    return p.resolve()


def git_toplevel(start: Optional[Path] = None) -> Optional[Path]:
    value = run_git_rev_parse(["--show-toplevel"], start or Path.cwd())
    if value:
        return Path(value).expanduser().resolve()
    return None


def find_workspace_root(start: Optional[Path] = None) -> Path:
    """Return the current worktree root when possible, including linked worktrees."""
    top = git_toplevel(start)
    if top:
        return top

    p = (start or Path.cwd()).resolve()
    for candidate in [p, *p.parents]:
        # In linked worktrees .git is a file, not a directory; exists() handles both.
        if (candidate / ".git").exists():
            return candidate
    return p


def safe_path_component(value: str) -> str:
    cleaned = []
    for ch in value.strip():
        if ch.isalnum() or ch in {"-", "_", "."}:
            cleaned.append(ch)
        else:
            cleaned.append("_")
    result = "".join(cleaned).strip("._")
    return result or "local"


def default_registry_namespace() -> str:
    # Port namespaces are normally per host/network namespace. Including the host
    # avoids false conflicts and flaky SQLite locking when HOME is shared via NFS.
    env = os.environ.get("PORT_REGISTRY_NAMESPACE")
    if env:
        return safe_path_component(env)
    return safe_path_component(socket.gethostname() or "local")


def user_home_db_path() -> Path:
    home = os.environ.get("PORT_REGISTRY_HOME")
    root = Path(home).expanduser() if home else Path.home() / ".agent" / "port-registry"
    return root / f"{default_registry_namespace()}.sqlite3"


def default_db_path(scope: Optional[str] = None, start: Optional[Path] = None) -> Path:
    env = os.environ.get("PORT_REGISTRY_DB")
    if env:
        return Path(env).expanduser().resolve()

    selected = (
        (scope or os.environ.get("PORT_REGISTRY_SCOPE") or "global").strip().lower()
    )
    if selected in {"global", "home", "user"}:
        return user_home_db_path().resolve()
    if selected in {"workspace", "worktree"}:
        return (find_workspace_root(start) / ".agent" / "ports.sqlite3").resolve()
    if selected in {"git-common", "git", "repo", "repository"}:
        common = git_common_dir(start)
        if common:
            return (common / "agent" / "ports.sqlite3").resolve()
        return (find_workspace_root(start) / ".agent" / "ports.sqlite3").resolve()
    raise PortCtlError(f"Unknown registry scope: {selected}")


def default_agent_id() -> str:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown-user"
    host = socket.gethostname()
    return os.environ.get("AGENT_ID") or f"{user}@{host}:{os.getpid()}"


def default_project(start: Optional[Path] = None) -> str:
    env = os.environ.get("PORT_REGISTRY_PROJECT")
    if env:
        return env

    common = git_common_dir(start)
    if common:
        # Normal repository: /path/repo/.git -> repo.
        # Bare/worktree manager repository: /path/repo.git -> repo.
        if common.name == ".git" and common.parent.name:
            return common.parent.name
        if common.name.endswith(".git") and len(common.name) > 4:
            return common.name[:-4]
        return common.name or "repository"

    name = find_workspace_root(start).name
    return name or "workspace"


def parse_duration(value: str) -> Optional[int]:
    """Return seconds. 0, none, never => no expiration."""
    text = str(value).strip().lower()
    if text in {"0", "none", "never", "inf", "infinite"}:
        return None
    units = {
        "s": 1,
        "sec": 1,
        "secs": 1,
        "second": 1,
        "seconds": 1,
        "m": 60,
        "min": 60,
        "mins": 60,
        "minute": 60,
        "minutes": 60,
        "h": 3600,
        "hr": 3600,
        "hrs": 3600,
        "hour": 3600,
        "hours": 3600,
        "d": 86400,
        "day": 86400,
        "days": 86400,
    }
    for suffix, multiplier in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            if not number:
                raise PortCtlError(f"Invalid duration: {value}")
            return int(float(number) * multiplier)
    try:
        return int(float(text))
    except ValueError as exc:
        raise PortCtlError(f"Invalid duration: {value}") from exc


def parse_ranges(range_specs: Sequence[str]) -> List[int]:
    ports: List[int] = []
    seen = set()
    for spec in range_specs:
        for part in str(spec).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                left, right = part.split("-", 1)
                lo, hi = int(left), int(right)
                if lo > hi:
                    lo, hi = hi, lo
                candidates = range(lo, hi + 1)
            else:
                candidates = [int(part)]
            for port in candidates:
                if not (1 <= port <= 65535):
                    raise PortCtlError(f"Port out of range: {port}")
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
    if not ports:
        raise PortCtlError("No ports specified")
    return ports


def pid_exists(pid: Optional[int]) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        # signal 0: existence check on POSIX; on Windows this can raise OSError.
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def port_bindable(host: str, port: int) -> bool:
    """True if this process can bind the port right now.

    This is not a reservation; it is an availability check to avoid ports used by
    non-cooperating processes.
    """
    families = [socket.AF_INET6] if ":" in host else [socket.AF_INET]
    for family in families:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            # Do not set SO_REUSEADDR here; we want a conservative answer.
            sock.bind((host, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()
    return False


def connectable(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --- safe stop support (Linux, /proc based) --------------------------------
#
# Why this exists: agents used to "free a port" with `lsof -ti:PORT | xargs kill -9`
# or `ps | awk | kill -9`. Those match connection peers, FD-inheriting ancestors,
# or the wrong PID, and -9 on the user's `systemd --user` manager tears the whole
# desktop session down. `stop` instead resolves ONLY the real LISTEN-socket owner
# via /proc and refuses to signal session-critical or non-owned processes.

# /proc/<pid>/comm is capped at 15 chars; entries below are already truncated.
CRITICAL_COMMS = frozenset(
    {
        "init",
        "dbus-daemon",
        "dbus-broker",
        "gnome-shell",
        "gnome-session",
        "gnome-session-b",  # gnome-session-binary
        "Xorg",
        "X",
        "Xwayland",
        "gdm",
        "gdm3",
        "gdm-session-wor",  # gdm-session-worker
        "gdm-x-session",
        "gdm-wayland-ses",  # gdm-wayland-session
        "sddm",
        "sddm-helper",
        "lightdm",
        "mutter",
        "mutter-x11-fram",  # mutter-x11-frames
        "kwin_wayland",
        "kwin_x11",
        "plasmashell",
        "sway",
        "Hyprland",
        "weston",
        "pipewire",
        "pipewire-pulse",
        "wireplumber",
        "pulseaudio",
        "login",
        "agetty",
        "sshd",
    }
)


def is_critical_comm(comm: Optional[str]) -> bool:
    """True for session-critical process names that must never be signalled."""
    if not comm:
        return False
    if comm == "systemd" or comm.startswith("systemd-"):
        return True
    return comm in CRITICAL_COMMS


def read_comm(pid: int) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_uid(pid: int) -> Optional[int]:
    """Real UID of a process from /proc/<pid>/status, or None if unavailable."""
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return int(line.split()[1])  # real uid
    except (OSError, ValueError, IndexError):
        return None
    return None


def _listen_inodes(port: int) -> set[str]:
    """Socket inodes of IPv4+IPv6 TCP listeners bound to the given local port."""
    inodes: set[str] = set()
    for proc in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc, "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)  # skip header
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, state, inode = parts[1], parts[3], parts[9]
                    if state != "0A":  # 0A == TCP_LISTEN
                        continue
                    try:
                        local_port = int(local.rsplit(":", 1)[1], 16)
                    except (ValueError, IndexError):
                        continue
                    if local_port == port:
                        inodes.add(inode)
        except OSError:
            continue
    return inodes


def listener_pids(port: int) -> set[int]:
    """PIDs holding a TCP LISTEN socket on the given local port (Linux /proc).

    Resolves the real socket owner via socket inode, avoiding the false matches
    that `lsof -ti:PORT` (connection peers, inherited FDs) or name-based `ps`
    filtering can produce.
    """
    inodes = _listen_inodes(port)
    if not inodes:
        return set()
    wanted = {f"socket:[{i}]" for i in inodes}
    pids: set[int] = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # process gone, or not ours to inspect
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") in wanted:
                    pids.add(pid)
                    break
            except OSError:
                continue
    return pids


def stop_blockers(pid: int, *, caller_uid: int) -> Optional[str]:
    """Return a human reason why `pid` must NOT be signalled, or None if safe."""
    if pid <= 1:
        return "refusing to signal pid <= 1"
    if pid == os.getpid():
        return "refusing to signal portctl itself"
    comm = read_comm(pid)
    if comm is None:
        return "process is gone"
    if is_critical_comm(comm):
        return f"refusing to kill session-critical process {comm!r}"
    uid = read_uid(pid)
    if uid is not None and uid != caller_uid:
        return f"refusing to kill another user's process (uid={uid}, comm={comm!r})"
    return None


def stop_port(
    db_path: Path,
    *,
    port: int,
    host: str = "127.0.0.1",
    force: bool = False,
    grace: float = 5.0,
    dry_run: bool = False,
) -> dict:
    """Safely stop the process(es) holding a TCP LISTEN socket on `port`.

    Only real listeners (resolved via /proc) are considered; session-critical and
    non-owned processes are never signalled. Sends SIGTERM, then escalates to
    SIGKILL after `grace` seconds when `force` is set. `host` is accepted for API
    symmetry; matching is by local port across all bind addresses.
    """
    del host  # matching is by port; bind address is intentionally ignored
    caller_uid = os.getuid()
    resolved = sorted(listener_pids(port))
    targets: List[int] = []
    skipped: List[dict] = []
    for pid in resolved:
        reason = stop_blockers(pid, caller_uid=caller_uid)
        if reason:
            skipped.append({"pid": pid, "comm": read_comm(pid), "reason": reason})
        else:
            targets.append(pid)

    result: dict = {
        "port": port,
        "resolved": resolved,
        "targets": list(targets),
        "skipped": skipped,
        "signaled": [],
        "killed": [],
        "still_alive": [],
        "dry_run": dry_run,
    }

    if dry_run or not targets:
        return result

    def _send(pid: int, sig: int) -> bool:
        # Re-verify immediately before signalling to limit PID-reuse races.
        reason = stop_blockers(pid, caller_uid=caller_uid)
        if reason:
            skipped.append({"pid": pid, "comm": read_comm(pid), "reason": reason})
            return False
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            skipped.append(
                {"pid": pid, "comm": read_comm(pid), "reason": "permission denied"}
            )
            return False

    for pid in targets:
        if _send(pid, signal.SIGTERM):
            result["signaled"].append(pid)

    deadline = time.monotonic() + max(grace, 0.0)
    alive = list(result["signaled"])
    while alive and time.monotonic() < deadline:
        time.sleep(0.1)
        alive = [p for p in alive if pid_exists(p)]

    if force:
        for pid in alive:
            if _send(pid, signal.SIGKILL):
                result["killed"].append(pid)
        kdeadline = time.monotonic() + 2.0
        while time.monotonic() < kdeadline and any(
            pid_exists(p) for p in result["killed"]
        ):
            time.sleep(0.05)

    result["still_alive"] = sorted(p for p in result["signaled"] if pid_exists(p))

    # Best-effort: drop a matching reservation so the ledger stays consistent.
    try:
        release(db_path, token=None, port=port)
    except PortCtlError:
        pass
    except sqlite3.Error:
        pass

    return result


def execute_with_retry(
    conn: sqlite3.Connection, sql: str, params: tuple = ()
) -> sqlite3.Cursor:
    last_exc: Optional[sqlite3.OperationalError] = None
    for attempt in range(80):
        try:
            return conn.execute(sql, params)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            last_exc = exc
            time.sleep(min(0.05 * (attempt + 1), 0.5))
    assert last_exc is not None
    raise last_exc


def executescript_with_retry(conn: sqlite3.Connection, sql: str) -> None:
    last_exc: Optional[sqlite3.OperationalError] = None
    for attempt in range(80):
        try:
            conn.executescript(sql)
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            last_exc = exc
            time.sleep(min(0.05 * (attempt + 1), 0.5))
    assert last_exc is not None
    raise last_exc


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    execute_with_retry(conn, "PRAGMA busy_timeout=30000")
    # WAL improves concurrent readers, but changing journal mode needs an exclusive
    # moment during first initialization. Retry and fall back silently if another
    # process is initializing the DB at the exact same time.
    try:
        execute_with_retry(conn, "PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    execute_with_retry(conn, "PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    executescript_with_retry(
        conn,
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reservations (
          port INTEGER PRIMARY KEY,
          host TEXT NOT NULL DEFAULT '127.0.0.1',
          project TEXT NOT NULL,
          service TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          token TEXT NOT NULL UNIQUE,
          pid INTEGER,
          command TEXT,
          cwd TEXT,
          note TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          expires_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_reservations_project_service
          ON reservations(project, service);
        CREATE INDEX IF NOT EXISTS idx_reservations_expires_at
          ON reservations(expires_at);
        """,
    )
    execute_with_retry(
        conn,
        "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()


def cleanup_locked(conn: sqlite3.Connection, *, remove_dead_pids: bool = True) -> int:
    t = now()
    cur = conn.execute(
        "DELETE FROM reservations WHERE expires_at IS NOT NULL AND expires_at < ?",
        (t,),
    )
    removed = cur.rowcount if cur.rowcount is not None else 0

    if remove_dead_pids:
        rows = conn.execute(
            "SELECT port, pid FROM reservations WHERE pid IS NOT NULL"
        ).fetchall()
        dead_ports = [int(row["port"]) for row in rows if not pid_exists(row["pid"])]
        if dead_ports:
            conn.executemany(
                "DELETE FROM reservations WHERE port = ?",
                [(p,) for p in dead_ports],
            )
            removed += len(dead_ports)
    return removed


def claimed_ports_locked(conn: sqlite3.Connection) -> set[int]:
    return {int(row["port"]) for row in conn.execute("SELECT port FROM reservations")}


def claim_port(
    db_path: Path,
    *,
    service: str,
    project: str,
    agent_id: str,
    host: str,
    ranges: Sequence[str],
    preferred: Sequence[int],
    ttl: Optional[int],
    command: Optional[str],
    note: Optional[str],
    randomize: bool,
    cwd: Path,
) -> Claim:
    conn = connect(db_path)
    init_db(conn)
    t = now()
    expires_at = None if ttl is None else t + ttl
    token = uuid.uuid4().hex
    all_ports = parse_ranges(ranges)

    ordered: List[int] = []
    seen = set()
    for p in preferred:
        if p not in seen:
            if not (1 <= p <= 65535):
                raise PortCtlError(f"Port out of range: {p}")
            ordered.append(p)
            seen.add(p)
    rest = [p for p in all_ports if p not in seen]
    if randomize:
        random.shuffle(rest)
    ordered.extend(rest)

    try:
        conn.execute("BEGIN IMMEDIATE")
        cleanup_locked(conn)
        reserved = claimed_ports_locked(conn)
        for port in ordered:
            if port in reserved:
                continue
            if not port_bindable(host, port):
                continue
            try:
                conn.execute(
                    """
                    INSERT INTO reservations(
                      port, host, project, service, agent_id, token,
                      pid, command, cwd, note, created_at, updated_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        port,
                        host,
                        project,
                        service,
                        agent_id,
                        token,
                        command,
                        str(cwd),
                        note,
                        t,
                        t,
                        expires_at,
                    ),
                )
                conn.commit()
                return Claim(
                    port=port,
                    host=host,
                    project=project,
                    service=service,
                    agent_id=agent_id,
                    token=token,
                    created_at=t,
                    expires_at=expires_at,
                    db=str(db_path),
                )
            except sqlite3.IntegrityError:
                # A defensive guard; BEGIN IMMEDIATE should prevent this for cooperative users.
                continue
        conn.rollback()
        raise PortCtlError(
            f"No available port for service={service!r} in range(s): {', '.join(ranges)}"
        )
    finally:
        conn.close()


def update_pid(db_path: Path, token: str, pid: int) -> None:
    conn = connect(db_path)
    init_db(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE reservations SET pid = ?, updated_at = ? WHERE token = ?",
            (pid, now(), token),
        )
        conn.commit()
        if cur.rowcount != 1:
            raise PortCtlError("Reservation token not found")
    finally:
        conn.close()


def release(db_path: Path, *, token: Optional[str], port: Optional[int]) -> int:
    if token is None and port is None:
        raise PortCtlError("release requires --token or --port")
    conn = connect(db_path)
    init_db(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if token is not None:
            cur = conn.execute("DELETE FROM reservations WHERE token = ?", (token,))
        else:
            cur = conn.execute("DELETE FROM reservations WHERE port = ?", (port,))
        conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0
    finally:
        conn.close()


def heartbeat(db_path: Path, *, token: str, ttl: Optional[int]) -> Claim:
    conn = connect(db_path)
    init_db(conn)
    t = now()
    expires_at = None if ttl is None else t + ttl
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE reservations SET updated_at = ?, expires_at = ? WHERE token = ?",
            (t, expires_at, token),
        )
        row = conn.execute(
            "SELECT * FROM reservations WHERE token = ?",
            (token,),
        ).fetchone()
        conn.commit()
        if cur.rowcount != 1 or row is None:
            raise PortCtlError("Reservation token not found")
        return Claim(
            port=int(row["port"]),
            host=row["host"],
            project=row["project"],
            service=row["service"],
            agent_id=row["agent_id"],
            token=row["token"],
            created_at=int(row["created_at"]),
            expires_at=row["expires_at"],
            db=str(db_path),
        )
    finally:
        conn.close()


def list_rows(db_path: Path, *, do_cleanup: bool = True) -> List[dict]:
    conn = connect(db_path)
    init_db(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if do_cleanup:
            cleanup_locked(conn)
        rows = [
            dict(r) for r in conn.execute("SELECT * FROM reservations ORDER BY port")
        ]
        conn.commit()
        for row in rows:
            row["connectable"] = connectable(row["host"], int(row["port"]))
            row["pid_alive"] = pid_exists(row.get("pid")) if row.get("pid") else None
        return rows
    finally:
        conn.close()


def cleanup(db_path: Path, *, dead: bool) -> int:
    conn = connect(db_path)
    init_db(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        removed = cleanup_locked(conn, remove_dead_pids=dead)
        conn.commit()
        return removed
    finally:
        conn.close()


def print_claim(claim: Claim, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(claim.as_dict(), ensure_ascii=False, indent=2))
    elif fmt == "env":
        print(f"PORT={claim.port}")
        print(f"PORT_REGISTRY_TOKEN={claim.token}")
        print(f"PORT_REGISTRY_DB={claim.db}")
    elif fmt == "plain":
        print(claim.port)
    else:
        raise PortCtlError(f"Unknown format: {fmt}")


def print_info(info: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    for key in [
        "db",
        "scope",
        "namespace",
        "project",
        "cwd",
        "workspace_root",
        "git_common_dir",
    ]:
        print(f"{key}: {info.get(key) or ''}")


def build_info(db_path: Path, scope: str, project: str, workdir: Path) -> dict:
    common = git_common_dir(workdir)
    return {
        "db": str(db_path),
        "scope": scope,
        "namespace": default_registry_namespace(),
        "project": project,
        "cwd": str(workdir),
        "workspace_root": str(find_workspace_root(workdir)),
        "git_common_dir": str(common) if common else None,
        "port_registry_db_env": os.environ.get("PORT_REGISTRY_DB"),
        "port_registry_home_env": os.environ.get("PORT_REGISTRY_HOME"),
        "port_registry_scope_env": os.environ.get("PORT_REGISTRY_SCOPE"),
        "port_registry_namespace_env": os.environ.get("PORT_REGISTRY_NAMESPACE"),
        "port_registry_cwd_env": os.environ.get("PORT_REGISTRY_CWD"),
    }


def print_rows(rows: List[dict], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        print("No active reservations")
        return
    headers = [
        "PORT",
        "HOST",
        "PROJECT",
        "SERVICE",
        "AGENT",
        "PID",
        "EXPIRES",
        "LIVE",
        "NOTE",
    ]
    widths = [6, 15, 18, 18, 24, 8, 20, 6, 24]
    print(" ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print(" ".join("-" * w for w in widths))
    for r in rows:
        expires = (
            "never"
            if r.get("expires_at") is None
            else time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(int(r["expires_at"]))
            )
        )
        live = "yes" if r.get("connectable") else "no"
        values = [
            str(r.get("port", "")),
            str(r.get("host", "")),
            str(r.get("project", ""))[:18],
            str(r.get("service", ""))[:18],
            str(r.get("agent_id", ""))[:24],
            str(r.get("pid") or ""),
            expires,
            live,
            str(r.get("note") or "")[:24],
        ]
        print(" ".join(v.ljust(w) for v, w in zip(values, widths)))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Atomic local port registry for dev agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/portctl.py run --service web --preferred 3000 --range 3000-3999 -- npm run dev\n"
            "  python scripts/portctl.py --cwd /path/to/project run --service api --preferred 4000 --range 4000-4999 -- npm run dev\n"
            "  python scripts/portctl.py claim --service storybook --preferred 6006 --range 6000-6999 --format env\n\n"
            "Exit codes: 0 for success, 2 for portctl usage/registry errors. The run command returns the wrapped process exit code."
        ),
    )
    p.add_argument(
        "--db",
        default=None,
        help="SQLite registry path. Overrides --scope and PORT_REGISTRY_DB",
    )
    p.add_argument(
        "--cwd",
        default=None,
        help="Project working directory for git detection and for the run subcommand. Defaults to PORT_REGISTRY_CWD or the current directory",
    )
    p.add_argument(
        "--scope",
        choices=["global", "git-common", "workspace"],
        default=os.environ.get("PORT_REGISTRY_SCOPE", "global"),
        help=(
            "Registry location when --db/PORT_REGISTRY_DB is not set: "
            "global stores it under ~/.agent/port-registry and coordinates all repos for this user; "
            "git-common shares one registry across linked git worktrees; "
            "workspace stores it in the current worktree"
        ),
    )
    p.add_argument(
        "--project",
        default=None,
        help="Project name. Defaults to PORT_REGISTRY_PROJECT, git repository name, or workspace directory name",
    )
    p.add_argument("--agent-id", default=default_agent_id(), help="Agent identifier")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_claim_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--service", required=True, help="Service name, e.g. web/api/storybook"
        )
        sp.add_argument("--host", default="127.0.0.1", help="Bind host to check")
        sp.add_argument(
            "--range",
            action="append",
            default=[],
            help=f"Allowed port range, e.g. 3000-3999. May repeat. Default: {DEFAULT_RANGE}",
        )
        sp.add_argument(
            "--preferred",
            action="append",
            type=int,
            default=[],
            help="Preferred port; may repeat",
        )
        sp.add_argument("--ttl", default=DEFAULT_TTL, help="TTL, e.g. 30m, 4h, never")
        sp.add_argument("--note", default=None)
        sp.add_argument("--command", default=None)
        sp.add_argument(
            "--random", action="store_true", help="Randomize non-preferred candidates"
        )

    sp = sub.add_parser("claim", help="Claim an available port")
    add_claim_args(sp)
    sp.add_argument("--format", choices=["json", "env", "plain"], default="json")

    sp = sub.add_parser(
        "run", help="Claim a port, run a command with PORT set, release on exit"
    )
    add_claim_args(sp)
    sp.add_argument("command_argv", nargs=argparse.REMAINDER, help="Command after --")

    sp = sub.add_parser("release", help="Release a claim")
    sp.add_argument("--token")
    sp.add_argument("--port", type=int)
    sp.add_argument(
        "--force",
        action="store_true",
        help="Required when releasing by --port without a token",
    )

    sp = sub.add_parser(
        "stop",
        help="Safely stop the process holding a port (LISTEN owner only; never lsof|kill -9)",
    )
    sp.add_argument("--port", type=int, required=True, help="Local TCP port to free")
    sp.add_argument(
        "--host", default="127.0.0.1", help="Accepted for symmetry; matching is by port"
    )
    sp.add_argument(
        "--force", action="store_true", help="Escalate to SIGKILL after --grace seconds"
    )
    sp.add_argument(
        "--grace",
        type=float,
        default=5.0,
        help="Seconds to wait after SIGTERM before SIGKILL",
    )
    sp.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be stopped without signalling",
    )
    sp.add_argument("--format", choices=["json", "plain"], default="json")

    sp = sub.add_parser("heartbeat", help="Extend a claim TTL")
    sp.add_argument("--token", required=True)
    sp.add_argument("--ttl", default=DEFAULT_TTL)
    sp.add_argument("--format", choices=["json", "env", "plain"], default="json")

    sp = sub.add_parser("list", help="List active reservations")
    sp.add_argument("--format", choices=["table", "json"], default="table")
    sp.add_argument("--no-cleanup", action="store_true")

    sp = sub.add_parser(
        "cleanup", help="Remove expired and optionally dead-PID reservations"
    )
    sp.add_argument(
        "--dead", action="store_true", help="Also remove reservations with dead PIDs"
    )

    sp = sub.add_parser(
        "info", help="Show resolved registry path and git/worktree context"
    )
    sp.add_argument("--format", choices=["table", "json"], default="table")

    return p


def normalize_command_argv(argv: Sequence[str]) -> List[str]:
    args = list(argv)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise PortCtlError("run requires a command after --")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    workdir = (
        Path(args.cwd or os.environ.get("PORT_REGISTRY_CWD") or Path.cwd())
        .expanduser()
        .resolve()
    )
    project = args.project or default_project(workdir)
    db_path = (
        Path(args.db).expanduser().resolve()
        if args.db
        else default_db_path(args.scope, workdir)
    )

    try:
        if args.cmd == "info":
            print_info(build_info(db_path, args.scope, project, workdir), args.format)
            return 0

        if args.cmd == "claim":
            ranges = args.range or [DEFAULT_RANGE]
            ttl = parse_duration(args.ttl)
            claim = claim_port(
                db_path,
                service=args.service,
                project=project,
                agent_id=args.agent_id,
                host=args.host,
                ranges=ranges,
                preferred=args.preferred,
                ttl=ttl,
                command=args.command,
                note=args.note,
                randomize=args.random,
                cwd=workdir,
            )
            print_claim(claim, args.format)
            return 0

        if args.cmd == "run":
            command_argv = normalize_command_argv(args.command_argv)
            ranges = args.range or [DEFAULT_RANGE]
            ttl = parse_duration(args.ttl)
            claim = claim_port(
                db_path,
                service=args.service,
                project=project,
                agent_id=args.agent_id,
                host=args.host,
                ranges=ranges,
                preferred=args.preferred,
                ttl=ttl,
                command=" ".join(command_argv),
                note=args.note,
                randomize=args.random,
                cwd=workdir,
            )
            env = os.environ.copy()
            env["PORT"] = str(claim.port)
            env["PORT_REGISTRY_TOKEN"] = claim.token
            env["PORT_REGISTRY_DB"] = str(db_path)
            print(
                f"portctl: reserved PORT={claim.port} service={claim.service} db={db_path}",
                file=sys.stderr,
            )
            proc = subprocess.Popen(command_argv, env=env, cwd=str(workdir))
            update_pid(db_path, claim.token, proc.pid)
            try:
                return proc.wait()
            finally:
                release(db_path, token=claim.token, port=None)

        if args.cmd == "release":
            if args.port is not None and args.token is None and not args.force:
                raise PortCtlError(
                    "release by --port can remove another agent's reservation; use --token or add --force after checking list"
                )
            count = release(db_path, token=args.token, port=args.port)
            print(json.dumps({"released": count}, ensure_ascii=False))
            return 0

        if args.cmd == "stop":
            res = stop_port(
                db_path,
                port=args.port,
                host=args.host,
                force=args.force,
                grace=args.grace,
                dry_run=args.dry_run,
            )
            if args.format == "json":
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                for pid in res["resolved"]:
                    print(pid)
            return 0

        if args.cmd == "heartbeat":
            claim = heartbeat(db_path, token=args.token, ttl=parse_duration(args.ttl))
            print_claim(claim, args.format)
            return 0

        if args.cmd == "list":
            rows = list_rows(db_path, do_cleanup=not args.no_cleanup)
            print_rows(rows, args.format)
            return 0

        if args.cmd == "cleanup":
            removed = cleanup(db_path, dead=args.dead)
            print(json.dumps({"removed": removed}, ensure_ascii=False))
            return 0

        raise PortCtlError(f"Unknown command: {args.cmd}")
    except PortCtlError as exc:
        print(f"portctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
