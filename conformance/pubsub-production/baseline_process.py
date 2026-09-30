"""Bounded coordinator child ownership; never signals a process group.

Admission requires reviewed no-spawn commands. A session census detects unexpected children but does not prove containment of arbitrary session-escaping programs.
"""
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


@dataclass(frozen=True)
class Identity:
    pid: int
    ppid: int
    sid: int
    birth: tuple
    comm: str
    args: str


class ProcessGone(ProcessLookupError):
    """Kernel-confirmed process disappearance."""


class InspectionUnavailable(ProcessLookupError):
    """Live process metadata cannot establish ownership or exit."""
    def __init__(self, message, *, members=()):
        super().__init__(message)
        self.members = list(members)


def gone_or_unavailable(pid):
    try:
        os.getsid(pid)
    except ProcessLookupError:
        raise ProcessGone("process disappeared") from None
    except OSError:
        pass
    raise InspectionUnavailable("process ownership unavailable")


class ProcessStopped(RuntimeError):
    def __init__(self, *, quiescent=False, reaped=False, unexpected_descendant=False, reason="failed"):
        super().__init__("owned command did not complete within verified process contract")
        self.quiescent = quiescent
        self.reaped = reaped
        self.unexpected_descendant = unexpected_descendant
        self.reason = reason


def birth_identity(pid):
    if sys.platform == "darwin":
        # Darwin sys/proc_info.h: PROC_PIDTBSDINFO=3 and struct proc_bsdinfo.
        class BsdInfo(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in
                ("flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
                 "ruid", "rgid", "svuid", "svgid", "reserved")] + [
                ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
                (name, ctypes.c_uint32) for name in
                ("nfiles", "pgid", "jobc", "ttydev", "ttypgid")] + [
                ("nice", ctypes.c_int32), ("start_seconds", ctypes.c_uint64),
                ("start_microseconds", ctypes.c_uint64)]
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                        ctypes.c_void_p, ctypes.c_int]
        library.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        size = ctypes.sizeof(info)
        if size != 136 or library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size or info.pid != pid:
            gone_or_unavailable(pid)
        return (info.start_seconds, info.start_microseconds)
    if sys.platform.startswith("linux"):
        # proc_pid_stat(5): starttime is field22; comm may contain spaces or ')'.
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            gone_or_unavailable(pid)
        return (int(fields[19]),)
    raise RuntimeError("verified process birth adapter unavailable")


def inspect(pid, deadline):
    before = birth_identity(pid)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("process metadata deadline")
    row = subprocess.run(["ps", "-p", str(pid), "-o", "ppid=", "-o", "comm=", "-o", "args="],
        capture_output=True, text=True, timeout=remaining, check=False)
    fields = row.stdout.strip().split(None, 2)
    if row.returncode != 0 or len(fields) != 3:
        gone_or_unavailable(pid)
    sid = os.getsid(pid)
    if before != birth_identity(pid):
        raise InspectionUnavailable("process identity changed during inspection")
    return Identity(pid, int(fields[0]), sid, before, fields[1], fields[2])


def signal_verified(identity, number, *, inspect, signal_pid=os.kill):
    try:
        if inspect(identity.pid) != identity:
            return False
        signal_pid(identity.pid, number)
        return True
    except ProcessGone:
        return False


def session_members(sid, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("process census deadline")
    census = subprocess.run(["ps", "-A", "-o", "pid="], capture_output=True,
        text=True, timeout=remaining, check=True)
    members, uncertain = [], False
    for field in census.stdout.split():
        pid = int(field)
        try:
            member_sid = os.getsid(pid)
        except ProcessLookupError:
            continue
        if member_sid != sid:
            continue
        try:
            members.append(inspect(pid, deadline))
        except ProcessGone:
            continue
        except (OSError, RuntimeError):
            uncertain = True
    if uncertain:
        raise InspectionUnavailable("owned session metadata unavailable", members=members)
    return members


def run_owned(argv, *, input=None, timeout, env, cleanup_seconds=5):
    """Main-thread owner; asynchronous operator signals never escape shutdown phases."""
    cancelled, previous = [False], {}
    def defer(*_):
        cancelled[0] = True
    try:
        # Install before creating any owned process. The caller's throwing signal handler
        # cannot abandon a child between cleanup operations or during Popen assignment.
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.getsignal(number)
            signal.signal(number, defer)
        result = _run_owned(argv, input=input, timeout=timeout, env=env,
                            cleanup_seconds=cleanup_seconds, cancelled=lambda: cancelled[0])
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    if cancelled[0]:
        raise ProcessStopped(quiescent=result.processQuiescent is True,
                             reaped=result.directChildReaped is True, reason="cancelled")
    return result


def _run_owned(argv, *, input, timeout, env, cleanup_seconds, cancelled):
    if timeout <= cleanup_seconds or cleanup_seconds <= 0:
        raise ValueError("execution budget must include positive shutdown reserve")
    deadline = time.monotonic() + timeout
    execution_deadline = deadline - cleanup_seconds
    child = subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
    unexpected, completed, quiescent, reaped = False, None, False, False
    failed, cleanup_unverified, reason = False, False, "failed"
    observed = {}
    unavailable = object()

    def observe(members):
        nonlocal unexpected, cleanup_unverified
        for identity in members:
            unexpected = unexpected or identity.pid != child.pid
            previous = observed.get(identity.pid)
            # Reparenting can follow the owned parent's exit. Birth, command and session
            # must remain unchanged before a refreshed identity can authorize a signal.
            if previous is not None and (identity.birth, identity.comm, identity.args, identity.sid) != (
                    previous.birth, previous.comm, previous.args, previous.sid):
                cleanup_unverified = True
                continue
            observed[identity.pid] = identity
        return members

    def cleanup_step(operation):
        nonlocal failed, reason, cleanup_unverified
        while time.monotonic() < deadline:
            try:
                return operation()
            except (KeyboardInterrupt, SystemExit):
                failed, reason = True, "cancelled"
                # Retry this phase within the original reserve; no deadline extension.
            except BaseException:
                failed, cleanup_unverified = True, True
                return unavailable
        cleanup_unverified = True
        return unavailable

    def cleanup_census():
        def census():
            nonlocal cleanup_unverified
            try:
                return observe(session_members(child.pid, deadline))
            except InspectionUnavailable as error:
                cleanup_unverified = True
                return observe(error.members)
        return cleanup_step(census)

    def terminate(number):
        for identity in list(observed.values()):
            def stop():
                nonlocal cleanup_unverified
                sent = signal_verified(identity, number, inspect=lambda pid: inspect(pid, deadline))
                if not sent:
                    try:
                        inspect(identity.pid, deadline)
                    except ProcessGone:
                        pass
                    else:
                        cleanup_unverified = True
            cleanup_step(stop)

    def absence():
        for identity in observed.values():
            try:
                inspect(identity.pid, deadline)
            except ProcessGone:
                continue
            return False
        return True

    try:
        initial = inspect(child.pid, execution_deadline)
        if initial.ppid != os.getpid() or initial.sid != child.pid:
            raise RuntimeError("owned child session unavailable")
        observe([initial])
        pending_input = input
        while time.monotonic() < execution_deadline:
            if cancelled():
                raise KeyboardInterrupt()
            members = observe(session_members(child.pid, execution_deadline))
            if unexpected:
                raise RuntimeError("no-spawn command created an unexpected descendant")
            try:
                stdout, stderr = child.communicate(input=pending_input,
                    timeout=min(0.1, execution_deadline - time.monotonic()))
                completed = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
                reaped = True
                break
            except subprocess.TimeoutExpired:
                pending_input = None
        if completed is None:
            raise TimeoutError("owned command execution deadline")
    except BaseException as error:
        failed = True
        if isinstance(error, InspectionUnavailable):
            cleanup_unverified = True
            observe(error.members)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            reason = "cancelled"
    finally:
        # Every phase tolerates cancellation independently, including after exit0.
        cleanup_census()
        terminate(signal.SIGTERM)
        if observed:
            cleanup_step(lambda: time.sleep(min(0.05, max(0, deadline - time.monotonic()))))
        cleanup_census()
        terminate(signal.SIGKILL)
        cleanup_census()
        waited = cleanup_step(lambda: child.wait(timeout=deadline - time.monotonic()))
        if waited is not unavailable:
            reaped = True
        while time.monotonic() < deadline:
            members = cleanup_census()
            absent = cleanup_step(absence)
            if members is not unavailable and not members and absent is True:
                quiescent = not cleanup_unverified
                break
            terminate(signal.SIGKILL)
            cleanup_step(lambda: time.sleep(min(0.01, max(0, deadline - time.monotonic()))))
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                cleanup_step(stream.close)
    if cancelled():
        failed, reason = True, "cancelled"
    if failed or unexpected or not quiescent or not reaped:
        raise ProcessStopped(quiescent=quiescent, reaped=reaped, unexpected_descendant=unexpected, reason=reason)
    completed.processQuiescent = True
    completed.directChildReaped = True
    return completed
