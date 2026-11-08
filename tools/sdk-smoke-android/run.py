#!/usr/bin/env python3
"""Run the real Android client on one disposable emulator against a local backend."""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import shlex
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

TOOL = Path(__file__).resolve().parent

REQUIRED_CASES = {
    "firestore.write-read", "firestore.transforms", "firestore.query", "firestore.listener",
    "firestore.transaction", "firestore.offline-resume", "firestore.batch-delete",
    "firestore.rules-anonymous-denied", "firestore.rules-owner", "firestore.rules-signout",
    "auth.signup", "auth.signin", "auth.refresh", "storage.upload-download", "storage.metadata",
    "storage.resumable", "storage.download-url", "storage.list-delete", "storage.rules-denied",
    "database.set-read", "database.listener", "database.transaction", "database.on-disconnect",
}


def checked(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=60, **kwargs).stdout


def process_start(pid):
    """Return the start time that, with the pid, identifies a live process (None if gone or a zombie)."""
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat=,lstart="], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError("ps failed")
    stat, _, started = result.stdout.strip().partition(" ")
    if not stat or stat.startswith("Z"):
        return None
    return started.strip() or None


def stop(pid, started):
    """Stop the process identified by (pid, start time). A different start time means the pid was reused: not ours."""
    if pid == os.getpid():
        return
    if process_start(pid) != started:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(30):
        if process_start(pid) != started:
            return
        time.sleep(0.1)
    if process_start(pid) != started:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    for _ in range(30):
        if process_start(pid) != started:
            return
        time.sleep(0.1)
    raise RuntimeError("process survived cleanup")


def descendants(pid, groups=None):
    """Return {pid: start time} for every live descendant of pid; record each one's current pgid in groups."""
    result = {}
    todo = [pid]
    while todo:
        if len(result) >= 100:
            raise RuntimeError("descendant scan truncated")
        parent = todo.pop()
        listing = subprocess.run(["pgrep", "-P", str(parent)], capture_output=True, text=True)
        if listing.returncode not in (0, 1):
            raise RuntimeError("pgrep failed")
        for child in map(int, listing.stdout.split()):
            if child in result:
                continue
            started = process_start(child)
            if started is None:
                continue
            try:
                group = os.getpgid(child)
            except ProcessLookupError:
                continue
            if groups is not None:
                groups.setdefault(group, {})[child] = started
            result[child] = started
            todo.append(child)
    return result


def observe_owned(children, owned, groups):
    """Scan every live identity-validated owned process, not only the launch roots.

    Identity of an owned process is (pid, start time); the command is never used.
    Each scan refreshes the current pgid of every validated seed, because a
    process may setsid() and exec() after it was first seen. A pid whose start
    time changed was reused: it is dropped from `owned` and never traversed.
    """
    seeds = []
    for process, _ in children:
        if process.poll() is None:
            started = process_start(process.pid)
            if started:
                owned[process.pid] = started  # an unreaped child's pid cannot be reused
                seeds.append(process.pid)
    seeds += [pid for pid in list(owned) if pid not in seeds]
    covered = set()
    for pid in seeds:
        if pid in covered:
            continue
        started = process_start(pid)
        if started is None:
            continue
        if owned.get(pid) != started:
            owned.pop(pid, None)
            continue
        try:
            group = os.getpgid(pid)
        except ProcessLookupError:
            continue
        groups.setdefault(group, {})[pid] = started
        found = descendants(pid, groups)
        owned.update(found)
        covered.add(pid)
        covered.update(found)


def member_of(group, pid, started):
    try:
        return process_start(pid) == started and os.getpgid(pid) == group
    except ProcessLookupError:
        return False


def group_alive(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # macOS answers EPERM for a group that holds only unreaped zombies
        # (and for a group we do not own); treat it as alive and keep polling.
        return True
    return True


def client(args):
    adb = [args.adb, "-P", str(args.adb_port), "-s", args.serial]
    command = adb + ["shell", "am", "instrument", "-w", "-r"]
    for key in ["FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST"]:
        value = os.environ.get(key, "")
        match = re.fullmatch(r"(?:127\.0\.0\.1|\[::1\]):([0-9]{1,5})", value)
        if not match or not 1 <= int(match[1]) <= 65535:
            raise ValueError("missing or unsafe host endpoint")
        command += ["-e", key, "10.0.2.2:" + match[1]]
    if os.environ.get("ANDROID_SMOKE_CASE"):
        command += ["-e", "caseFilter", os.environ["ANDROID_SMOKE_CASE"]]
    command += ["-e", "class", "dev.fireemu.smoke.SmokeInstrumentedTest", "dev.fireemu.smoke.test/androidx.test.runner.AndroidJUnitRunner"]
    adb_env = os.environ.copy()
    adb_env.pop("ADB_VENDOR_KEYS", None)
    adb_env["HOME"] = os.environ["ANDROID_SMOKE_ADB_HOME"]
    result = subprocess.run(command, env=adb_env, text=True, capture_output=True, timeout=660)
    raw = TOOL / "build/diagnostics" / ("instrumentation-" + str(time.time_ns()) + ".log")
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(result.stdout + "\n" + result.stderr)
    cases = []
    for match in re.finditer(r"CASE ([a-z.-]+) (passed|failed|blocked) ([A-Za-z_0-9-]+) ([0-9]+)", result.stdout):
        case = dict(id=match[1], status=match[2], classification=match[3], milliseconds=int(match[4]))
        cases.append(case)
        print(json.dumps(case), flush=True)
    summary = {"backend": args.backend, "cases": cases, "instrumentation_ok": "OK (1 test)" in result.stdout}
    Path(args.report).write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if result.returncode == 0 and summary["instrumentation_ok"] and len(cases) == 23 and len({x['id'] for x in cases}) == 23 and all(x["status"] == "passed" for x in cases) else 1


def cleanup(owned, children, leases, registry, work, temporary, observe, primary=None, groups=None):
    failures = []

    def attempt(stage, action):
        try:
            return action()
        except BaseException as error:
            failures.append((stage, type(error).__name__))
            return None

    observe_failures = len(failures)
    attempt("observe", observe)
    # An unobserved descendant tree cannot be proven stopped.
    owned_stopped = len(failures) == observe_failures
    groups = groups if groups is not None else {}
    # A launched root's group is ours by construction; any other group is ours
    # only while a recorded (pid, start time) member is still in it.
    proven = {process.pid for process, _ in children}
    unproven = set()

    def eligible(group):
        return group > 1 and group != os.getpgrp()

    def targets():
        return [group for group in sorted(proven) if eligible(group)]

    def refresh():
        unproven.clear()
        for group, members in list(groups.items()):
            if group in proven or not eligible(group):
                continue
            if any(member_of(group, pid, started) for pid, started in list(members.items())):
                proven.add(group)
            elif all(process_start(pid) is None for pid in members) and group_alive(group):
                # Every recorded member is gone but the group lives: it may hold
                # stragglers of ours, yet the id may also have been reused.
                unproven.add(group)

    def settle(pending, deadline_ticks):
        for _ in range(deadline_ticks):
            for process, _ in children:
                process.poll()
            pending = [group for group in pending if group_alive(group)]
            if not pending:
                break
            time.sleep(0.1)
        return pending

    def signal_groups(pending, number):
        for group in pending:
            if not eligible(group):
                continue
            try:
                os.killpg(group, number)
            except ProcessLookupError:
                pass

    def safe_refresh():
        # A failed ownership check must not stop us from signalling the launched groups.
        nonlocal owned_stopped
        try:
            refresh()
        except BaseException as error:
            owned_stopped = False
            failures.append(("refresh", type(error).__name__))

    try:
        safe_refresh()
        signal_groups(targets(), signal.SIGTERM)
        settle(targets(), 30)
        # A dying process may have forked a daemon during the grace period.
        rescan = len(failures)
        attempt("observe", observe)
        if len(failures) != rescan:
            owned_stopped = False
        safe_refresh()
        remaining = [group for group in targets() if group_alive(group)]
        if remaining:
            signal_groups(remaining, signal.SIGKILL)
            remaining = settle(remaining, 30)
        if remaining:
            raise RuntimeError("process group survived cleanup")
        if unproven:
            raise RuntimeError("process group ownership unproven")
    except BaseException as error:
        owned_stopped = False
        failures.append(("stop-group", type(error).__name__))
    for pid, started in reversed(list(owned.items())):
        before = len(failures)
        attempt("stop", lambda: stop(pid, started))
        if len(failures) != before:
            owned_stopped = False
    for process, stream in children:
        before = len(failures)
        attempt("wait", lambda: process.wait(timeout=5))
        if len(failures) != before and failures[-1][1] == "TimeoutExpired":
            owned_stopped = False
        attempt("stream-close", stream.close)
    diagnostics = TOOL / "build/diagnostics" / str(time.time_ns())
    attempt("diagnostics-directory", lambda: diagnostics.mkdir(parents=True))
    files = attempt("diagnostics-list", lambda: list(work.glob("*.log"))) or []
    for file in files:
        attempt("diagnostics-copy", lambda: shutil.copy2(file, diagnostics / file.name))
    attempt("temporary-cleanup", temporary.cleanup)
    for lease in reversed(leases) if owned_stopped else []:
        attempt("lease-release", lambda: checked(registry + ["release", "--token", lease["token"]]))
    attempt("diagnostics-report", lambda: print("Private diagnostics:", diagnostics))
    if failures:
        if primary is not None:
            attempt("cleanup-report", lambda: print("Cleanup failures: " + json.dumps(failures), file=sys.stderr))
            primary.cleanup_failures = tuple(failures)
        else:
            raise RuntimeError("Cleanup failures: " + json.dumps(failures))


class PortUnavailable(RuntimeError):
    pass


def claim_emulator_pair(claim, release):
    candidates = [5556] + [port for port in range(5554, 5585, 2) if port != 5556]
    for console in candidates:
        try:
            claimed = claim("console", console)
        except PortUnavailable:
            continue
        if claimed != console:
            raise RuntimeError("registry returned a different console port")
        try:
            device_adb = claim("device-adb", console + 1)
        except PortUnavailable:
            release(console)
            continue
        if device_adb != console + 1:
            raise RuntimeError("registry returned a different device ADB port")
        return console
    raise RuntimeError("no available emulator port pair")


def run(args):
    sdk = Path(args.sdk).resolve()
    adb = str(sdk / "platform-tools/adb")
    apk = TOOL / "build/outputs/apk/androidTest/debug/sdk-smoke-android-debug-androidTest.apk"
    if not apk.is_file():
        raise ValueError("build assembleDebugAndroidTest first")
    registry = [sys.executable, str(Path(args.portctl).resolve()), "--cwd", str(TOOL)] if args.portctl else None
    leases = []
    allocated = set()
    owned = {}
    groups = {}
    children = []
    temporary = tempfile.TemporaryDirectory(prefix="android-run-", dir=TOOL / "build")
    work = Path(temporary.name)
    env = os.environ.copy()
    env.pop("ADB_VENDOR_KEYS", None)
    env.update(ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk), ANDROID_USER_HOME=str(work / "android"), ANDROID_EMULATOR_HOME=str(work / "android"), ANDROID_AVD_HOME=str(work / "avd"), XDG_CONFIG_HOME=str(work / "config"), FIREBASE_EMULATORS_PATH=str(TOOL / ".emulators"), FIREBASE_CLI_DISABLE_UPDATE_CHECK="true", CI="true", GCLOUD_PROJECT="demo-app")
    for name in ["android", "avd", "config", "adb-home", "home"]:
        (work / name).mkdir()
    node = checked(["node", "-p", "process.execPath"]).strip()
    if args.case:
        env["ANDROID_SMOKE_CASE"] = args.case
    env["HOME"] = str(work / "home")
    env["JAVA_TOOL_OPTIONS"] = "-Xmx2g -Duser.home=" + str(work / "home")
    env["ANDROID_SMOKE_ADB_HOME"] = str(work / "adb-home")
    adb_env = env.copy()
    adb_env["HOME"] = str(work / "adb-home")
    report = TOOL / "reports" / (args.backend + "-" + str(time.time_ns()) + ".json")
    report.parent.mkdir(exist_ok=True)

    def claim(service, preferred=None):
        if registry is None:
            if os.environ.get("CI") != "true":
                raise ValueError("local runs require --portctl; OS allocation is only for an isolated CI job")
            with socket.socket() as handle:
                try:
                    handle.bind(("127.0.0.1", preferred or 0))
                except OSError as error:
                    if preferred is not None and error.errno == errno.EADDRINUSE:
                        raise PortUnavailable("exact port unavailable") from None
                    raise
                port = handle.getsockname()[1]
            if port in allocated:
                raise RuntimeError("duplicate port allocation")
            allocated.add(port)
            return port
        command = registry + ["claim", "--service", "android-" + service, "--range", "10000-19999", "--ttl", "30m", "--format", "json"]
        if preferred is not None:
            command = registry + ["claim", "--service", "android-" + service, "--range", str(preferred) + "-" + str(preferred), "--ttl", "30m", "--format", "json"]
        try:
            value = json.loads(checked(command))
        except subprocess.CalledProcessError as error:
            if preferred is not None and error.returncode == 2 and (error.stderr or "").startswith("portctl: No available port for service="):
                print("Port unavailable:", service, preferred)
                raise PortUnavailable("exact port unavailable") from None
            raise
        leases.append(value)
        print("Port claimed:", service, "requested", preferred, "returned", value["port"])
        return value["port"]

    def release(port):
        if registry is None:
            allocated.remove(port)
            return
        lease = next(value for value in leases if value["port"] == port)
        checked(registry + ["release", "--token", lease["token"]])
        leases.remove(lease)
        print("Port released:", port)

    def launch(command, log, process_env=None):
        stream = (work / log).open("w")
        try:
            process = subprocess.Popen(command, cwd=work, env=process_env or env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        except BaseException:
            stream.close()
            raise
        children.append((process, stream))
        groups.setdefault(process.pid, {})
        return process

    def observe():
        observe_owned(children, owned, groups)
        if owned:
            rss = subprocess.run(["ps", "-p", ",".join(map(str, owned)), "-o", "rss="], capture_output=True, text=True).stdout.split()
            if sum(map(int, rss)) > 8 * 1024 * 1024:
                raise RuntimeError("8 GiB process RSS budget exceeded")

    try:
        console = claim_emulator_pair(claim, release)
        adb_port = claim("adb-server")
        env.update(ANDROID_ADB_SERVER_PORT=str(adb_port), ADB_SERVER_SOCKET="tcp:127.0.0.1:" + str(adb_port))
        adb_env.update(ANDROID_ADB_SERVER_PORT=str(adb_port), ADB_SERVER_SOCKET="tcp:127.0.0.1:" + str(adb_port))
        # Foreground owned server makes lifecycle ownership explicit.
        server = launch([adb, "-L", "tcp:" + str(adb_port), "nodaemon", "server"], "adb.log", adb_env)
        checked([str(sdk / "cmdline-tools/latest/bin/avdmanager"), "create", "avd", "--name", "fireemu-smoke", "--package", "system-images;android-34;default;" + args.arch, "--path", str(work / "device.avd")], input="no\n", env=env)
        emulator = launch([str(sdk / "emulator/emulator"), "-avd", "fireemu-smoke", "-port", str(console), "-no-window", "-no-audio", "-no-snapshot", "-no-boot-anim", "-memory", "2048", "-cores", "2", "-gpu", "swiftshader_indirect"], "emulator.log", adb_env)
        serial = "emulator-" + str(console)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            observe()
            if emulator.poll() is not None or server.poll() is not None:
                raise RuntimeError("owned device process exited during boot")
            boot = subprocess.run([adb, "-P", str(adb_port), "-s", serial, "shell", "getprop", "sys.boot_completed"], env=adb_env, capture_output=True, text=True, timeout=10)
            if boot.returncode == 0 and boot.stdout.strip() == "1":
                break
            time.sleep(1)
        else:
            raise TimeoutError("Android boot deadline")
        checked([adb, "-P", str(adb_port), "-s", serial, "install", "-r", "-t", str(apk)], env=adb_env)
        config = json.loads((TOOL / "firebase.json").read_text())
        for service in ["auth", "firestore", "storage", "database", "hub", "logging"]:
            config["emulators"][service] = {"host": "127.0.0.1", "port": claim(service)}
        config["emulators"]["firestore"]["websocketPort"] = claim("firestore-websocket")
        for service, rules in [("firestore", "firestore.rules"), ("storage", "storage.rules"), ("database", "database.rules.json")]:
            config[service]["rules"] = str(TOOL / rules)
        config_path = work / "firebase.json"
        config_path.write_text(json.dumps(config))
        child = [sys.executable, str(TOOL / "run.py"), "client", "--adb", adb, "--adb-port", str(adb_port), "--serial", serial, "--backend", args.backend, "--report", str(report)]
        if args.backend == "fireemu":
            command = [str(Path(args.fireemu).resolve()), "exec", "--project", "demo-app", "--firebase-json", str(config_path), "--only", "auth,firestore,storage,database", "--hub-port", str(config["emulators"]["hub"]["port"]), "--"] + child
        else:
            command = [node, str(TOOL / "node_modules/firebase-tools/lib/bin/firebase.js"), "emulators:exec", "--project", "demo-app", "--config", str(config_path), "--only", "auth,firestore,storage,database", shlex.join(child)]
        backend = launch(command, "backend.log")
        deadline = time.monotonic() + 720
        while backend.poll() is None and time.monotonic() < deadline:
            observe()
            time.sleep(1)
        if backend.poll() is None:
            raise TimeoutError("backend deadline")
        if backend.returncode != 0:
            return backend.returncode
        try:
            summary = json.loads(report.read_text())
            print(json.dumps(summary))
            cases = summary["cases"]
            if (summary["instrumentation_ok"] is True and isinstance(cases, list)
                    and len(cases) == len(REQUIRED_CASES)
                    and {case["id"] for case in cases} == REQUIRED_CASES
                    and all(case["status"] == "passed" for case in cases)):
                return 0
        except (OSError, ValueError, TypeError, KeyError):
            pass
        return 1
    finally:
        cleanup(owned, children, leases, registry, work, temporary, observe, sys.exc_info()[1], groups=groups)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    outer = sub.add_parser("run")
    outer.add_argument("--sdk", required=True)
    outer.add_argument("--portctl")
    outer.add_argument("--backend", choices=["fireemu", "official"], required=True)
    outer.add_argument("--fireemu", default=str(TOOL.parents[1] / "target/debug/fireemu"))
    outer.add_argument("--case", help="Diagnostic only: other required cases remain blocked")
    outer.add_argument("--arch", choices=["arm64-v8a", "x86_64"], default="arm64-v8a")
    inner = sub.add_parser("client")
    inner.add_argument("--adb", required=True)
    inner.add_argument("--adb-port", type=int, required=True)
    inner.add_argument("--serial", required=True)
    inner.add_argument("--backend", required=True)
    inner.add_argument("--report", required=True)
    args = parser.parse_args()
    return client(args) if args.command == "client" else run(args)


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
