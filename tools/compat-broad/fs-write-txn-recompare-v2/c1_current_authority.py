"""Offline authority for the saved c1 transaction-stream comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

RUNTIME_COMMIT = "c1d24250a62d23b38bcfed6da51f1ba4ed5798bb"
ARTIFACT_REL = Path("docs.local/runs/fs-write-txn-current-c1-shadow/fireemu")
MANIFEST_REL = Path("docs.local/runs/fs-write-txn-current-c1-build/local.json")
RECEIPT_REL = Path("docs.local/runs/fs-write-txn-current-c1-shadow/receipt.json")
PRODUCTION_REL = Path(
    "docs.local/logs/2026-09-17/stream-production-preflight/"
    "execution-dee737c14/receipt.json"
)
ARTIFACT_SHA = "4f049d0c5bfce865319d8bdbc662c0d0ea3f9568c21497f507b6bcbaed695fa9"
MANIFEST_SHA = "dce277b011ec825bd92515431f07a05cac791dbaebe8896bfef1ee9e9bbd2bea"
RECEIPT_SHA = "6dd039ad0474b37a32629a3ec2d27681b8a4926860a66488d5709c4776fb0bce"
PRODUCTION_SHA = "12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3"
SAVED_RESULT_REL = Path(
    "spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json"
)
SAVED_RESULT_SHA = "22a45a9bf2e441f9ed7c675093f7bc8a130bbf58778c01c146b982ddb1131a3f"
SAVED_PREPARED_REL = Path(
    "docs.local/logs/2026-09-17/stream-production-preflight/"
    "approved-prepared-inputs-dee.json"
)
SAVED_PREPARED_SHA = "b43dbf0bffb4ea575467d12fa49727c78d15a34900401bbb9b3d0ebbc29d65d5"
SAVED_AUTHORITY_PATH = Path(
    "tools/compat-broad/fs-write-txn-recompare-v2/saved_authority.py"
)
BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
RUNTIME_INPUT_COUNT = 434
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
GIT_SAFETY_OVERRIDES = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.attributesFile=/dev/null",
)
FILTER_ATTRIBUTE_RE = re.compile(rb"(?:^|[\s;])filter\s*=")
V1_PATH = Path("tools/compat-broad/fs-write-txn/stream_comparison.mjs")
V2_DIR = Path("tools/compat-broad/fs-write-txn-recompare-v2")
BOUND_RUNTIME_SOURCES = (
    Path("tools/compat-broad/broad_contract.py"),
    Path("tools/compat-broad/fs-write-txn/credential_prep.py"),
    Path("tools/compat-broad/fs-write-txn/stream_bridge.py"),
    Path("tools/compat-broad/fs-write-txn/stream_production.py"),
    Path("tools/compat-broad/fs-write-txn/stream_shadow.py"),
    Path("tools/sdk-smoke/package-lock.json"),
)
LOCAL_OUTER_SHA256 = {
    "execution/inputs.json": "bc9f579bddbe19fa612e6dd613e24ed6fc758f6cd5d83a1f8c734db9037d054e",
    "execution/gate/state.json": "d3500fa9da0608857faf72be239165e3fdf57953a43061100604e5afab53388d",
    "execution/receipt.json": "cc9f60e4130db9b508dd6b6b23275dcf73d96cd0d87e36b18d61b3182b076445",
    "execution/credential-preparation/binding.json": "28b8c1fbe93850b9b77d0a184289ae2c999d2e676601397e09b6fd8f07194c7e",
    "execution/credential-preparation/refresh-charge.json": "826bc7a5acde2718c07b3f0ec69ae40fab76fc5eb990fc075126ae81ceb822a9",
    "execution/credential-preparation/refresh-receipt.json": "fa26768bcfb7031c888844fd6b7cd74cbc72cadbc928756dcdbc125ea7b7141f",
    "execution/credential-preparation/tokeninfo-charge.json": "4c8c21672ee40dfd5dd6e6b0435cd4bdd0f364d6c83bf995cae1251faf93a81f",
    "execution/credential-preparation/tokeninfo-receipt.json": "ba88870ffb79d88caefe23dcf75d800f41a0b621fca278c1f926ed90eccab5d0",
    "execution/credential-preparation/complete.json": "acbf6ec734f012defe6bc663ccab9de797ff44e98e0230e4dae21433af5644b1",
    "ledger/state.json": "12454748d4cd585fa2eed48293cd82c110d43cc3b10a738ebc4a035816266ce8",
    "config.json": "96f3bacf5f05aa6cfcb589351c1be213b815b998e08bf7881022fe0fb66b9c4b",
    "instance.json": "031d849c3708819a9dce1818267cef3dce55835c55cbb3d0cb3c7077d30bba4f",
    "child-identity.json": "4cde02db5013b8181490f803385ee6c38f23a48a9bc3146d99f09223c55e9693",
}


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def offline_subprocess_environment(
    node_executable: str | None = None,
) -> dict[str, str]:
    git_path = shutil.which("git")
    require(git_path is not None, "Git executable is unavailable")
    git_executable = Path(git_path).resolve(strict=True)
    regular(git_executable)
    require(os.access(git_executable, os.X_OK), "Git executable is not executable")
    search_path = [str(git_executable.parent)]
    if node_executable is not None:
        node_path = Path(node_executable).resolve(strict=True)
        require(
            node_path.is_file() and os.access(node_path, os.X_OK),
            "Node executable is unavailable",
        )
        search_path.append(str(node_path.parent))
    path_value = os.pathsep.join(dict.fromkeys(search_path))
    require(
        Path(shutil.which("git", path=path_value) or "").resolve() == git_executable,
        "isolated Git resolution differs",
    )
    if node_executable is not None:
        require(
            Path(shutil.which("node", path=path_value) or "").resolve()
            == Path(node_executable).resolve(),
            "isolated Node resolution differs",
        )
    return {
        "PATH": path_value,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
    }


def verified_node_executable(node_runtime: object) -> str:
    require(isinstance(node_runtime, dict), "Node runtime record is missing")
    raw_path = node_runtime.get("path")
    expected_sha = node_runtime.get("sha256")
    require(
        isinstance(raw_path, str)
        and isinstance(expected_sha, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None,
        "Node runtime record is malformed",
    )
    path = Path(raw_path)
    require(path.is_absolute(), "Node executable path must be absolute")
    regular(path)
    executable = path.resolve(strict=True)
    require(executable == path, "Node executable path is not canonical")
    require(os.access(executable, os.X_OK), "Node executable is not executable")
    require(
        sha(executable.read_bytes()) == expected_sha, "Node executable digest differs"
    )
    return str(executable)


def historical_worktree_parent(input_root: Path) -> Path:
    root = input_root.resolve(strict=True)
    parent = root / ".worktree"
    info = parent.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        "real worktree parent required",
    )
    resolved = parent.resolve(strict=True)
    require(
        resolved == parent and resolved.is_relative_to(root),
        "real worktree parent required",
    )
    return resolved


def require_classifications(v1: str, v2: str) -> None:
    require(v1 == "SEMANTIC_MISMATCH", "V1 classification differs")
    require(v2 == "EXPECTED_NONDETERMINISM", "V2 classification differs")


def require_saved_classifications(original: str, old_pair: str, new_pair: str) -> None:
    require(
        original == old_pair == "SEMANTIC_MISMATCH",
        "saved original classification differs",
    )
    require(
        new_pair == "EXPECTED_NONDETERMINISM",
        "saved repaired classification differs",
    )


def regular(path: Path) -> None:
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        "regular trust root required",
    )


def read(path: Path, expected: str, snapshots: dict[Path, bytes]) -> bytes:
    regular(path)
    value = path.read_bytes()
    require(sha(value) == expected, "trust root digest differs")
    path = path.resolve()
    require(
        path not in snapshots or snapshots[path] == value,
        "input changed during validation",
    )
    snapshots[path] = value
    return value


def git_command(root: Path, *args: str) -> list[str]:
    return ["git", *GIT_SAFETY_OVERRIDES, "-C", str(root), *args]


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        git_command(root, *args),
        text=True,
        capture_output=True,
        check=True,
        env=offline_subprocess_environment(),
    )


def git(root: Path, *args: str) -> str:
    return run_git(root, *args).stdout.strip()


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        git_command(root, *args), env=offline_subprocess_environment()
    )


def refuse_checkout_filters(root: Path, commits: tuple[str, ...]) -> None:
    filters = subprocess.run(
        git_command(
            root,
            "config",
            "--show-origin",
            "--name-only",
            "--get-regexp",
            r"^filter\.",
        ),
        text=True,
        capture_output=True,
        check=False,
        env=offline_subprocess_environment(),
    )
    require(filters.returncode in (0, 1), "checkout filter inventory failed")
    require(not filters.stdout.strip(), "checkout filter configuration refused")

    info_attributes = Path(git(root, "rev-parse", "--git-path", "info/attributes"))
    if not info_attributes.is_absolute():
        info_attributes = root / info_attributes
    if os.path.lexists(info_attributes):
        regular(info_attributes)
        require(
            FILTER_ATTRIBUTE_RE.search(info_attributes.read_bytes()) is None,
            "checkout filter attributes refused",
        )

    for commit in commits:
        require(COMMIT_RE.fullmatch(commit) is not None, "invalid checkout source commit")
        paths = git(root, "ls-tree", "-r", "--name-only", commit).splitlines()
        for name in paths:
            if Path(name).name != ".gitattributes":
                continue
            attributes = git_bytes(root, "show", f"{commit}:{name}")
            require(
                FILTER_ATTRIBUTE_RE.search(attributes) is None,
                "checkout filter attributes refused",
            )


def authority_sources(root: Path, authority_commit: str) -> dict[str, str]:
    require(
        COMMIT_RE.fullmatch(authority_commit) is not None, "invalid authority commit"
    )
    require(
        git(root, "rev-parse", "HEAD") == authority_commit, "authority commit differs"
    )
    require(
        not git(root, "status", "--porcelain", "--untracked-files=all"),
        "authority checkout is dirty",
    )
    v2_paths = sorted((root / V2_DIR).glob("*.mjs"))
    require(v2_paths, "reviewed V2 source closure is empty")
    paths = [
        Path(__file__).resolve().relative_to(root),
        SAVED_AUTHORITY_PATH,
        V1_PATH,
        *(path.relative_to(root) for path in v2_paths),
        *BOUND_RUNTIME_SOURCES,
        SAVED_RESULT_REL,
    ]
    result = {}
    for path in paths:
        current = (root / path).read_bytes()
        reviewed = git_bytes(root, "show", f"{authority_commit}:{path}")
        require(sha(current) == sha(reviewed), "reviewed source differs")
        result[str(path)] = sha(current)
    for path in BOUND_RUNTIME_SOURCES:
        current = (root / path).read_bytes()
        require(
            current == git_bytes(root, "show", f"{RUNTIME_COMMIT}:{path}"),
            "c1 validator source differs",
        )
    return result


def runtime_inputs_at_commit(root: Path) -> dict[str, str]:
    names = (
        git_bytes(
            root,
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            RUNTIME_COMMIT,
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "crates",
        )
        .decode()
        .split("\0")
    )
    names = sorted(name for name in names if name)
    require(len(names) == RUNTIME_INPUT_COUNT, "c1 runtime input count differs")
    return {
        name: sha(git_bytes(root, "show", f"{RUNTIME_COMMIT}:{name}")) for name in names
    }


def validate_manifest(
    manifest: dict, root: Path, artifact_sha: str
) -> dict[str, object]:
    runtime = manifest.get("runtimeSource")
    build = manifest.get("build")
    require(
        isinstance(runtime, dict) and isinstance(build, dict),
        "build manifest shape differs",
    )
    expected_inputs = runtime_inputs_at_commit(root)
    require(runtime.get("commit") == RUNTIME_COMMIT, "runtime source commit differs")
    require(runtime.get("files") == expected_inputs, "runtime source input map differs")
    require(build.get("inputs") == expected_inputs, "build input map differs")
    require(
        build.get("artifactSha256") == artifact_sha, "artifact build binding differs"
    )
    require(
        build.get("command") == BUILD_COMMAND and build.get("exitCode") == 0,
        "build record differs",
    )
    inputs_digest = sha(
        json.dumps(expected_inputs, sort_keys=True, separators=(",", ":")).encode()
    )
    return {
        "runtimeInputCount": len(expected_inputs),
        "runtimeInputsDigest": inputs_digest,
    }


def validate_local_receipt(
    root: Path, input_root: Path, receipt: dict, artifact_sha: str
) -> None:
    require(
        receipt.get("kind") == "stream-prepared-execution-v1",
        "local receipt kind differs",
    )
    for field in (
        "acquisitionValidated",
        "reservationReleased",
        "configurationUnchanged",
    ):
        require(receipt.get(field) is True, f"local {field} is false")
    require(
        receipt.get("productionExecuted") is False,
        "local receipt claims production execution",
    )
    require(
        receipt.get("productionDataExecuted") is False,
        "local receipt claims production data",
    )
    require(receipt.get("failures") == [], "local receipt contains failures")
    gate = receipt.get("gate")
    require(isinstance(gate, dict), "local gate is missing")
    sys.path[:0] = [
        str(root / "tools/compat-broad"),
        str(root / "tools/compat-broad/fs-write-txn"),
    ]
    import stream_bridge
    import stream_production
    import stream_shadow
    from broad_contract import digest

    require(
        Path(stream_shadow.__file__).resolve()
        == root / "tools/compat-broad/fs-write-txn/stream_shadow.py",
        "unexpected receipt validator",
    )
    lock_bytes = (root / "tools/sdk-smoke/package-lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    sdk_version = lock["packages"]["node_modules/@google-cloud/firestore"]["version"]
    require(sdk_version == "8.7.1", "c1 pricing SDK lock version differs")
    stream_production.pricing_sdk_binding = lambda directory=None: {
        "version": sdk_version,
        "clientSha256": stream_production.SDK_CLIENT_SHA256,
        "lockSha256": sha(lock_bytes),
        "encodedReceiveCeilingMiB": 17,
    }
    stream_shadow.validate_owned_receipt(receipt, artifact_sha)
    plan = gate.get("plan")
    require(
        isinstance(plan, dict) and gate.get("planDigest") == digest(plan),
        "local plan digest differs",
    )
    stream_bridge.validate_plan(plan)
    stream_bridge.validate_absence(gate, "stream")
    stream_production.metadata_valid(gate)
    require(
        gate.get("coordinatorInflight") is False, "local coordinator remains active"
    )
    require(
        gate.get("coordinatorDone") == plan.get("coordinatorRequests"),
        "local coordinator is incomplete",
    )
    for job in gate.get("jobs", {}).values():
        require(
            job.get("stopped") is True and not job.get("inflight"),
            "local job is not stopped",
        )
        require(
            set(job.get("absent", [])) == set(job.get("resources", [])),
            "local resources remain",
        )
    collection = receipt.get("collection", {})
    observations = collection.get("observations", [])
    recovery = collection.get("recoveryObservations", [])
    events = gate.get("events", [])
    require(
        len(observations) == 15 and len(recovery) == 10,
        "local observation counts differ",
    )
    require(
        len(events) == 23 and receipt.get("dataRequests") == 23,
        "local data request count differs",
    )
    nodes: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            nodes.add(digest(value))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(collection)
    for event in events:
        response = event.get("receipt", {})
        require(
            event.get("completed") is True and not event.get("failure"),
            "local request incomplete",
        )
        require(
            event.get("responseDigest") == digest(response),
            "local response digest differs",
        )
        require(
            event.get("requestDigest") == response.get("requestDigest"),
            "local request digest differs",
        )
        require(
            event.get("grpcCode") == stream_bridge.grpc_code(response.get("raw")),
            "local gRPC code differs",
        )
        require(
            digest(response.get("raw")) in nodes,
            "local response is not collection-bound",
        )


def validate_local_acquisition(
    root: Path,
    input_root: Path,
    receipt: dict,
    snapshots: dict[Path, bytes],
) -> str:
    run_dir = input_root / RECEIPT_REL.parent
    outer_hashes: dict[str, str] = {}

    def load(relative: str) -> dict:
        raw = read(run_dir / relative, LOCAL_OUTER_SHA256[relative], snapshots)
        outer_hashes[relative] = sha(raw)
        value = json.loads(raw)
        require(isinstance(value, dict), "local acquisition record shape differs")
        return value

    inputs = load("execution/inputs.json")
    gate = load("execution/gate/state.json")
    execution_receipt = load("execution/receipt.json")
    ledger = load("ledger/state.json")
    config = load("config.json")
    instance = load("instance.json")
    child = load("child-identity.json")
    journal = {
        name.removesuffix(".json"): load(f"execution/credential-preparation/{name}")
        for name in (
            "binding.json",
            "refresh-charge.json",
            "refresh-receipt.json",
            "tokeninfo-charge.json",
            "tokeninfo-receipt.json",
            "complete.json",
        )
    }

    sys.path[:0] = [
        str(root / "tools/compat-broad"),
        str(root / "tools/compat-broad/fs-write-txn"),
    ]
    import credential_prep
    import stream_bridge
    from broad_contract import digest

    require(
        Path(credential_prep.__file__).resolve()
        == root / "tools/compat-broad/fs-write-txn/credential_prep.py",
        "unexpected acquisition validator",
    )
    plan = inputs.get("plan")
    permission = inputs.get("permission")
    claim = inputs.get("claim")
    envelope = inputs.get("envelope")
    ticket = inputs.get("ticket")
    require(
        isinstance(plan, dict)
        and isinstance(permission, dict)
        and isinstance(claim, dict)
        and isinstance(envelope, dict)
        and isinstance(ticket, dict),
        "local execution inputs are incomplete",
    )
    require(
        gate == receipt.get("gate") == execution_receipt.get("gate"),
        "local execution gate differs",
    )
    require(
        plan == gate.get("plan")
        and gate.get("planDigest") == digest(plan)
        and plan.get("permissionDigest") == digest(permission),
        "local execution permission or plan differs",
    )
    require(
        inputs.get("plan") == receipt["gate"]["plan"]
        and ticket.get("ledgerPath") == str(run_dir / "ledger"),
        "local inputs are not bound to this saved run",
    )
    require(
        ledger.get("identity") == ticket.get("ledgerIdentity"),
        "local ledger identity differs",
    )
    reservation_id = ticket.get("reservation")
    reservations = ledger.get("reservations")
    require(
        isinstance(reservations, dict)
        and len(reservations) == 1
        and reservation_id in reservations,
        "local reservation is missing or ambiguous",
    )
    row = reservations[reservation_id]
    require(
        row.get("state") == "released" and row.get("finalGateDigest") == digest(gate),
        "local reservation is not released against the final gate",
    )
    require(
        row.get("claim") == claim
        and row.get("claimDigest") == digest(claim) == ticket.get("claimDigest"),
        "local claim binding differs",
    )
    require(
        row.get("envelopeDigest") == digest(envelope) == ticket.get("envelopeDigest"),
        "local envelope binding differs",
    )
    envelopes = ledger.get("envelopes")
    require(
        isinstance(envelopes, dict)
        and envelopes.get(row["envelopeDigest"], {}).get("envelope") == envelope,
        "local ledger envelope differs",
    )
    binding = journal["binding"]
    proof = receipt.get("credentialPreparation")
    require(
        isinstance(proof, dict)
        and proof.get("attempts") == 2
        and proof.get("journalDigest") == digest(journal),
        "local credential journal seal differs",
    )
    require(
        binding.get("observerSha256") == stream_bridge.source_digest()
        and binding.get("contractDigest") == digest(credential_prep.contract()),
        "local credential preparation source differs",
    )
    require(
        journal["complete"].get("verified") is True,
        "local credential preparation is incomplete",
    )
    for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):
        charge = journal[f"{slot}-charge"]
        response = journal[f"{slot}-receipt"]
        require(
            charge.get("ordinal") == ordinal
            and charge.get("slot") == slot
            and charge.get("bindingDigest") == digest(binding),
            "local credential charge differs",
        )
        require(
            response.get("chargeDigest") == digest(charge)
            and response.get("verified") is True
            and response.get("workerReaped") is True,
            "local credential receipt differs",
        )
    outer = receipt.get("outerAccounting")
    require(isinstance(outer, dict), "local outer accounting is missing")
    require(
        outer.get("requests") == gate.get("total") + 2 == 33
        and outer.get("costMicrousd") == gate.get("costMicrousd") + 200 == 1303300,
        "local outer accounting differs",
    )
    started, finished = outer.get("reservationStartedAt"), outer.get("finishedAt")
    require(
        started
        == proof.get("reservationStartedAt")
        == binding.get("reservationStartedAt")
        and type(started) in (int, float)
        and type(finished) in (int, float)
        and 0 < finished - started < credential_prep.OUTER_SECONDS,
        "local reservation time window differs",
    )
    require(
        started < finished < permission.get("expiresAt"),
        "local permission window differs",
    )
    require(
        binding.get("ticketDigest") == digest(ticket)
        and binding.get("claimDigest") == digest(claim)
        and binding.get("permissionDigest") == digest(permission)
        and binding.get("planDigest") == digest(plan),
        "local credential admission binding differs",
    )
    require(
        envelope.get("permissionDigest") == digest(permission)
        and envelope.get("issuedAt") <= started < finished < envelope.get("expiresAt"),
        "local envelope permission window differs",
    )
    require(
        instance.get("nonce") == plan.get("nonce")
        and instance.get("project") == plan.get("projectId")
        and instance.get("profile") == config.get("profile")
        and child.get("parentPid") == instance.get("parentPid")
        and child.get("childPid") == instance.get("childPid")
        and child.get("nonce") == instance.get("nonce"),
        "local process identity differs",
    )
    require(
        isinstance(config, dict)
        and isinstance(instance, dict)
        and isinstance(child, dict)
        and receipt.get("configurationUnchanged") is True,
        "local cleanup metadata is incomplete",
    )
    return sha(json.dumps(outer_hashes, sort_keys=True, separators=(",", ":")).encode())


def validate_saved_production_authority(root: Path, input_root: Path) -> str:
    source_dir = root / V2_DIR
    script = source_dir / "saved_authority.py"
    worktree_base = historical_worktree_parent(input_root)
    frozen_path = worktree_base / "stream-credential-preparation"
    repaired_path = worktree_base / "stream-repair-shadow"
    sdk_source = (
        input_root
        / ".worktree/compatibility-inventory/tools/sdk-smoke/node_modules"
        / "@google-cloud/firestore"
    )
    for path in (frozen_path, repaired_path):
        require(not os.path.lexists(path), "historical authority worktree path exists")
    commits = (
        "dee737c14e68eb4f546b7ca4c827871fc48a2503",
        "567565bdd654cab00dbb84101edcc7bdc628e230",
    )
    refuse_checkout_filters(input_root, commits)
    base_env = offline_subprocess_environment()
    registered = subprocess.check_output(
        git_command(input_root, "worktree", "list", "--porcelain"),
        text=True,
        env=base_env,
    )
    require(
        all(str(path) not in registered for path in (frozen_path, repaired_path)),
        "historical authority worktree path is already registered",
    )
    package_json = sdk_source / "package.json"
    client_source = sdk_source / "build/src/v1/firestore_client.js"
    require(
        json.loads(package_json.read_text()).get("version") == "8.7.1"
        and sha(client_source.read_bytes())
        == "ab6947259f63e324aaa87ab6934fd538b5defce75a19f40a8896728223c23dc7",
        "historical pricing SDK source differs",
    )
    prepared_bytes = read(input_root / SAVED_PREPARED_REL, SAVED_PREPARED_SHA, {})
    prepared = json.loads(prepared_bytes)
    saved_node = verified_node_executable(prepared["plan"]["nodeRuntime"])
    child_env = offline_subprocess_environment(saved_node)
    created: list[Path] = []
    aliases: list[Path] = []
    preserve_paths: set[Path] = set()

    def run_git(*args: str) -> None:
        subprocess.run(
            git_command(input_root, *args),
            text=True,
            capture_output=True,
            check=True,
            env=child_env,
        )

    try:
        for path, commit in zip((frozen_path, repaired_path), commits, strict=True):
            # A failed add can leave an ambiguous partial path; only successful adds
            # become owned cleanup targets, avoiding deletion of concurrent paths.
            run_git("worktree", "add", "--detach", str(path), commit)
            created.append(path)
            alias = path / "tools/sdk-smoke/node_modules/@google-cloud/firestore"
            if os.path.lexists(alias):
                preserve_paths.add(path)
                raise ValueError("historical SDK alias path exists")
            alias.parent.mkdir(parents=True, exist_ok=True)
            try:
                alias.symlink_to(sdk_source, target_is_directory=True)
            except FileExistsError as error:
                preserve_paths.add(path)
                raise ValueError("historical SDK alias path exists") from error
            aliases.append(alias)
        with tempfile.TemporaryDirectory(prefix="c1-saved-authority-") as temp:
            output = Path(temp) / "proof.json"
            child_env["HOME"] = temp
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--root",
                    str(input_root),
                    "--output",
                    str(output),
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
                env=child_env,
            )
            require(
                result.returncode == 0 and output.is_file(),
                "saved production authority refused",
            )
            proof = json.loads(output.read_bytes())
        require(
            proof.get("kind") == "stream-saved-authority-v2"
            and proof.get("acquisitionValidated") is True
            and proof.get("promotionReady") is False,
            "saved production acquisition is not validated",
        )
        require_saved_classifications(
            proof.get("originalComparison", {}).get("classification"),
            proof.get("oldPair", {}).get("classification"),
            proof.get("newPair", {}).get("classification"),
        )
        bound = proof.get("bindings")
        require(
            isinstance(bound, dict) and bound,
            "saved production proof bindings are missing",
        )
        production_suffix = "/docs.local/logs/2026-09-17/stream-production-preflight/execution-dee737c14/receipt.json"
        require(
            any(
                path.endswith(production_suffix) and value == PRODUCTION_SHA
                for path, value in bound.items()
            ),
            "saved production receipt is not bound by its acquisition authority",
        )
        return sha(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode())
    finally:
        cleanup_errors: list[Exception] = []
        for alias in reversed(aliases):
            if alias.is_symlink() and alias.resolve() == sdk_source.resolve():
                alias.unlink()
            else:
                preserve_paths.update(
                    path for path in created if alias.is_relative_to(path)
                )
                cleanup_errors.append(
                    ValueError("historical SDK alias identity changed")
                )
        for path in reversed(created):
            if path in preserve_paths:
                cleanup_errors.append(ValueError("historical source path is not owned"))
                continue
            try:
                dirty = subprocess.check_output(
                    git_command(path, "status", "--porcelain", "--untracked-files=all"),
                    text=True,
                    env=child_env,
                ).strip()
                require(not dirty, "historical source worktree is dirty")
                run_git("worktree", "remove", str(path))
            except Exception as error:  # noqa: BLE001 -- Cleanup must attempt every owned path.
                cleanup_errors.append(error)
        if cleanup_errors:
            raise ValueError("historical authority temporary cleanup incomplete")


def compare(
    root: Path, production: dict, local: dict, artifact_sha: str, node: str
) -> dict:
    comparator = root / V1_PATH
    v2_paths = sorted((root / V2_DIR).glob("*.mjs"))
    sources = {path.name: path.read_text() for path in v2_paths}
    sys.path[:0] = [
        str(root / "tools/compat-broad"),
        str(root / "tools/compat-broad/fs-write-txn"),
    ]
    import stream_production

    expected = stream_production.comparison_contract(production["gate"]["plan"])
    local_plan = local["gate"]["plan"]
    expected["local"] = {
        "projectId": local_plan["projectId"],
        "documentPrefix": local_plan["documentPrefix"],
    }
    payload = {
        "production": production["collection"],
        "local": local["collection"],
        "expected": expected,
        "v1Source": comparator.read_text(),
        "v2Sources": sources,
        "artifact": {
            "sha256": artifact_sha,
            "executionCommit": local["ownedArtifact"]["executionCommit"],
        },
        "permission": {
            "kind": "c1-current-local-authority-v1",
            "planDigest": local["gate"]["planDigest"],
        },
    }
    script = """
const ambient = ['GOOGLE_APPLICATION_CREDENTIALS', 'FIREBASE_CONFIG', 'FIREBASE_TOKEN',
  'AWS_SECRET_ACCESS_KEY', 'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS'];
if (ambient.some((key) => process.env[key] !== undefined)) {
  throw new Error('ambient child environment refused');
}
import { compareStreamReceipts } from './stream_comparison.mjs';
import { compareStreamReceiptsV2, v2Digest, v2TextDigest } from '../fs-write-txn-recompare-v2/stream_recompare_v2.mjs';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const x = JSON.parse(input);
const v1Comparison = compareStreamReceipts({production:x.production, local:x.local, expected:x.expected});
const binding = {permission:x.permission, v1Source:x.v1Source, v1Comparison, v2Sources:x.v2Sources, artifact:x.artifact};
for (const k of ['permission','v1Comparison','v2Sources','artifact']) binding[k+'Sha256'] = v2Digest(binding[k]);
binding.v1SourceSha256 = v2TextDigest(binding.v1Source);
binding.productionReceiptSha256 = v2Digest(x.production);
binding.localReceiptSha256 = v2Digest(x.local);
const v2 = compareStreamReceiptsV2({production:x.production, local:x.local, expected:x.expected, binding});
process.stdout.write(JSON.stringify({v1Classification:v1Comparison.classification, v2Classification:v2.classification,
  v1Indeterminate:v1Comparison.classification === 'INDETERMINATE' ? 1 : 0,
  v2Indeterminate:v2.classification === 'INDETERMINATE' ? 1 : 0,
  v1Comparison}));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=comparator.parent,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        env=offline_subprocess_environment(node),
    )
    require(result.returncode == 0, "comparison execution failed")
    value = json.loads(result.stdout)
    require(
        value["v1Indeterminate"] == 0 and value["v2Indeterminate"] == 0,
        "comparison is indeterminate",
    )
    differences = value["v1Comparison"].get("differences", {})
    left, right = differences.get("production"), differences.get("local")
    require(
        isinstance(left, list) and isinstance(right, list) and len(left) == len(right),
        "V1 projection is incomplete",
    )
    leaf_counts = [
        difference_leaf_count(a, b) for a, b in zip(left, right, strict=True)
    ]
    result_value = {key: value[key] for key in ("v1Classification", "v2Classification")}
    result_value.update(
        {
            "v1ComparedSlotCount": len(left),
            "v1DifferingSlotCount": sum(count > 0 for count in leaf_counts),
            "v1DifferenceLeafCount": sum(leaf_counts),
            "indeterminate": value["v1Indeterminate"] + value["v2Indeterminate"],
        }
    )
    return result_value


MISSING = object()


def difference_leaf_count(left: object, right: object) -> int:
    if left is MISSING or right is MISSING:
        return 1
    if type(left) is not type(right):
        return 1
    if isinstance(left, dict):
        assert isinstance(right, dict)
        return sum(
            difference_leaf_count(left.get(key, MISSING), right.get(key, MISSING))
            for key in set(left) | set(right)
        )
    if isinstance(left, list):
        assert isinstance(right, list)
        return sum(
            difference_leaf_count(
                left[i] if i < len(left) else MISSING,
                right[i] if i < len(right) else MISSING,
            )
            for i in range(max(len(left), len(right)))
        )
    return int(left != right)


def run(args: argparse.Namespace) -> dict:
    root = Path(args.root).resolve(strict=True)
    inputs = Path(args.input_root or root).resolve(strict=True)
    snapshots: dict[Path, bytes] = {}
    artifact_path = Path(args.artifact) if args.artifact else inputs / ARTIFACT_REL
    manifest_path = (
        Path(args.build_manifest) if args.build_manifest else inputs / MANIFEST_REL
    )
    receipt_path = Path(args.receipt) if args.receipt else inputs / RECEIPT_REL
    production_path = (
        Path(args.production) if args.production else inputs / PRODUCTION_REL
    )
    artifact_bytes = read(artifact_path, ARTIFACT_SHA, snapshots)
    manifest_bytes = read(manifest_path, MANIFEST_SHA, snapshots)
    receipt_bytes = read(receipt_path, RECEIPT_SHA, snapshots)
    production_bytes = read(production_path, PRODUCTION_SHA, snapshots)
    saved_result_bytes = read(root / SAVED_RESULT_REL, SAVED_RESULT_SHA, snapshots)
    artifact_sha = sha(artifact_bytes)
    manifest = json.loads(manifest_bytes)
    local = json.loads(receipt_bytes)
    production = json.loads(production_bytes)
    saved_result = json.loads(saved_result_bytes)
    closure_before = authority_sources(root, args.authority_commit)
    manifest_binding = validate_manifest(manifest, root, artifact_sha)
    validate_local_receipt(root, inputs, local, artifact_sha)
    local_outer_proof_digest = validate_local_acquisition(
        root, inputs, local, snapshots
    )
    saved_production_proof_digest = validate_saved_production_authority(root, inputs)
    require(
        local.get("ownedArtifact", {}).get("executionCommit") == RUNTIME_COMMIT,
        "local execution commit differs",
    )
    require(
        production.get("acquisitionValidated") is True
        and production.get("productionExecuted") is True,
        "saved production receipt is not validated",
    )
    require(
        production.get("failures") == []
        and production.get("reservationReleased") is True,
        "saved production receipt is incomplete",
    )
    require(
        len(production.get("gate", {}).get("events", [])) == 23,
        "saved production request count differs",
    )
    require(
        len(production.get("collection", {}).get("observations", [])) == 15,
        "saved production observation count differs",
    )
    require(
        len(production.get("collection", {}).get("recoveryObservations", [])) == 10,
        "saved production recovery count differs",
    )
    require(
        saved_result.get("kind") == "fs-write-transaction-saved-comparison-v2"
        and saved_result.get("acquisitionValidated") is True
        and saved_result.get("originalClassification") == "SEMANTIC_MISMATCH"
        and saved_result.get("preFixClassificationWithV2") == "SEMANTIC_MISMATCH"
        and saved_result.get("repairedClassification") == "EXPECTED_NONDETERMINISM"
        and saved_result.get("campaignId") == "FS-WRITE-TXN-PRECEDENCE-01"
        and saved_result.get("privateEvidenceSha256", {}).get(
            "originalProductionReceipt"
        )
        == PRODUCTION_SHA,
        "published saved comparison does not corroborate the historical proof",
    )
    node = verified_node_executable(local["gate"]["plan"]["nodeRuntime"])
    result = compare(root, production, local, artifact_sha, node)
    require_classifications(result["v1Classification"], result["v2Classification"])
    for path, expected in (
        (artifact_path, ARTIFACT_SHA),
        (manifest_path, MANIFEST_SHA),
        (receipt_path, RECEIPT_SHA),
        (production_path, PRODUCTION_SHA),
    ):
        read(path, expected, snapshots)
    closure_after = authority_sources(root, args.authority_commit)
    require(
        closure_before == closure_after, "authority sources changed during comparison"
    )
    require(
        result["v2Classification"] in {"MATCH", "MISMATCH", "EXPECTED_NONDETERMINISM"},
        "unexpected comparison classification",
    )
    return {
        "kind": "fs-write-txn-c1-current-authority-v1",
        "acquisitionValidated": True,
        "promotionReady": False,
        "classification": result["v2Classification"],
        "v1Classification": result["v1Classification"],
        "productionExecuted": False,
        "rowCounts": {
            "observations": 15,
            "recoveryObservations": 10,
            "gateEvents": 23,
            "v1ComparedSlotCount": result["v1ComparedSlotCount"],
            "v1DifferingSlotCount": result["v1DifferingSlotCount"],
            "v1DifferenceLeafCount": result["v1DifferenceLeafCount"],
            "indeterminate": result["indeterminate"],
        },
        "bindings": {
            "artifactSha256": artifact_sha,
            "manifestSha256": sha(manifest_bytes),
            "localReceiptSha256": sha(receipt_bytes),
            "productionReceiptSha256": sha(production_bytes),
            "productionSavedAuthorityKind": "stream-saved-authority-v2",
            "productionSavedAuthorityDigest": saved_production_proof_digest,
            "localOuterProofDigest": local_outer_proof_digest,
            "runtimeSourceCommit": RUNTIME_COMMIT,
            "runtimeInputCount": manifest_binding["runtimeInputCount"],
            "runtimeInputsDigest": manifest_binding["runtimeInputsDigest"],
            "authorityCommit": args.authority_commit,
            "authoritySources": closure_after,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, required=True, help="clean committed authority checkout"
    )
    parser.add_argument(
        "--input-root", type=Path, help="repository containing ignored saved run inputs"
    )
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = run(args)
        output = args.output.resolve()
        if output.exists():
            raise FileExistsError("fresh output required")
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        return 0
    except Exception as error:  # noqa: BLE001 -- CLI sanitizes every refusal.
        print(
            f"c1 current authority refused ({type(error).__name__}).", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
