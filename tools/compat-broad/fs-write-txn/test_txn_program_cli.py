"""Exact packet, review and GO pins are checked before credential access."""

import hashlib
import importlib
import json
from pathlib import Path

import pytest

import txn_program_cli as cli

support = importlib.import_module("txn_program_support_for_tests")
NAME = "toy-failed-commit"
REQUESTS = 19 + 4 + 14 + 7 + 2


@pytest.fixture
def table(monkeypatch):
    monkeypatch.setitem(cli.TABLES, NAME, "txn_program_support_for_tests")
    return cli.table_for(NAME)


@pytest.fixture
def packet(tmp_path, monkeypatch, table):
    monkeypatch.setattr(cli, "verify_runtime", lambda _runtime: None)
    baseline = tmp_path / "baseline.json"; baseline.write_text("{}\n")
    envelope = tmp_path / "envelope.md"; envelope.write_text("scope proposal\n")
    value = cli.packet_value(table=table, source_commit="b" * 40, runtime={"reviewed": True}, baseline_sha256=cli.sha(baseline.read_bytes()), envelope_sha256=cli.sha(envelope.read_bytes()), packet_id="fs-transaction-toy-failed-commit-unit", envelope_relative="docs.local/reviews/toy-envelope.md")
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    def load():
        return cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, table=table, source_commit="b" * 40, packet_relative="docs.local/reviews/toy-unit.json", envelope_relative=value["envelopePath"])
    return path, baseline, envelope, value, load


def test_the_registry_is_closed_and_names_its_own_table(table):
    assert table["name"] == NAME
    with pytest.raises(ValueError, match="table"):
        cli.table_for("not-registered")
    with pytest.raises(ValueError, match="table"):
        cli.table_for("../txn_program_support_for_tests")
    assert set(cli.TABLES) >= {NAME}


def test_a_registry_entry_must_be_the_table_it_names(monkeypatch):
    monkeypatch.setitem(cli.TABLES, "other-name", "txn_program_support_for_tests")
    with pytest.raises(ValueError, match="table"):
        cli.table_for("other-name")


def test_scope_and_caps_are_exact(packet, table):
    _path, _baseline, _envelope, value, load = packet
    pins = load()
    assert pins["requestsPerRecording"] == REQUESTS == sum(table["caps"].values())
    assert pins["packetName"] == NAME and pins["estimatedUsdPerRecording"] == 0.01
    assert pins["scope"]["writes"] == "owned-2-documents" and pins["scope"]["transports"] == "grpc+rest"
    assert value["observationSeconds"] == 240 and value["recoverySeconds"] == 180
    assert value["timing"] == "wall-clock" and value["timingSource"] == "parent-wire-envelope"
    assert value["maxTokens"] == 2 and value["reserveUsd"] == 0.04 and value["maxUnresolvedTokens"] == 1
    assert value["releasePolicy"] == "rollback-zero-before-next-chain"
    assert value["caps"] == table["caps"]
    assert value["cases"] == [step["caseId"] for step in table["steps"] if step["caseId"]]
    assert value["envelopeId"] == table["envelopeId"]
    assert value["scope"] == pins["scope"]


@pytest.mark.parametrize("field,changed", [("extra", True), ("requestsPerRecording", REQUESTS + 1), ("recordings", True), ("packetName", "expiry-retry-04"), ("envelopeId", "FS-TRANSACTION-expiry-retry-04-003"), ("envelopeId", "FS-TRANSACTION-toy-failed-commit-002"), ("project", "fireemu-oracle-idp"), ("runnerSha256", "0" * 64), ("sourceCommit", "c" * 40), ("closureSha256", "0" * 64), ("corpusDigest", "0" * 64), ("planSourceDigest", "0" * 64), ("maxUnresolvedTokens", 2), ("releasePolicy", "assume-invalidated"), ("observationSeconds", 900), ("caps", {}), ("cases", []), ("scope", {}), ("packetId", "fs-transaction-p10b-unit")])
def test_a_changed_packet_is_refused_before_any_wire(packet, field, changed):
    path, _baseline, _envelope, value, load = packet
    path.write_text(json.dumps({**value, field: changed}))
    with pytest.raises(ValueError): load()


def test_baseline_or_envelope_bytes_cannot_change(packet):
    _path, baseline, envelope, _value, load = packet
    baseline.write_text('{"changed":true}')
    with pytest.raises(ValueError): load()
    baseline.write_text("{}\n"); envelope.write_text("changed")
    with pytest.raises(ValueError): load()


def test_envelope_and_packet_paths_are_private_relative_paths(packet, tmp_path, table):
    path, baseline, envelope, value, _load = packet
    for relative in ["/tmp/envelope.md", "docs/envelope.md", "docs.local/reviews/../../x.md"]:
        changed = cli.packet_value(table=table, source_commit="b" * 40, runtime={"reviewed": True}, baseline_sha256=cli.sha(baseline.read_bytes()), envelope_sha256=cli.sha(envelope.read_bytes()), packet_id="fs-transaction-toy-failed-commit-unit", envelope_relative=relative)
        path.write_text(json.dumps(changed, sort_keys=True))
        with pytest.raises(ValueError, match="path"):
            cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, table=table, source_commit="b" * 40, packet_relative="docs.local/reviews/toy-unit.json", envelope_relative=relative)
    path.write_text(json.dumps(value, sort_keys=True))
    with pytest.raises(ValueError, match="path"):
        cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, table=table, source_commit="b" * 40, packet_relative="docs/toy-unit.json", envelope_relative=value["envelopePath"])


def test_exact_approve_without_must_or_should_and_explicit_go_are_required(packet, tmp_path):
    _path, _baseline, _envelope, _value, load = packet
    pins = load()
    review = tmp_path / "review.txt"
    text = cli.review_template(pins)
    review.write_text(text)
    cli.verify_review(review, cli.sha(review.read_bytes()), pins)
    cli.verify_go(pins["packetSha256"], pins)
    for changed in [text.replace("APPROVE\n", "APPROVE WITH CHANGES\n"), text.replace("Must=NONE", "Must=CHANGES"), text + "unreviewed-extra=YES\n"]:
        review.write_text(changed)
        with pytest.raises(ValueError): cli.verify_review(review, cli.sha(review.read_bytes()), pins)
    with pytest.raises(ValueError): cli.verify_go("0" * 64, pins)


def _isolate_admission(monkeypatch, tmp_path, value):
    monkeypatch.setattr(cli, "_git", lambda *_args: str(tmp_path / ".git"))
    monkeypatch.setattr(cli, "_private", lambda path, _root: Path(path))
    monkeypatch.setattr(cli, "signed_source_commit", lambda: value["sourceCommit"])
    monkeypatch.setattr(cli, "assert_clean_environment", lambda: None)
    monkeypatch.setattr(cli, "verify_review", lambda *_args: None)


def _argv(reviewed, digest, baseline, tmp_path):
    return ["record-production", "--packet", str(reviewed), "--packet-sha256", digest, "--baseline", str(baseline), "--review", str(tmp_path / "review.txt"), "--review-sha256", "a" * 64, "--go-packet-sha256", digest]


@pytest.mark.parametrize("initial", ["unreviewed-runtime", "oversize"])
def test_the_initial_packet_snapshot_is_hash_checked_before_the_runtime_is_retained(packet, tmp_path, monkeypatch, initial):
    path, baseline, envelope, value, _load = packet
    private = tmp_path / "docs.local/reviews"
    private.mkdir(parents=True)
    reviewed = private / "packet.json"
    reviewed.write_bytes(path.read_bytes())
    (private / "toy-envelope.md").write_bytes(envelope.read_bytes())
    digest = cli.sha(reviewed.read_bytes())
    unreviewed = json.dumps({**value, "runtime": {"unreviewed": True}}).encode()
    if initial == "oversize": unreviewed = b" " * 65536 + reviewed.read_bytes()
    decoded = []
    loads = json.loads
    def observed_decode(raw, *args, **kwargs):
        if raw == unreviewed: decoded.append(True)
        return loads(raw, *args, **kwargs)
    monkeypatch.setattr(cli.json, "loads", observed_decode)
    read_bytes = Path.read_bytes
    reads = 0
    def replaced_first_read(self):
        nonlocal reads
        if self == reviewed:
            reads += 1
            if reads == 1: return unreviewed
        return read_bytes(self)
    monkeypatch.setattr(Path, "read_bytes", replaced_first_read)
    _isolate_admission(monkeypatch, tmp_path, value)
    invoked = []
    def record(**kwargs):
        invoked.append(True)
        kwargs["record_once"](0, "a" * 32, "b" * 32, tmp_path)
        return {}
    monkeypatch.setattr(cli, "record_twice", record)
    monkeypatch.setattr(cli, "run_once", lambda *_args, **kwargs: invoked.append(kwargs["runtime"]))
    with pytest.raises(ValueError, match="packet bytes differ"):
        cli.main(_argv(reviewed, digest, baseline, tmp_path))
    assert invoked == [] and decoded == []


@pytest.mark.parametrize("changed_read", [1, 2])
def test_the_baseline_snapshot_cannot_differ_from_its_packet_pin(packet, tmp_path, monkeypatch, changed_read):
    path, baseline, envelope, value, _load = packet
    private = tmp_path / "docs.local/reviews"
    private.mkdir(parents=True)
    reviewed = private / "packet.json"
    reviewed.write_bytes(path.read_bytes())
    (private / "toy-envelope.md").write_bytes(envelope.read_bytes())
    digest = cli.sha(reviewed.read_bytes())
    read_bytes = Path.read_bytes
    reads = 0
    def replaced_read(self):
        nonlocal reads
        if self == baseline:
            reads += 1
            if reads == changed_read: return b'{"unreviewed": true}'
        return read_bytes(self)
    monkeypatch.setattr(Path, "read_bytes", replaced_read)
    _isolate_admission(monkeypatch, tmp_path, value)
    invoked = []
    def run(*_args, **kwargs):
        kwargs["check"]()
        invoked.append(kwargs["baseline"])
    def record(**kwargs):
        kwargs["record_once"](0, "a" * 32, "b" * 32, tmp_path)
        return {}
    monkeypatch.setattr(cli, "record_twice", record)
    monkeypatch.setattr(cli, "run_once", run)
    monkeypatch.setattr(cli, "authorize", lambda *_args: None)
    monkeypatch.setattr(cli, "remaining_task_budget", lambda *_args: 10)
    monkeypatch.setattr(cli, "read_ledger", lambda *_args: [])
    (tmp_path / "docs.local/instructions").mkdir()
    (tmp_path / "docs.local/instructions/owner-decisions.md").write_text("local test only")
    with pytest.raises(ValueError): cli.main(_argv(reviewed, digest, baseline, tmp_path))
    assert invoked == []


def test_the_recording_receives_the_packets_own_table(packet, tmp_path, monkeypatch, table):
    path, baseline, envelope, value, _load = packet
    private = tmp_path / "docs.local/reviews"
    private.mkdir(parents=True)
    reviewed = private / "packet.json"
    reviewed.write_bytes(path.read_bytes())
    (private / "toy-envelope.md").write_bytes(envelope.read_bytes())
    digest = cli.sha(reviewed.read_bytes())
    _isolate_admission(monkeypatch, tmp_path, value)
    seen = {}
    def record(**kwargs):
        seen["record_table"] = kwargs["table"]
        kwargs["record_once"](0, "a" * 32, "b" * 32, tmp_path)
        return {}
    monkeypatch.setattr(cli, "record_twice", record)
    monkeypatch.setattr(cli, "run_once", lambda index, table_, *_args, **kwargs: seen.update(run_table=table_, index=index))
    monkeypatch.setattr(cli, "authorize", lambda *_args: None)
    monkeypatch.setattr(cli, "remaining_task_budget", lambda *_args: 10)
    monkeypatch.setattr(cli, "read_ledger", lambda *_args: [])
    (tmp_path / "docs.local/instructions").mkdir()
    (tmp_path / "docs.local/instructions/owner-decisions.md").write_text("local test only")
    assert cli.main(_argv(reviewed, digest, baseline, tmp_path)) == 0
    assert seen["record_table"] is table and seen["run_table"] is table and seen["index"] == 0


def test_inspect_local_authorizes_nothing_and_names_every_bound_source(table, capsys):
    assert cli.main(["inspect-local", "--table", NAME]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["authorizesProduction"] is False and report["requestsPerRecording"] == REQUESTS and report["recordings"] == 2
    assert report["runnerSha256"] == cli.runner_sha256(NAME)
    for name in ["program.py", "collector.py", "runner.py", "authority.py", "wire.py", "cli.py", "transport.mjs", "transport.test.mjs"]:
        assert f"tools/compat-broad/fs-write-txn/txn_program_{name}" in report["sourceManifest"]
    assert report["corpusDigest"] and report["planSourceDigest"]


def test_the_manifest_binds_the_framework_and_the_selected_table_only(table):
    manifest = cli.source_manifest(NAME)
    assert all(not path.rsplit("/", 1)[-1].startswith("txn_boundary_grpc") for path in manifest)
    assert "tools/compat-broad/fs-write-txn/txn_program_support_for_tests.py" in manifest
    assert "tools/compat-broad/fs-write-txn/txn_program_authority.py" in manifest
    assert "tools/compat-broad/fs-write-txn/txn_sandbox_admission.py" in manifest, "local imports are followed transitively"


def test_the_prior_families_manifests_are_unchanged_by_the_shared_graph():
    # Loaded by name so this test's own imports do not bind the prior families into the manifest.
    boundary = importlib.import_module("txn_boundary_grpc_cli")
    prior_idle = importlib.import_module("txn_idle_grpc_cli")
    prior_retry = importlib.import_module("txn_retry_grpc_cli")
    assert prior_idle.runner_sha256() == "0c5befa05db71835c1ed2236b9caeeee8c954ca77f13f68f59f6ac2e312d49d3"
    assert prior_retry.runner_sha256() == "23c95d428a0e0f5cc7edfcb3a582811dbb30315ea4158638025175c3970cd4a9"
    assert not any("txn_program" in path for path in boundary.source_manifest())


def test_private_inputs_must_sit_under_docs_local_with_mode_600(tmp_path):
    root = tmp_path
    (root / "docs.local").mkdir()
    good = root / "docs.local/a.json"; good.write_text("{}"); good.chmod(0o600)
    assert cli._private(good, root) == good.resolve()
    open_mode = root / "docs.local/b.json"; open_mode.write_text("{}"); open_mode.chmod(0o644)
    outside = root / "c.json"; outside.write_text("{}"); outside.chmod(0o600)
    for path in [open_mode, outside, root / "docs.local"]:
        with pytest.raises(ValueError, match="private"):
            cli._private(path, root)


def test_a_proxy_credential_or_interpreter_override_in_the_environment_is_refused(monkeypatch):
    for key in ["GOOGLE_APPLICATION_CREDENTIALS", "HTTPS_PROXY", "http_proxy", "CLOUDSDK_CORE_PROJECT", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "FIREBASE_TOKEN"]:
        with monkeypatch.context() as scoped:
            scoped.setenv(key, "x")
            with pytest.raises(ValueError, match="override"):
                cli.assert_clean_environment()
    for key in [name for name in __import__("os").environ if name.upper().endswith("_PROXY") or name.startswith("CLOUDSDK_")]:
        monkeypatch.delenv(key)
    cli.assert_clean_environment()


def test_the_review_is_exactly_this_eight_line_gate(packet):
    pins = packet[4]()
    assert cli.review_template(pins) == "\n".join(["APPROVE", f"packetSha256={pins['packetSha256']}", f"sourceCommit={pins['sourceCommit']}", f"runnerSha256={pins['runnerSha256']}", f"envelopeId={pins['envelopeId']}", "withinEnvelope=YES", "Must=NONE", "Should=NONE"]) + "\n"


def test_a_packet_over_the_size_cap_is_refused_even_with_its_own_digest(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 70000 + b"{}")
    with pytest.raises(ValueError, match="bytes differ"):
        cli._read_packet(big, cli.sha(big.read_bytes()))


def test_the_packets_own_path_cannot_climb(packet, table):
    path, baseline, envelope, value, _load = packet
    with pytest.raises(ValueError, match="path"):
        cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, table=table, source_commit="b" * 40, packet_relative="docs.local/reviews/../toy-unit.json", envelope_relative=value["envelopePath"])


def test_a_packet_never_pins_a_virtualenv_interpreter(tmp_path, table):
    # a virtualenv is a `pyvenv.cfg` beside the interpreter's directory or its parent; a plain interpreter has neither
    plain = tmp_path / "plain" / "bin" / "python3.12"
    venv = tmp_path / "venv" / "bin" / "python3"
    for path in (plain, venv):
        path.parent.mkdir(parents=True); path.write_text("")
    (tmp_path / "venv" / "pyvenv.cfg").write_text("home = /x\n")
    cli.refuse_virtualenv({"pythonExecutable": str(plain)})
    cli.refuse_virtualenv({"reviewed": True})
    with pytest.raises(ValueError, match="virtualenv"):
        cli.refuse_virtualenv({"pythonExecutable": str(venv)})
    (tmp_path / "beside").mkdir()
    (tmp_path / "beside" / "pyvenv.cfg").write_text("home = /x\n")
    (tmp_path / "beside" / "python3").write_text("")
    with pytest.raises(ValueError, match="virtualenv"):
        cli.refuse_virtualenv({"pythonExecutable": str(tmp_path / "beside" / "python3")})
    args = dict(table=table, source_commit="b" * 40, baseline_sha256="0" * 64, envelope_sha256="1" * 64, packet_id="fs-transaction-toy-failed-commit-unit", envelope_relative="docs.local/reviews/toy-envelope.md")
    with pytest.raises(ValueError, match="virtualenv"):
        cli.packet_value(runtime={"pythonExecutable": str(venv)}, **args)
    cli.packet_value(runtime={"pythonExecutable": str(plain)}, **args)


def test_the_interpreter_running_the_builder_is_refused_when_it_is_a_virtualenv(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "prefix", "/venv")
    monkeypatch.setattr(sys, "base_prefix", "/base")
    with pytest.raises(ValueError, match="virtualenv"):
        cli.refuse_virtualenv({"pythonExecutable": sys.executable})
    monkeypatch.setattr(sys, "prefix", "/base")
    if not any((base / "pyvenv.cfg").exists() for base in (Path(sys.executable).parent, Path(sys.executable).parent.parent)):
        cli.refuse_virtualenv({"pythonExecutable": sys.executable})


def test_a_wrong_branch_or_a_dirty_tree_is_refused_with_the_branch_it_needs(monkeypatch):
    def git(answers):
        return lambda *args: answers.get(args, "")
    monkeypatch.setattr(cli, "_git", git({("status", "--porcelain"): "", ("branch", "--show-current"): "work/fs-txn-p13b-packet"}))
    with pytest.raises(ValueError, match=r"branch work/codex-fs-transaction \(this one is on work/fs-txn-p13b-packet\)"):
        cli.signed_source_commit()
    monkeypatch.setattr(cli, "_git", git({("status", "--porcelain"): " M x", ("branch", "--show-current"): "work/codex-fs-transaction"}))
    with pytest.raises(ValueError, match="and has uncommitted changes"):
        cli.signed_source_commit()
    monkeypatch.setattr(cli, "_git", git({("status", "--porcelain"): "", ("branch", "--show-current"): ""}))
    with pytest.raises(ValueError, match="a detached head"):
        cli.signed_source_commit()


def test_sdk_packet_scope_pins_its_own_branch_runtime_and_attempt_budget(monkeypatch):
    table = cli.table_for('p17-admin-sdk-retry')
    monkeypatch.setattr(cli, 'runner_sha256', lambda _name: 'c' * 64)
    monkeypatch.setattr(cli, 'refuse_virtualenv', lambda _runtime: None)
    value = cli.packet_value(table=table, source_commit='a' * 40, runtime={}, baseline_sha256='b' * 64, envelope_sha256='d' * 64, packet_id='fs-transaction-p17-admin-sdk-retry-test', envelope_relative='docs.local/reviews/sdk-envelope.md')
    assert value['sourceBranch'] == 'work/fs-txn-s5a-admin'
    assert value['project'] == 'fireemu-oracle-txn'
    assert value['caps'] == {'observation': 64, 'tokenCleanup': 0, 'documentCleanup': 27, 'management': 6, 'credential': 1}
    assert value['requestsPerRecording'] == 98
    assert value['scope']['writes'] == 'owned-9-documents'
    assert value['scope']['retries'] == 'sdk-aborted-callback-only-max-two'
    assert value['scope']['timingSource'] == 'grpc-js-client-interceptor'
    assert value['retries'] == value['scope']['retries']
    assert value['timingSource'] == value['scope']['timingSource']
    assert value['observationSeconds'] == 180
    assert value['recoverySeconds'] == 120


def test_sdk_source_manifest_binds_the_reused_adapter_transitively():
    manifest = cli.source_manifest('p17-admin-sdk-retry')
    assert 'tools/compat-broad/fs-write-txn/admin_sdk_retry.mjs' in manifest
    assert 'tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs' in manifest
    assert 'tools/compat-broad/fs-listen-resume/listen_journal.mjs' in manifest
    assert 'tools/compat-broad/fs-listen-resume/listen_collector.mjs' in manifest
    assert 'conformance/package.json' in manifest
