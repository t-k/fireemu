"""Exact-version program entry; production requires review, ledger authority and GO."""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import fcntl
import importlib
import json
import os
import re
import signal
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))

from txn_program_authority import authorize, envelope_scope, remaining_task_budget
from txn_program_program import budget_for, compile_plan, corpus_digest, source_digest
from txn_program_runner import record_twice, run_once, record_sdk_action
from txn_program_wire import verify_runtime
from txn_sandbox_admission import read_ledger
from txn_sandbox_runtime import require_packet_runtime

CLOSURE = ROOT / 'spec/compatibility/closure/FS-TRANSACTION.json'
# Program name -> the module holding its TABLE; the registry is closed and bound by the runner manifest.
TABLES = {'p01-lifecycle': 'fs_txn_table_p01', 'p02-readonly': 'fs_txn_table_p02', 'p02b-readonly-refused': 'fs_txn_table_p02b', 'p03-readtime': 'fs_txn_table_p03', 'p05-readlock': 'fs_txn_table_p05', 'p06-multiwrite': 'fs_txn_table_p06', 'p08-failed-commit': 'fs_txn_table_p08', 'p11-lifetime': 'fs_txn_table_p11', 'p12-first-request': 'fs_txn_table_p12', 'p13a-inferred-answers': 'fs_txn_table_p13a', 'p13b-retry-answers': 'fs_txn_table_p13b'}
FIELDS = {'schemaVersion', 'program', 'packetName', 'packetId', 'project', 'database', 'recordings', 'requestsPerRecording', 'estimatedUsdPerRecording', 'sourceCommit', 'runnerSha256', 'closureSha256', 'corpusDigest', 'planSourceDigest', 'baselineSha256', 'envelopeId', 'envelopePath', 'envelopeSha256', 'runtime', 'iamConfig', 'retries', 'onStop', 'observationSeconds', 'recoverySeconds', 'maxTokens', 'timing', 'timingSource', 'reserveUsd', 'maxUnresolvedTokens', 'releasePolicy', 'caps', 'cases', 'scope'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def table_for(name):
    if name == 'p17-admin-sdk-retry':
        return {'name': name, 'program': 'FS-TRANSACTION-P17-ADMIN-SDK-RETRY', 'slug': 'txn-p17', 'documents': [f'{case}-{role}' for case in ('conflict', 'control', 'retry', 'retry-older') for role in ('a', 'b', 'c')], 'states': ['baseline', 'writer', 'transaction-baseline', 'transaction-writer'], 'steps': [], 'cases': ['conflict', 'control', 'retry', 'retry-older'], 'caps': {'observation': 88, 'tokenCleanup': 0, 'documentCleanup': 36, 'management': 6, 'credential': 1}, 'observationSeconds': 180, 'recoverySeconds': 120, 'maxTokens': 9, 'envelopeId': 'FS-TRANSACTION-p17-admin-sdk-retry-001', 'project': 'fireemu-oracle-txn', 'sourceFile': str(HERE / 'admin_sdk_retry.mjs')}
    if not isinstance(name, str) or name not in TABLES:
        raise ValueError('program table is not registered')
    table = importlib.import_module(TABLES[name]).TABLE
    if table.get('name') != name:
        raise ValueError('program table does not carry the name it is registered under')
    return table


@lru_cache(maxsize=8)
def _source_paths(name):
    # Bind local imports transitively, plus the reviewed dynamic preflight entry and the selected table.
    table_file = Path(table_for(name)['sourceFile']).resolve()
    search = [HERE, HERE.parent, ROOT / 'tools/compat-broad/fs-request-bytes-boundary']
    pending = list(HERE.glob('*txn_program*.py')) + list(HERE.glob('*txn_program*.mjs')) + [table_file]
    pending.append(ROOT / 'tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py')
    if name == 'p17-admin-sdk-retry': pending.extend([HERE / 'admin_sdk_retry.mjs', ROOT / 'conformance/package.json'])
    result = set()
    while pending:
        path = pending.pop()
        relative = path.relative_to(ROOT).as_posix()
        if relative in result: continue
        if path.is_symlink() or not path.is_file(): raise ValueError('program source entry must be regular')
        raw = path.read_bytes(); result.add(relative)
        if path.suffix == '.mjs':
            for imported in re.findall(r'''(?:from\s+|import\s*)['"](\.[^'"]+)['"]''', raw.decode()):
                candidate = (path.parent / imported).resolve()
                if not candidate.is_relative_to(ROOT): raise ValueError('program adapter import escaped checkout')
                pending.append(candidate)
            continue
        if path.suffix != '.py': continue
        for node in ast.walk(ast.parse(raw, filename=relative)):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
            for module in modules:
                for directory in search:
                    candidate = directory / (module.replace('.', '/') + '.py')
                    if candidate.is_file(): pending.append(candidate)
    return tuple(sorted(result))


def source_manifest(name):
    paths = _source_paths(name)
    for path in list(HERE.glob('*txn_program*.py')) + list(HERE.glob('*txn_program*.mjs')):
        if path.relative_to(ROOT).as_posix() not in paths:
            raise ValueError('program source entry set changed after dependency resolution')
    result = {}
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file(): raise ValueError('program source bytes became unavailable')
        result[relative] = sha(path.read_bytes())
    return result


def runner_sha256(name):
    return sha(json.dumps(source_manifest(name), sort_keys=True, separators=(',', ':')).encode())


def requests_per_recording(table):
    return sum(table['caps'].values())


def refuse_virtualenv(runtime):
    """A packet pins the plain interpreter, never a virtualenv's. A virtualenv runs `_virtualenv.pth` and imports from a `site-packages`
    that other sessions install into, so under it the runner would run code the review did not see. A virtualenv is recognised by a
    `pyvenv.cfg` beside the pinned executable's directory or its parent, and, for the interpreter running this code, by a prefix that
    differs from the base prefix."""
    executable = runtime.get('pythonExecutable') if isinstance(runtime, dict) else None
    if executable is None:
        return
    path = Path(executable)
    if any((base / 'pyvenv.cfg').exists() for base in (path.parent, path.parent.parent)) or (executable == sys.executable and sys.prefix != sys.base_prefix):
        raise ValueError('program packet pins a virtualenv interpreter; build it with the plain interpreter')


def packet_value(*, table, source_commit, runtime, baseline_sha256, envelope_sha256, packet_id, envelope_relative, sdk_recovery=None):
    refuse_virtualenv(runtime)
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    value = {'schemaVersion': 1, 'program': table['program'], 'packetName': table['name'], 'packetId': packet_id, 'project': plan['project'], 'database': '(default)', 'recordings': 2, 'requestsPerRecording': requests_per_recording(table), 'estimatedUsdPerRecording': budget_for(plan['project'])[0], 'sourceCommit': source_commit, 'runnerSha256': runner_sha256(table['name']), 'closureSha256': sha(CLOSURE.read_bytes()), 'corpusDigest': corpus_digest(table), 'planSourceDigest': source_digest(table), 'baselineSha256': baseline_sha256, 'envelopeId': table['envelopeId'], 'envelopePath': envelope_relative, 'envelopeSha256': envelope_sha256, 'runtime': runtime, 'iamConfig': 'none', 'retries': ('sdk-aborted-callback-only-max-two' if table['name'] == 'p17-admin-sdk-retry' else 'none'), 'onStop': 'needs-recovery-lock-held', 'observationSeconds': plan['observationSeconds'], 'recoverySeconds': plan['recoverySeconds'], 'maxTokens': plan['maxTokens'], 'timing': 'wall-clock', 'timingSource': ('grpc-js-client-interceptor' if table['name'] == 'p17-admin-sdk-retry' else 'parent-wire-envelope'), 'reserveUsd': budget_for(plan['project'])[1], 'maxUnresolvedTokens': plan['maxUnresolvedTokens'], 'releasePolicy': plan['releasePolicy'], 'caps': plan['caps'], 'cases': plan['cases'], 'scope': envelope_scope(table), **({'sourceBranch': 'work/fs-txn-s5a-admin'} if table['name'] == 'p17-admin-sdk-retry' else {})}

    if sdk_recovery is not None:
        if table['name'] != 'p17-admin-sdk-retry' or not isinstance(sdk_recovery, dict) or set(sdk_recovery) != {'action', 'snapshotPath', 'snapshotSha256', 'notBefore', 'originalPacketId', 'lockSha256'}:
            raise ValueError('closed SDK recovery packet scope required')
        if sdk_recovery['action'] not in ('cleanup', 'a2') or not isinstance(sdk_recovery['snapshotPath'], str) or not sdk_recovery['snapshotPath'].startswith('docs.local/runs/') or '..' in Path(sdk_recovery['snapshotPath']).parts or not re.fullmatch(r'[a-f0-9]{64}', sdk_recovery['snapshotSha256']) or not re.fullmatch(r'[a-f0-9]{64}', sdk_recovery['lockSha256']) or not re.fullmatch(r'fs-transaction-p17-admin-sdk-retry-[A-Za-z0-9_-]{4,64}', sdk_recovery['originalPacketId']) or packet_id == sdk_recovery['originalPacketId']:
            raise ValueError('SDK recovery binding differs')
        from txn_sandbox_admission import _instant
        _instant(sdk_recovery['notBefore'])
        value['sdkRecovery'] = dict(sdk_recovery)
        value['envelopeId'] = f"FS-TRANSACTION-p17-admin-sdk-retry-{sdk_recovery['action']}-001"
        value['scope'] = {**value['scope'], 'retries': 'none', 'releasePolicy': 'sdk-recovery-lock-held', **({'writes': 'none'} if sdk_recovery['action'] == 'a2' else {})}
        value['retries'] = 'none'
        value['releasePolicy'] = 'sdk-recovery-lock-held'
    return value


def _read_packet(path, digest, *, label='packet'):
    raw = Path(path).read_bytes()
    if len(raw) > (4194304 if label == 'SDK snapshot' else 262144) or sha(raw) != digest: raise ValueError(f'program {label} bytes differ from review')
    if len(raw) > 65536 and label != 'SDK snapshot' and (label != 'packet' or json.loads(raw).get('packetName') not in {*TABLES, 'p17-admin-sdk-retry'}): raise ValueError(f'program {label} bytes differ from review')
    return json.loads(raw)


def load_packet(path, digest, baseline_path, envelope_path, *, table, source_commit, packet_relative, envelope_relative):
    value = _read_packet(path, digest)
    if not isinstance(value, dict) or set(value) != (FIELDS | {'sourceBranch'} | ({'sdkRecovery'} if 'sdkRecovery' in value else set()) if table['name'] == 'p17-admin-sdk-retry' else FIELDS) or type(value['schemaVersion']) is not int or type(value['recordings']) is not int or type(value['requestsPerRecording']) is not int:
        raise ValueError('closed program packet schema differs')
    if not isinstance(value['packetId'], str) or not re.fullmatch(rf"fs-transaction-{re.escape(table['name'])}-[A-Za-z0-9_-]{{4,64}}", value['packetId']): raise ValueError('program packet identity differs')
    if not isinstance(envelope_relative, str) or not envelope_relative.startswith('docs.local/reviews/') or '..' in Path(envelope_relative).parts or not packet_relative.startswith('docs.local/reviews/') or '..' in Path(packet_relative).parts:
        raise ValueError('program private packet or envelope path differs')
    expected = packet_value(table=table, source_commit=source_commit, runtime=value['runtime'], baseline_sha256=sha(Path(baseline_path).read_bytes()), envelope_sha256=sha(Path(envelope_path).read_bytes()), packet_id=value['packetId'], envelope_relative=envelope_relative, sdk_recovery=value.get('sdkRecovery'))
    if json.dumps(value, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
        raise ValueError('program source, scope, baseline or envelope differs')
    verify_runtime(value['runtime'])
    return {key: value[key] for key in ['packetId', 'packetName', 'sourceCommit', 'runnerSha256', 'requestsPerRecording', 'estimatedUsdPerRecording', 'reserveUsd', 'project', 'envelopeId', 'envelopePath', 'scope']} | {'packetSha256': digest, 'packetPath': packet_relative}


def review_template(pins):
    lines = ['APPROVE'] + [f'{key}={pins[key]}' for key in ['packetSha256', 'sourceCommit', 'runnerSha256', 'envelopeId']] + ['withinEnvelope=YES', 'Must=NONE', 'Should=NONE']
    return '\n'.join(lines) + '\n'


def verify_review(path, digest, pins):
    raw = Path(path).read_bytes()
    if sha(raw) != digest or raw.decode() != review_template(pins):
        raise ValueError('program exact APPROVE review with no Must or Should required')


def verify_go(go_sha256, pins):
    if go_sha256 != pins['packetSha256']:
        raise ValueError('program explicit GO must name this packet SHA-256')


def _git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def signed_source_commit(expected_branch='work/codex-fs-transaction'):
    dirty, branch = _git('status', '--porcelain'), _git('branch', '--show-current')
    if dirty or branch != expected_branch:
        raise ValueError(f"program requires a clean checkout on branch {expected_branch} (this one is on {branch or 'a detached head'}{' and has uncommitted changes' if dirty else ''})")
    commit = _git('rev-parse', 'HEAD')
    if not re.fullmatch(r'[a-f0-9]{40}', commit): raise ValueError('program source commit invalid')
    _git('verify-commit', commit)
    if _git('log', '-1', '--format=%G?') != 'G': raise ValueError('program source signature invalid')
    return commit


def assert_clean_environment():
    forbidden = {'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_OAUTH_ACCESS_TOKEN', 'FIREBASE_TOKEN', 'GCLOUD_ACCESS_TOKEN', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME'}
    if any(key.upper().endswith('_PROXY') or key.startswith('CLOUDSDK_') or key in forbidden for key in os.environ):
        raise ValueError('program proxy or credential/interpreter environment override refused')


def _private(path, main_root):
    value = Path(path).resolve(strict=True)
    if not value.is_relative_to(main_root / 'docs.local') or not value.is_file() or value.stat().st_mode & 0o777 != 0o600:
        raise ValueError('program private inputs require root docs.local and mode 600')
    return value


def main(argv=None):
    require_packet_runtime('3.12.13')
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['inspect-local', 'record-production', 'sdk-cleanup', 'sdk-a2'])
    parser.add_argument('--table')
    for name in ['packet', 'packet-sha256', 'review', 'review-sha256', 'baseline', 'go-packet-sha256']: parser.add_argument('--' + name)
    args = parser.parse_args(argv)
    if args.command == 'inspect-local':
        table = table_for(args.table)
        print(json.dumps({'runnerSha256': runner_sha256(table['name']), 'sourceManifest': source_manifest(table['name']), 'closureSha256': sha(CLOSURE.read_bytes()), 'corpusDigest': corpus_digest(table), 'planSourceDigest': source_digest(table), 'requestsPerRecording': requests_per_recording(table), 'recordings': 2, 'authorizesProduction': False}, sort_keys=True))
        return 0
    if not all([args.packet, args.packet_sha256, args.review, args.review_sha256, args.baseline, args.go_packet_sha256]): raise ValueError('program production needs exact review, packet, baseline and explicit GO')
    main_root = Path(_git('rev-parse', '--path-format=absolute', '--git-common-dir')).parent
    packet = _private(args.packet, main_root)
    review = _private(args.review, main_root)
    baseline = _private(args.baseline, main_root)
    value = _read_packet(packet, args.packet_sha256)
    table = table_for(value.get('packetName'))
    envelope_relative = value.get('envelopePath')
    if not isinstance(envelope_relative, str): raise ValueError('program envelope path missing')
    envelope = _private(main_root / envelope_relative, main_root)
    baseline_value = _read_packet(baseline, value['baselineSha256'], label='baseline')
    decisions_path = main_root / 'docs.local/instructions/owner-decisions.md'
    ledger = main_root / 'docs.local/runs/sandbox-ledger.jsonl'
    def admit():
        assert_clean_environment()
        pins = load_packet(packet, args.packet_sha256, baseline, envelope, table=table, source_commit=(signed_source_commit(value['sourceBranch']) if table['name'] == 'p17-admin-sdk-retry' else signed_source_commit()), packet_relative=packet.relative_to(main_root).as_posix(), envelope_relative=envelope_relative)
        verify_review(review, args.review_sha256, pins); verify_go(args.go_packet_sha256, pins)
        return pins
    pins = admit()
    if bool(value.get('sdkRecovery')) != (args.command in ('sdk-cleanup', 'sdk-a2')): raise ValueError('SDK action requires its own packet')
    if value.get('sdkRecovery') and args.command != 'sdk-' + value['sdkRecovery']['action']: raise ValueError('SDK action differs from packet')
    if table['name'] == 'p17-admin-sdk-retry':
        import txn_sandbox_admission as shared
        # Retain the O_EXCL launch guard for coordinator PID/inode-checked closure.
        shared.acquire_shared_lock(ledger.parent / (pins['packetId'] + '.launch-guard'), pins['packetId'])
    def check():
        if admit() != pins: raise ValueError('program admission pins changed')
        authorize(decisions_path.read_text(), pins)
        remaining_task_budget(read_ledger(ledger), 0)
    def interrupted(_signum, _frame): raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        if value.get('sdkRecovery'):
            recovery = value['sdkRecovery']
            snapshot_path = _private(main_root / recovery['snapshotPath'], main_root)
            snapshot = _read_packet(snapshot_path, recovery['snapshotSha256'], label='SDK snapshot')
            lock_path = ledger.parent / 'sandbox-locks/fireemu-oracle-txn.lock'
            with lock_path.open('rb') as guard:
                fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_raw = guard.read()
                lock_stat = os.fstat(guard.fileno())
                lock = json.loads(lock_raw)
                if sha(lock_raw) != recovery['lockSha256'] or lock.get('packetId') != recovery['originalPacketId'] or lock.get('taskId') != 'FS-TRANSACTION-SANDBOX': raise ValueError('SDK original lock differs')
                if type(lock.get('pid')) is not int or lock['pid'] <= 0: raise ValueError('SDK original PID invalid')
                try: os.kill(lock['pid'], 0)
                except ProcessLookupError: pass
                else: raise ValueError('SDK original process is still running')
                rows = read_ledger(ledger)
                if any(row.get('packetId') == pins['packetId'] for row in rows): raise ValueError('SDK recovery packet already used')
                original = [row for row in rows if row.get('packetId') == recovery['originalPacketId'] and row.get('nonce') == snapshot['nonce'] and row.get('project') == pins['project']]
                if not original or original[-1].get('outcome') not in ('reserved', 'stopped-needs-review'): raise ValueError('SDK original responsibility missing')
                not_before = shared._instant(recovery['notBefore'])
                latest = max(shared._instant(row['ts']) for row in original)
                snapshot_time = dt.datetime.fromtimestamp(snapshot_path.stat().st_mtime, dt.timezone.utc)
                if not_before < max(latest, snapshot_time) + dt.timedelta(minutes=10) or dt.datetime.now(dt.timezone.utc) < not_before: raise ValueError('SDK 10-minute A2 wait has not elapsed')
                def recovery_check():
                    check()
                    if lock_path.stat().st_ino != lock_stat.st_ino or lock_path.read_bytes() != lock_raw or sha(snapshot_path.read_bytes()) != recovery['snapshotSha256']: raise ValueError('SDK recovery responsibility changed')
                recovery_check()
                directory = ledger.parent / (pins['packetId'] + '-recovery')
                row = {'ts': dt.datetime.now(dt.timezone.utc).isoformat(), 'taskId': 'FS-TRANSACTION-SANDBOX', 'project': pins['project'], 'packetId': pins['packetId'], 'envelopeId': pins['envelopeId'], 'attemptId': pins['packetId'], 'originalPacketId': recovery['originalPacketId'], 'runDir': str(directory), 'nonce': snapshot['nonce'], 'estimatedUsd': 0.0}
                shared.append_ledger(ledger, {**row, 'outcome': 'reserved'})
                try:
                    result = record_sdk_action(table=table, snapshot=snapshot, action=recovery['action'], directory=directory, baseline=baseline_value, runtime=value['runtime'], check=recovery_check, now=lambda: dt.datetime.now(dt.timezone.utc))
                    shared.append_ledger(ledger, {**row, 'ts': dt.datetime.now(dt.timezone.utc).isoformat(), 'outcome': 'sdk-recovery-observed' if result['complete'] else 'stopped-needs-review'})
                except (Exception, KeyboardInterrupt):
                    shared.append_ledger(ledger, {**row, 'ts': dt.datetime.now(dt.timezone.utc).isoformat(), 'outcome': 'stopped-needs-review'})
                    raise
                print(json.dumps({'receiptPath': str(directory / 'sdk-recovery-receipt.json'), 'complete': result['complete'], 'lockRetained': True}))
                return 0 if result['complete'] else 1
        result = record_twice(table=table, ledger_path=ledger, private_dir=ledger.parent, pins=pins, decisions=lambda: decisions_path.read_text(), now=lambda: dt.datetime.now(dt.timezone.utc), admission_check=admit, record_once=lambda index, nonce, owner, directory: run_once(index, table, nonce, owner, directory, baseline=baseline_value, runtime=value['runtime'], check=check))
        print(json.dumps({key: str(path) for key, path in result.items()}, sort_keys=True))
    finally: signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
