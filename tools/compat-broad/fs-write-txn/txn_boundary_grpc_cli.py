"""Exact-version P10-B entry; production requires review, ledger authority and GO."""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
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

from txn_boundary_grpc_authority import authorize, remaining_task_budget
from txn_boundary_grpc_program import PROGRAM, corpus_digest, source_digest
from txn_boundary_grpc_runner import record_twice, run_once
from txn_boundary_grpc_wire import verify_runtime
from txn_sandbox_admission import read_ledger
from txn_sandbox_runtime import require_packet_runtime

CLOSURE = ROOT / 'spec/compatibility/closure/FS-TRANSACTION.json'
ENVELOPE_ID = 'FS-TRANSACTION-p10-grpc-boundary-001'
FIELDS = {'schemaVersion', 'program', 'packetName', 'packetId', 'project', 'database', 'recordings', 'requestsPerRecording', 'estimatedUsdPerRecording', 'sourceCommit', 'runnerSha256', 'closureSha256', 'corpusDigest', 'planSourceDigest', 'baselineSha256', 'envelopeId', 'envelopePath', 'envelopeSha256', 'runtime', 'iamConfig', 'retries', 'onStop', 'observationSeconds', 'recoverySeconds', 'maxTokens', 'timing', 'timingSource', 'reserveUsd', 'maxUnresolvedTokens', 'releasePolicy', 'candidates'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def _source_paths():
    # Bind local imports transitively, plus the reviewed dynamic preflight entry.
    search = [HERE, HERE.parent, ROOT / 'tools/compat-broad/fs-request-bytes-boundary']
    pending = list(HERE.glob('*txn_boundary_grpc*.py')) + list(HERE.glob('*txn_boundary_grpc*.mjs'))
    pending.append(ROOT / 'tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py')
    result = set()
    while pending:
        path = pending.pop()
        relative = path.relative_to(ROOT).as_posix()
        if relative in result: continue
        if path.is_symlink() or not path.is_file(): raise ValueError('P10-B source entry must be regular')
        raw = path.read_bytes(); result.add(relative)
        if path.suffix != '.py': continue
        for node in ast.walk(ast.parse(raw, filename=relative)):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
            for module in modules:
                for directory in search:
                    candidate = directory / (module.replace('.', '/') + '.py')
                    if candidate.is_file(): pending.append(candidate)
    return tuple(sorted(result))


def source_manifest():
    paths = _source_paths()
    for path in list(HERE.glob('*txn_boundary_grpc*.py')) + list(HERE.glob('*txn_boundary_grpc*.mjs')):
        if path.relative_to(ROOT).as_posix() not in paths:
            raise ValueError('P10-B source entry set changed after dependency resolution')
    result = {}
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file(): raise ValueError('P10-B source bytes became unavailable')
        result[relative] = sha(path.read_bytes())
    return result


def runner_sha256():
    return sha(json.dumps(source_manifest(), sort_keys=True, separators=(',', ':')).encode())


def packet_value(*, source_commit, runtime, baseline_sha256, envelope_sha256, packet_id, envelope_relative):
    return {'schemaVersion': 1, 'program': PROGRAM, 'packetName': 'p10-grpc-boundary', 'packetId': packet_id, 'project': 'fireemu-oracle-sbx', 'database': '(default)', 'recordings': 2, 'requestsPerRecording': 48, 'estimatedUsdPerRecording': 0.01, 'sourceCommit': source_commit, 'runnerSha256': runner_sha256(), 'closureSha256': sha(CLOSURE.read_bytes()), 'corpusDigest': corpus_digest(), 'planSourceDigest': source_digest(), 'baselineSha256': baseline_sha256, 'envelopeId': ENVELOPE_ID, 'envelopePath': envelope_relative, 'envelopeSha256': envelope_sha256, 'runtime': runtime, 'iamConfig': 'none', 'retries': 'none', 'onStop': 'needs-recovery-lock-held', 'observationSeconds': 1200, 'recoverySeconds': 180, 'maxTokens': 6, 'timing': 'wall-clock', 'timingSource': 'parent-wire-envelope', 'reserveUsd': 0.04, 'maxUnresolvedTokens': 1, 'releasePolicy': 'rollback-zero-before-next-sample', 'candidates': list(range(65, 71))}


def _read_packet(path, digest, *, label='packet'):
    raw = Path(path).read_bytes()
    if len(raw) > 65536 or sha(raw) != digest: raise ValueError(f'P10-B {label} bytes differ from review')
    return json.loads(raw)


def load_packet(path, digest, baseline_path, envelope_path, *, source_commit, packet_relative, envelope_relative):
    value = _read_packet(path, digest)
    if not isinstance(value, dict) or set(value) != FIELDS or type(value['schemaVersion']) is not int or type(value['recordings']) is not int or type(value['requestsPerRecording']) is not int:
        raise ValueError('closed P10-B packet schema differs')
    if not isinstance(value['packetId'], str) or not re.fullmatch(r'fs-transaction-p10b-[A-Za-z0-9_-]{4,64}', value['packetId']): raise ValueError('P10-B packet identity differs')
    if not isinstance(envelope_relative, str) or not envelope_relative.startswith('docs.local/reviews/') or '..' in Path(envelope_relative).parts or not packet_relative.startswith('docs.local/reviews/'):
        raise ValueError('P10-B private packet or envelope path differs')
    expected = packet_value(source_commit=source_commit, runtime=value['runtime'], baseline_sha256=sha(Path(baseline_path).read_bytes()), envelope_sha256=sha(Path(envelope_path).read_bytes()), packet_id=value['packetId'], envelope_relative=envelope_relative)
    if json.dumps(value, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
        raise ValueError('P10-B source, scope, baseline or envelope differs')
    verify_runtime(value['runtime'])
    return {key: value[key] for key in ['packetId', 'packetName', 'sourceCommit', 'runnerSha256', 'requestsPerRecording', 'estimatedUsdPerRecording', 'envelopeId', 'envelopePath']} | {'packetSha256': digest, 'packetPath': packet_relative}


def review_template(pins):
    lines = ['APPROVE'] + [f'{key}={pins[key]}' for key in ['packetSha256', 'sourceCommit', 'runnerSha256', 'envelopeId']] + ['withinEnvelope=YES', 'Must=NONE', 'Should=NONE']
    return '\n'.join(lines) + '\n'


def verify_review(path, digest, pins):
    raw = Path(path).read_bytes()
    if sha(raw) != digest or raw.decode() != review_template(pins):
        raise ValueError('P10-B exact APPROVE review with no Must or Should required')


def verify_go(go_sha256, pins):
    if go_sha256 != pins['packetSha256']:
        raise ValueError('P10-B explicit GO must name this packet SHA-256')


def _git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def signed_source_commit():
    if _git('status', '--porcelain') or _git('branch', '--show-current') != 'work/codex-fs-transaction':
        raise ValueError('P10-B requires its clean isolated branch')
    commit = _git('rev-parse', 'HEAD')
    if not re.fullmatch(r'[a-f0-9]{40}', commit): raise ValueError('P10-B source commit invalid')
    _git('verify-commit', commit)
    if _git('log', '-1', '--format=%G?') != 'G': raise ValueError('P10-B source signature invalid')
    return commit


def assert_clean_environment():
    forbidden = {'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_OAUTH_ACCESS_TOKEN', 'FIREBASE_TOKEN', 'GCLOUD_ACCESS_TOKEN', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME'}
    if any(key.upper().endswith('_PROXY') or key.startswith('CLOUDSDK_') or key in forbidden for key in os.environ):
        raise ValueError('P10-B proxy or credential/interpreter environment override refused')


def _private(path, main_root):
    value = Path(path).resolve(strict=True)
    if not value.is_relative_to(main_root / 'docs.local') or not value.is_file() or value.stat().st_mode & 0o777 != 0o600:
        raise ValueError('P10-B private inputs require root docs.local and mode 600')
    return value


def main(argv=None):
    require_packet_runtime('3.12.13')
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['inspect-local', 'record-production'])
    for name in ['packet', 'packet-sha256', 'review', 'review-sha256', 'baseline', 'go-packet-sha256']: parser.add_argument('--' + name)
    args = parser.parse_args(argv)
    if args.command == 'inspect-local':
        print(json.dumps({'runnerSha256': runner_sha256(), 'sourceManifest': source_manifest(), 'closureSha256': sha(CLOSURE.read_bytes()), 'corpusDigest': corpus_digest(), 'planSourceDigest': source_digest(), 'requestsPerRecording': 48, 'recordings': 2, 'authorizesProduction': False}, sort_keys=True))
        return 0
    if not all([args.packet, args.packet_sha256, args.review, args.review_sha256, args.baseline, args.go_packet_sha256]): raise ValueError('P10-B production needs exact review, packet, baseline and explicit GO')
    main_root = Path(_git('rev-parse', '--path-format=absolute', '--git-common-dir')).parent
    packet = _private(args.packet, main_root)
    review = _private(args.review, main_root)
    baseline = _private(args.baseline, main_root)
    value = _read_packet(packet, args.packet_sha256)
    envelope_relative = value.get('envelopePath')
    if not isinstance(envelope_relative, str): raise ValueError('P10-B envelope path missing')
    envelope = _private(main_root / envelope_relative, main_root)
    baseline_value = _read_packet(baseline, value['baselineSha256'], label='baseline')
    decisions_path = main_root / 'docs.local/instructions/owner-decisions.md'
    ledger = main_root / 'docs.local/runs/sandbox-ledger.jsonl'
    def admit():
        assert_clean_environment()
        pins = load_packet(packet, args.packet_sha256, baseline, envelope, source_commit=signed_source_commit(), packet_relative=packet.relative_to(main_root).as_posix(), envelope_relative=envelope_relative)
        verify_review(review, args.review_sha256, pins); verify_go(args.go_packet_sha256, pins)
        return pins
    pins = admit()
    def check():
        if admit() != pins: raise ValueError('P10-B admission pins changed')
        authorize(decisions_path.read_text(), pins)
        remaining_task_budget(read_ledger(ledger), 0)
    def interrupted(_signum, _frame): raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        result = record_twice(ledger_path=ledger, private_dir=ledger.parent, pins=pins, decisions=lambda: decisions_path.read_text(), now=lambda: dt.datetime.now(dt.timezone.utc), admission_check=admit, record_once=lambda index, nonce, owner, directory: run_once(index, nonce, owner, directory, baseline=baseline_value, runtime=value['runtime'], check=check))
        print(json.dumps({key: str(path) for key, path in result.items()}, sort_keys=True))
    finally: signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
