#!/usr/bin/env python3
"""Run the real macOS integration test with bounded, local emulator processes."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
REQUIRED = [
    'firestore.write-read', 'firestore.transforms', 'firestore.query',
    'firestore.listener', 'firestore.transaction', 'firestore.offline-resume',
    'firestore.batch-delete', 'firestore.rules-anonymous-denied',
    'firestore.rules-owner', 'firestore.rules-signout',
    'auth.signup', 'auth.signin', 'auth.refresh',
    'storage.upload-download', 'storage.metadata', 'storage.resumable',
    'storage.download-url', 'storage.list-delete', 'storage.rules-denied',
    'database.set-read', 'database.listener', 'database.transaction',
    'database.on-disconnect', 'flutter.timestamp-roundtrip',
    'flutter.fieldvalue-roundtrip', 'flutter.firestore-stream-error',
    'flutter.database-stream-error',
]
CLASSES = {'ok', 'assertion', 'sdk-error', 'timeout', 'macos-keychain-provisioning', 'prerequisite'}


def summarize(records, required):
    indexed = {}
    for record in records:
        if set(record) != {'case', 'status', 'classification'}:
            raise ValueError('Unexpected result fields.')
        case = record['case']
        if case not in required or case in indexed:
            raise ValueError('Unknown or duplicate case.')
        if record['status'] not in {'passed', 'failed', 'blocked'} or record['classification'] not in CLASSES:
            raise ValueError('Unsafe result classification.')
        indexed[case] = record
    cases = [indexed.get(case, {'case': case, 'status': 'blocked', 'classification': 'prerequisite'}) for case in required]
    return {'passed': all(case['status'] == 'passed' for case in cases), 'cases': cases}


def execute(command, environment, directory, log, seconds):
    """Own the process group from launch through deadline and cleanup."""
    def terminated(signum, frame):
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, terminated)
    process = None
    try:
        with log.open('x') as output:
            process = subprocess.Popen(command, cwd=directory, env=environment, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                return process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                return 124
    finally:
        try:
            if process is not None and process.poll() is None:
                try:
                    if os.getpgid(process.pid) == process.pid:
                        os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        finally:
            signal.signal(signal.SIGTERM, previous)


def environment():
    env = os.environ.copy()
    for key in ['GOOGLE_APPLICATION_CREDENTIALS', 'FIREBASE_TOKEN',
                'GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'FIREBASE_CONFIG']:
        env.pop(key, None)
    env.pop('LUCI_CI', None)
    env.update({
        'PATH': str(ROOT / 'scripts') + os.pathsep + str(ROOT / '.toolchain/node/bin') + os.pathsep + env['PATH'],
        'PUB_CACHE': str(ROOT / '.pub-cache'),
        'CP_HOME_DIR': str(ROOT / '.cocoapods'),
        'CP_CACHE_DIR': str(ROOT / '.cocoapods/cache'),
        'FLUTTER_SUPPRESS_ANALYTICS': 'true',
        'FLUTTER_XCODE_CODE_SIGN_ENTITLEMENTS': 'Runner/DebugProfile.entitlements',
        'FIREBASE_CLI_DISABLE_UPDATE_CHECK': 'true',
        'FIREBASE_EMULATORS_PATH': str(ROOT / '.emulator-cache'),
        'XDG_CONFIG_HOME': str(ROOT / '.local-config'),
        'CLOUDSDK_CONFIG': str(ROOT / '.local-config/gcloud'),
        'GCLOUD_PROJECT': 'demo-app',
        'GOOGLE_CLOUD_PROJECT': 'demo-app',
        'CI': 'true',
        'JAVA_TOOL_OPTIONS': '-Xms128m -Xmx1g',
    })
    return env


def child(backend, run_id):
    env = environment()
    flutter = ROOT / '.toolchain/flutter/bin/flutter'
    command = [str(flutter), 'test', 'integration_test/smoke_test.dart', '-d', 'macos', '--reporter', 'expanded']
    for key in ['GCLOUD_PROJECT', 'FIRESTORE_EMULATOR_HOST', 'FIREBASE_AUTH_EMULATOR_HOST', 'FIREBASE_STORAGE_EMULATOR_HOST', 'FIREBASE_DATABASE_EMULATOR_HOST']:
        value = env.get(key)
        if not value:
            raise ValueError('Required emulator endpoint is missing.')
        command.append('--dart-define=' + key + '=' + value)
    log = ROOT / 'reports' / (run_id + '-' + backend + '-native.raw.log')
    started = time.monotonic()
    status = execute(command, env, ROOT, log, 900)
    records = []
    with log.open() as lines:
        for line in lines:
            if 'FIREEMU_CASE ' in line:
                records.append(json.loads(line.split('FIREEMU_CASE ', 1)[1]))
    summary = summarize(records, REQUIRED)
    summary.update({'backend': backend, 'processExit': status, 'seconds': round(time.monotonic() - started, 3)})
    summary['passed'] = summary['passed'] and status == 0
    report = ROOT / 'reports' / (run_id + '-' + backend + '.json')
    with report.open('x') as output:
        json.dump(summary, output, indent=2)
        output.write('\n')
    for case in summary['cases']:
        print(json.dumps(case), flush=True)
    return 0 if summary['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['fireemu', 'official', 'both'], default='both')
    parser.add_argument('--fireemu', type=Path, default=ROOT / '../../target/debug/fireemu')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run-id', help=argparse.SUPPRESS)
    args = parser.parse_args()
    (ROOT / 'reports').mkdir(exist_ok=True)
    run_id = args.run_id or datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    if args.child:
        return child(args.backend, run_id)
    backends = ['fireemu', 'official'] if args.backend == 'both' else [args.backend]
    overall = 0
    for backend in backends:
        child_command = [sys.executable, str(ROOT / 'run.py'), '--child', '--backend', backend, '--run-id', run_id]
        if backend == 'fireemu':
            command = [str(args.fireemu.resolve()), 'exec', '--project', 'demo-app', '--firebase-json', str(ROOT / 'firebase.json'), '--only', 'auth,firestore,storage,database', '--hub-port', '0', '--logging-port', '0', '--', *child_command]
        else:
            command = [str(ROOT / 'node_modules/.bin/firebase'), 'emulators:exec', '--project', 'demo-app', '--config', str(ROOT / 'firebase.json'), '--only', 'auth,firestore,storage,database', '--non-interactive', shlex.join(child_command)]
        log = ROOT / 'reports' / (run_id + '-' + backend + '-emulators.raw.log')
        with tempfile.TemporaryDirectory(prefix='flutter-smoke-') as directory:
            status = execute(command, environment(), directory, log, 1020)
        report = ROOT / 'reports' / (run_id + '-' + backend + '.json')
        if not report.exists():
            summary = summarize([], REQUIRED)
            summary.update({'backend': backend, 'processExit': status, 'seconds': None})
            with report.open('x') as output:
                json.dump(summary, output, indent=2)
                output.write('\n')
        summary = json.loads(report.read_text())
        overall |= int(status != 0 or not summary['passed'])
        print(backend + ': ' + str(sum(case['status'] == 'passed' for case in summary['cases'])) + '/' + str(len(REQUIRED)) + ' passed; exit=' + str(status), flush=True)
    return overall


if __name__ == '__main__':
    sys.exit(main())
