"""Replay the closed public transaction expectations using the supplied installed binary."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import signal
import time
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
INPUT = ROOT / 'spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json'
KEYS = ('p01', 'p02', 'p02b', 'p03', 'p05', 'p08', 'p09', 'p10a', 'p10b', 'p10c', 'p11', 'p12', 'p13a', 'p13b', 'p14', 'p16')
SECTIONS = ('cases', 'reads', 'commitTimes', 'skipped', 'idleCandidates', 'orders', 'clock', 'tokenAges')
ACTIVE = set()
ACTIVE_LOCK = threading.Lock()
STOP = threading.Event()
DEADLINE = None


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def row_id(row):
    return row.get('caseId', row.get('site'))


def result_rows(prefix, value, inventory):
    if value.get('complete') is not True or value.get('failure') is not None or value.get('mismatches') != 0:
        raise ValueError(f'{prefix}: actual collector failed')
    rows = []
    for section, expected in inventory.items():
        actual = value.get(section) or []
        identities = [row_id(row) for row in actual]
        if len(set(identities)) != len(identities) or sorted(identities) != sorted(expected) or any(row.get('match') is not True for row in actual):
            raise ValueError(f'{prefix}: {section} inventory or response differs')
        rows.extend({'row': f'{prefix}/{section}/{identity}', 'status': 'MATCH'} for identity in identities)
    return rows


def load_inputs(path=INPUT):
    value = json.loads(path.read_text())
    if value.get('kind') != 'fs-transaction-release-replay-inputs-v1' or [recipe.get('key') for recipe in value.get('programs', [])] != list(KEYS):
        raise ValueError('closed recipe inventory differs')
    if set(value.get('special', {})) != {'e04', 'p17', 'web', 'listen'}:
        raise ValueError('special recipe inventory differs')
    for kind, recipe in value['special'].items():
        if len(recipe.get('recordings', [])) != 2:
            raise ValueError(f'{kind}: recording inventory differs')
    for recipe in value['programs']:
        if len(recipe['recordings']) != 2 or any(not item.get('inventory') for item in recipe['recordings']):
            raise ValueError('recording inventory missing')
    return value


def validate_export(value, expected, binary_sha):
    if value.get('artifactSha256') != binary_sha or any(value.get(key) != expected.get(key) for key in ('kind', 'fixtureSha256', 'summary', 'rows')):
        raise ValueError('release inventory, semantic rows, fixture or installed binary binding differs')


def validate_expiry(value):
    idles = value['replay']['localIdleSeconds']
    expiry = ('idle/commit-after', 'idle/rollback-after', 'idle/lock-released')
    if value['summary']['mismatches'] or value['summary']['rows'] != 36 or set(idles) != {'idle/commit-before', *expiry} or idles['idle/commit-before'] != 20 or any(not 120 < idles[site] < 122.96 for site in expiry):
        raise ValueError('expiry replay responses or idle boundaries differ')


def invoke(argv, out, env=None, cwd=HERE):
    command = [str(arg) for arg in argv]
    if STOP.is_set():
        raise InterruptedError('release replay interrupted')
    started = time.monotonic()
    with out.open('wb') as log:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        with ACTIVE_LOCK:
            ACTIVE.add(child)
        try:
            timeout = 580 if DEADLINE is None else max(0.01, DEADLINE - time.monotonic())
            code = child.wait(timeout=timeout)
            if code:
                raise subprocess.CalledProcessError(code, command)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            with ACTIVE_LOCK:
                ACTIVE.discard(child)
            out.with_suffix(out.suffix + '.process.json').write_text(json.dumps({'pid': child.pid, 'argv': command, 'exitCode': child.returncode, 'reaped': child.poll() is not None, 'elapsedSeconds': time.monotonic() - started}, indent=2) + '\n')


def environment():
    env = dict(os.environ)
    for key in ('NODE_PATH', 'NODE_OPTIONS', 'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT', 'FIRESTORE_EMULATOR_HOST', 'AUTH_EMULATOR_HOST'):
        env.pop(key, None)
    env.update(PYTHONPATH=f'{ROOT}/tools/compat-broad:{ROOT}/tools/compat-inventory', NODE_BINARY=shutil.which('node') or '')
    return env


def exec_args(binary, config, project, only='firestore'):
    return [binary, 'exec', '--config', config, '--project', project, '--only', only, '--firestore-port', '0', '--http-port', '0', '--hub-port', '0', '--ui-port', '0', '--logging-port', '0', '--log-verbosity', 'silent', '--']


def p16_command(nonce, script, expectation, result):
    # Patch only the comparison entry point, as the original named-database adapter does.
    bootstrap = "import sys,fs_txn_compare_local as m; nonce=sys.argv[1]; original=m.compile_plan; m.compile_plan=lambda table,unused,owner:original(table,nonce,owner);sys.argv=sys.argv[2:];m.main()"
    return [sys.executable, '-c', bootstrap, nonce, str(script), str(expectation), str(result)]


def run_program(binary, binary_sha, out, recipe, number, tools):
    label = f"{recipe['key']}-r{number}"
    entry = recipe['recordings'][number - 1]
    expectation = out / f'{label}.input.json'
    expectation.write_text(json.dumps(entry['expectation']))
    result = out / f'{label}.json'
    env = environment()
    env.update(COMPARE_PROFILE='strict', COMPARE_CLOCK=recipe['clock'], COMPARE_BINARY_SHA256=binary_sha)
    config = json.loads((ROOT / 'tools/sdk-smoke/fireemu.smoke.json').read_text())
    if recipe['family'] == 'framework':
        env['SMOKE_TABLE'] = recipe['table']
        script = 'fs_txn_compare_local.py'
    else:
        env['SMOKE_FAMILY'] = recipe['family']
        script = 'fs_txn_compare_local_grpc.py'
    if recipe.get('frozen'):
        frozen = recipe['frozen']
        env.update(COMPARE_CLOCK_START=frozen['start'], COMPARE_ADVANCE_SECONDS=str(frozen['advanceSeconds']), COMPARE_ADVANCE_AFTER=frozen['advanceAfter'])
        config['daemon'] = {**config.get('daemon', {}), 'clockStart': frozen['start']}
    child = [sys.executable, tools / script, expectation, result]
    if recipe['key'] == 'p16':
        nonce = os.urandom(16).hex()
        firebase = out / f'{label}.firebase.json'
        firebase.write_text(json.dumps({'firestore': [{'database': '(default)'}, {'database': f'txn-{nonce}'}]}))
        config['firebaseJson'] = str(firebase)
        child = p16_command(nonce, tools / script, expectation, result)
    config_path = out / f'{label}.config.json'
    config_path.write_text(json.dumps(config))
    invoke(exec_args(binary, config_path, 'demo-program')[:-1] + ['--ready-file', str(out / f'{label}.ready.json'), '--'] + child, out / f'{label}.log', env, tools)
    return result_rows(f"{recipe['key']}/r{number}", json.loads(result.read_text()), entry['inventory'])


def run_release(binary, out):
    global DEADLINE
    DEADLINE = time.monotonic() + 570
    source = load_inputs()
    binary = binary.resolve(strict=True)
    binary_sha = digest(binary)
    out.mkdir(parents=True, exist_ok=False)
    node = shutil.which('node')
    if not node:
        raise ValueError('Node runtime missing')
    overlays = []
    try:
        programs = []
        for recipe in source['programs']:
            tools = HERE
            if recipe.get('asRecorded'):
                tools = Path(tempfile.mkdtemp(prefix='fs-write-txn-release-', dir=HERE.parent))
                overlays.append(tools)
                shutil.copytree(HERE, tools, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
                for binding in recipe['asRecorded']:
                    name = Path(binding['path']).name
                    if binding['path'] != f'tools/compat-broad/fs-write-txn/{name}':
                        raise ValueError('historical source path differs')
                    subprocess.run(['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', binding['commit'], 'HEAD'], check=True)
                    blob = subprocess.check_output(['git', '-C', str(ROOT), 'show', f"{binding['commit']}:{binding['path']}"])
                    if hashlib.sha256(blob).hexdigest() != binding['sha256']:
                        raise ValueError('historical source digest differs')
                    (tools / name).write_bytes(blob)
            programs.extend((recipe, number, tools) for number in (1, 2))
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = [row for batch in pool.map(lambda job: run_program(binary, binary_sha, out, *job), programs) for row in batch]
        rows.extend(run_special(binary, binary_sha, out, source['special'], node))
        if digest(binary) != binary_sha:
            raise ValueError('installed binary changed during replay')
        rows.sort(key=lambda row: row['row'])
        if len({row['row'] for row in rows}) != len(rows):
            raise ValueError('duplicate release row')
        result = {'kind': 'fs-transaction-integrated-regression-v1', 'artifactSha256': binary_sha, 'fixtureSha256': digest(INPUT), 'summary': {'rows': len(rows), 'MATCH': len(rows)}, 'rows': rows}
        expected = json.loads(INPUT.with_name('fs-transaction-integrated-regression-v1.json').read_text())
        validate_export(result, expected, binary_sha)
        return result
    finally:
        for tools in overlays:
            shutil.rmtree(tools)
        expiry_overlay = HERE.parent / 'fs-write-txn-overlay-idle'
        if expiry_overlay.exists():
            shutil.rmtree(expiry_overlay)


def run_special(binary, binary_sha, out, special, node):
    def acquire(kind):
        expectation = out / f'{kind}.input.json'
        expectation.write_text(json.dumps(special[kind]))
        if kind == 'e04':
            result = out / 'e04.json'
            invoke([sys.executable, HERE / 'fs_txn_expiry_idle_replay.py', '--binary', binary, '--expectations', expectation, '--out', result, '--keep', out / 'e04-shadow'], out / 'e04.log', environment())
            value = json.loads(result.read_text())
            validate_expiry(value)
            return [{'row': f"e04/r{entry['recording']}/{row['caseId']}", 'status': 'MATCH'} for entry in value['recordings'] for row in entry['rows'] if row['match'] is True]
        rows = []
        for local_number in ((1, 2) if kind == 'p17' else (1,)):
            result = out / f'{kind}-local-{local_number}.json'
            env = environment()
            config = out / f'{kind}.config.json'
            config.write_text(json.dumps({'schemaVersion': 1, 'profile': 'strict'}))
            transient = None
            if kind == 'p17':
                transient = ROOT / 'target/codex-out' / f'release-p17-{os.urandom(16).hex()}.json'
                command = exec_args(binary, config, 'demo-admin-retry') + [node, HERE / 'admin_sdk_retry.mjs', 'local', transient]
            elif kind == 'web':
                rules = out / 'web.rules'
                rules.write_text("rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{collection}/{document} { allow read, write: if collection.matches('^s5b_[a-f0-9]{32}$'); } } }\n")
                config.write_text(json.dumps({'schemaVersion': 1, 'profile': 'strict', 'rules': {'source': str(rules)}}))
                env.pop('S5B_ARTIFACT_SOURCE', None)
                env.update(S5B_FIREEMU=str(binary), S5B_RECEIPT=str(result))
                command = exec_args(binary, config, 'demo-web-retry', 'auth,firestore') + [node, HERE / 'web_sdk_retry.mjs']
            else:
                env['FIREEMU_BIN'] = str(binary)
                command = [node, ROOT / 'conformance/src/fs-listen/record.mjs', 'native', '--target', 'local', '--profile', 'strict', '--out', result]
            try:
                invoke(command, out / f'{kind}-local-{local_number}.log', env)
                if transient:
                    shutil.copyfile(transient, result)
                receipt = json.loads(result.read_text())
                if kind == 'web' and receipt['bindings']['artifact']['sha256'] != binary_sha or kind == 'listen' and (receipt['provenance']['binarySha256'] != binary_sha or receipt['provenance']['profile'] != 'strict' or receipt['provenance']['buildInputs']['dirty'] is not False):
                    raise ValueError('local artifact binding differs')
                compared = out / f'{kind}-local-{local_number}.comparison.json'
                invoke([node, HERE / 'txn_release_compare.mjs', 'compare', expectation, result, compared], out / f'{kind}-local-{local_number}.comparison.log', env)
                actual_rows = json.loads(compared.read_text())
                if kind == 'p17':
                    actual_rows = [{**row, 'row': f"p17/local{local_number}/" + row['row'].removeprefix('p17/')} for row in actual_rows]
                rows.extend(actual_rows)
            finally:
                if transient:
                    transient.unlink(missing_ok=True)
        return rows
    with ThreadPoolExecutor(max_workers=2) as pool:
        return [row for batch in pool.map(acquire, ('e04', 'p17', 'web', 'listen')) for row in batch]


def interrupt(*_):
    STOP.set()
    with ACTIVE_LOCK:
        for child in ACTIVE:
            if child.poll() is None and os.getpgid(child.pid) == child.pid:
                os.killpg(child.pid, signal.SIGTERM)
    raise KeyboardInterrupt()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('check', 'export', 'export-comparison'))
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    output = args.out.resolve()
    runs = output if args.action == 'check' else output.parent / (output.name + '.replay')
    result = run_release(args.binary, runs)
    destination = runs / 'comparison.json' if args.action == 'check' else output
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
