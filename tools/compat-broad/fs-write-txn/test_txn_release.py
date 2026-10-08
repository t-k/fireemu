"""Release replay refuses incomplete expectations and unsuccessful actual collectors."""
import copy
import importlib
import pytest


def test_public_expectation_requires_all_evidence():
    publisher = importlib.import_module('publish_recorded_comparison')
    value = {'kind': 'txn-release-expectation-v1', 'projection': {}, 'commitRelations': {}, 'dispatchGaps': {}, 'waitGaps': {}, 'tokenAges': {}, 'orders': {}, 'clockEvidence': {}}
    assert publisher.release_input(value, native=False) == value
    for key in ('projection', 'commitRelations', 'dispatchGaps', 'waitGaps', 'tokenAges', 'orders', 'clockEvidence'):
        changed = copy.deepcopy(value)
        del changed[key]
        with pytest.raises(ValueError, match='missing'):
            publisher.release_input(changed, native=False)


def test_native_expectation_requires_pacing_and_age_evidence():
    publisher = importlib.import_module('publish_recorded_comparison')
    value = {'kind': 'txn-release-expectation-v1', 'projection': {}, 'idleGaps': {}, 'tokenAges': {}}
    assert publisher.release_input(value, native=True) == value
    for key in ('idleGaps', 'tokenAges'):
        changed = copy.deepcopy(value)
        del changed[key]
        with pytest.raises(ValueError, match='missing'):
            publisher.release_input(changed, native=True)


def test_actual_result_refuses_failure_even_with_success_exit():
    release = importlib.import_module('fs_txn_release')
    value = {'complete': True, 'failure': None, 'mismatches': 0, 'cases': [{'caseId': 'a', 'match': True}], 'reads': []}
    expected = {'cases': ['a'], 'reads': []}
    assert release.result_rows('p01/r1', value, expected) == [{'row': 'p01/r1/cases/a', 'status': 'MATCH'}]
    for changed in ({**value, 'complete': False}, {**value, 'failure': 'runtime'}, {**value, 'mismatches': 1}, {**value, 'cases': []}, {**value, 'cases': value['cases'] * 2}, {**value, 'cases': [{'caseId': 'a', 'match': False}]}):
        with pytest.raises(ValueError):
            release.result_rows('p01/r1', changed, expected)


def test_listen_uses_recording_row_map_and_rejects_unfinished():
    import subprocess
    from pathlib import Path
    module = (Path(__file__).parent / 'txn_release_compare.mjs').as_uri()
    code = f"""import assert from 'node:assert/strict';import {{projectListen}} from {module!r};
const receipt={{version:1,cleanup:{{complete:true}},rows:{{atomic:{{rows:[],end:{{code:0}}}}}}}};
assert.equal(projectListen(receipt,['atomic']).length,1);
receipt.rows.atomic.programError=true;assert.throws(()=>projectListen(receipt,['atomic']));"""
    subprocess.run(['node', '--input-type=module', '-e', code], check=True)


def test_missing_saved_recipe_is_refused(tmp_path):
    import json
    release = importlib.import_module('fs_txn_release')
    value = json.loads(release.INPUT.read_text())
    value['programs'].pop()
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='inventory'):
        release.load_inputs(path)


def test_age_limit_side_is_not_hidden_by_tolerance():
    from txn_replay_clock import judge_token_ages
    rows = judge_token_ages({'commit': 120.5}, {'commit': 119.8}, tolerance=4, minimum=100)
    assert rows and rows[0]['match'] is False


def test_projected_sdk_response_mutation_and_listen_filter_change():
    import json
    import subprocess
    from pathlib import Path
    tools = Path(__file__).parent
    module = (tools / 'txn_release_compare.mjs').as_uri()
    admin = (tools / 'admin_sdk_retry.mjs').as_uri()
    fixture = tools.parents[2] / 'spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json'
    code = f"""import assert from 'node:assert/strict';import {{readFileSync}} from 'node:fs';import {{compareAdminProjections}} from {admin!r};import {{compareListenProjection}} from {module!r};
const source=JSON.parse(readFileSync({str(fixture)!r}));const left=source.special.p17.recordings[0].projection,right=structuredClone(left);
assert.equal(compareAdminProjections(left,right).mismatches,0);right.cases[0].attempts[0].refusalCode=999;assert.ok(compareAdminProjections(left,right).mismatches>0);
assert.equal(compareListenProjection({{id:'atomic',canonical:{{}},places:{{p:['a']}}}},{{id:'atomic',canonical:{{}},places:{{p:['b']}}}}),false);
assert.equal(compareListenProjection({{id:'atomic',canonical:{{}},places:{{p:['a']}}}},{{id:'atomic',canonical:{{}},places:{{}}}},{{id:'atomic',canonical:{{}},places:{{}}}}),true);"""
    subprocess.run(['node', '--input-type=module', '-e', code], check=True)


def test_real_clock_does_not_derive_virtual_pacing(monkeypatch):
    import txn_replay_clock
    publisher = importlib.import_module('publish_recorded_comparison')
    def forbidden(_):
        raise AssertionError('real and frozen recordings do not use virtual dispatch pacing')
    monkeypatch.setattr(txn_replay_clock, 'production_age_steps', forbidden)
    value = publisher.release_expectation({'complete': True, 'failureType': None, 'steps': []}, {'steps': []}, {}, clock='real')
    assert value['dispatchGaps'] == value['waitGaps'] == value['tokenAges'] == {}


def test_both_original_special_recordings_are_required(tmp_path):
    import json
    release = importlib.import_module('fs_txn_release')
    for kind in ('e04', 'p17', 'web', 'listen'):
        value = json.loads(release.INPUT.read_text())
        value['special'][kind]['recordings'].pop()
        path = tmp_path / f'{kind}.json'
        path.write_text(json.dumps(value))
        with pytest.raises(ValueError, match='recording inventory'):
            release.load_inputs(path)


def test_final_export_requires_all_rows_and_installed_binary_binding():
    import json
    release = importlib.import_module('fs_txn_release')
    fixture = json.loads(release.INPUT.with_name('fs-transaction-integrated-regression-v1.json').read_text())
    value = {**fixture, 'artifactSha256': 'a' * 64}
    release.validate_export(value, fixture, 'a' * 64)
    for changed in ({**value, 'artifactSha256': 'b' * 64}, {**value, 'rows': value['rows'][:-1]}, {**value, 'fixtureSha256': '0' * 64}, {**value, 'summary': {'rows': 0, 'MATCH': 0}}):
        with pytest.raises(ValueError):
            release.validate_export(changed, fixture, 'a' * 64)


def test_expiry_control_keeps_its_twenty_second_wait():
    release = importlib.import_module('fs_txn_release')
    value = {'summary': {'mismatches': 0, 'rows': 36}, 'replay': {'localIdleSeconds': {'idle/commit-before': 20.0, 'idle/commit-after': 121.0, 'idle/rollback-after': 121.0, 'idle/lock-released': 121.0}}}
    release.validate_expiry(value)
    changed = copy.deepcopy(value)
    changed['replay']['localIdleSeconds']['idle/commit-after'] = 119.8
    with pytest.raises(ValueError):
        release.validate_expiry(changed)


@pytest.mark.parametrize('gap', [float('nan'), float('inf'), -1, True])
def test_invalid_relative_age_is_refused(gap):
    publisher = importlib.import_module('publish_recorded_comparison')
    value = {'kind': 'txn-release-expectation-v1', 'projection': {}, 'idleGaps': {'commit': gap}, 'tokenAges': {}}
    with pytest.raises(ValueError, match='relative'):
        publisher.release_input(value, native=True)


def test_named_database_bootstrap_captures_nonce_without_changing_projector():
    import subprocess
    release = importlib.import_module('fs_txn_release')
    nonce = '1' * 32
    command = release.p16_command(nonce, 'comparison.py', 'expectation.json', 'result.json')
    prefix = """import sys,types
p=types.ModuleType('txn_program_program');p.compile_plan=lambda table,nonce,owner:nonce
m=types.ModuleType('fs_txn_compare_local');m.compile_plan=p.compile_plan
original=p.compile_plan
def main():
 assert sys.argv==['comparison.py','expectation.json','result.json']
 assert m.compile_plan({},'unused','owner')=='1'*32
 assert p.compile_plan is original
m.main=main
sys.modules['txn_program_program']=p;sys.modules['fs_txn_compare_local']=m
"""
    subprocess.run([command[0], '-c', prefix + command[2], *command[3:]], check=True)


@pytest.mark.parametrize('signal_name', ['SIGTERM', 'SIGINT'])
def test_cli_interrupt_reaps_active_executor_child(tmp_path, signal_name):
    import json
    import os
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path
    release = importlib.import_module('fs_txn_release')
    code = """import json,sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,sys.argv[1])
import fs_txn_release as release
out=Path(sys.argv[2])
def blocked(*args):
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            pool.submit(release.invoke,[sys.executable,'-c','import os,time;print(os.getpid(),flush=True);time.sleep(30)'],out/'child.log').result()
    finally:
        (out/'stop.json').write_text(json.dumps({'stop':release.STOP.is_set()}))
release.run_release=blocked
release.main(['check','--binary',sys.executable,'--out',str(out/'unused')])
"""
    child_pid = None
    timed_out = False
    with (tmp_path / 'parent.stdout').open('wb') as stdout, (tmp_path / 'parent.stderr').open('wb') as stderr:
        parent = subprocess.Popen([sys.executable, '-c', code, str(Path(release.__file__).parent), str(tmp_path)], stdout=stdout, stderr=stderr)
        try:
            ready_deadline = time.monotonic() + 10
            while time.monotonic() < ready_deadline:
                log = tmp_path / 'child.log'
                if log.exists() and log.read_text().strip():
                    child_pid = int(log.read_text().strip())
                    break
                assert parent.poll() is None, 'interruption setup exited'
                time.sleep(.01)
            assert child_pid is not None, 'blocked child never became ready'
            identities = subprocess.check_output(['ps', '-p', f'{parent.pid},{child_pid}', '-o', 'pid=,ppid=,comm=,args='], text=True)
            (tmp_path / 'owned-processes.txt').write_text(identities)
            started = time.monotonic()
            parent.send_signal(getattr(signal, signal_name))
            try:
                parent.wait(timeout=3)
            except subprocess.TimeoutExpired:
                timed_out = True
            elapsed = time.monotonic() - started
        finally:
            if parent.poll() is None:
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=10)
    receipt_path = tmp_path / 'child.log.process.json'
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {'reaped': False}
    try:
        os.kill(child_pid, 0)
    except ProcessLookupError:
        absent = True
    else:
        absent = False
    stop = json.loads((tmp_path / 'stop.json').read_text())['stop']
    proof = {'signal': signal_name, 'parentPid': parent.pid, 'childPid': child_pid, 'parentExit': parent.returncode, 'timedOut': timed_out, 'elapsedSeconds': elapsed, 'childReaped': receipt['reaped'], 'childAbsent': absent, 'stopAfterCleanup': stop, 'networkOperations': 0}
    (tmp_path / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    assert not timed_out, proof
    assert receipt['reaped'] and absent
    assert parent.returncode != 0 and stop
    assert not (tmp_path / 'unused/comparison.json').exists()


def test_listen_informative_filters_follow_both_recordings():
    import subprocess
    from pathlib import Path
    module = (Path(__file__).parent / 'txn_release_compare.mjs').as_uri()
    code = f"""import assert from 'node:assert/strict';import {{compareListenProjection}} from {module!r};
const row=places=>({{id:'atomic',canonical:{{}},places}}),empty=row({{}}),filter=row({{p:['a']}}),other=row({{p:['b']}});
assert.equal(compareListenProjection(empty,empty,empty),true);
assert.equal(compareListenProjection(empty,filter,empty),false);
assert.equal(compareListenProjection(filter,empty,filter),false);
assert.equal(compareListenProjection(filter,filter,filter),true);
assert.equal(compareListenProjection(filter,empty,empty),true);
assert.equal(compareListenProjection(filter,filter,empty),true);
assert.equal(compareListenProjection(filter,other,empty),false);"""
    subprocess.run(['node', '--input-type=module', '-e', code], check=True)


def test_local_artifact_unknown_source_keeps_actual_executable_hash():
    import subprocess
    from pathlib import Path
    module = (Path(__file__).parent / 'web_sdk_retry.mjs').as_uri()
    code = "import {localConfig,scenarioComplete} from " + repr(module) + ";const moduleUrl=" + repr(module) + ";" + """
import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const text=readFileSync(new URL(moduleUrl),'utf8'),body=text.slice(text.indexOf('export async function runLocalRetry'),text.indexOf('export async function recordWebRetries'));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex'),actualSha=sha(readFileSync(process.execPath)),known='a'.repeat(40);
const sdk=()=>({events:[],ready:async()=>{throw new Error('stop before network')},send:async()=>{},waitFor:async()=>({event:'exit',code:0}),close:async()=>({code:0})});
const run=new Function('localConfig','SOURCE_PATHS','sha','readFile','ROOT','spawnSdk','randomUUID','DRIVERS','fetch','writeFile','scenarioComplete',`return (${body.replace('export ','')})`)(localConfig,[],sha,readFile,import.meta.url,sdk,()=> 'unit',{},async()=>{throw new Error('unexpected network')},async()=>{},scenarioComplete);
const target={projectId:'demo-web-retry',firestoreHost:'127.0.0.1:12345',authHost:'127.0.0.1:12346'};
for(const options of [{artifact:process.execPath},{artifact:process.execPath,artifactSource:null},{artifact:process.execPath,artifactSource:known}]){const receipt=await run(target,options);assert.equal(receipt.complete,false);assert.deepEqual(receipt.bindings.artifact,{sha256:actualSha,sourceCommit:options.artifactSource??null});}
for(const source of ['', 'not-a-commit', 'b'.repeat(64)]) await assert.rejects(run(target,{artifact:process.execPath,artifactSource:source}));
await assert.rejects(run(target,{artifactSource:null}));
"""
    subprocess.run(['node', '--input-type=module', '-e', code], check=True)


def test_expiry_unknown_source_is_null_and_keeps_binary_hash():
    expiry = importlib.import_module('fs_txn_expiry_idle_replay')
    record = expiry.build_record(commit=None, binary_sha256='a' * 64, recording_digests=[], rows_by_recording=[], idles={}, cases_blob='b' * 40, file_digests={})
    assert record['artifact'] == {'sourceCommit': None, 'binarySha256': 'a' * 64}


def test_release_does_not_copy_oracle_source_to_another_binary(tmp_path, monkeypatch):
    import hashlib
    import sys
    from pathlib import Path
    release = importlib.import_module('fs_txn_release')
    source = release.load_inputs()['special']
    calls = []
    class CapturedCommand(Exception):
        pass
    def capture(argv, out, env=None, cwd=None):
        calls.append(([str(arg) for arg in argv], dict(env)))
        raise CapturedCommand()
    class SelectedCollectors:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def map(self, acquire, kinds):
            for kind in ('e04', 'web'):
                with pytest.raises(CapturedCommand):
                    acquire(kind)
            return []
    monkeypatch.setattr(release, 'invoke', capture)
    monkeypatch.setattr(release, 'ThreadPoolExecutor', SelectedCollectors)
    monkeypatch.setenv('S5B_ARTIFACT_SOURCE', source['web']['binaryBuildSource'])
    actual = Path(sys.executable)
    release.run_special(actual, hashlib.sha256(actual.read_bytes()).hexdigest(), tmp_path, source, 'node')
    assert len(calls) == 2
    assert '--commit' not in calls[0][0]
    assert 'S5B_ARTIFACT_SOURCE' not in calls[1][1]
    assert calls[1][1]['S5B_FIREEMU'] == str(actual)
