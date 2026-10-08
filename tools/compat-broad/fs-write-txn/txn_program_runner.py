"""Program session counters use explicit final recovery, not per-chain releases."""

from __future__ import annotations

import copy
import datetime as dt
import functools
import hashlib
import math
import json
import os
import selectors
import subprocess
import re
import secrets
import signal
import time
from pathlib import Path

import txn_sandbox_admission as shared
from txn_program_http import refresh, request_once
from txn_idle_grpc_runner import save_private
from txn_program_authority import TASK_ID, authorize, remaining_task_budget, verify_initial_gates
from txn_program_collector import Collector, projection
from txn_program_program import PROJECT, RequestBudget, compile_plan
from txn_program_wire import NodeWire
from txn_program_management import MetadataSession


def wire_scope(table):
    return {'slug': table['slug'], 'documents': list(table['documents']), 'states': list(table['states']), **{key: copy.deepcopy(table[key]) for key in ('databases', 'placements') if key in table}}


class SessionBudget(RequestBudget):
    def __init__(self, plan, table, check, save_count):
        super().__init__(plan, table)
        self.check = check
        self.save_count = save_count
        self.sdk = table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry')
        self.started = time.monotonic()
        if not math.isfinite(self.started):
            raise ValueError("program monotonic clock is invalid")
        self._last_time = self.started
        self.observation_deadline = self.started + plan["observationSeconds"]
        self.recovery_deadline = None
        self.recovery_seconds = plan["recoverySeconds"]
        self.failed = False

    def _now(self):
        now = time.monotonic()
        if not math.isfinite(now) or now < self._last_time:
            raise ValueError("program monotonic clock is invalid or moved backwards")
        self._last_time = now
        return now

    def begin_recovery(self):
        if self.recovery_deadline is None:
            self.recovery_deadline = min(self._now() + self.recovery_seconds, self.started + 300) if self.sdk else self._now() + self.recovery_seconds

    def charge(self, phase):
        if self.failed:
            raise ValueError("program count journal failed; dispatch blocked")
        if phase == "observation" and self.recovery_deadline is not None:
            raise ValueError("program observation cannot resume after final recovery")
        if phase == "documentCleanup" and self.recovery_deadline is None:
            raise ValueError("program document cleanup requires explicit recovery")
        self.check()
        deadline = self.recovery_deadline if self.recovery_deadline is not None else self.observation_deadline
        if deadline - self._now() < (30 if self.sdk and phase in ("observation", "documentCleanup") else 13):
            raise TimeoutError("program request cannot fit its fixed phase deadline")
        super().charge(phase)
        try:
            self.save_count({"kind": "txn-program-charged-count-v1", "phase": phase, "requests": self.total, "phaseRequests": dict(self.used)})
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise
        self.check()
        if deadline - self._now() < (30 if self.sdk and phase in ("observation", "documentCleanup") else 13):
            raise TimeoutError("program dispatch no longer fits after charged-count journal")


def web_process_identity(pid):
    if type(pid) is not int or pid < 1: raise ValueError('S5b process PID differs')
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'comm=', '-o', 'args='], capture_output=True, text=True, timeout=2, check=False)
    if result.returncode not in (0, 1): raise ValueError('S5b process observation unavailable')
    return result.stdout.strip() or None


def web_version(value):
    """Normalize only typed timestamp representations without losing nanoseconds."""
    if isinstance(value, dict) and set(value) <= {'seconds', 'nanos'} and 'seconds' in value and re.fullmatch(r'-?[0-9]+', str(value['seconds'])) and type(value.get('nanos', 0)) is int and 0 <= value.get('nanos', 0) < 1_000_000_000:
        return int(value['seconds']), value.get('nanos', 0)
    if isinstance(value, str):
        match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
        if match:
            try: return int(dt.datetime.fromisoformat(match[1] + '+00:00').timestamp()), int((match[2] or '').ljust(9, '0'))
            except ValueError: pass
    raise ValueError('S5b typed updateTime required')


def web_event(event, *, state, plan, budget, wire, bearer, journal, check, web_config, web_baseline, bindings):
    """One fixed Web event in the existing parent's durable before-send loop."""
    expected_id = 'web-' + str(state.setdefault('next', 0) + 1)
    if event.get('id') != expected_id: raise ValueError('S5b parent correlation differs')
    state['next'] += 1
    reply = {'authorized': True, 'id': event['id']}
    names = set(plan['documents'].values())
    writable = names - {name for role, name in plan['documents'].items() if role.endswith('-probe')}
    check()
    if event['event'] == 'ready':
        if state.get('ready') or web_config is None: raise ValueError('S5b private configuration missing or duplicate ready')
        from broad_contract import digest
        if not isinstance(web_config, dict) or set(web_config) != {'apiKey', 'authDomain', 'projectId'} or web_config['projectId'] != 'fireemu-oracle-query' or not isinstance(web_config['apiKey'], str) or not web_config['apiKey'] or digest(web_config) != web_baseline['webConfigSha256']: raise ValueError('S5b reviewed private configuration differs')
        state['ready'] = True
        return {**reply, 'nonce': plan['nonce'], 'ownerId': plan['ownerId'], 'web': web_config, 'origin': web_baseline['origin'], 'bindings': bindings}
    if not state.get('ready'): raise ValueError('S5b event before ready')
    if event['event'] == 'check': return reply
    if event['event'] == 'driver-lifecycle':
        client, pid = event.get('client'), event.get('pid')
        if client not in ('node-probe', 'browser-probe', 'node-main', 'browser-main'): raise ValueError('S5b driver identity differs')
        identities = state.setdefault('processes', {})
        drivers = state.setdefault('drivers', {})
        if event.get('phase') == 'launch':
            if client in drivers or type(pid) is not int or pid < 1: raise ValueError('S5b duplicate or absent driver PID')
            driver = Path(__file__).resolve().parents[3] / 'conformance/src/auth-fs-cross' / ('browser-driver.mjs' if client.startswith('browser') else 'sdk-driver.mjs')
            proof = web_process_identity(pid)
            if proof is None or str(driver) not in proof or 'node' not in proof: raise ValueError('S5b driver PID ownership differs')
            drivers[client] = pid; identities[pid] = proof
        elif event.get('phase') == 'exit':
            if drivers.get(client) != pid or event.get('closed') is not True or any(web_process_identity(owned) is not None for owned in state.get('clientProcesses', {}).get(client, [pid])): raise ValueError('S5b owned driver/browser processes remain')
        else: raise ValueError('S5b lifecycle phase differs')
    elif event['event'] == 'browser-processes':
        client, entries = event.get('client'), event.get('processes')
        if client not in ('browser-probe', 'browser-main') or event.get('driverPid') != state.get('drivers', {}).get(client) or event.get('origin') != web_baseline['origin'] or not isinstance(entries, list) or not 1 <= len(entries) <= 20: raise ValueError('S5b browser process inventory differs')
        owned = [event['driverPid']]
        for entry in entries:
            pid = entry.get('pid'); proof = web_process_identity(pid)
            if proof is None or not re.search(r'chromium|chrome|Chromium|Chrome|headless_shell', proof): raise ValueError('S5b browser process ownership differs')
            state.setdefault('processes', {})[pid] = proof; owned.append(pid)
        state.setdefault('clientProcesses', {})[client] = owned
    elif event['event'] == 'responsibility':
        if event.get('nonce') != plan['nonce'] or event.get('ownerId') != plan['ownerId'] or not isinstance(event.get('documents'), dict) or any(role.replace('_', '-') not in plan['documents'] or doc.get('name') != plan['documents'][role.replace('_', '-')] or doc.get('name') not in writable for role, doc in event['documents'].items()): raise ValueError('S5b responsibility scope differs')
        state['documents'] = copy.deepcopy(event['documents'])
    elif event['event'] == 'parent-call':
        phase, method, request = event.get('phase'), event.get('method'), event.get('request')
        if phase not in ('observation', 'documentCleanup') or method not in ('GetDocument', 'Commit', 'DeleteDocument') or not isinstance(request, dict): raise ValueError('S5b parent call differs')
        if state.get('unknown') and phase == 'observation': return {**reply, 'authorized': False}
        if phase == 'documentCleanup': budget.begin_recovery()
        if method in ('GetDocument', 'DeleteDocument') and request.get('name') not in names: raise ValueError('S5b exact parent read/delete name differs')
        if method == 'DeleteDocument':
            doc = state.get('ownedReads', {}).get(request['name'])
            if phase != 'documentCleanup' or request['name'] not in writable or not doc or web_version(request.get('currentDocument', {}).get('updateTime')) != web_version(doc.get('updateTime')): raise ValueError('S5b delete lacks an owned version witness')
        if method == 'Commit':
            if phase != 'observation' or request.get('database') != plan['database'] or len(request.get('writes', [])) != 1: raise ValueError('S5b parent write scope differs')
            write = request['writes'][0]
            name = write.get('update', {}).get('name')
            marker = next((role for role, resource in plan['documents'].items() if resource == name), None)
            field = write.get('update', {}).get('fields', {})
            if name not in writable or set(field) != {'owner', 'nonce', 'case', 'value'} or field['owner'] != {'stringValue': plan['ownerId']} or field['nonce'] != {'stringValue': plan['nonce']} or field['case'] != {'stringValue': marker.split('-', 1)[1].replace('-', '_')} or str(field['value'].get('integerValue')) not in ('1', '2'): raise ValueError('S5b parent ownership differs')
            if 'updateTime' in write.get('currentDocument', {}):
                prior = state.get('seedVersions', {}).get(name)
                if not prior or web_version(prior) != web_version(write['currentDocument']['updateTime']): raise ValueError('S5b witness lacks its acknowledged seed version')
        budget.charge(phase)
        row = {'event': 'parent-dispatch', 'id': event['id'], 'method': method, 'request': copy.deepcopy(request), 'phase': phase, 'pending': True}
        state.setdefault('parent', []).append(row)
        # Both journals precede the payload; any failure blocks the NodeWire call.
        journal(row); check()
        answer = wire.send('grpc', method, request, nonce=plan['nonce'], owner_id=plan['ownerId'], bearer=bearer, deadline_ms=10000)
        row.update(pending=False, answer=copy.deepcopy(answer))
        journal({**row, 'event': 'parent-status'}); check()
        known = answer.get('complete') is True and type(answer.get('code')) is int and 0 <= answer['code'] <= 16 and answer['code'] not in (1, 2, 4, 13, 14)
        if not known: state.setdefault('unknown', []).append(copy.deepcopy(row))
        if known and answer['code'] == 0 and method == 'Commit':
            version = (answer.get('response', {}).get('writeResults') or [{}])[0].get('updateTime')
            web_version(version)
            state.setdefault('seedVersions', {})[name] = version
        if known and answer['code'] == 0 and method == 'GetDocument':
            doc = answer.get('response')
            role = next((role for role, resource in plan['documents'].items() if resource == request['name']), None)
            if doc and doc.get('name') in writable and doc.get('fields', {}).get('owner') == {'stringValue': plan['ownerId']} and doc['fields'].get('nonce') == {'stringValue': plan['nonce']} and doc['fields'].get('case') == {'stringValue': role.split('-', 1)[1].replace('-', '_')}:
                web_version(doc.get('updateTime')); state.setdefault('ownedReads', {})[doc['name']] = copy.deepcopy(doc)
        reply['answer'] = answer
    elif event['event'] == 'dispatch':
        row = event.get('row', {}); client = row.get('client'); record = row.get('record', {}); request = row.get('request', {}); method = row.get('method')
        if state.get('unknown'): return {**reply, 'authorized': False}
        if client not in ('node-probe', 'browser-probe', 'node-main', 'browser-main') or record.get('host') != 'firestore.googleapis.com' or record.get('bearer') is not None or method not in ('BatchGetDocuments', 'Commit'): raise ValueError('S5b SDK transport/auth scope differs')
        transport, mode = client.split('-'); n = record.get('n')
        count = state.setdefault('clients', {}).get(client, 0)
        if type(n) is not int or n != count + 1 or n > (1 if mode == 'probe' else 6): raise ValueError('S5b SDK request cap/order differs')
        path = record.get('path')
        allowed_paths = (f'/google.firestore.v1.Firestore/{method}', f"/v1/{plan['database']}/documents:{'batchGet' if method == 'BatchGetDocuments' else 'commit'}")
        if path not in allowed_paths or request.get('transaction') or request.get('newTransaction') or request.get('readTime') or request.get('database', plan['database']) != plan['database']: raise ValueError('S5b SDK exact path/database differs')
        allowed = {plan['documents'][f'{transport}-probe']} if mode == 'probe' else {plan['documents'][f'{transport}-{case}'] for case in ('control', 'conflict')}
        if method == 'BatchGetDocuments':
            if set(request) - {'database', 'documents'} or not isinstance(request.get('documents'), list) or len(request['documents']) != 1 or request['documents'][0] not in allowed: raise ValueError('S5b SDK exact read differs')
        else:
            if mode == 'probe' or set(request) - {'database', 'writes'} or len(request.get('writes', [])) != 1: raise ValueError('S5b probe/write scope differs')
            write = request['writes'][0]; update = write.get('update', {}); field = update.get('fields', {}); name = update.get('name')
            case = next((case for case in ('control', 'conflict') if name == plan['documents'][f'{transport}-{case}']), None)
            if name not in allowed or set(write) != {'update', 'currentDocument'} or set(update) != {'name', 'fields'} or set(field) != {'owner', 'nonce', 'case', 'value'} or field['owner'] != {'stringValue': plan['ownerId']} or field['nonce'] != {'stringValue': plan['nonce']} or field['case'] != {'stringValue': case} or str(field['value'].get('integerValue')) != '3' or set(write.get('currentDocument', {})) != {'updateTime'}: raise ValueError('S5b SDK ownership/precondition differs')
            read = state.get('sdkReads', {}).get((client, name))
            if not read or web_version(write['currentDocument']['updateTime']) != web_version(read): raise ValueError('S5b SDK Commit lacks its read-version lineage')
        key = f'{client}:{n}'
        if n > 1 and not state.get('sdk', {}).get(f'{client}:{n-1}', {}).get('evidence'): raise ValueError('S5b next SDK request before prior known status')
        budget.charge('observation')
        state['clients'][client] = n
        state.setdefault('sdk', {})[key] = copy.deepcopy(row)
    elif event['event'] == 'status':
        row = event.get('row', {}); evidence = row.get('evidence', {}); key = f"{row.get('client')}:{evidence.get('n')}"
        before = state.get('sdk', {}).get(key)
        if before is None or before.get('evidence') or evidence.get('method') != before['method']: raise ValueError('S5b SDK status correlation differs')
        shaped = evidence.get('request', {})
        if before['method'] == 'BatchGetDocuments' and shaped.get('documents') != before['request']['documents']: raise ValueError('S5b SDK read status differs')
        if before['method'] == 'Commit':
            writes = shaped.get('writes')
            if not isinstance(writes, list) or len(writes) != 1 or writes[0].get('update', {}).get('name') != before['request']['writes'][0]['update']['name'] or web_version(writes[0].get('currentDocument', {}).get('updateTime')) != web_version(before['request']['writes'][0]['currentDocument']['updateTime']): raise ValueError('S5b SDK write status differs')
        before['evidence'] = copy.deepcopy(evidence)
        status = evidence.get('status')
        code = evidence.get('grpcCode')
        error = evidence.get('response', {}).get('error')
        known = evidence.get('complete') is True and type(status) is int and (200 <= status < 300 or 400 <= status < 500 and error) and (code is None or type(code) is int and 0 <= code <= 16 and code not in (1, 2, 4, 13, 14))
        if not known: state.setdefault('unknown', []).append(copy.deepcopy(before)); reply['authorized'] = False
        elif before['method'] == 'BatchGetDocuments':
            documents = evidence.get('response', {}).get('documents', [])
            if len(documents) != 1: raise ValueError('S5b SDK response count differs')
            doc = documents[0]
            if doc.get('name') == before['request']['documents'][0]:
                web_version(doc.get('updateTime')); state.setdefault('sdkReads', {})[(row['client'], doc['name'])] = doc['updateTime']
            elif doc.get('missing') != before['request']['documents'][0]: raise ValueError('S5b SDK response exact name differs')
    else: raise ValueError('S5b parent event outside fixed set')
    try: journal(event)
    except (Exception, KeyboardInterrupt): budget.failed = True; raise
    check()
    return reply


def web_projection(receipt):
    """The producer's existing comparator verifies lineage; retain semantic answers for pair comparison."""
    if receipt.get('complete') is not True or len(receipt.get('transports', [])) != 2 or receipt.get('unknownWrites'): raise ValueError('S5b complete known receipt required')
    result = []
    for report, transport in zip(receipt['transports'], ('node', 'browser'), strict=True):
        if report.get('transport') != transport or not report.get('closed') or not report.get('probe', {}).get('complete') or not report['probe'].get('closed'): raise ValueError('S5b transport/probe receipt differs')
        scenarios = []
        if len(report.get('scenarios', [])) != 2: raise ValueError('S5b scenario count differs')
        for row, case in zip(report['scenarios'], ('control', 'conflict'), strict=True):
            if row.get('scenario') != case or row.get('complete') is not True or row.get('answer', {}).get('attempts') != (1 if case == 'control' else 2): raise ValueError('S5b callback comparison differs')
            scenarios.append({'scenario': case, 'attempts': row['answer']['attempts'], 'finalValue': row.get('final', {}).get('value'), 'wire': [{key: event.get(key) for key in ('method', 'status', 'grpcCode', 'complete')} | {'refusal': event.get('response', {}).get('error')} for event in row['events'] if event.get('event') == 'transaction-wire']})
        result.append({'transport': transport, 'scenarios': scenarios})
    return result


def run_once(index, table, nonce, owner_id, directory, *, baseline, runtime, check, web_config=None):
    directory = Path(directory) / f'journal-{index + 1}'
    directory.mkdir(mode=0o700)
    sequence = 0
    def journal(value):
        nonlocal sequence
        sequence += 1
        save_private(directory / f'{sequence:04d}.json', value)
    plan = compile_plan(table, nonce, owner_id)
    budget = SessionBudget(plan, table, check, journal)
    receipt = None
    dispatched = {}
    documents = {}
    metadata = None
    collector = None
    child = None
    producer_started = None
    bearer = None
    is_web = table['name'] == 's5b-web-sdk-retry'
    web_state = {}
    stderr_tail = bytearray()
    stderr_truncated = False
    try:
        check()
        project = table.get('project', PROJECT)
        if is_web:
            from broad_contract import digest
            if runtime.get('webSdk') is not True: raise ValueError('S5b Firebase/Playwright runtime closure required before refresh')
            if not isinstance(baseline.get('s5b'), dict) or not isinstance(web_config, dict) or web_config.get('projectId') != project or digest(web_config) != baseline['s5b'].get('webConfigSha256'): raise ValueError('S5b reviewed private configuration/baseline required before refresh')
        bearer = refresh(baseline, budget, before_send=check)
        # the shared project keeps the call exactly as it was; another project's name rides along
        extra = {} if project == PROJECT else {'project': project}
        metadata = MetadataSession(bearer, {key: value for key, value in baseline.items() if key != 's5b'} if is_web else baseline, budget, **({'s5b': baseline.get('s5b')} if is_web else {}), request_fn=request_once if project == PROJECT else functools.partial(request_once, project=project, **({'project_number': baseline['projectNumber']} if is_web else {})), **extra)
        preflight = metadata.preflight()
        if table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry'):
            if is_web:
                if not baseline.get('s5b'): raise ValueError('S5b reviewed baseline required')
                web_wire = NodeWire(runtime, wire_scope(table), project=project)
                from txn_program_cli import source_manifest
                web_bindings = {'sources': source_manifest(table['name']), 'runtime': copy.deepcopy(runtime), 'corpusDigest': plan['corpusDigest'], 'configSha256': baseline['s5b']['webConfigSha256'], 'keyRestrictionsSha256': baseline['s5b']['keyRestrictionsSha256'], 'origin': baseline['s5b']['origin']}
            worker = Path(table['sourceFile'])
            producer_started = time.monotonic()
            child = subprocess.Popen([runtime['nodeExecutable'], str(worker), 'production'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}, close_fds=True)
            end = budget.started + 300
            buffered = bytearray()
            try:
                os.set_blocking(child.stderr.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    selector.register(child.stderr, selectors.EVENT_READ)
                    while selector.get_map():
                        if time.monotonic() >= end: raise TimeoutError('SDK recording wall cap exceeded')
                        for key, _ in selector.select(min(0.2, end - time.monotonic())):
                            block = os.read(key.fd, 4096)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            if key.fileobj is child.stderr:
                                stderr_tail.extend(block)
                                if len(stderr_tail) > 8192:
                                    stderr_truncated = True
                                    del stderr_tail[:-8192]
                                continue
                            buffered.extend(block)
                            if len(buffered) > 4194304: raise ValueError('SDK IPC capacity exceeded')
                            while b'\n' in buffered:
                                raw, _, buffered = buffered.partition(b'\n')
                                event = json.loads(raw)
                                if event.get('event') == 'receipt':
                                    if receipt is not None: raise ValueError('duplicate SDK receipt')
                                    receipt = event['receipt']
                                    continue
                                check()
                                if is_web:
                                    def web_journal(value):
                                        try:
                                            shared.append_ledger(directory / 'sdk-journal.jsonl', value)
                                            journal(value)
                                        except (Exception, KeyboardInterrupt): budget.failed = True; raise
                                    reply = web_event(event, state=web_state, plan=plan, budget=budget, wire=web_wire, bearer=bearer, journal=web_journal, check=check, web_config=web_config, web_baseline=baseline['s5b'], bindings=web_bindings)
                                    child.stdin.write((json.dumps(reply) + '\n').encode()); child.stdin.flush()
                                    continue
                                if event.get('event') == 'ready':
                                    reply = {'authorized': True, 'bearer': bearer, 'nonce': nonce, 'ownerId': owner_id, 'observationRemaining': budget.observation_deadline - time.monotonic()}
                                else:
                                    if event.get('event') == 'dispatch':
                                        row = event['row']
                                        if row['sequence'] != len(dispatched) or row['phase'] not in ('observation', 'documentCleanup'): raise ValueError('SDK dispatch accounting differs')
                                        if row['phase'] == 'documentCleanup': budget.begin_recovery()
                                        if 'x-goog-user-project' not in row.get('metadataKeys', []) or row.get('quotaProject') != project: raise ValueError('SDK quota project metadata missing')
                                        request = row['request']
                                        if any(value.get('outcomeClass') == 'UNKNOWN' for value in dispatched.values()): raise ValueError('SDK unknown answer blocks redispatch')
                                        if row.get('transport') != 'grpc' or row.get('rpc') not in ('BatchGetDocuments', 'Commit', 'Rollback', 'DeleteDocument'): raise ValueError('SDK RPC scope differs')
                                        if row['rpc'] in ('BatchGetDocuments', 'Commit', 'Rollback') and request.get('database') != plan['database']: raise ValueError('SDK database scope differs')
                                        names = set(plan['documents'].values())
                                        if row['rpc'] == 'BatchGetDocuments' and (not isinstance(request.get('documents'), list) or not 1 <= len(request['documents']) <= 3 or not set(request['documents']) <= names): raise ValueError('SDK read scope differs')
                                        if row['rpc'] == 'DeleteDocument': raise ValueError('SDK direct delete is not used')
                                        if row['rpc'] == 'Commit':
                                            if not isinstance(request.get('writes'), list) or not 1 <= len(request['writes']) <= 1: raise ValueError('SDK write scope differs')
                                            for write in request['writes']:
                                                if 'delete' in write:
                                                    name = write['delete']
                                                    if set(write) != {'delete', 'currentDocument'} or set(write.get('currentDocument', {})) != {'updateTime'} or row['phase'] != 'documentCleanup' or name not in names or not write.get('currentDocument', {}).get('updateTime'): raise ValueError('SDK cleanup delete scope differs')
                                                    witness = next((value for value in reversed(list(dispatched.values())) if value['rpc'] == 'BatchGetDocuments' and value['site'] == row['site'] and value['request'].get('documents') == [name] and value.get('result', {}).get('code') == 0), None)
                                                    frame = next((frame for frame in (witness or {}).get('frames', []) if frame and frame.get('found', {}).get('name') == name), None)
                                                    if frame is None or frame['found'].get('fields', {}).get('owner', {}).get('stringValue') != owner_id or frame['found']['fields'].get('nonce', {}).get('stringValue') != nonce or frame['found'].get('updateTime') != write['currentDocument']['updateTime']: raise ValueError('SDK cleanup delete lacks owned witness precondition')
                                                    continue
                                                if row['phase'] != 'observation': raise ValueError('SDK cleanup cannot update a document')
                                                update = write.get('update', {})
                                                fields = update.get('fields', {})
                                                if update.get('name') not in names or set(fields) != {'owner', 'nonce', 'role', 'state'} or fields['owner'] != {'stringValue': owner_id} or fields['nonce'] != {'stringValue': nonce} or fields['role'] != {'stringValue': update['name'].rsplit('/', 1)[1]} or fields['state'].get('stringValue') not in table['states']: raise ValueError('SDK write ownership differs')
                                        if not 0 < row.get('timing', {}).get('deadlineSeconds', 0) <= 30: raise ValueError('SDK native deadline differs')
                                        if request.get('transaction') and not any(frame and frame.get('transaction') == request['transaction'] for value in dispatched.values() for frame in value.get('frames', [])): raise ValueError('SDK transaction was not issued in this recording')
                                        budget.charge(row['phase'])
                                        dispatched[row['sequence']] = row
                                    elif event.get('event') == 'status':
                                        row = event['row']
                                        before = dispatched.get(row['sequence'])
                                        if before is None or before.get('result') or any(row.get(key) != before.get(key) for key in ('transport', 'rpc', 'request', 'client', 'site', 'phase', 'caseId', 'attempt', 'metadataKeys', 'quotaProject')) or row.get('frames') != before.get('frames', []): raise ValueError('SDK status does not match its dispatch')
                                        if any(row['timing'].get(key) != before['timing'].get(key) for key in ('deadlineSeconds', 'dispatchMonotonic', 'dispatchUtc')): raise ValueError('SDK status changed dispatch timing')
                                        result = row.get('result', {})
                                        if type(result.get('code')) is not int or not 0 <= result['code'] <= 16 or not isinstance(result.get('details'), str) or len(result['details']) > 4096 or bearer in result['details']: raise ValueError('SDK native status differs')
                                        from txn_program_program import outcome_class
                                        partial_start = row['rpc'] == 'BatchGetDocuments' and row['request'].get('newTransaction') and row['frames'] and result['code'] != 0
                                        if row['outcomeClass'] != ('UNKNOWN' if partial_start else outcome_class(result['code'])): raise ValueError('SDK outcome class differs')
                                        dispatched[row['sequence']] = row
                                    elif event.get('event') == 'responsibility':
                                        if event.get('nonce') != nonce or event.get('ownerId') != owner_id or any(role not in plan['documents'] or value.get('name') != plan['documents'][role] for role, value in event['documents'].items()): raise ValueError('SDK document responsibility differs')
                                        documents = event['documents']
                                    elif event.get('event') == 'frame':
                                        before = dispatched.get(event.get('sequence'))
                                        if before is None or before.get('result'): raise ValueError('SDK frame does not match dispatch')
                                        before.setdefault('frames', []).append(event['frame'])
                                        if len(before['frames']) > 3: raise ValueError('SDK frame cap exceeded')
                                    else: raise ValueError('SDK journal event differs')
                                    try:
                                        shared.append_ledger(directory / 'sdk-journal.jsonl', event)
                                        journal(event)
                                    except (Exception, KeyboardInterrupt):
                                        budget.failed = True
                                        raise
                                    check()
                                    reply = {'authorized': True}
                                child.stdin.write((json.dumps(reply) + '\n').encode()); child.stdin.flush()
                child.wait(timeout=max(0.01, end - time.monotonic()))
                if child.returncode != 0 or receipt is None or buffered: raise ValueError('SDK worker receipt incomplete')
                if is_web:
                    if receipt.get('nonce') != nonce or receipt.get('ownerId') != owner_id or receipt.get('bindings') != web_bindings or web_state.get('unknown') or sum(web_state.get('clients', {}).values()) != 14 or len(web_state.get('parent', [])) != 38: raise ValueError('S5b receipt/count/binding differs')
                    web_projection(receipt)
                    budget.begin_recovery()
                    receipt.update(metadata=preflight, postflight=metadata.postflight())
                    check()
                elif receipt.get('receiptDigest') != hashlib.sha256(json.dumps({key: value for key, value in receipt.items() if key != 'receiptDigest'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest(): raise ValueError('SDK native receipt digest differs')
                if not is_web:
                    if receipt['nonce'] != nonce or receipt['ownerId'] != owner_id or receipt['sandboxRequests'] != len(dispatched) or len(dispatched) != budget.used['observation'] + budget.used['documentCleanup']: raise ValueError('SDK receipt disagrees with dispatch journal')
                    if receipt.get('runtime', {}).get('manifest', {}).get('dependencies') != runtime['dependencies'] or receipt['runtime'].get('nodeSha256') != runtime['nodeSha256'] or receipt['runtime'].get('lockSha256') != runtime['lockSha256'] or receipt['runtime'].get('target') != 'production': raise ValueError('SDK child runtime differs from reviewed manifest')
                    native_rows = receipt.get('steps', []) + receipt.get('cleanupSteps', [])
                    if len(native_rows) != len(dispatched): raise ValueError('SDK receipt lost native rows')
                    for row in native_rows:
                        original = copy.deepcopy(dispatched.get(row['sequence']))
                        if original is None: raise ValueError('SDK receipt contains an undispatched row')
                        if original.get('result'): original['result'].update(childReaped=True, workerExitCode=0)
                        if row != original: raise ValueError('SDK receipt changed native evidence')
                    receipt['metadata'] = preflight
                    if receipt.get('complete') is not True: raise ValueError('SDK unknown responsibility requires A2')
                    budget.begin_recovery()
                    receipt['postflight'] = metadata.postflight()
                    check()
            finally:
                if child.poll() is None:
                    proof = subprocess.run(['ps', '-p', str(child.pid), '-o', 'comm=', '-o', 'args='], capture_output=True, text=True, timeout=2).stdout
                    if Path(runtime['nodeExecutable']).name not in proof or str(worker) not in proof: raise RuntimeError('SDK child identity differs')
                    child.terminate()
                    try: child.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proof = subprocess.run(['ps', '-p', str(child.pid), '-o', 'comm=', '-o', 'args='], capture_output=True, text=True, timeout=2).stdout
                        if str(worker) not in proof: raise RuntimeError('SDK child identity changed')
                        child.kill(); child.wait(timeout=2)
                while True:
                    try: block = os.read(child.stderr.fileno(), 4096)
                    except BlockingIOError: break
                    if not block: break
                    stderr_tail.extend(block)
                    if len(stderr_tail) > 8192:
                        stderr_truncated = True
                        del stderr_tail[:-8192]
                for pipe in (child.stdin, child.stdout, child.stderr): pipe.close()
                if is_web:
                    process_cleanup = []
                    for pid, expected in web_state.get('processes', {}).items():
                        proof = web_process_identity(pid)
                        if proof is None:
                            process_cleanup.append({'pid': pid, 'absent': True}); continue
                        if proof != expected:
                            process_cleanup.append({'pid': pid, 'absent': False, 'identityChanged': True}); continue
                        os.kill(pid, signal.SIGTERM)
                        until = time.monotonic() + 1
                        while time.monotonic() < until and web_process_identity(pid) == expected: time.sleep(0.05)
                        if web_process_identity(pid) == expected: os.kill(pid, signal.SIGKILL)
                        process_cleanup.append({'pid': pid, 'absent': web_process_identity(pid) is None})
                    web_state['processCleanup'] = process_cleanup
                    if receipt is not None and any(row.get('absent') is not True for row in process_cleanup): receipt['complete'] = False
        else:
            if table['name'] == 'p16-foreign-tokens':
                metadata.create_named_database(plan['databases']['named'], journal)
            wire = NodeWire(runtime, wire_scope({**table, **plan}), **({} if project == PROJECT else {'project': project}))
            collector = Collector(plan, table, budget, wire, bearer, save=journal, before_send=check, observation_deadline=budget.observation_deadline)
            receipt = collector.run()
            receipt['metadata'] = preflight
            if receipt.get('journalFailure') or budget.failed:
                raise ValueError('program journal failed; metadata postflight is forbidden')
            budget.begin_recovery()
            if table['name'] == 'p16-foreign-tokens':
                named = plan['databases']['named']
                if any(receipt.get('tokens', {}).get(role, {}).get('database', plan['database']) == named for role in receipt.get('openTokens', []) + receipt.get('unknownRollbacks', [])) or any(plan['documents'][role].split('/documents/')[0] == named and document['status'] in ('possibly-owned', 'created') for role, document in receipt.get('documents', {}).items()) or any(step['id'] in receipt.get('unknownStarts', []) + receipt.get('unknownCommits', []) and plan['databases'].get(step.get('onDatabase'), plan['database']) == named for step in plan['steps']):
                    raise ValueError('named database retained while its resources are unrecovered')
                if not metadata.delete_named_database(journal)['closureReady']:
                    raise ValueError('named database deletion requires A2 readback')
            receipt['postflight'] = metadata.postflight()
            check()
    except (Exception, KeyboardInterrupt) as error:
        if receipt is None:
            receipt = {'kind': 'txn-program-recording-v1', 'complete': False, 'graphComplete': False, 'program': plan['program'], 'packetName': plan['packetName'], 'sourceDigest': plan['sourceDigest'], 'corpusDigest': plan['corpusDigest'], 'nonce': nonce, 'ownerId': owner_id, 'unknownStarts': [], 'openTokens': [], 'cleanup': {'absent': None}, 'unrecovered': not (table['name'] == 'p16-foreign-tokens' and collector is None and metadata is not None and hasattr(metadata, 'named_database'))}
        receipt['complete'] = False
        receipt['failureType'] = type(error).__name__
        if table['name'] == 'p17-admin-sdk-retry':
            tail = stderr_tail.decode('utf-8', errors='replace')
            if stderr_truncated:
                # Drop a clipped first line so a credential prefix cannot be lost at the tail boundary.
                tail = tail.partition('\n')[2]
            receipt.update(failureMessage=str(error), childExitCode=None if child is None else child.returncode, childStderrTail=tail)
            for field in ('failureMessage', 'childStderrTail'):
                value = receipt[field]
                if bearer: value = value.replace(bearer, '[credential-redacted]')
                value = re.sub(r'(?s)-----BEGIN[^-\r\n]*PRIVATE KEY-----.*?(?:-----END[^-\r\n]*PRIVATE KEY-----|$)', '[credential-redacted]', value)
                value = re.sub(r'(?s)^.*?-----END[^-\r\n]*PRIVATE KEY-----', '[credential-redacted]', value)
                value = re.sub(r'AIza[A-Za-z0-9_-]*|ya29\.[A-Za-z0-9._~-]*|(?i:Bearer)\s+[^\s\"<>]+', '[credential-redacted]', value)
                receipt[field] = value if field == 'failureMessage' else value.encode('utf-8')[-8192:].decode('utf-8', errors='ignore')
            receipt.update(documents=documents, steps=list(dispatched.values()), cleanupSteps=[], unknownCommits=[seq for seq, row in dispatched.items() if row['rpc'] == 'Commit' and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')], unknownStarts=[seq for seq, row in dispatched.items() if row['rpc'] == 'BatchGetDocuments' and row['request'].get('newTransaction') and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')], timingMode='wall-clock', timingSource='grpc-js-client-interceptor', unrecovered=True)
            receipt['tokens'] = {}
            for row in dispatched.values():
                for frame in row.get('frames', []):
                    if frame and frame.get('transaction'): receipt['tokens'][f"{row.get('caseId')}-{row.get('client')}-{row.get('attempt')}"] = {'value': frame['transaction'], 'transport': 'grpc', 'state': 'open'}
                for token in receipt['tokens'].values():
                    if token['value'] == row['request'].get('transaction') and (row['rpc'] == 'Commit' and row.get('result', {}).get('code') == 0 or row['rpc'] == 'Rollback' and row.get('result') and row.get('outcomeClass') != 'UNKNOWN'): token['state'] = 'closed'
            receipt['openTokens'] = [role for role, token in receipt['tokens'].items() if token['state'] == 'open']
            receipt['unknownRollbacks'] = [seq for seq, row in dispatched.items() if row['rpc'] == 'Rollback' and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')]
            receipt['unknownWrites'] = [seq for seq, row in dispatched.items() if row['rpc'] in ('Commit', 'DeleteDocument') and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')]
            receipt['journalFailure'] = budget.failed
    if metadata is not None and hasattr(metadata, 'named_database'):
        receipt['namedDatabase'] = copy.deepcopy(metadata.named_database)
        receipt['closureReady'] = metadata.named_database['closureReady']
        if not receipt['closureReady']:
            receipt['complete'] = False
    receipt['sandboxRequests'] = budget.total
    receipt['phaseRequests'] = dict(budget.used)
    if table['name'] == 'p17-admin-sdk-retry':
        if 'receiptDigest' in receipt: receipt['sdkReceiptDigest'] = receipt.pop('receiptDigest')
        receipt['runtimeManifest'] = copy.deepcopy(runtime)
        from txn_program_cli import source_manifest
        receipt['sourceManifest'] = source_manifest(table['name'])
        receipt['receiptDigest'] = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=False).encode()).hexdigest()
        try:
            shared.append_ledger(directory / 'sdk-journal.jsonl', {'event': 'final', 'receiptDigest': receipt['receiptDigest'], 'complete': receipt['complete']})
        except (Exception, KeyboardInterrupt) as error:
            receipt.update(complete=False, unrecovered=True, journalFailure=True, failureType=type(error).__name__)
            receipt['receiptDigest'] = hashlib.sha256(json.dumps({key: value for key, value in receipt.items() if key != 'receiptDigest'}, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=False).encode()).hexdigest()
            save_private(directory / 'sdk-final-receipt.json', receipt)
            raise
        save_private(directory / 'sdk-final-receipt.json', receipt)
    else: receipt['runtime'] = copy.deepcopy(runtime)
    if is_web:
        receipt['producerStartedMonotonic'] = producer_started
        if web_state.get('documents'): receipt['documents'] = copy.deepcopy(web_state['documents'])
        pending = [row for row in web_state.get('parent', []) if row.get('pending')] + [row for row in web_state.get('sdk', {}).values() if not row.get('evidence')]
        if pending: web_state.setdefault('unknown', []).extend(copy.deepcopy(pending))
        receipt['processCleanup'] = copy.deepcopy(web_state.get('processCleanup', []))
        receipt.update(program=plan['program'], packetName=plan['packetName'], sourceDigest=plan['sourceDigest'], corpusDigest=plan['corpusDigest'], parentJournal=copy.deepcopy(web_state.get('parent', [])), sdkJournal=list(copy.deepcopy(web_state.get('sdk', {})).values()), unknownAnswers=copy.deepcopy(web_state.get('unknown', [])), journalFailure=budget.failed)
        receipt['complete'] = receipt.get('complete') is True and not receipt['unknownAnswers'] and not budget.failed
        save_private(directory / 'web-final-receipt.json', receipt)
    return receipt


def sdk_document_action(snapshot, action, send, *, now):
    """Recover exact SDK-owned names; A2 reads never settle an unknown create by absence."""
    from txn_program_cli import table_for
    if action not in ('cleanup', 'a2') or snapshot.get('kind') not in ('txn-program-recording-v1', 'txn-admin-sdk-recovery-v1') or snapshot.get('packetName') != 'p17-admin-sdk-retry' or now.tzinfo is None:
        raise ValueError('SDK cleanup or A2 snapshot required')
    plan = compile_plan(table_for('p17-admin-sdk-retry'), snapshot['nonce'], snapshot['ownerId'])
    documents = copy.deepcopy(snapshot['documents'])
    if any(role not in plan['documents'] or doc.get('name') != plan['documents'][role] for role, doc in documents.items()): raise ValueError('SDK recovery document scope differs')
    rows = snapshot.get('steps', []) + snapshot.get('cleanupSteps', [])
    unknown = [row for row in rows if row.get('outcomeClass') == 'UNKNOWN' or not row.get('result')]
    if unknown and any(now - shared._instant(row['timing']['dispatchUtc']) < dt.timedelta(minutes=10) for row in unknown): raise ValueError('SDK 10-minute A2 wait has not elapsed')
    unknown_writes = {row['sequence']: row for row in unknown if row['rpc'] in ('Commit', 'DeleteDocument') and row['sequence'] not in snapshot.get('settledWrites', [])}
    original_unknown_writes = set(unknown_writes)
    tokens = copy.deepcopy(snapshot.get('tokens', {}))
    evidence = []
    blocked = False
    def dispatch(rpc, request):
        nonlocal blocked
        if blocked or len(evidence) >= 45: raise ValueError('SDK recovery dispatch blocked')
        try: result = send(rpc, request)
        except (Exception, KeyboardInterrupt): result = {'complete': False, 'code': 2, 'details': 'SDK recovery IPC or journal incomplete'}
        row = {'sequence': max((row['sequence'] for row in rows), default=-1) + len(evidence) + 1, 'rpc': rpc, 'request': copy.deepcopy(request), 'result': copy.deepcopy(result), 'timing': {'dispatchUtc': now.isoformat()}, 'outcomeClass': 'UNKNOWN' if not result.get('complete') or result.get('code') in (1, 2, 4, 13, 14) else 'OK' if result.get('code') == 0 else 'REFUSED'}
        evidence.append(row)
        if row['outcomeClass'] == 'UNKNOWN' and rpc in ('Commit', 'DeleteDocument'): unknown_writes[row['sequence']] = row
        if not result.get('complete') or result.get('code') in (1, 2, 4, 13, 14): blocked = True
        return result
    if action == 'cleanup':
        for token in tokens.values():
            if token['state'] != 'open': continue
            result = dispatch('Rollback', {'database': plan['database'], 'transaction': token['value']})
            if blocked: break
            token['state'] = 'rolled-back' if result['code'] == 0 else 'released-refused'
    for role, document in documents.items():
        if blocked: break
        name = document['name']
        read = dispatch('GetDocument', {'name': name})
        if blocked: break
        body = read.get('response')
        absent = read.get('code') == 5
        owned = read.get('code') == 0 and isinstance(body, dict) and body.get('name') == name and body.get('fields', {}).get('owner') == {'stringValue': snapshot['ownerId']} and body['fields'].get('nonce') == {'stringValue': snapshot['nonce']} and body['fields'].get('role') == {'stringValue': name.rsplit('/', 1)[1]} and body.get('updateTime')
        if not absent and not owned: continue
        for sequence, row in list(unknown_writes.items()):
            writes = row['request'].get('writes', []) if row['rpc'] == 'Commit' else [{'delete': row['request'].get('name')}]
            if len(writes) != 1: continue
            write = writes[0]
            if absent and write.get('delete') == name or owned and write.get('update', {}).get('name') == name and write['update'].get('fields') == body['fields']:
                del unknown_writes[sequence]
        unresolved_update = any(any(write.get('update', {}).get('name') == name for write in row['request'].get('writes', [])) for row in unknown_writes.values())
        if action == 'cleanup' and owned and not unresolved_update:
            deleted = dispatch('DeleteDocument', {'name': name, 'currentDocument': {'updateTime': body['updateTime']}})
            if blocked: break
            if deleted.get('code') != 0: continue
            verified = dispatch('GetDocument', {'name': name})
            if blocked: break
            absent = verified.get('code') == 5
        document['status'] = 'confirmed-absent' if absent else 'owned-readback'
    open_tokens = [role for role, token in tokens.items() if token['state'] == 'open']
    complete = not blocked and not unknown_writes and not open_tokens and not snapshot.get('unknownStarts') and all(doc.get('status') == 'confirmed-absent' for doc in documents.values())
    return {'kind': 'txn-admin-sdk-recovery-v1', 'packetName': 'p17-admin-sdk-retry', 'action': action, 'complete': complete, 'nonce': snapshot['nonce'], 'ownerId': snapshot['ownerId'], 'documents': documents, 'tokens': tokens, 'openTokens': open_tokens, 'unknownStarts': snapshot.get('unknownStarts', []), 'unknownWrites': sorted(unknown_writes), 'settledWrites': sorted(set(snapshot.get('settledWrites', [])) | (original_unknown_writes - set(unknown_writes))), 'unknownAnswers': blocked, 'steps': rows + evidence, 'cleanupSteps': [], 'requests': len(evidence)}


def record_sdk_action(*, table, snapshot, action, directory, baseline, runtime, check, now):
    """Run a separately packet-pinned SDK action through the existing bounded native wire."""
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    plan = compile_plan(table, snapshot['nonce'], snapshot['ownerId'])
    budget = SessionBudget(plan, table, check, lambda value: save_private(directory / f"charged-{value['requests']:03d}.json", value))
    journal = directory / 'sdk-recovery-journal.jsonl'
    result = None
    try:
        check()
        bearer = refresh(baseline, budget, before_send=check)
        metadata = MetadataSession(bearer, baseline, budget, request_fn=functools.partial(request_once, project=plan['project']), project=plan['project'])
        before = metadata.preflight()
        def send(rpc, request):
            check()
            phase = 'observation' if rpc == 'Rollback' else 'documentCleanup'
            if phase == 'documentCleanup': budget.begin_recovery()
            budget.charge(phase)
            name = request.get('name') or request.get('writes', [{}])[0].get('delete')
            case = name.split('/')[-2].removeprefix('txn-p17-') if name else 'conflict'
            wire = NodeWire(runtime, {'slug': 'txn-p17-' + case, 'documents': ['a', 'b', 'c'], 'states': table['states']}, project=plan['project'])
            shared.append_ledger(journal, {'event': 'dispatch', 'rpc': rpc, 'request': request, 'ts': now().isoformat()})
            answer = wire.send('grpc', rpc, request, nonce=snapshot['nonce'], owner_id=snapshot['ownerId'], bearer=bearer)
            shared.append_ledger(journal, {'event': 'status', 'rpc': rpc, 'result': answer})
            return answer
        result = sdk_document_action(snapshot, action, send, now=now())
        budget.begin_recovery()
        if not result['unknownAnswers']:
            after = metadata.postflight()
            if before.get('project') != after.get('project') or before.get('database') != after.get('database'): result['complete'] = False
            result.update(metadata=before, postflight=after)
    except (Exception, KeyboardInterrupt):
        if result is not None: result['complete'] = False
        raise
    finally:
        save_private(directory / 'sdk-recovery-receipt.json', {'complete': False, 'failure': 'action-incomplete', 'requests': budget.total} if result is None else {**result, 'sandboxRequests': budget.total, 'phaseRequests': budget.used})
    return result


def _row(pins, attempt, directory, nonce, outcome, requests, now):
    if requests is not None and (type(requests) is not int or not 0 <= requests <= pins['requestsPerRecording']):
        raise ValueError('program charged request count escaped its cap')
    return {'ts': now.isoformat().replace('+00:00', 'Z'), 'project': pins.get('project', PROJECT), 'projects': sorted({resource.split('/')[0] for resource in pins['scope']['project'].split('+')}), 'database': '(default)', 'taskId': TASK_ID, 'envelopeId': pins['envelopeId'], 'packetId': pins['packetId'], 'gitSha': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'attemptId': attempt, 'runDir': str(directory), 'nonce': nonce, 'outcome': outcome, 'requests': requests, 'estimatedUsd': pins.get('estimatedUsdPerRecording', 0.01), 'pythonVersion': '3.12.13'}


def record_twice(*, table, ledger_path, private_dir, pins, decisions, now, record_once, admission_check):
    ledger_path, private_dir = Path(ledger_path), Path(private_dir)
    campaign_deadline = None if table['name'] == 's5b-web-sdk-retry' else time.monotonic() + 600
    verify_initial_gates(shared.read_ledger(ledger_path), now(), decisions(), pins)
    held = shared.acquire_project_locks(private_dir, sorted({resource.split('/')[0] for resource in pins['scope']['project'].split('+')}), task_id=TASK_ID, packet_id=pins['packetId'], source_commit=pins['sourceCommit'])
    release = False
    reserved = False
    attempt = nonce = directory = None
    try:
        admission_check()
        verify_initial_gates(shared.read_ledger(ledger_path), now(), decisions(), pins)
        directory = private_dir / f"fs-transaction-{pins['packetName']}-{secrets.token_hex(8)}"
        directory.mkdir(mode=0o700)
        receipts = []
        sdk_projections = []
        for index in range(2):
            if table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry') and campaign_deadline is not None and campaign_deadline - time.monotonic() < 300: raise TimeoutError('SDK campaign wall cap exceeded')
            admission_check(); authorize(decisions(), pins)
            remaining_task_budget(shared.read_ledger(ledger_path), pins.get('estimatedUsdPerRecording', 0.01))
            attempt, nonce, owner_id = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'reserved', None, now()))
            reserved = True
            receipt = record_once(index, nonce, owner_id, directory)
            if not isinstance(receipt, dict): raise ValueError('program recording receipt missing')
            if table['name'] == 's5b-web-sdk-retry' and index == 0:
                started = receipt.get('producerStartedMonotonic')
                if type(started) not in (int, float) or not 0 < started <= time.monotonic(): raise ValueError('S5b parent producer launch timestamp missing')
                campaign_deadline = started + 600
            requests = receipt.get('sandboxRequests')
            save_private(directory / f'recording-{index + 1}.json', receipt)
            if receipt.get('complete') is not True or receipt.get('timingMode') != 'wall-clock' or receipt.get('timingSource') != ('sdk-parent-before-payload' if table['name'] == 's5b-web-sdk-retry' else 'grpc-js-client-interceptor' if table['name'] == 'p17-admin-sdk-retry' else 'parent-wire-envelope'):
                raise ValueError('program acquisition stopped; second recording is forbidden')
            if table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry'):
                if campaign_deadline - time.monotonic() < 30: raise TimeoutError('SDK campaign projection cannot fit wall cap')
                sdk_projections.append(web_projection(receipt) if table["name"] == "s5b-web-sdk-retry" else projection(receipt, table))
            else: projection(receipt, table)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'recorded', requests, now()))
            receipts.append(receipt)
        admission_check(); authorize(decisions(), pins)
        first, second = sdk_projections if table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry') else (projection(receipt, table) for receipt in receipts)
        if pins.get('project', PROJECT) == PROJECT:
            metadata = [{key: receipt.get('metadata', {}).get(key) for key in ['rulesetName', 'rulesSourceSha256']} for receipt in receipts]
            rules_ok = all(metadata[0].values())
        elif pins.get('project') == 'fireemu-oracle-query':
            metadata = [{key: receipt.get('metadata', {}).get(key) for key in (['project', 'database', 'databaseSettings', 'rulesetName', 'rulesSourceSha256', 'keyRestrictionsSha256'] if table['name'] == 's5b-web-sdk-retry' else ['project', 'database', 'databaseSettings'])} for receipt in receipts]
            rules_ok = all(row['project'] and row['database'] and isinstance(row['databaseSettings'], dict) for row in metadata) and all(receipt.get('metadata', {}).get('oauth-tokeninfo', {}).get('verified') is True for receipt in receipts)
        else:
            # A project with no Rules release: the session proved the absence before each recording (the rules-absent slot).
            metadata = [{'rulesRelease': receipt.get('metadata', {}).get('rules-absent')} for receipt in receipts]
            rules_ok = metadata[0] == {'rulesRelease': 'absent'}
        if first != second or metadata[0] != metadata[1] or not rules_ok:
            save_private(directory / 'freeze-differences.json', {'first': first, 'second': second, 'metadata': metadata})
            raise ValueError('program independent recordings differ; shared lock retained')
        if table['name'] in ('p17-admin-sdk-retry', 's5b-web-sdk-retry'):
            if time.monotonic() >= campaign_deadline: raise TimeoutError('SDK campaign wall cap exceeded')
            save_private(directory / 'comparison.json', {'kind': 'txn-admin-sdk-independent-recordings-v1', 'projection': first, 'recordingSha256': [hashlib.sha256((directory / f'recording-{i + 1}.json').read_bytes()).hexdigest() for i in range(2)], 'authorizesProduction': False})
            release = True
            return {'runDir': directory, 'comparisonPath': directory / 'comparison.json'}
        frozen = {'kind': 'txn-program-freeze-v1', 'packetSha256': pins['packetSha256'], 'sourceCommit': pins['sourceCommit'], 'projection': first, 'rules': metadata[0], 'recordingSha256': [hashlib.sha256((directory / f'recording-{index + 1}.json').read_bytes()).hexdigest() for index in range(2)], 'authorizesProduction': False}
        save_private(directory / 'freeze.json', frozen)
        release = True
        return {'runDir': directory, 'freezePath': directory / 'freeze.json'}
    except (Exception, KeyboardInterrupt):
        if reserved:
            # Even a receipt write failure must leave a nonterminal ledger line.
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'stopped-needs-review', None, now()))
        raise
    finally:
        if release or not reserved: shared.release_project_locks(held)


def recover_named_databases(command, table, runs, directory, *, baseline, check):
    """One separately pinned A2 read or owned delete per journaled run; never resume the graph."""
    if command not in ("readback-a2", "recover-database") or table["name"] != "p16-foreign-tokens" or not 1 <= len(runs) <= 2 or len({run["nonce"] for run in runs}) != len(runs):
        raise ValueError("one or two distinct p16 journal nonces required")
    epoch = time.time()
    for run in runs:
        state = run["state"]
        nonce = run["nonce"]
        if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce) or state.get("database") != "projects/fireemu-oracle-query/databases/txn-" + nonce or type(state.get("lastRequestEpoch")) not in (int, float) or not math.isfinite(state["lastRequestEpoch"]):
            raise ValueError("named database journal identity differs")
        if not 600 <= epoch - state["lastRequestEpoch"] < float("inf"):
            raise ValueError("database action requires at least ten minutes after the last request")
        if command == "recover-database" and (state.get("createConfirmed") is not True or state.get("unknownCreate") is not False or state.get("deleteAttempted") is not False):
            raise ValueError("recovery delete requires a confirmed database; unknown deletes are sticky")
    check()
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    sequence = 0
    def journal(value):
        nonlocal sequence
        sequence += 1
        save_private(directory / f"{sequence:04d}.json", value)
    plan = compile_plan(table, runs[0]["nonce"], "b" * 32)
    budget = SessionBudget(plan, table, check, journal)
    budget._caps = {**budget._caps, "management": 5 + len(runs) * (2 if command == "recover-database" else 1), "credential": 1}
    budget._max = budget._caps["management"] + 1
    budget.begin_recovery()
    result = {"command": command, "runs": [], "complete": False, "settlesDocumentOrTokenObservations": False}
    metadata = None
    try:
        bearer = refresh(baseline, budget, before_send=check)
        metadata = MetadataSession(bearer, baseline, budget, project="fireemu-oracle-query", request_fn=functools.partial(request_once, project="fireemu-oracle-query"))
        result["preflight"] = metadata.preflight()
        for run in runs:
            budget._caps["management"] = 5 + (len(result["runs"]) + 1) * (2 if command == "recover-database" else 1)
            metadata.named_database = copy.deepcopy(run["state"])
            state = metadata.readback_named_database(time.time(), journal) if command == "readback-a2" else metadata.delete_named_database(journal)
            result["runs"].append(state)
        result["postflight"] = metadata.postflight()
        result["complete"] = True
    except (Exception, KeyboardInterrupt) as error:
        result["failureType"] = type(error).__name__
        if metadata is not None and hasattr(metadata, "named_database"):
            result["runs"].append(copy.deepcopy(metadata.named_database))
    result["requests"] = budget.total
    result["phaseRequests"] = dict(budget.used)
    save_private(directory / "result.json", result)
    return result
