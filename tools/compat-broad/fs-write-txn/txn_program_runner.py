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
import secrets
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
    return {'slug': table['slug'], 'documents': list(table['documents']), 'states': list(table['states'])}


class SessionBudget(RequestBudget):
    def __init__(self, plan, table, check, save_count):
        super().__init__(plan, table)
        self.check = check
        self.save_count = save_count
        self.sdk = table['name'] == 'p17-admin-sdk-retry'
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


def run_once(index, table, nonce, owner_id, directory, *, baseline, runtime, check):
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
    try:
        check()
        project = table.get('project', PROJECT)
        bearer = refresh(baseline, budget, before_send=check)
        # the shared project keeps the call exactly as it was; another project's name rides along
        extra = {} if project == PROJECT else {'project': project}
        metadata = MetadataSession(bearer, baseline, budget, request_fn=request_once if project == PROJECT else functools.partial(request_once, project=project), **extra)
        preflight = metadata.preflight()
        if table['name'] == 'p17-admin-sdk-retry':
            worker = Path(table['sourceFile'])
            child = subprocess.Popen([runtime['nodeExecutable'], str(worker), 'production'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}, close_fds=True)
            end = budget.started + 300
            buffered = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        if time.monotonic() >= end: raise TimeoutError('SDK recording wall cap exceeded')
                        for key, _ in selector.select(min(0.2, end - time.monotonic())):
                            block = os.read(key.fd, 4096)
                            if not block:
                                selector.unregister(key.fileobj)
                                break
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
                                if event.get('event') == 'ready':
                                    reply = {'authorized': True, 'bearer': bearer, 'nonce': nonce, 'ownerId': owner_id, 'observationRemaining': budget.observation_deadline - time.monotonic()}
                                else:
                                    if event.get('event') == 'dispatch':
                                        row = event['row']
                                        if row['sequence'] != len(dispatched) or row['phase'] not in ('observation', 'documentCleanup'): raise ValueError('SDK dispatch accounting differs')
                                        if row['phase'] == 'documentCleanup': budget.begin_recovery()
                                        request = row['request']
                                        if any(value.get('outcomeClass') == 'UNKNOWN' for value in dispatched.values()): raise ValueError('SDK unknown answer blocks redispatch')
                                        if row.get('transport') != 'grpc' or row.get('rpc') not in ('BatchGetDocuments', 'Commit', 'Rollback', 'DeleteDocument'): raise ValueError('SDK RPC scope differs')
                                        if row['rpc'] in ('BatchGetDocuments', 'Commit', 'Rollback') and request.get('database') != plan['database']: raise ValueError('SDK database scope differs')
                                        names = set(plan['documents'].values())
                                        if row['rpc'] == 'BatchGetDocuments' and (not isinstance(request.get('documents'), list) or not 1 <= len(request['documents']) <= 3 or not set(request['documents']) <= names): raise ValueError('SDK read scope differs')
                                        if row['rpc'] == 'DeleteDocument' and (request.get('name') not in names or not request.get('currentDocument', {}).get('updateTime')): raise ValueError('SDK delete scope differs')
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
                                        if before is None or before.get('result') or any(row.get(key) != before.get(key) for key in ('transport', 'rpc', 'request', 'client', 'site', 'phase', 'caseId', 'attempt')) or row.get('frames') != before.get('frames', []): raise ValueError('SDK status does not match its dispatch')
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
                if receipt.get('receiptDigest') != hashlib.sha256(json.dumps({key: value for key, value in receipt.items() if key != 'receiptDigest'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest(): raise ValueError('SDK native receipt digest differs')
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
                for pipe in (child.stdin, child.stdout): pipe.close()
        else:
            wire = NodeWire(runtime, wire_scope(table), **({} if project == PROJECT else {'project': project}))
            collector = Collector(plan, table, budget, wire, bearer, save=journal, before_send=check, observation_deadline=budget.observation_deadline)
            receipt = collector.run()
            receipt['metadata'] = preflight
            if receipt.get('journalFailure') or budget.failed:
                raise ValueError('program journal failed; metadata postflight is forbidden')
            budget.begin_recovery()
            receipt['postflight'] = metadata.postflight()
            check()
    except (Exception, KeyboardInterrupt) as error:
        if receipt is None:
            receipt = {'kind': 'txn-program-recording-v1', 'complete': False, 'graphComplete': False, 'program': plan['program'], 'packetName': plan['packetName'], 'sourceDigest': plan['sourceDigest'], 'corpusDigest': plan['corpusDigest'], 'nonce': nonce, 'ownerId': owner_id, 'unknownStarts': [], 'openTokens': [], 'cleanup': {'absent': None}, 'unrecovered': True}
        receipt['complete'] = False
        receipt['failureType'] = type(error).__name__
        if table['name'] == 'p17-admin-sdk-retry':
            receipt.update(documents=documents, steps=list(dispatched.values()), cleanupSteps=[], unknownCommits=[seq for seq, row in dispatched.items() if row['rpc'] == 'Commit' and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')], unknownStarts=[seq for seq, row in dispatched.items() if row['rpc'] == 'BatchGetDocuments' and row['request'].get('newTransaction') and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')], timingMode='wall-clock', timingSource='grpc-js-client-interceptor', unrecovered=True)
            receipt['tokens'] = {}
            for row in dispatched.values():
                for frame in row.get('frames', []):
                    if frame and frame.get('transaction'): receipt['tokens'][f"{row.get('caseId')}-{row.get('client')}-{row.get('attempt')}"] = {'value': frame['transaction'], 'transport': 'grpc', 'state': 'open'}
                for token in receipt['tokens'].values():
                    if token['value'] == row['request'].get('transaction') and (row['rpc'] == 'Commit' and row.get('result', {}).get('code') == 0 or row['rpc'] == 'Rollback' and (row.get('result', {}).get('code') == 0 or row.get('result', {}).get('code') == 10 and row['result'].get('details') == 'The referenced transaction has expired or is no longer valid.')): token['state'] = 'closed'
            receipt['openTokens'] = [role for role, token in receipt['tokens'].items() if token['state'] == 'open']
            receipt['unknownRollbacks'] = [seq for seq, row in dispatched.items() if row['rpc'] == 'Rollback' and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')]
            receipt['unknownWrites'] = [seq for seq, row in dispatched.items() if row['rpc'] in ('Commit', 'DeleteDocument') and (not row.get('result') or row.get('outcomeClass') == 'UNKNOWN')]
            receipt['journalFailure'] = budget.failed
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
    return receipt


def _row(pins, attempt, directory, nonce, outcome, requests, now):
    if requests is not None and (type(requests) is not int or not 0 <= requests <= pins['requestsPerRecording']):
        raise ValueError('program charged request count escaped its cap')
    return {'ts': now.isoformat().replace('+00:00', 'Z'), 'project': pins.get('project', PROJECT), 'database': '(default)', 'taskId': TASK_ID, 'envelopeId': pins['envelopeId'], 'packetId': pins['packetId'], 'gitSha': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'attemptId': attempt, 'runDir': str(directory), 'nonce': nonce, 'outcome': outcome, 'requests': requests, 'estimatedUsd': pins.get('estimatedUsdPerRecording', 0.01), 'pythonVersion': '3.12.13'}


def record_twice(*, table, ledger_path, private_dir, pins, decisions, now, record_once, admission_check):
    ledger_path, private_dir = Path(ledger_path), Path(private_dir)
    campaign_deadline = time.monotonic() + 600
    verify_initial_gates(shared.read_ledger(ledger_path), now(), decisions(), pins)
    held = shared.acquire_project_locks(private_dir, [pins.get('project', PROJECT)], task_id=TASK_ID, packet_id=pins['packetId'], source_commit=pins['sourceCommit'])
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
            if table['name'] == 'p17-admin-sdk-retry' and campaign_deadline - time.monotonic() < 300: raise TimeoutError('SDK campaign wall cap exceeded')
            admission_check(); authorize(decisions(), pins)
            remaining_task_budget(shared.read_ledger(ledger_path), pins.get('estimatedUsdPerRecording', 0.01))
            attempt, nonce, owner_id = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'reserved', None, now()))
            reserved = True
            receipt = record_once(index, nonce, owner_id, directory)
            if not isinstance(receipt, dict): raise ValueError('program recording receipt missing')
            requests = receipt.get('sandboxRequests')
            save_private(directory / f'recording-{index + 1}.json', receipt)
            if receipt.get('complete') is not True or receipt.get('timingMode') != 'wall-clock' or receipt.get('timingSource') != ('grpc-js-client-interceptor' if table['name'] == 'p17-admin-sdk-retry' else 'parent-wire-envelope'):
                raise ValueError('program acquisition stopped; second recording is forbidden')
            if table['name'] == 'p17-admin-sdk-retry':
                if campaign_deadline - time.monotonic() < 30: raise TimeoutError('SDK campaign projection cannot fit wall cap')
                sdk_projections.append(projection(receipt, table))
            else: projection(receipt, table)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'recorded', requests, now()))
            receipts.append(receipt)
        admission_check(); authorize(decisions(), pins)
        first, second = sdk_projections if table['name'] == 'p17-admin-sdk-retry' else (projection(receipt, table) for receipt in receipts)
        if pins.get('project', PROJECT) == PROJECT:
            metadata = [{key: receipt.get('metadata', {}).get(key) for key in ['rulesetName', 'rulesSourceSha256']} for receipt in receipts]
            rules_ok = all(metadata[0].values())
        else:
            # A project with no Rules release: the session proved the absence before each recording (the rules-absent slot).
            metadata = [{'rulesRelease': receipt.get('metadata', {}).get('rules-absent')} for receipt in receipts]
            rules_ok = metadata[0] == {'rulesRelease': 'absent'}
        if first != second or metadata[0] != metadata[1] or not rules_ok:
            save_private(directory / 'freeze-differences.json', {'first': first, 'second': second, 'metadata': metadata})
            raise ValueError('program independent recordings differ; shared lock retained')
        if table['name'] == 'p17-admin-sdk-retry':
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
