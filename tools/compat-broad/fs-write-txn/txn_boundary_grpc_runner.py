"""P10-B session counters use explicit final recovery, not per-sample releases."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import math
import secrets
import time
from pathlib import Path

import txn_sandbox_admission as shared
from txn_boundary_grpc_authority import TASK_ID, authorize, remaining_task_budget, verify_initial_gates
from txn_boundary_grpc_collector import Collector, projection
from txn_idle_grpc_http import refresh, request_once
from txn_idle_grpc_runner import save_private
from txn_boundary_grpc_wire import NodeWire
from txn_sandbox_management import MetadataSession

from txn_boundary_grpc_program import RequestBudget, compile_plan


class SessionBudget(RequestBudget):
    def __init__(self, plan, check, save_count):
        super().__init__(plan)
        self.check = check
        self.save_count = save_count
        self.started = time.monotonic()
        if not math.isfinite(self.started):
            raise ValueError("P10-B monotonic clock is invalid")
        self._last_time = self.started
        self.observation_deadline = self.started + plan["observationSeconds"]
        self.recovery_deadline = None
        self.recovery_seconds = plan["recoverySeconds"]
        self.failed = False

    def _now(self):
        now = time.monotonic()
        if not math.isfinite(now) or now < self._last_time:
            raise ValueError("P10-B monotonic clock is invalid or moved backwards")
        self._last_time = now
        return now

    def begin_recovery(self):
        if self.recovery_deadline is None:
            self.recovery_deadline = self._now() + self.recovery_seconds

    def charge(self, phase):
        if self.failed:
            raise ValueError("P10-B count journal failed; dispatch blocked")
        if phase == "observation" and self.recovery_deadline is not None:
            raise ValueError("P10-B observation cannot resume after final recovery")
        if phase == "documentCleanup" and self.recovery_deadline is None:
            raise ValueError("P10-B document cleanup requires explicit recovery")
        self.check()
        deadline = self.recovery_deadline if self.recovery_deadline is not None else self.observation_deadline
        if deadline - self._now() < 13:
            raise TimeoutError("P10-B request cannot fit its fixed phase deadline")
        super().charge(phase)
        try:
            self.save_count({"kind": "txn-p10b-charged-count-v1", "phase": phase, "requests": self.total, "phaseRequests": dict(self.used)})
        except (Exception, KeyboardInterrupt):
            self.failed = True
            raise
        self.check()
        if deadline - self._now() < 13:
            raise TimeoutError("P10-B dispatch no longer fits after charged-count journal")


def run_once(index, nonce, owner_id, directory, *, baseline, runtime, check):
    directory = Path(directory) / f'journal-{index + 1}'
    directory.mkdir(mode=0o700)
    sequence = 0
    def journal(value):
        nonlocal sequence
        sequence += 1
        save_private(directory / f'{sequence:04d}.json', value)
    plan = compile_plan(nonce, owner_id)
    budget = SessionBudget(plan, check, journal)
    receipt = None
    metadata = None
    try:
        check()
        bearer = refresh(baseline, budget, before_send=check)
        metadata = MetadataSession(bearer, baseline, budget, request_fn=request_once)
        preflight = metadata.preflight()
        wire = NodeWire(runtime)
        collector = Collector(plan, budget, wire, bearer, save=journal, before_send=check, observation_deadline=budget.observation_deadline)
        receipt = collector.run()
        receipt['metadata'] = preflight
        if receipt.get('journalFailure') or budget.failed:
            raise ValueError('P10-B journal failed; metadata postflight is forbidden')
        budget.begin_recovery()
        receipt['postflight'] = metadata.postflight()
        check()
    except (Exception, KeyboardInterrupt) as error:
        if receipt is None:
            receipt = {'kind': 'txn-p10b-recording-v1', 'complete': False, 'graphComplete': False, 'program': plan['program'], 'sourceDigest': plan['sourceDigest'], 'corpusDigest': plan['corpusDigest'], 'nonce': nonce, 'ownerId': owner_id, 'unknownStarts': [], 'openTokens': [], 'cleanup': {'absent': None}, 'unrecovered': True}
        receipt['complete'] = False
        receipt['failureType'] = type(error).__name__
    receipt['sandboxRequests'] = budget.total
    receipt['phaseRequests'] = dict(budget.used)
    receipt['runtime'] = copy.deepcopy(runtime)
    return receipt


def _row(pins, attempt, directory, nonce, outcome, requests, now):
    if requests is not None and (type(requests) is not int or not 0 <= requests <= 48):
        raise ValueError('P10-B charged request count escaped its cap')
    return {'ts': now.isoformat().replace('+00:00', 'Z'), 'project': 'fireemu-oracle-sbx', 'database': '(default)', 'taskId': TASK_ID, 'envelopeId': pins['envelopeId'], 'packetId': pins['packetId'], 'gitSha': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'attemptId': attempt, 'runDir': str(directory), 'nonce': nonce, 'outcome': outcome, 'requests': requests, 'estimatedUsd': 0.01, 'pythonVersion': '3.12.13'}


def record_twice(*, ledger_path, private_dir, pins, decisions, now, record_once, admission_check):
    ledger_path, private_dir = Path(ledger_path), Path(private_dir)
    verify_initial_gates(shared.read_ledger(ledger_path), now(), decisions(), pins)
    held = shared.acquire_project_locks(private_dir, ['fireemu-oracle-sbx'], task_id=TASK_ID, packet_id=pins['packetId'], source_commit=pins['sourceCommit'])
    release = False
    reserved = False
    attempt = nonce = directory = None
    try:
        admission_check()
        verify_initial_gates(shared.read_ledger(ledger_path), now(), decisions(), pins)
        directory = private_dir / f'fs-transaction-p10b-{secrets.token_hex(8)}'
        directory.mkdir(mode=0o700)
        receipts = []
        for index in range(2):
            admission_check(); authorize(decisions(), pins)
            remaining_task_budget(shared.read_ledger(ledger_path), 0.01)
            attempt, nonce, owner_id = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'reserved', None, now()))
            reserved = True
            receipt = record_once(index, nonce, owner_id, directory)
            if not isinstance(receipt, dict): raise ValueError('P10-B recording receipt missing')
            requests = receipt.get('sandboxRequests')
            save_private(directory / f'recording-{index + 1}.json', receipt)
            if receipt.get('complete') is not True or receipt.get('timingMode') != 'wall-clock' or receipt.get('timingSource') != 'parent-wire-envelope':
                raise ValueError('P10-B acquisition stopped; second recording is forbidden')
            projection(receipt)
            shared.append_ledger(ledger_path, _row(pins, attempt, directory, nonce, 'recorded', requests, now()))
            receipts.append(receipt)
        admission_check(); authorize(decisions(), pins)
        first, second = map(projection, receipts)
        metadata = [{key: receipt.get('metadata', {}).get(key) for key in ['rulesetName', 'rulesSourceSha256']} for receipt in receipts]
        if first != second or metadata[0] != metadata[1] or any(not value for value in metadata[0].values()):
            save_private(directory / 'freeze-differences.json', {'first': first, 'second': second, 'metadata': metadata})
            raise ValueError('P10-B independent recordings differ; shared lock retained')
        frozen = {'kind': 'txn-p10b-freeze-v1', 'packetSha256': pins['packetSha256'], 'sourceCommit': pins['sourceCommit'], 'projection': first, 'rules': metadata[0], 'recordingSha256': [hashlib.sha256((directory / f'recording-{index + 1}.json').read_bytes()).hexdigest() for index in range(2)], 'authorizesProduction': False}
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
