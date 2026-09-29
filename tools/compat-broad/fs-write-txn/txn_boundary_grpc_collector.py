"""Finite native P10-B graph with durable responsibility before each dispatch."""

from __future__ import annotations

import copy
import time
import re
import math

from txn_boundary_grpc_program import GraphCursor, canonical_token, compile_plan, request_for_step, validate_plan


from txn_idle_grpc_collector import _timing, idle_interval, utc_now

STATES = ['created'] + [f'accepted-idle-{seconds}' for seconds in range(65, 71)]


def _string_field(value):
    # Native protobuf decoding can include its matching oneof discriminator.
    return isinstance(value, dict) and set(value) in ({'stringValue'}, {'stringValue', 'valueType'}) and isinstance(value.get('stringValue'), str) and value.get('valueType', 'stringValue') == 'stringValue'


def _native_timestamp(value):
    if not isinstance(value, dict) or set(value) - {'seconds', 'nanos'} or not isinstance(value.get('seconds'), str) or not re.fullmatch(r'[0-9]{1,12}', value['seconds']) or type(value.get('nanos', 0)) is not int or not 0 <= value.get('nanos', 0) <= 999999999:
        raise ValueError('P10-B native updateTime required')
    return {'seconds': value['seconds'], 'nanos': value.get('nanos', 0)}


class Collector:
    def __init__(self, plan, budget, wire, bearer, *, save, before_send=lambda: None, monotonic=time.monotonic, observation_deadline=None, utc=utc_now, sleep=time.sleep, timing_mode="wall-clock"):
        validate_plan(plan)
        self.plan = copy.deepcopy(plan)
        self.budget = budget
        self.wire = wire
        self.bearer = bearer
        self.save = save
        self.before_send = before_send
        self.monotonic = monotonic
        self.utc = utc
        self.sleep = sleep
        if timing_mode not in ["wall-clock", "control-clock"]: raise ValueError("P10-B timing mode differs")
        self.timing_mode = timing_mode
        self.waits = []
        self.expected_state = None
        self.cleanup_readback = False
        self.unknown_commits = set()
        self.observation_deadline = observation_deadline or monotonic() + plan['observationSeconds']
        self.deadline = self.observation_deadline
        self.tokens = {}
        self.unknown_starts = set()
        self.unknown_rollbacks = set()
        self.document_status = 'unexamined'
        self.rows = []
        self.cleanup_rows = []
        self.pending = None
        self.journal_failure = False
        self._last_monotonic = monotonic()
        self.last_timing = None

    def _now(self):
        current = self.monotonic()
        if type(current) not in (int, float) or not math.isfinite(current) or current < self._last_monotonic:
            raise ValueError('P10-B clock is invalid or moved backwards')
        self._last_monotonic = current
        return current

    def _state(self):
        return {'kind': 'txn-p10b-responsibility-v1', 'plan': self.plan, 'documentStatus': self.document_status, 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'unknownCommits': sorted(self.unknown_commits), 'expectedState': self.expected_state, 'waits': copy.deepcopy(self.waits), 'pending': copy.deepcopy(self.pending), 'rows': copy.deepcopy(self.rows), 'cleanupRows': copy.deepcopy(self.cleanup_rows), 'requests': self.budget.total}

    def _persist(self):
        try:
            self.save(self._state())
        except (Exception, KeyboardInterrupt):
            self.journal_failure = True
            self.budget.failed = True
            raise

    def _rpc(self, site, method, request, phase, *, step=None):
        if self.journal_failure:
            raise ValueError('P10-B journal failed; no further dispatch is safe')
        if method == 'BeginTransaction' and any(entry['state'] in ['open', 'unconfirmed-release'] for entry in self.tokens.values()):
            raise ValueError('P10-B prior sample token is unresolved')
        if method == 'Rollback' and any(entry['value'] == request['transaction'] and entry['state'] != 'open' for entry in self.tokens.values()):
            raise ValueError('P10-B token release cannot repeat')
        self.before_send()
        remaining = self.deadline - self._now()
        if remaining < 13:
            raise TimeoutError('P10-B phase deadline exceeded')
        self.budget.charge(phase)
        self.pending = {'site': site, 'rpc': method}
        if method == 'BeginTransaction': self.unknown_starts.add(site)
        if method == 'Commit': self.unknown_commits.add(site)
        if method == 'Rollback':
            for role, entry in self.tokens.items():
                if entry['value'] == request['transaction']:
                    self.pending['tokenRole'] = role
                    self.unknown_rollbacks.add(role)
                    if entry['state'] == 'open': entry['state'] = 'unconfirmed-release'
        if site == 'setup/create': self.document_status = 'possibly-owned'
        self._persist()
        self.before_send()
        remaining = self.deadline - self._now()
        if remaining < 13:
            raise TimeoutError('P10-B dispatch no longer fits after durable journal')
        timing = {'dispatchMonotonic': self._now(), 'dispatchUtc': self.utc()}
        result = self.wire.send(method, request, nonce=self.plan['nonce'], owner_id=self.plan['ownerId'], bearer=self.bearer, deadline_ms=max(1, min(10000, int(remaining * 1000))))
        timing.update(responseMonotonic=self._now(), responseUtc=self.utc())
        _timing(timing)
        if self.last_timing is not None: idle_interval(self.last_timing, timing)
        self.last_timing = copy.deepcopy(timing)
        row = {'sequence': len(self.rows) + len(self.cleanup_rows), 'phase': phase, 'timing': timing, 'site': site, 'rpc': method, 'caseId': step['caseId'] if step else None, 'request': copy.deepcopy(request), 'result': copy.deepcopy(result)}
        (self.rows if phase == 'observation' else self.cleanup_rows).append(row)
        if result.get('kind') != 'txn-p10b-grpc-receipt-v1' or type(result.get('dispatchedRequests')) is not int or result.get('dispatchedRequests') != 1 or result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('code')) is not int or result['code'] in [1, 2, 4, 13, 14] or not 0 <= result['code'] <= 16:
            self._persist()
            raise ValueError('P10-B native outcome is indeterminate')
        if result['code'] == 0 and not isinstance(result.get('response'), dict):
            self._persist()
            raise ValueError('P10-B native success has no typed response')
        if method == 'BeginTransaction':
            if result['code'] == 0:
                token = canonical_token(result['response'].get('transaction'))
                if token in {entry['value'] for entry in self.tokens.values()}:
                    raise ValueError('P10-B minted token is not fresh')
                self.tokens[step['tokenOutput']] = {'value': token, 'state': 'open', 'start': copy.deepcopy(timing), 'lastUse': copy.deepcopy(timing)}
                previous = step['tokenInput']
                if previous in self.tokens: self.tokens[previous]['state'] = 'retried'
            self.unknown_starts.discard(site)
        if method == 'Commit' and result['code'] == 0:
            writes = result['response'].get('writeResults')
            if not isinstance(writes, list) or len(writes) != 1:
                raise ValueError('P10-B commit lacks its single-write acknowledgement')
            _native_timestamp(writes[0].get('updateTime'))
            if site == 'setup/create': self.document_status = 'created'
            self.expected_state = request['writes'][0]['update']['fields']['state']['stringValue']
            for entry in self.tokens.values():
                if entry['value'] == request.get('transaction'): entry['state'] = 'committed'
        if method == 'Commit': self.unknown_commits.discard(site)
        if method == 'Rollback':
            for role, entry in self.tokens.items():
                if entry['value'] == request['transaction']:
                    self.unknown_rollbacks.discard(role)
                    if result['code'] == 0: entry['state'] = 'rolled-back'
        if result['code'] == 0 and method != 'BeginTransaction':
            for entry in self.tokens.values():
                if entry['value'] == request.get('transaction'): entry['lastUse'] = copy.deepcopy(timing)
        self.pending = None
        self._persist()
        return result

    def _owned(self, document):
        if not isinstance(document, dict) or document.get('name') != self.plan['document']:
            raise ValueError('P10-B read did not return its exact document')
        fields = document.get('fields')
        if not isinstance(fields, dict): raise ValueError('P10-B owned marker fields missing')
        expected = {'owner': self.plan['ownerId'], 'nonce': self.plan['nonce'], 'role': 'control'}
        if any(not isinstance(fields.get(key), dict) or fields[key].get('stringValue') != value for key, value in expected.items()):
            raise ValueError('P10-B document owner differs; deletion refused')
        if not isinstance(fields.get('state'), dict) or fields['state'].get('stringValue') not in STATES:
            raise ValueError('P10-B state marker is invalid')
        if set(fields) != {'owner', 'nonce', 'role', 'state'} or any(not _string_field(field) for field in fields.values()):
            raise ValueError('P10-B owned marker schema differs')
        _native_timestamp(document.get('updateTime'))
        return fields['state']['stringValue']

    def _wait(self, site, seconds):
        previous = self.rows[-1]
        if previous['rpc'] != 'GetDocument' or previous['result']['code'] != 0:
            raise ValueError('P10-B idle wait requires the preceding successful read')
        started = self._now()
        target = started + seconds
        while self._now() < target:
            self.before_send()
            current = self._now()
            if self.observation_deadline - current < target - current + 13:
                raise TimeoutError('P10-B idle candidate cannot fit the observation phase')
            if current >= target:
                break
            self.sleep(min(1, target - current))
            if self._now() <= current:
                raise ValueError('P10-B wait clock did not advance')
        if self._now() - target > 1:
            raise TimeoutError('P10-B idle candidate wait overshot its scheduling slack')
        self.waits.append({'site': site, 'seconds': seconds, 'previousSite': previous['site'], 'previousTiming': copy.deepcopy(previous['timing'])})
        self._persist()

    def _observe(self):
        cursor = GraphCursor(self.plan)
        for declared in self.plan['steps']:
            step = cursor.claim(declared['id'])
            if step['id'] in self.plan['waits']:
                self._wait(step['id'], self.plan['waits'][step['id']])
                start = self.tokens[step['tokenInput']]['start']
                if self._now() - start['dispatchMonotonic'] + 13 >= 270:
                    raise TimeoutError('P10-B sample no longer fits below the total lifetime')
            request = request_for_step(self.plan, step, {role: entry['value'] for role, entry in self.tokens.items()})
            result = self._rpc(step['id'], step['rpc'], request, 'observation', step=step)
            if step['id'] in self.plan['waits']:
                wait = self.waits[-1]
                wait['currentTiming'] = copy.deepcopy(self.rows[-1]['timing'])
                wait['idleInterval'] = idle_interval(wait['previousTiming'], wait['currentTiming'])
                wait['tokenRole'] = step['tokenInput']
                wait['totalAgeInterval'] = idle_interval(self.tokens[step['tokenInput']]['start'], wait['currentTiming'], 270)
                self._persist()
                if wait['totalAgeInterval']['upperSeconds'] >= 270:
                    raise ValueError('P10-B sample cannot isolate idle from total lifetime')
            if step['id'] == 'setup/absence':
                self.document_status = 'confirmed-absent' if result['code'] == 5 else 'pre-existing'
                self._persist()
                if result['code'] != 5:
                    raise ValueError('P10-B setup document was not absent; no write admitted')
            elif step['rpc'] == 'GetDocument':
                if result['code'] != 0 or self._owned(result['response']) != self.expected_state:
                    raise ValueError('P10-B required read or acknowledged post-state differs')
            elif not step['caseId'] and result['code'] != 0:
                raise ValueError('P10-B required transaction context was refused')
            if step['id'].endswith('/post-state'):
                role = step['id'].split('/')[0]
                entry = self.tokens[role]
                if entry['state'] == 'open':
                    released = self._rpc(f'cleanup/token/{role}', 'Rollback', {'database': self.plan['database'], 'transaction': entry['value']}, 'tokenCleanup')
                    if released['code'] != 0 or entry['state'] != 'rolled-back':
                        raise ValueError('P10-B sample release is unconfirmed; next sample forbidden')
                if entry['state'] not in ['committed', 'rolled-back']:
                    raise ValueError('P10-B sample token is unresolved')
        return cursor.complete

    def _cleanup(self):
        for role, entry in self.tokens.items():
            if entry['state'] != 'open':
                continue
            try:
                self._rpc(f'cleanup/token/{role}', 'Rollback', {'database': self.plan['database'], 'transaction': entry['value']}, 'tokenCleanup')
            except (Exception, KeyboardInterrupt):
                # A release attempted during observation or recovery cannot repeat.
                continue
        if self.document_status in ['unexamined', 'confirmed-absent', 'pre-existing']:
            return self.document_status == 'confirmed-absent'
        try:
            read = self._rpc('cleanup/read-owner', 'GetDocument', {'name': self.plan['document']}, 'documentCleanup')
            if read['code'] != 0 or self._owned(read['response']) != self.expected_state:
                return False
            self.cleanup_readback = True
            stamp = _native_timestamp(read['response'].get('updateTime'))
            deleted = self._rpc('cleanup/delete-version', 'DeleteDocument', {'name': self.plan['document'], 'currentDocument': {'updateTime': stamp}}, 'documentCleanup')
            if deleted['code'] != 0:
                return False
            absent = self._rpc('cleanup/verify-absence', 'GetDocument', {'name': self.plan['document']}, 'documentCleanup')
            if absent['code'] == 5:
                self.document_status = 'confirmed-absent'
                self._persist()
                return True
        except (Exception, KeyboardInterrupt):
            pass
        return False

    def run(self):
        failure = None
        graph_complete = False
        try:
            graph_complete = self._observe()
        except (Exception, KeyboardInterrupt) as error:
            failure = type(error).__name__
        absent = self.document_status == 'confirmed-absent'
        try:
            if hasattr(self.budget, 'begin_recovery'):
                self.budget.begin_recovery()
            self.deadline = self._now() + self.plan['recoverySeconds']
            absent = self._cleanup()
        except (Exception, KeyboardInterrupt) as error:
            failure = failure or type(error).__name__
        open_tokens = [role for role, entry in self.tokens.items() if entry['state'] in ['open', 'unconfirmed-release']]
        observations = [row for row in self.rows if row['caseId']]
        unrecovered = bool(open_tokens or self.unknown_starts or self.unknown_rollbacks or self.unknown_commits or not absent or self.journal_failure)
        complete = graph_complete and failure is None and not unrecovered and [row['caseId'] for row in observations] == self.plan['cases']
        return {'kind': 'txn-p10b-recording-v1', 'complete': complete, 'graphComplete': graph_complete, 'program': self.plan['program'], 'sourceDigest': self.plan['sourceDigest'], 'corpusDigest': self.plan['corpusDigest'], 'nonce': self.plan['nonce'], 'ownerId': self.plan['ownerId'], 'observations': copy.deepcopy(observations), 'steps': copy.deepcopy(self.rows), 'cleanupSteps': copy.deepcopy(self.cleanup_rows), 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'unknownCommits': sorted(self.unknown_commits), 'waits': copy.deepcopy(self.waits), 'timingMode': self.timing_mode, 'timingSource': 'parent-wire-envelope' if self.timing_mode == 'wall-clock' else 'local-control-clock', 'expectedState': self.expected_state, 'expectedStateReadback': self.cleanup_readback, 'openTokens': open_tokens, 'journalFailure': self.journal_failure, 'cleanup': {'absent': absent}, 'unrecovered': unrecovered, 'failureType': failure, 'sandboxRequests': self.budget.total, 'phaseRequests': dict(self.budget.used)}


def boundary_classification(waits, observations):
    codes = [row['result']['code'] for row in observations]
    if len(codes) != 6 or len(waits) != 6:
        raise ValueError('P10-B boundary classification needs six samples')
    if not any(code == 0 for code in codes) or not any(code != 0 for code in codes):
        return 'INDETERMINATE'
    first_refusal = next(index for index, code in enumerate(codes) if code != 0)
    if any(code == 0 for code in codes[first_refusal:]):
        return 'INDETERMINATE'
    if any(row['result']['code'] != 10 or row['result'].get('details') != 'The referenced transaction has expired or is no longer valid.' for row in observations[first_refusal:]):
        return 'INDETERMINATE'
    latest_success_upper = max(wait['idleInterval']['upperSeconds'] for wait in waits[:first_refusal])
    earliest_refusal_lower = min(wait['idleInterval']['lowerSeconds'] for wait in waits[first_refusal:])
    return 'SEPARATED_OBSERVATIONS' if latest_success_upper < earliest_refusal_lower else 'INDETERMINATE'


def projection(receipt):
    """Derive every completed sample, release, timing and deletion from native rows."""
    if not isinstance(receipt, dict) or receipt.get('kind') != 'txn-p10b-recording-v1' or receipt.get('complete') is not True or receipt.get('graphComplete') is not True or receipt.get('journalFailure') is not False or receipt.get('unrecovered') is not False or receipt.get('failureType') is not None or any(receipt.get(key) for key in ['openTokens', 'unknownStarts', 'unknownRollbacks', 'unknownCommits']) or receipt.get('cleanup') != {'absent': True}:
        raise ValueError('only complete P10-B acquisitions can freeze')
    plan = compile_plan(receipt.get('nonce'), receipt.get('ownerId'))
    if any(receipt.get(key) != plan[key] for key in ['program', 'sourceDigest', 'corpusDigest']):
        raise ValueError('P10-B acquisition source binding differs')
    counts = receipt.get('phaseRequests')
    if not isinstance(counts, dict) or set(counts) != set(plan['caps']) or any(type(value) is not int or not 0 <= value <= plan['caps'][key] for key, value in counts.items()) or type(receipt.get('sandboxRequests')) is not int or sum(counts.values()) != receipt['sandboxRequests'] or receipt['sandboxRequests'] > plan['maxRequests']:
        raise ValueError('P10-B request accounting differs')
    steps, cleanup = receipt.get('steps'), receipt.get('cleanupSteps')
    if not isinstance(steps, list) or len(steps) != 26 or not isinstance(cleanup, list) or len(cleanup) != counts['tokenCleanup'] + counts['documentCleanup'] or counts['observation'] != 26:
        raise ValueError('P10-B graph or cleanup accounting differs')
    rows = steps + cleanup
    if any(not isinstance(row, dict) or type(row.get('sequence')) is not int for row in rows) or sorted(row['sequence'] for row in rows) != list(range(len(rows))):
        raise ValueError('P10-B native sequence differs')
    ordered = sorted(rows, key=lambda row: row['sequence'])
    issued, tokens, starts, last_uses = {}, {}, {}, {}
    expected_state = None
    observations, waits, reads = [], [], []
    index, releases = 0, 0
    previous = None
    document_index = 0
    marker_time = None

    def native(row):
        result = row.get('result')
        if not isinstance(result, dict) or result.get('kind') != 'txn-p10b-grpc-receipt-v1' or result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('dispatchedRequests')) is not int or result['dispatchedRequests'] != 1 or type(result.get('code')) is not int or not 0 <= result['code'] <= 16 or result['code'] in [1, 2, 4, 13, 14] or not isinstance(result.get('details'), str) or len(result['details'].encode()) > 16384 or result['code'] == 0 and not isinstance(result.get('response'), dict):
            raise ValueError('P10-B incomplete native result cannot freeze')
        _timing(row.get('timing'))
        if previous is not None:
            idle_interval(previous['timing'], row['timing'])
        return result

    def owned(document):
        if not isinstance(document, dict) or document.get('name') != plan['document'] or not isinstance(document.get('fields'), dict) or set(document['fields']) != {'owner', 'nonce', 'role', 'state'}:
            raise ValueError('P10-B document marker differs')
        fields = document['fields']
        if any(not _string_field(field) for field in fields.values()) or any(fields[key]['stringValue'] != value for key, value in {'owner': plan['ownerId'], 'nonce': plan['nonce'], 'role': 'control'}.items()) or fields['state']['stringValue'] != expected_state:
            raise ValueError('P10-B acknowledged document state or owner differs')
        return _native_timestamp(document.get('updateTime'))

    for row in ordered:
        result = native(row)
        request = row.get('request')
        if row.get('phase') == 'observation':
            if index >= len(steps) or row != steps[index]:
                raise ValueError('P10-B observation sequence differs')
            declared = plan['steps'][index]
            if row.get('site') != declared['id'] or row.get('rpc') != declared['rpc'] or row.get('caseId') != declared['caseId'] or request != request_for_step(plan, declared, issued) or row.get('skipped'):
                raise ValueError('P10-B closed request graph differs')
            if not declared['caseId'] and result['code'] != (5 if declared['id'] == 'setup/absence' else 0):
                raise ValueError('P10-B required sample context is missing')
            role = declared['tokenInput']
            if declared['rpc'] == 'BeginTransaction':
                if any(value == 'open' for value in tokens.values()):
                    raise ValueError('P10-B preceding sample token was not released')
                value = canonical_token(result['response'].get('transaction'))
                if value in issued.values():
                    raise ValueError('P10-B issued sample token is not fresh')
                output = declared['tokenOutput']
                issued[output], tokens[output] = value, 'open'
                starts[output] = copy.deepcopy(row['timing'])
                last_uses[output] = copy.deepcopy(row['timing'])
            elif declared['rpc'] == 'Commit':
                if role:
                    if previous is None or previous['site'] != role + '/read' or previous['result']['code'] != 0:
                        raise ValueError('P10-B candidate has no successful prior read')
                    interval = idle_interval(previous['timing'], row['timing'])
                    age = idle_interval(starts[role], row['timing'], 270)
                    if interval['lowerSeconds'] < plan['waits'][declared['id']] or age['upperSeconds'] >= 270:
                        raise ValueError('P10-B idle timing or total-age isolation differs')
                    waits.append({'site': declared['id'], 'seconds': plan['waits'][declared['id']], 'previousSite': previous['site'], 'previousTiming': previous['timing'], 'currentTiming': row['timing'], 'idleInterval': interval, 'tokenRole': role, 'totalAgeInterval': age})
                if result['code'] == 0:
                    write_results = result['response'].get('writeResults')
                    if not isinstance(write_results, list) or len(write_results) != 1 or not isinstance(write_results[0], dict):
                        raise ValueError('P10-B single write acknowledgement differs')
                    _native_timestamp(write_results[0].get('updateTime'))
                    expected_state = declared['state']
                    if role:
                        tokens[role] = 'committed'
            elif declared['rpc'] == 'GetDocument':
                if result['code'] == 0:
                    owned(result['response'])
                reads.append({'site': row['site'], 'code': result['code'], 'state': (result.get('response') or {}).get('fields', {}).get('state', {}).get('stringValue')})
            if role and result['code'] == 0:
                last_uses[role] = copy.deepcopy(row['timing'])
            if declared['caseId']:
                observations.append(row)
            index += 1
        elif row.get('phase') == 'tokenCleanup':
            role = str(row.get('site')).removeprefix('cleanup/token/')
            if row.get('rpc') != 'Rollback' or role not in issued or tokens[role] != 'open' or result['code'] != 0 or request != {'database': plan['database'], 'transaction': issued[role]} or previous is None or previous['site'] != role + '/post-state' or index >= 26 and role != 'idle-70':
                raise ValueError('P10-B per-sample release proof differs')
            tokens[role] = 'rolled-back'
            last_uses[role] = copy.deepcopy(row['timing'])
            releases += 1
        elif row.get('phase') == 'documentCleanup':
            if index != 26 or any(value == 'open' for value in tokens.values()) or document_index >= 3:
                raise ValueError('P10-B final recovery ordering differs')
            sites = ['cleanup/read-owner', 'cleanup/delete-version', 'cleanup/verify-absence']
            if row.get('site') != sites[document_index]:
                raise ValueError('P10-B cleanup graph differs')
            if document_index == 0:
                if row.get('rpc') != 'GetDocument' or request != {'name': plan['document']} or result['code'] != 0:
                    raise ValueError('P10-B final owner readback differs')
                marker_time = owned(result['response'])
            elif document_index == 1:
                if row.get('rpc') != 'DeleteDocument' or request != {'name': plan['document'], 'currentDocument': {'updateTime': marker_time}} or result['code'] != 0:
                    raise ValueError('P10-B version deletion differs')
            elif row.get('rpc') != 'GetDocument' or request != {'name': plan['document']} or result['code'] != 5:
                raise ValueError('P10-B typed absence differs')
            document_index += 1
        else:
            raise ValueError('P10-B undeclared native phase')
        previous = row
    derived_tokens = {role: {'value': value, 'state': tokens[role], 'start': starts[role], 'lastUse': last_uses[role]} for role, value in issued.items()}
    if index != 26 or document_index != 3 or counts['documentCleanup'] != 3 or releases != counts['tokenCleanup'] or observations != receipt.get('observations') or waits != receipt.get('waits') or derived_tokens != receipt.get('tokens') or receipt.get('expectedState') != expected_state or receipt.get('expectedStateReadback') is not True:
        raise ValueError('P10-B completion claims cannot be derived from native rows')
    if receipt.get('timingMode') not in ['wall-clock', 'control-clock'] or receipt.get('timingSource') != ('parent-wire-envelope' if receipt['timingMode'] == 'wall-clock' else 'local-control-clock'):
        raise ValueError('P10-B timing provenance differs')
    def details(row):
        value = row['result']['details']
        for role, token in issued.items():
            value = value.replace(token, f'<token:{role}>')
        return value.replace(receipt['nonce'], '<nonce>').replace(receipt['ownerId'], '<owner>')
    cases = [{'caseId': row['caseId'], 'rpc': row['rpc'], 'candidateSeconds': seconds, 'code': row['result']['code'], 'details': details(row)} for seconds, row in zip(plan['candidates'], observations, strict=True)]
    return {'program': plan['program'], 'corpusDigest': plan['corpusDigest'], 'cases': cases, 'reads': reads, 'timingMode': receipt['timingMode'], 'idleCandidates': [{'site': wait['site'], 'seconds': wait['seconds'], 'classification': wait['idleInterval']['classification'], 'thresholdSeconds': 60} for wait in waits], 'boundaryClassification': boundary_classification(waits, observations), 'exactThresholdProven': False, 'cleanup': {'absent': True}}
