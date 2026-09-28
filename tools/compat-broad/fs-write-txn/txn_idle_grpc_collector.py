"""Finite native P10-A graph with durable responsibility before each dispatch."""

from __future__ import annotations

import copy
import time
import datetime as dt
import math

from txn_idle_grpc_program import GraphCursor, canonical_token, compile_plan, request_for_step, validate_plan


INVALIDATED_DETAILS = 'The referenced transaction has expired or is no longer valid.'
STATES = ['created', 'committed-before-idle', 'attempted-after-idle', 'after-rollback-first', 'after-get-first']


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def _utc_seconds(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('P10-A UTC endpoint required')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def _timing(value):
    if not isinstance(value, dict) or set(value) != {'dispatchMonotonic', 'responseMonotonic', 'dispatchUtc', 'responseUtc'}:
        raise ValueError('P10-A closed RPC timing required')
    a, b = value['dispatchMonotonic'], value['responseMonotonic']
    if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in (a, b)) or b < a:
        raise ValueError('P10-A monotonic endpoint invalid')
    ua, ub = _utc_seconds(value['dispatchUtc']), _utc_seconds(value['responseUtc'])
    if ub < ua or abs((ub - ua) - (b - a)) > 0.25:
        raise ValueError('P10-A UTC and monotonic RPC elapsed differ')
    return a, b, ua, ub


def idle_interval(previous, current, threshold=60):
    pd, pr, pu, pv = _timing(previous)
    nd, nr, nu, nv = _timing(current)
    lower, upper = nd - pr, nr - pd
    if lower < 0 or nu < pv or abs(lower - (nu - pv)) > 0.25 or abs(upper - (nv - pu)) > 0.25:
        raise ValueError('P10-A idle clocks differ or moved backwards')
    classification = 'BEFORE' if upper < threshold else 'AFTER' if lower > threshold else 'INDETERMINATE'
    return {'lowerSeconds': lower, 'upperSeconds': upper, 'classification': classification, 'thresholdSeconds': threshold}


def invalidated_cleanup(role, result, expired_refused):
    # Only the coordinator-approved late-token cleanup refusal is terminal.
    return role == 'late' and expired_refused and result['code'] == 10 and result.get('details') == INVALIDATED_DETAILS


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
        if timing_mode not in ["wall-clock", "control-clock"]: raise ValueError("P10-A timing mode differs")
        self.timing_mode = timing_mode
        self.waits = []
        self.expected_state = None
        self.expired_refused = False
        self.cleanup_readback = False
        self.unknown_commits = set()
        self.observation_deadline = observation_deadline or monotonic() + plan['observationSeconds']
        self.deadline = self.observation_deadline
        self.tokens = {}
        self.unknown_starts = set()
        self.unknown_rollbacks = set()
        self.refused_outputs = set()
        self.document_status = 'unexamined'
        self.rows = []
        self.cleanup_rows = []
        self.pending = None
        self.journal_failure = False

    def _state(self):
        return {'kind': 'txn-p10-responsibility-v1', 'plan': self.plan, 'documentStatus': self.document_status, 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'unknownCommits': sorted(self.unknown_commits), 'expectedState': self.expected_state, 'waits': copy.deepcopy(self.waits), 'pending': copy.deepcopy(self.pending), 'rows': copy.deepcopy(self.rows), 'cleanupRows': copy.deepcopy(self.cleanup_rows), 'requests': self.budget.total}

    def _persist(self):
        try:
            self.save(self._state())
        except (Exception, KeyboardInterrupt):
            self.journal_failure = True
            self.budget.failed = True
            raise

    def _rpc(self, site, method, request, phase, *, step=None):
        if self.journal_failure:
            raise ValueError('P10-A journal failed; no further dispatch is safe')
        self.before_send()
        remaining = self.deadline - self.monotonic()
        if remaining < 13:
            raise TimeoutError('P10-A phase deadline exceeded')
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
        remaining = self.deadline - self.monotonic()
        if remaining < 13:
            raise TimeoutError('P10-A dispatch no longer fits after durable journal')
        timing = {'dispatchMonotonic': self.monotonic(), 'dispatchUtc': self.utc()}
        result = self.wire.send(method, request, nonce=self.plan['nonce'], owner_id=self.plan['ownerId'], bearer=self.bearer, deadline_ms=max(1, min(10000, int(remaining * 1000))))
        timing.update(responseMonotonic=self.monotonic(), responseUtc=self.utc())
        _timing(timing)
        row = {'timing': timing, 'site': site, 'rpc': method, 'caseId': step['caseId'] if step else None, 'request': copy.deepcopy(request), 'result': copy.deepcopy(result)}
        (self.rows if phase == 'observation' else self.cleanup_rows).append(row)
        if result.get('dispatchedRequests') != 1 or result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('code')) is not int or result['code'] in [1, 2, 4, 13, 14] or not 0 <= result['code'] <= 16:
            self._persist()
            raise ValueError('P10-A native outcome is indeterminate')
        if result['code'] == 0 and not isinstance(result.get('response'), dict):
            self._persist()
            raise ValueError('P10-A native success has no typed response')
        if method == 'BeginTransaction':
            if result['code'] == 0:
                token = canonical_token(result['response'].get('transaction'))
                if token in {entry['value'] for entry in self.tokens.values()}:
                    raise ValueError('P10-A minted token is not fresh')
                self.tokens[step['tokenOutput']] = {'value': token, 'state': 'open', 'start': copy.deepcopy(timing), 'lastUse': copy.deepcopy(timing)}
                previous = step['tokenInput']
                if previous in self.tokens: self.tokens[previous]['state'] = 'retried'
            else:
                self.refused_outputs.add(step['tokenOutput'])
            self.unknown_starts.discard(site)
        if method == 'Commit':
            if site == 'expired/commit': self.expired_refused = result['code'] != 0
        if method == 'Commit' and result['code'] == 0:
            writes = result['response'].get('writeResults')
            if not isinstance(writes, list) or len(writes) != 1:
                raise ValueError('P10-A commit lacks its single-write acknowledgement')
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
                    elif site.startswith('cleanup/token/') and invalidated_cleanup(role, result, self.expired_refused): entry['state'] = 'invalidated'
        if result['code'] == 0 and method != 'BeginTransaction':
            for entry in self.tokens.values():
                if entry['value'] == request.get('transaction'): entry['lastUse'] = copy.deepcopy(timing)
        self.pending = None
        self._persist()
        return result

    def _owned(self, document):
        if not isinstance(document, dict) or document.get('name') != self.plan['document']:
            raise ValueError('P10-A read did not return its exact document')
        fields = document.get('fields')
        if not isinstance(fields, dict): raise ValueError('P10-A owned marker fields missing')
        expected = {'owner': self.plan['ownerId'], 'nonce': self.plan['nonce'], 'role': 'control'}
        if any(not isinstance(fields.get(key), dict) or fields[key].get('stringValue') != value for key, value in expected.items()):
            raise ValueError('P10-A document owner differs; deletion refused')
        if not isinstance(fields.get('state'), dict) or fields['state'].get('stringValue') not in STATES:
            raise ValueError('P10-A state marker is invalid')
        return fields['state']['stringValue']

    def _wait(self, site, seconds):
        previous = self.rows[-1]
        if previous['rpc'] != 'GetDocument' or previous['result']['code'] != 0:
            raise ValueError('P10-A idle wait requires the preceding successful read')
        started = self.monotonic()
        target = started + seconds
        while self.monotonic() < target:
            self.before_send()
            current = self.monotonic()
            if self.observation_deadline - current < target - current + 13:
                raise TimeoutError('P10-A idle candidate cannot fit the observation phase')
            if current >= target:
                break
            self.sleep(min(1, target - current))
            if self.monotonic() <= current:
                raise ValueError('P10-A wait clock did not advance')
        self.waits.append({'site': site, 'seconds': seconds, 'previousSite': previous['site'], 'previousTiming': copy.deepcopy(previous['timing'])})
        self._persist()

    def _observe(self):
        cursor = GraphCursor(self.plan)
        for declared in self.plan['steps']:
            step = cursor.claim(declared['id'])
            binding = step['tokenInput']
            if binding in self.refused_outputs and step['id'] in self.plan['conditionalSkips']:
                self.rows.append({'site': step['id'], 'rpc': step['rpc'], 'caseId': None, 'skipped': 'definitive-earlier-begin-refusal', 'tokenRole': binding})
                self._persist()
                continue
            if step['id'] in self.plan['waits']:
                self._wait(step['id'], self.plan['waits'][step['id']])
            request = request_for_step(self.plan, step, {key: entry['value'] for key, entry in self.tokens.items()})
            result = self._rpc(step['id'], step['rpc'], request, 'observation', step=step)
            if step['id'] in self.plan['waits']:
                self.waits[-1]['currentTiming'] = copy.deepcopy(self.rows[-1]['timing'])
                self.waits[-1]['idleInterval'] = idle_interval(self.waits[-1]['previousTiming'], self.waits[-1]['currentTiming'])
                role = step['tokenInput']
                self.waits[-1]['tokenRole'] = role
                self.waits[-1]['totalAgeInterval'] = idle_interval(self.tokens[role]['start'], self.rows[-1]['timing'], 270)
                self._persist()
            if step['id'] == 'setup/absence':
                if result['code'] != 5:
                    self.document_status = 'pre-existing'
                    self._persist()
                    raise ValueError('P10-A setup document was not absent; no write admitted')
                self.document_status = 'confirmed-absent'
                self._persist()
            elif step['rpc'] == 'GetDocument' and result['code'] == 0:
                state = self._owned(result['response'])
                if step['id'] in ['live/post-state', 'expired/post-state', 'post-state'] and state != self.expected_state:
                    raise ValueError('P10-A observed write state differs from its definite acknowledgement')
            elif step['rpc'] in ['BeginTransaction', 'Commit', 'Rollback', 'GetDocument'] and result['code'] != 0 and not step['caseId']:
                raise ValueError('P10-A required setup or transaction context was refused')
        return cursor.complete

    def _cleanup(self):
        for role, entry in self.tokens.items():
            if entry['state'] != 'open': continue
            try:
                result = self._rpc(f'cleanup/token/{role}', 'Rollback', {'database': self.plan['database'], 'transaction': entry['value']}, 'tokenCleanup')
                if result['code'] != 0 and entry['state'] != 'invalidated': entry['state'] = 'unconfirmed-release'
                self._persist()
            except (Exception, KeyboardInterrupt):
                # A stop never triggers a second attempt for this token.
                continue
        if self.document_status in ['unexamined', 'confirmed-absent', 'pre-existing']:
            return self.document_status == 'confirmed-absent'
        try:
            read = self._rpc('cleanup/read-owner', 'GetDocument', {'name': self.plan['document']}, 'documentCleanup')
            if read['code'] == 5:
                self.document_status = 'confirmed-absent'; self._persist(); return True
            if read['code'] != 0: return False
            if self._owned(read['response']) != self.expected_state:
                raise ValueError('P10-A cleanup final state differs')
            self.cleanup_readback = True
            stamp = read['response'].get('updateTime')
            if not isinstance(stamp, dict) or not isinstance(stamp.get('seconds'), str):
                raise ValueError('P10-A cleanup requires native updateTime')
            stamp = {'seconds': stamp['seconds'], 'nanos': stamp.get('nanos', 0)}
            deleted = self._rpc('cleanup/delete-version', 'DeleteDocument', {'name': self.plan['document'], 'currentDocument': {'updateTime': stamp}}, 'documentCleanup')
            if deleted['code'] != 0: return False
            absent = self._rpc('cleanup/verify-absence', 'GetDocument', {'name': self.plan['document']}, 'documentCleanup')
            if absent['code'] == 5:
                self.document_status = 'confirmed-absent'; self._persist(); return True
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
        if hasattr(self.budget, 'begin_recovery'): self.budget.begin_recovery()
        self.deadline = self.monotonic() + self.plan['recoverySeconds']
        absent = self._cleanup()
        open_tokens = [role for role, entry in self.tokens.items() if entry['state'] in ['open', 'unconfirmed-release']]
        observations = [row for row in self.rows if row.get('caseId')]
        missing_readback = any(entry['state'] == 'invalidated' for entry in self.tokens.values()) and not self.cleanup_readback
        complete = graph_complete and failure is None and absent and not missing_readback and not open_tokens and not self.unknown_starts and not self.unknown_rollbacks and not self.unknown_commits and not self.journal_failure and [row['caseId'] for row in observations] == self.plan['cases']
        return {'kind': 'txn-p10-recording-v1', 'complete': complete, 'graphComplete': graph_complete, 'program': self.plan['program'], 'sourceDigest': self.plan['sourceDigest'], 'corpusDigest': self.plan['corpusDigest'], 'nonce': self.plan['nonce'], 'ownerId': self.plan['ownerId'], 'observations': observations, 'steps': copy.deepcopy(self.rows), 'cleanupSteps': copy.deepcopy(self.cleanup_rows), 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'unknownCommits': sorted(self.unknown_commits), 'waits': copy.deepcopy(self.waits), 'timingMode': self.timing_mode, 'timingSource': 'parent-wire-envelope' if self.timing_mode == 'wall-clock' else 'local-control-clock', 'expectedState': self.expected_state, 'expectedStateReadback': self.cleanup_readback, 'openTokens': open_tokens, 'journalFailure': self.journal_failure, 'cleanup': {'absent': absent}, 'unrecovered': bool(missing_readback or open_tokens or self.unknown_starts or self.unknown_rollbacks or self.unknown_commits or not absent or self.journal_failure), 'failureType': failure, 'sandboxRequests': self.budget.total, 'phaseRequests': dict(self.budget.used)}


def projection(receipt):
    if not isinstance(receipt, dict) or receipt.get('complete') is not True or receipt.get('unknownStarts') or receipt.get('unknownRollbacks') or receipt.get('unknownCommits') or receipt.get('openTokens') or receipt.get('cleanup') != {'absent': True}:
        raise ValueError('only complete P10-A acquisitions can freeze')
    plan = compile_plan(receipt.get('nonce'), receipt.get('ownerId'))
    if any(receipt.get(key) != plan[key] for key in ['program', 'sourceDigest', 'corpusDigest']) or receipt.get('graphComplete') is not True or receipt.get('journalFailure') is not False:
        raise ValueError('P10-A acquisition source or completeness differs')
    counts = receipt.get('phaseRequests')
    if not isinstance(counts, dict) or set(counts) != set(plan['caps']) or any(type(value) is not int or not 0 <= value <= plan['caps'][key] for key, value in counts.items()) or type(receipt.get('sandboxRequests')) is not int or sum(counts.values()) != receipt['sandboxRequests']:
        raise ValueError('P10-A acquisition request accounting differs')
    steps = receipt.get('steps')
    if not isinstance(steps, list) or len(steps) != len(plan['steps']): raise ValueError('P10-A graph is not complete')
    issued, refused, terminal_states = {}, set(), {}
    starts, last_uses, expected_state = {}, {}, None
    expired_refused = False
    derived_waits = []
    previous = None
    def native(row):
        result = row.get('result')
        if not isinstance(result, dict) or result.get('dispatchedRequests') != 1 or result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('code')) is not int or not 0 <= result['code'] <= 16 or result['code'] in [1, 2, 4, 13, 14]:
            raise ValueError('P10-A graph has an incomplete native result')
        if result['code'] == 0 and not isinstance(result.get('response'), dict): raise ValueError('P10-A typed native result missing')
        return result
    actual_observations = []
    actual_requests = 0
    for declared, row in zip(plan['steps'], steps, strict=True):
        if not isinstance(row, dict) or row.get('site') != declared['id'] or row.get('rpc') != declared['rpc']: raise ValueError('P10-A graph order or RPC differs')
        if row.get('skipped'):
            if declared['id'] not in plan['conditionalSkips'] or declared['tokenInput'] not in refused or row['skipped'] != 'definitive-earlier-begin-refusal' or row.get('tokenRole') != declared['tokenInput'] or row.get('caseId') is not None:
                raise ValueError('P10-A graph skip has no definite refusal')
            continue
        actual_requests += 1
        if row.get('request') != request_for_step(plan, declared, issued) or row.get('caseId') != declared['caseId']: raise ValueError('P10-A request or observation binding differs')
        result = native(row)
        _timing(row.get('timing'))
        if previous is not None: idle_interval(previous['timing'], row['timing'])
        if declared['id'] in plan['waits']:
            if previous is None or previous['rpc'] != 'GetDocument' or previous['result']['code'] != 0:
                raise ValueError('P10-A wait has no successful previous read')
            interval = idle_interval(previous['timing'], row['timing'])
            if interval['lowerSeconds'] < plan['waits'][declared['id']]:
                raise ValueError('P10-A idle candidate was not awaited')
            role = declared['tokenInput']
            derived_waits.append({'site': declared['id'], 'seconds': plan['waits'][declared['id']], 'previousSite': previous['site'], 'previousTiming': previous['timing'], 'currentTiming': row['timing'], 'idleInterval': interval, 'tokenRole': role, 'totalAgeInterval': idle_interval(starts[role], row['timing'], 270)})
        previous = row
        expected_context_code = 5 if declared['id'] == 'setup/absence' else 0
        if not declared['caseId'] and result['code'] != expected_context_code:
            raise ValueError('P10-A required case context was not acquired')
        if declared['rpc'] == 'BeginTransaction':
            if result['code'] == 0:
                token = canonical_token(result['response'].get('transaction'))
                if token in issued.values(): raise ValueError('P10-A token is not fresh')
                issued[declared['tokenOutput']] = token
                terminal_states[declared['tokenOutput']] = 'open'
                starts[declared['tokenOutput']] = row['timing']
                last_uses[declared['tokenOutput']] = row['timing']
                if declared['tokenInput'] in terminal_states: terminal_states[declared['tokenInput']] = 'retried'
            else: refused.add(declared['tokenOutput'])
        elif declared['rpc'] in ['Rollback', 'Commit'] and result['code'] == 0:
            for role, token in issued.items():
                if token == row['request'].get('transaction'):
                    terminal_states[role] = 'rolled-back' if declared['rpc'] == 'Rollback' else 'committed'
        if declared['rpc'] == 'Commit':
            if declared['id'] == 'expired/commit': expired_refused = result['code'] != 0
            if result['code'] == 0:
                if not isinstance(result['response'].get('writeResults'), list) or len(result['response']['writeResults']) != 1:
                    raise ValueError('P10-A write acknowledgement differs')
                expected_state = row['request']['writes'][0]['update']['fields']['state']['stringValue']
        if declared['rpc'] == 'GetDocument' and result['code'] == 0:
            document = result['response']; fields = document.get('fields', {})
            if document.get('name') != plan['document'] or any((fields.get(key) or {}).get('stringValue') != value for key, value in {'owner': plan['ownerId'], 'nonce': plan['nonce'], 'role': 'control'}.items()):
                raise ValueError('P10-A observation owner differs')
            state = (fields.get('state') or {}).get('stringValue')
            if state not in STATES or declared['id'] in ['live/post-state', 'expired/post-state', 'post-state'] and state != expected_state:
                raise ValueError('P10-A observed state differs')
        if result['code'] == 0 and declared['rpc'] != 'BeginTransaction':
            for role, token in issued.items():
                if token == row['request'].get('transaction'): last_uses[role] = row['timing']
        if declared['caseId']: actual_observations.append(row)
    if actual_observations != receipt.get('observations') or [row['caseId'] for row in actual_observations] != plan['cases'] or actual_requests != counts['observation']:
        raise ValueError('P10-A case inventory or observation count differs')
    if derived_waits != receipt.get('waits') or receipt.get('timingMode') not in ['wall-clock', 'control-clock'] or receipt.get('timingSource') != ('parent-wire-envelope' if receipt.get('timingMode') == 'wall-clock' else 'local-control-clock') or receipt.get('expectedState') != expected_state:
        raise ValueError('P10-A timing or expected state cannot be derived')
    tokens = receipt.get('tokens')
    if not isinstance(tokens, dict) or set(tokens) != set(issued) or any(not isinstance(entry, dict) or entry.get('value') != issued[role] or entry.get('state') not in ['committed', 'retried', 'rolled-back', 'invalidated'] for role, entry in tokens.items()):
        raise ValueError('P10-A issued tokens are not all accounted for')
    cleanup = receipt.get('cleanupSteps')
    if not isinstance(cleanup, list) or len(cleanup) != counts['tokenCleanup'] + counts['documentCleanup']: raise ValueError('P10-A cleanup count differs')
    marker_time = None
    expected_readback = False
    released = set()
    for row in cleanup:
        result = native(row)
        _timing(row.get('timing'))
        if previous is not None: idle_interval(previous['timing'], row['timing'])
        previous = row
        request = row.get('request')
        if row.get('rpc') == 'Rollback':
            role = str(row.get('site')).removeprefix('cleanup/token/')
            if role not in issued or role in released or request != {'database': plan['database'], 'transaction': issued[role]} or not (result['code'] == 0 or invalidated_cleanup(role, result, expired_refused)):
                raise ValueError('P10-A cleanup token binding differs')
            released.add(role)
            terminal_states[role] = 'rolled-back' if result['code'] == 0 else 'invalidated'
            if result['code'] == 0: last_uses[role] = row['timing']
        elif row.get('rpc') == 'GetDocument':
            if row.get('site') not in ['cleanup/read-owner', 'cleanup/verify-absence'] or request != {'name': plan['document']}:
                raise ValueError('P10-A cleanup read scope differs')
            if row['site'] == 'cleanup/read-owner' and result['code'] == 0:
                document = result['response']; fields = document.get('fields', {})
                if document.get('name') != plan['document'] or any((fields.get(key) or {}).get('stringValue') != value for key, value in {'owner': plan['ownerId'], 'nonce': plan['nonce'], 'role': 'control'}.items()):
                    raise ValueError('P10-A cleanup owner proof differs')
                if (fields.get('state') or {}).get('stringValue') != expected_state:
                    raise ValueError('P10-A cleanup final state differs')
                expected_readback = True
                stamp = document.get('updateTime', {}); marker_time = {'seconds': stamp.get('seconds'), 'nanos': stamp.get('nanos', 0)}
        elif row.get('rpc') == 'DeleteDocument':
            if row.get('site') != 'cleanup/delete-version' or marker_time is None or request != {'name': plan['document'], 'currentDocument': {'updateTime': marker_time}} or result['code'] != 0:
                raise ValueError('P10-A cleanup conditional delete differs')
        else: raise ValueError('P10-A cleanup contains an undeclared RPC')
    document_rows = [row for row in cleanup if row['rpc'] != 'Rollback']
    sites = [row['site'] for row in document_rows]
    if sites not in [['cleanup/read-owner'], ['cleanup/read-owner', 'cleanup/delete-version', 'cleanup/verify-absence']] or len(released) != counts['tokenCleanup'] or len(document_rows) != counts['documentCleanup'] or any(entry['state'] != terminal_states[role] for role, entry in tokens.items()):
        raise ValueError('P10-A cleanup ordering or derived terminal token state differs')
    if any(entry.get('start') != starts[role] or entry.get('lastUse') != last_uses[role] for role, entry in tokens.items()):
        raise ValueError('P10-A token start or last-use timing differs')
    if receipt.get('expectedStateReadback') is not expected_readback or any(state == 'invalidated' for state in terminal_states.values()) and not expected_readback:
        raise ValueError('P10-A invalidated token has no expected document readback')
    if not document_rows or document_rows[-1]['rpc'] != 'GetDocument' or document_rows[-1]['result']['code'] != 5:
        raise ValueError('P10-A typed document absence missing')
    def details(row):
        value = row['result'].get('details', '')
        for role, entry in receipt['tokens'].items(): value = value.replace(entry['value'], f'<token:{role}>')
        return value.replace(receipt['nonce'], '<nonce>').replace(receipt['ownerId'], '<owner>')
    cases = [{'caseId': row['caseId'], 'rpc': row['rpc'], 'code': row['result']['code'], 'details': details(row), 'issuedToken': bool((row['result'].get('response') or {}).get('transaction'))} for row in receipt['observations']]
    reads = []
    skipped = []
    for row in receipt['steps']:
        if row.get('skipped'):
            skipped.append({'site': row['site'], 'basis': row['skipped'], 'tokenRole': row['tokenRole']})
        elif row['rpc'] == 'GetDocument':
            document = row['result'].get('response') or {}
            state = ((document.get('fields') or {}).get('state') or {}).get('stringValue')
            reads.append({'site': row['site'], 'code': row['result']['code'], 'state': state, 'details': details(row)})
    return {'program': receipt['program'], 'corpusDigest': receipt['corpusDigest'], 'cases': cases, 'reads': reads, 'skipped': skipped, 'timingMode': receipt['timingMode'], 'idleCandidates': [{'site': wait['site'], 'seconds': wait['seconds'], 'classification': wait['idleInterval']['classification'], 'thresholdSeconds': 60} for wait in derived_waits], 'exactThresholdProven': False, 'cleanup': {'absent': True}}
