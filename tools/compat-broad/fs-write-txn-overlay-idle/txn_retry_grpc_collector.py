"""Finite native P09 graph with durable responsibility before each dispatch."""

from __future__ import annotations

import copy
import time

from txn_retry_grpc_program import GraphCursor, canonical_token, compile_plan, request_for_step, validate_plan


class Collector:
    def __init__(self, plan, budget, wire, bearer, *, save, before_send=lambda: None, monotonic=time.monotonic, observation_deadline=None):
        validate_plan(plan)
        self.plan = copy.deepcopy(plan)
        self.budget = budget
        self.wire = wire
        self.bearer = bearer
        self.save = save
        self.before_send = before_send
        self.monotonic = monotonic
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
        return {'kind': 'txn-p09-responsibility-v1', 'plan': self.plan, 'documentStatus': self.document_status, 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'pending': copy.deepcopy(self.pending), 'rows': copy.deepcopy(self.rows), 'cleanupRows': copy.deepcopy(self.cleanup_rows), 'requests': self.budget.total}

    def _persist(self):
        try:
            self.save(self._state())
        except (Exception, KeyboardInterrupt):
            self.journal_failure = True
            raise

    def _rpc(self, site, method, request, phase, *, step=None):
        if self.journal_failure:
            raise ValueError('P09 journal failed; no further dispatch is safe')
        self.before_send()
        remaining = self.deadline - self.monotonic()
        if remaining <= 0:
            raise TimeoutError('P09 phase deadline exceeded')
        self.budget.charge(phase)
        self.pending = {'site': site, 'rpc': method}
        if method == 'BeginTransaction': self.unknown_starts.add(site)
        if method == 'Rollback':
            for role, entry in self.tokens.items():
                if entry['value'] == request['transaction']:
                    self.pending['tokenRole'] = role
                    self.unknown_rollbacks.add(role)
                    if entry['state'] == 'open': entry['state'] = 'unconfirmed-release'
        if site == 'setup/create': self.document_status = 'possibly-owned'
        self._persist()
        result = self.wire.send(method, request, nonce=self.plan['nonce'], owner_id=self.plan['ownerId'], bearer=self.bearer, deadline_ms=max(1, min(10000, int(remaining * 1000))))
        row = {'site': site, 'rpc': method, 'caseId': step['caseId'] if step else None, 'request': copy.deepcopy(request), 'result': copy.deepcopy(result)}
        (self.rows if phase == 'observation' else self.cleanup_rows).append(row)
        if result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('code')) is not int or result['code'] in [1, 2, 4, 13, 14] or not 0 <= result['code'] <= 16:
            self._persist()
            raise ValueError('P09 native outcome is indeterminate')
        if result['code'] == 0 and not isinstance(result.get('response'), dict):
            self._persist()
            raise ValueError('P09 native success has no typed response')
        if method == 'BeginTransaction':
            if result['code'] == 0:
                token = canonical_token(result['response'].get('transaction'))
                if token in {entry['value'] for entry in self.tokens.values()}:
                    raise ValueError('P09 minted token is not fresh')
                self.tokens[step['tokenOutput']] = {'value': token, 'state': 'open'}
                previous = step['tokenInput']
                if previous in self.tokens: self.tokens[previous]['state'] = 'retried'
            else:
                self.refused_outputs.add(step['tokenOutput'])
            self.unknown_starts.discard(site)
        if method == 'Commit' and result['code'] == 0:
            writes = result['response'].get('writeResults')
            if not isinstance(writes, list) or len(writes) != 1:
                raise ValueError('P09 commit lacks its single-write acknowledgement')
            if site == 'setup/create': self.document_status = 'created'
            for entry in self.tokens.values():
                if entry['value'] == request.get('transaction'): entry['state'] = 'committed'
        if method == 'Rollback':
            for role, entry in self.tokens.items():
                if entry['value'] == request['transaction']:
                    self.unknown_rollbacks.discard(role)
                    if result['code'] == 0: entry['state'] = 'rolled-back'
        self.pending = None
        self._persist()
        return result

    def _owned(self, document):
        if not isinstance(document, dict) or document.get('name') != self.plan['document']:
            raise ValueError('P09 read did not return its exact document')
        fields = document.get('fields')
        if not isinstance(fields, dict): raise ValueError('P09 owned marker fields missing')
        expected = {'owner': self.plan['ownerId'], 'nonce': self.plan['nonce'], 'role': 'control'}
        if any(not isinstance(fields.get(key), dict) or fields[key].get('stringValue') != value for key, value in expected.items()):
            raise ValueError('P09 document owner differs; deletion refused')
        if not isinstance(fields.get('state'), dict) or fields['state'].get('stringValue') not in ['created', 'committed', 'outside', 'after-readonly-start']:
            raise ValueError('P09 state marker is invalid')
        return fields['state']['stringValue']

    def _observe(self):
        cursor = GraphCursor(self.plan)
        for declared in self.plan['steps']:
            step = cursor.claim(declared['id'])
            binding = step['tokenInput']
            if binding in self.refused_outputs and step['id'] in self.plan['conditionalSkips']:
                self.rows.append({'site': step['id'], 'rpc': step['rpc'], 'caseId': None, 'skipped': 'definitive-earlier-begin-refusal', 'tokenRole': binding})
                self._persist()
                continue
            request = request_for_step(self.plan, step, {key: entry['value'] for key, entry in self.tokens.items()})
            result = self._rpc(step['id'], step['rpc'], request, 'observation', step=step)
            if step['id'] == 'setup/absence':
                if result['code'] != 5:
                    self.document_status = 'pre-existing'
                    self._persist()
                    raise ValueError('P09 setup document was not absent; no write admitted')
                self.document_status = 'confirmed-absent'
                self._persist()
            elif step['rpc'] == 'GetDocument' and result['code'] == 0:
                self._owned(result['response'])
            elif step['rpc'] in ['BeginTransaction', 'Commit', 'Rollback', 'GetDocument'] and result['code'] != 0 and not step['caseId']:
                raise ValueError('P09 required setup or transaction context was refused')
        return cursor.complete

    def _cleanup(self):
        for role, entry in self.tokens.items():
            if entry['state'] != 'open': continue
            try:
                result = self._rpc(f'cleanup/token/{role}', 'Rollback', {'database': self.plan['database'], 'transaction': entry['value']}, 'tokenCleanup')
                if result['code'] != 0: entry['state'] = 'unconfirmed-release'
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
            self._owned(read['response'])
            stamp = read['response'].get('updateTime')
            if not isinstance(stamp, dict) or not isinstance(stamp.get('seconds'), str):
                raise ValueError('P09 cleanup requires native updateTime')
            stamp = {'seconds': stamp['seconds'], 'nanos': stamp.get('nanos', 0)}
            self._rpc('cleanup/delete-version', 'DeleteDocument', {'name': self.plan['document'], 'currentDocument': {'updateTime': stamp}}, 'documentCleanup')
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
        self.deadline = self.monotonic() + self.plan['recoverySeconds']
        absent = self._cleanup()
        open_tokens = [role for role, entry in self.tokens.items() if entry['state'] in ['open', 'unconfirmed-release']]
        observations = [row for row in self.rows if row.get('caseId')]
        complete = graph_complete and failure is None and absent and not open_tokens and not self.unknown_starts and not self.unknown_rollbacks and not self.journal_failure and [row['caseId'] for row in observations] == self.plan['cases']
        return {'kind': 'txn-p09-recording-v1', 'complete': complete, 'graphComplete': graph_complete, 'program': self.plan['program'], 'sourceDigest': self.plan['sourceDigest'], 'corpusDigest': self.plan['corpusDigest'], 'nonce': self.plan['nonce'], 'ownerId': self.plan['ownerId'], 'observations': observations, 'steps': copy.deepcopy(self.rows), 'cleanupSteps': copy.deepcopy(self.cleanup_rows), 'tokens': copy.deepcopy(self.tokens), 'unknownStarts': sorted(self.unknown_starts), 'unknownRollbacks': sorted(self.unknown_rollbacks), 'openTokens': open_tokens, 'journalFailure': self.journal_failure, 'cleanup': {'absent': absent}, 'unrecovered': bool(open_tokens or self.unknown_starts or self.unknown_rollbacks or not absent or self.journal_failure), 'failureType': failure, 'sandboxRequests': self.budget.total, 'phaseRequests': dict(self.budget.used)}


def projection(receipt):
    if not isinstance(receipt, dict) or receipt.get('complete') is not True or receipt.get('unknownStarts') or receipt.get('unknownRollbacks') or receipt.get('openTokens') or receipt.get('cleanup') != {'absent': True}:
        raise ValueError('only complete P09 acquisitions can freeze')
    plan = compile_plan(receipt.get('nonce'), receipt.get('ownerId'))
    if any(receipt.get(key) != plan[key] for key in ['program', 'sourceDigest', 'corpusDigest']) or receipt.get('graphComplete') is not True or receipt.get('journalFailure') is not False:
        raise ValueError('P09 acquisition source or completeness differs')
    counts = receipt.get('phaseRequests')
    if not isinstance(counts, dict) or set(counts) != set(plan['caps']) or any(type(value) is not int or not 0 <= value <= plan['caps'][key] for key, value in counts.items()) or type(receipt.get('sandboxRequests')) is not int or sum(counts.values()) != receipt['sandboxRequests']:
        raise ValueError('P09 acquisition request accounting differs')
    steps = receipt.get('steps')
    if not isinstance(steps, list) or len(steps) != len(plan['steps']): raise ValueError('P09 graph is not complete')
    issued, refused, terminal_states = {}, set(), {}
    def native(row):
        result = row.get('result')
        if not isinstance(result, dict) or result.get('complete') is not True or result.get('childReaped') is not True or type(result.get('code')) is not int or not 0 <= result['code'] <= 16 or result['code'] in [1, 2, 4, 13, 14]:
            raise ValueError('P09 graph has an incomplete native result')
        if result['code'] == 0 and not isinstance(result.get('response'), dict): raise ValueError('P09 typed native result missing')
        return result
    actual_observations = []
    actual_requests = 0
    for declared, row in zip(plan['steps'], steps, strict=True):
        if not isinstance(row, dict) or row.get('site') != declared['id'] or row.get('rpc') != declared['rpc']: raise ValueError('P09 graph order or RPC differs')
        if row.get('skipped'):
            if declared['id'] not in plan['conditionalSkips'] or declared['tokenInput'] not in refused or row['skipped'] != 'definitive-earlier-begin-refusal' or row.get('tokenRole') != declared['tokenInput'] or row.get('caseId') is not None:
                raise ValueError('P09 graph skip has no definite refusal')
            continue
        actual_requests += 1
        if row.get('request') != request_for_step(plan, declared, issued) or row.get('caseId') != declared['caseId']: raise ValueError('P09 request or observation binding differs')
        result = native(row)
        expected_context_code = 5 if declared['id'] == 'setup/absence' else 0
        if not declared['caseId'] and result['code'] != expected_context_code:
            raise ValueError('P09 required case context was not acquired')
        if declared['rpc'] == 'BeginTransaction':
            if result['code'] == 0:
                token = canonical_token(result['response'].get('transaction'))
                if token in issued.values(): raise ValueError('P09 token is not fresh')
                issued[declared['tokenOutput']] = token
                terminal_states[declared['tokenOutput']] = 'open'
                if declared['tokenInput'] in terminal_states: terminal_states[declared['tokenInput']] = 'retried'
            else: refused.add(declared['tokenOutput'])
        elif declared['rpc'] in ['Rollback', 'Commit'] and result['code'] == 0:
            for role, token in issued.items():
                if token == row['request'].get('transaction'):
                    terminal_states[role] = 'rolled-back' if declared['rpc'] == 'Rollback' else 'committed'
        if declared['caseId']: actual_observations.append(row)
    if actual_observations != receipt.get('observations') or [row['caseId'] for row in actual_observations] != plan['cases'] or actual_requests != counts['observation']:
        raise ValueError('P09 case inventory or observation count differs')
    tokens = receipt.get('tokens')
    if not isinstance(tokens, dict) or set(tokens) != set(issued) or any(not isinstance(entry, dict) or entry.get('value') != issued[role] or entry.get('state') not in ['committed', 'retried', 'rolled-back'] for role, entry in tokens.items()):
        raise ValueError('P09 issued tokens are not all accounted for')
    cleanup = receipt.get('cleanupSteps')
    if not isinstance(cleanup, list) or len(cleanup) != counts['tokenCleanup'] + counts['documentCleanup']: raise ValueError('P09 cleanup count differs')
    marker_time = None
    released = set()
    for row in cleanup:
        result = native(row)
        request = row.get('request')
        if row.get('rpc') == 'Rollback':
            role = str(row.get('site')).removeprefix('cleanup/token/')
            if role not in issued or role in released or request != {'database': plan['database'], 'transaction': issued[role]} or result['code'] != 0:
                raise ValueError('P09 cleanup token binding differs')
            released.add(role)
            terminal_states[role] = 'rolled-back'
        elif row.get('rpc') == 'GetDocument':
            if row.get('site') not in ['cleanup/read-owner', 'cleanup/verify-absence'] or request != {'name': plan['document']}:
                raise ValueError('P09 cleanup read scope differs')
            if row['site'] == 'cleanup/read-owner' and result['code'] == 0:
                document = result['response']; fields = document.get('fields', {})
                if document.get('name') != plan['document'] or any((fields.get(key) or {}).get('stringValue') != value for key, value in {'owner': plan['ownerId'], 'nonce': plan['nonce'], 'role': 'control'}.items()):
                    raise ValueError('P09 cleanup owner proof differs')
                stamp = document.get('updateTime', {}); marker_time = {'seconds': stamp.get('seconds'), 'nanos': stamp.get('nanos', 0)}
        elif row.get('rpc') == 'DeleteDocument':
            if row.get('site') != 'cleanup/delete-version' or marker_time is None or request != {'name': plan['document'], 'currentDocument': {'updateTime': marker_time}} or result['code'] != 0:
                raise ValueError('P09 cleanup conditional delete differs')
        else: raise ValueError('P09 cleanup contains an undeclared RPC')
    document_rows = [row for row in cleanup if row['rpc'] != 'Rollback']
    sites = [row['site'] for row in document_rows]
    if sites not in [['cleanup/read-owner'], ['cleanup/read-owner', 'cleanup/delete-version', 'cleanup/verify-absence']] or len(released) != counts['tokenCleanup'] or len(document_rows) != counts['documentCleanup'] or any(entry['state'] != terminal_states[role] for role, entry in tokens.items()):
        raise ValueError('P09 cleanup ordering or derived terminal token state differs')
    if not document_rows or document_rows[-1]['rpc'] != 'GetDocument' or document_rows[-1]['result']['code'] != 5:
        raise ValueError('P09 typed document absence missing')
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
    return {'program': receipt['program'], 'corpusDigest': receipt['corpusDigest'], 'cases': cases, 'reads': reads, 'skipped': skipped, 'cleanup': {'absent': True}}
