"""Pure, non-authorizing review of proposed local recovery evidence.

This state model neither gathers evidence nor authenticates caller assertions.
It does not contact an emulator, read credentials, signal a PID or delete a
resource. A successful review STILL requires independently implemented current-
instance, producer-stop and permission adapters before execution can be allowed.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SHA = re.compile(r'[0-9a-f]{64}')
NONCE = re.compile(r'[0-9a-f]{32}')
MAX_RESOURCES = 64


def review(record: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        'schema': 'local-recovery-review-v1', 'state': 'blocked',
        'authorizesCleanup': False, 'authorizesProduction': False,
        'productionExecuted': False, 'executionImplemented': False,
        'reasons': [], 'candidates': [],
    }
    reasons = result['reasons']
    if type(record) is not dict:
        reasons.append('invalid-record')
        return result
    try:
        raw = json.dumps(record, sort_keys=True, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        reasons.append('invalid-json-record')
        return result
    if len(raw) > 262_144:
        reasons.append('record-exceeds-bound')
        return result
    result['recordDigest'] = hashlib.sha256(raw).hexdigest()
    if record.get('mode') != 'local' or record.get('productionExecuted') is not False:
        reasons.append('not-explicitly-local')
    nonce = record.get('nonce')
    if type(nonce) is not str or NONCE.fullmatch(nonce) is None:
        reasons.append('unbound-run')
    for key in ('journalDigest', 'artifactDigest', 'configDigest'):
        value = record.get(key)
        if type(value) is not str or SHA.fullmatch(value) is None:
            reasons.append('invalid-' + key)
    original, current = record.get('originalInstance'), record.get('currentInstance')
    if type(original) is not dict or type(current) is not dict:
        reasons.append('instance-evidence-missing')
    else:
        # A PID/port by itself is never an instance identity. The adapter must
        # bind a new boot/generation identity and the exact project/database.
        for key in ('bootId', 'project', 'database'):
            if (type(original.get(key)) is not str or not original[key]
                    or type(current.get(key)) is not str or current[key] != original[key]):
                reasons.append('instance-' + key + '-mismatch')
        if current.get('independentlyVerified') is not True:
            reasons.append('instance-not-independently-verified')
    stopped = record.get('producer')
    if (type(stopped) is not dict or stopped.get('exitObserved') is not True
            or stopped.get('descendantsStopped') is not True
            or type(stopped.get('pendingOperations')) is not int
            or stopped['pendingOperations'] != 0):
        reasons.append('producer-or-inflight-state-unconfirmed')
    permission = record.get('permission')
    if (type(permission) is not dict or permission.get('currentlyVerified') is not True
            or permission.get('runNonce') != nonce
            or permission.get('journalDigest') != record.get('journalDigest')
            or permission.get('artifactDigest') != record.get('artifactDigest')
            or permission.get('configDigest') != record.get('configDigest')
            or permission.get('localOnly') is not True):
        reasons.append('current-permission-unbound')
    resources = record.get('resources')
    if type(resources) is not list or len(resources) > MAX_RESOURCES:
        reasons.append('invalid-resource-set')
        return result
    seen = set()
    for resource in resources:
        if type(resource) is not dict:
            reasons.append('invalid-resource')
            continue
        identity = resource.get('id')
        if type(identity) is not str or not identity or len(identity) > 6144:
            reasons.append('invalid-resource-identity')
            continue
        if identity in seen:
            reasons.append('duplicate-resource')
            continue
        seen.add(identity)
        if resource.get('creationAcknowledged') is not True or resource.get('runNonce') != nonce:
            # Even a later not-found result cannot settle a potentially delayed
            # create. Do not search by guessed UID or transfer that authority.
            reasons.append('unknown-or-unbound-creation')
            continue
        if resource.get('kind') == 'document':
            if (resource.get('ownerMatches') is not True
                    or type(resource.get('version')) is not str or not resource['version']
                    or resource.get('versionIndependentlyVerified') is not True
                    or resource.get('conditionalDeleteSupported') is not True):
                reasons.append('document-owner-version-unconfirmed')
                continue
            operation = 'conditional-document-delete-then-typed-absence'
        elif resource.get('kind') == 'account':
            if (resource.get('newAccountAcknowledged') is not True
                    or resource.get('uidCurrentRunMatches') is not True
                    or resource.get('currentAccountVerified') is not True):
                reasons.append('account-ownership-unconfirmed')
                continue
            operation = 'owned-account-delete-then-typed-absence'
        else:
            reasons.append('unsupported-resource-kind')
            continue
        result['candidates'].append({
            'identityDigest': hashlib.sha256(identity.encode()).hexdigest(),
            'proposedOperation': operation,
        })
    if reasons:
        # Do not publish executable-looking partial actions when any condition
        # failed. The input remains the responsibility record; this is a review.
        result['candidates'] = []
    else:
        result['state'] = 'candidate-for-independent-validation'
    return result
