"""Regressions use actual collector receipts; no credentials or network."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_credential_comparator import _receipt, _classifications
from credential_comparator import compare


@pytest.mark.parametrize('value', [False, 0.0, True, '0', None])
def test_remaining_account_count_requires_an_integer(value):
    local, remote = _receipt('local'), _receipt('production')
    remote['cleanup']['remainingAccounts'] = value
    assert compare(local, remote)['reason'] == 'incomplete-cleanup'


@pytest.mark.parametrize('side', ['local', 'production'])
@pytest.mark.parametrize('value', [0, 1, 'false', None])
def test_production_flag_never_uses_truthiness(side, value):
    local, remote = _receipt('local'), _receipt('production')
    (local if side == 'local' else remote)['productionExecuted'] = value
    assert compare(local, remote)['productionCompared'] is False


@pytest.mark.parametrize('value', [0, 1, '', [], {}, None, 1.0])
def test_assertions_are_booleans_not_comparable_python_values(value):
    local, remote = _receipt('local'), _receipt('production')
    row = remote['rows'][0]
    name = next(iter(row['assertions']))
    row['assertions'][name] = value
    assert _classifications(compare(local, remote))[row['caseId']] == 'INDETERMINATE'


@pytest.mark.parametrize(('left', 'right'), [(False, 0), (True, 1), (1, 1.0), ([False], [0]), ({'n': 2}, {'n': 2.0})])
def test_semantic_payloads_preserve_nested_json_types(left, right):
    local, remote = _receipt('local'), _receipt('production')
    local['rows'][0]['extra'] = left
    remote['rows'][0]['extra'] = right
    assert _classifications(compare(local, remote))[remote['rows'][0]['caseId']] == 'DIFFERENT'


@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf'), {1: 'not-json'}, ('tuple',)])
def test_non_json_receipts_are_indeterminate_without_raising(value):
    local, remote = _receipt('local'), _receipt('production')
    remote['rows'][0]['extra'] = value
    result = compare(local, remote)
    assert result['productionCompared'] is False
    assert set(_classifications(result).values()) == {'INDETERMINATE'}


def test_cyclic_receipt_is_not_a_recursion_crash():
    local, remote = _receipt('local'), _receipt('production')
    remote['cycle'] = remote
    assert compare(local, remote)['productionCompared'] is False


def test_normal_pair_and_false_assertions_remain_comparable():
    local, remote = _receipt('local'), _receipt('production')
    for side in (local, remote):
        row = side['rows'][0]
        row['assertions'][next(iter(row['assertions']))] = False
    before = copy.deepcopy(remote)
    assert _classifications(compare(local, remote))[remote['rows'][0]['caseId']] == 'MATCH'
    assert remote == before

@pytest.mark.parametrize('field,value', [
    ('intentCount',False), ('intentCount',1), ('unknownCreates',1),
    ('confirmedCreates',0.0), ('recordingComplete',False),
    ('durable','true'), ('authorizesCleanup',True),
])
def test_contradictory_creation_summary_cannot_be_ignored(field,value):
    local,remote=_receipt('local'),_receipt('production')
    local['creationResponsibility']={'intentCount':0,'unknownCreates':0,
        'confirmedCreates':0,'existingAccounts':0,'recordingComplete':True,
        'durable':True,'authorizesCleanup':False}
    local['creationResponsibility'][field]=value
    assert compare(local,remote)['reason']=='incomplete-creation-responsibility'


def test_extremely_large_integer_does_not_crash_json_comparison():
    local,remote=_receipt('local'),_receipt('production')
    remote['rows'][0]['extra']=1 << 15000
    assert compare(local,remote)['productionCompared'] is False
