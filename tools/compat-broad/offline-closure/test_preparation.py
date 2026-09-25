import copy
import hashlib
import json
import os
import socket
from pathlib import Path
import pytest
import preparation as p

@pytest.fixture(scope='module')
def report():
    return p.prepare('a'*32)


def test_recompiles_real_boundaries_and_retains_no_execution_claim(report,monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *_:pytest.fail('network forbidden'))
    assert len(report['boundaryCases'])==42
    assert len({c['id'] for c in report['boundaryCases']})==42
    assert all(c['nativeExecuted'] is False for c in report['boundaryCases'])
    assert report['authorizesProduction'] is False and report['authorizesCleanup'] is False
    assert report['promotionReady'] is False and report['independentReviewCompleted'] is False
    p.validate(report)


def test_500_501_is_per_document_field_transforms_not_commit_write_count(report):
    pair=report['fieldTransformBoundary']['cases']
    assert [c['fieldTransformsOnOneDocument'] for c in pair]==[500,501]
    assert [c['writeCount'] for c in pair]==[2,2]
    assert pair[0]['transformsPerWrite']==[250,250]
    assert pair[1]['transformsPerWrite']==[250,251]
    assert all(c['existingDocumentPrecondition'] is True for c in pair)
    assert report['fieldTransformBoundary']['repeatProductionRequested'] is False


def test_actual_commit_plan_has_two_owned_resources_and_finite_recovery(report):
    plan=report['commitPlan']
    assert len(plan['ownedResources'])==2
    assert len(plan['observation'])==11 and len(plan['recovery'])==6
    assert plan['budget']['requestUpperBound']==17
    assert [s['versionFrom'] for s in plan['recovery'] if s['method']=='DELETE']==[0,3]
    assert plan['productionReady'] is False

@pytest.mark.parametrize('field', ['authorizesProduction','authorizesCleanup','nativeExecuted','productionExecuted','promotionReady'])
def test_rehash_cannot_turn_preparation_into_authority(report,field):
    changed=copy.deepcopy(report);changed[field]=True
    changed['preparationDigest']=p.digest({k:v for k,v in changed.items() if k!='preparationDigest'})
    with pytest.raises(ValueError):p.validate(changed)


def test_source_and_historical_hashes_are_exact_and_immutable(report):
    for path,expected in (report['sourceBinding']|report['historicalReferences']).items():
        assert hashlib.sha256((p.ROOT/path).read_bytes()).hexdigest()==expected


def test_safe_publication_does_not_overwrite_or_follow_links(report,tmp_path):
    out=tmp_path/'preparation.json';p.publish(report,out)
    assert json.loads(out.read_bytes())==report
    assert out.stat().st_mode & 0o077==0
    with pytest.raises(FileExistsError):p.publish(report,out)
    link=tmp_path/'link';link.symlink_to(out)
    with pytest.raises(FileExistsError):p.publish(report,link)


def test_missing_or_symlink_source_is_not_accepted(tmp_path):
    (tmp_path/'source').write_text('test')
    (tmp_path/'alias').symlink_to(tmp_path/'source')
    with pytest.raises(ValueError):p.source_binding(tmp_path,('alias',))
    with pytest.raises(FileNotFoundError):p.source_binding(tmp_path,('missing',))

@pytest.mark.parametrize('nonce',[None,'A'*32,'a'*31,'a'*33,False,'../outside'])
def test_nonce_is_strict(nonce):
    with pytest.raises(ValueError):p.prepare(nonce)
