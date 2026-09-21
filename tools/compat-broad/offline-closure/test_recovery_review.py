import copy
import itertools
import socket
import pytest
from recovery_review import review


def record():
    nonce='a'*32
    instance={'bootId':'boot-1','project':'demo-local','database':'(default)'}
    return {'mode':'local','productionExecuted':False,'nonce':nonce,
        'journalDigest':'b'*64,'artifactDigest':'c'*64,'configDigest':'d'*64,
        'originalInstance':instance,'currentInstance':dict(instance,independentlyVerified=True),
        'producer':{'exitObserved':True,'descendantsStopped':True,'pendingOperations':0},
        'permission':{'currentlyVerified':True,'localOnly':True,'runNonce':nonce,
            'journalDigest':'b'*64,'artifactDigest':'c'*64,'configDigest':'d'*64},
        'resources':[{'id':'projects/demo-local/databases/(default)/documents/a/b',
            'kind':'document','runNonce':nonce,'creationAcknowledged':True,
            'ownerMatches':True,'version':'opaque-validated-version',
            'versionIndependentlyVerified':True,'conditionalDeleteSupported':True}]}


def test_review_is_pure_and_never_authorizes_even_a_candidate(monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *_:pytest.fail('network forbidden'))
    value=record();before=copy.deepcopy(value)
    result=review(value)
    assert result['state']=='candidate-for-independent-validation'
    assert result['authorizesCleanup'] is False and result['executionImplemented'] is False
    assert value==before
    assert value['resources'][0]['id'] not in str(result)

@pytest.mark.parametrize('key', ['bootId','project','database'])
def test_same_port_or_pid_cannot_hide_instance_change(key):
    value=record();value['currentInstance'][key]='changed'
    assert review(value)['state']=='blocked'

@pytest.mark.parametrize('key', ['journalDigest','artifactDigest','configDigest','runNonce'])
def test_permission_is_bound_to_exact_inputs(key):
    value=record();value['permission'][key]='changed'
    assert review(value)['state']=='blocked'

@pytest.mark.parametrize('value', [False,True,0.0,-1,1,None,'0'])
def test_no_ambiguous_pending_operation_count(value):
    r=record();r['producer']['pendingOperations']=value
    assert review(r)['state']=='blocked'

@pytest.mark.parametrize('kind', ['unknown','existing-account','wrong-owner','missing-version','duplicate'])
def test_responsibility_never_becomes_unconditional_cleanup(kind):
    r=record();item=r['resources'][0]
    if kind=='unknown':item.update(creationAcknowledged=False,absenceObserved=True)
    if kind=='existing-account':item.update(kind='account',newAccountAcknowledged=False,uidCurrentRunMatches=True,currentAccountVerified=True)
    if kind=='wrong-owner':item['ownerMatches']=False
    if kind=='missing-version':item.pop('version')
    if kind=='duplicate':r['resources'].append(copy.deepcopy(item))
    result=review(r);assert result['state']=='blocked';assert result['candidates']==[]


def test_all_128_stop_ownership_permission_combinations_stay_non_authorizing():
    for flags in itertools.product((False,True),repeat=7):
        r=record();p=r['producer'];item=r['resources'][0]
        (p['exitObserved'],p['descendantsStopped'],item['creationAcknowledged'],
         item['ownerMatches'],item['versionIndependentlyVerified'],
         r['permission']['currentlyVerified'],r['currentInstance']['independentlyVerified'])=flags
        out=review(r)
        assert out['authorizesCleanup'] is False and out['productionExecuted'] is False
        assert (out['state']=='candidate-for-independent-validation')==all(flags)

@pytest.mark.parametrize('value',[None,[],float('nan')])
def test_malformed_record_is_blocked(value):
    assert review(value)['state']=='blocked'


def test_cyclic_record_is_blocked():
    r=record();r['cycle']=r
    assert review(r)['state']=='blocked'


def test_known_account_is_only_a_review_candidate():
    r=record();r['resources']=[{'id':'private-uid','kind':'account','runNonce':r['nonce'],
        'creationAcknowledged':True,'newAccountAcknowledged':True,'uidCurrentRunMatches':True,
        'currentAccountVerified':True}]
    assert review(r)['state']=='candidate-for-independent-validation'
    assert review(r)['authorizesCleanup'] is False
