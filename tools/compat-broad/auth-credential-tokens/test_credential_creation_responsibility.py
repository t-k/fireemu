"""Real journal/files and actual case runner, with explicit local transport doubles."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
import credential_responsibility as responsibility
import credential_shadow as shadow
from credential_collector import new_tracker, cleanup_report
from test_credential_shadow import _service, _poster


def setup(tmp_path):
    tracker=new_tracker('a'*32)
    root=tmp_path/'journal'
    responsibility.attach(tracker,root,{'artifactSha256':'b'*64,'commit':None})
    return tracker,root


def records(root):
    return [json.loads(p.read_bytes()) for p in sorted(root.glob('*.json'))]


def test_signup_intent_is_synced_before_sender_and_missing_ack_remains_unknown(tmp_path):
    tracker,root=setup(tmp_path)
    def lost(*args,**kwargs):
        record=records(root)[-1]
        assert record['event']['type']=='intent'
        assert record['event']['operation']=='signup'
        raise OSError('synthetic lost ACK')
    with pytest.raises(OSError):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=lost)
    assert responsibility.summary(tracker)['unknownCreates']==1
    assert cleanup_report(tracker)['cleanupComplete'] is False
    assert not tracker['accounts']
    responsibility.close(tracker)


def test_failed_intent_publication_sends_nothing(tmp_path,monkeypatch):
    tracker,root=setup(tmp_path);calls=[]
    journal=tracker['_responsibilityJournal'];original=journal.append
    def fail(event):
        if event['type']=='intent':raise OSError('private detail')
        original(event)
    monkeypatch.setattr(journal,'append',fail)
    with pytest.raises(OSError):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=lambda *a,**k:calls.append(a))
    assert calls==[]
    assert responsibility.summary(tracker)['recordingComplete'] is False
    responsibility.close(tracker)


@pytest.mark.parametrize('error',['missing-token','ack-journal-failure'])
def test_confirmed_uid_survives_later_processing_or_recording_failure(tmp_path,monkeypatch,error):
    tracker,root=setup(tmp_path)
    if error=='ack-journal-failure':
        original=tracker['_responsibilityJournal'].append
        def fail(event):
            if event['type']=='acknowledgement':raise OSError('failure')
            original(event)
        monkeypatch.setattr(tracker['_responsibilityJournal'],'append',fail)
    def send(*a,**k):return 200,{'localId':'known-uid'}
    with pytest.raises((KeyError,OSError)):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=send)
    assert 'known-uid' in tracker['accounts']
    calls=[]
    def recover(b,base,path,body,**kwargs):
        calls.append((path,body));return (200,{}) if path.endswith(':delete') else (200,{'users':[]})
    shadow.cleanup('http://127.0.0.1:1',shadow.shadow_budget(),tracker,poster=recover)
    assert len(calls)==3
    assert cleanup_report(tracker)['remainingAccounts']==0
    responsibility.close(tracker)


@pytest.mark.parametrize('bad',[None,True,0,'', 'x'*129])
def test_malformed_uid_does_not_grant_ownership(tmp_path,bad):
    tracker,root=setup(tmp_path)
    with pytest.raises(shadow.ShadowError):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=lambda *a,**k:(200,{'localId':bad}))
    assert not tracker['accounts']
    assert responsibility.summary(tracker)['unknownCreates']==1
    responsibility.close(tracker)


def test_existing_custom_account_is_not_mutated_or_deleted(tmp_path,monkeypatch):
    tracker,root=setup(tmp_path);service=_service();uid='custom-'+tracker['nonce']
    service['accounts'][uid]={'email':None,'validSince':0,'customAttributes':{'preserve':True}}
    monkeypatch.setattr(shadow,'_rest',lambda *a:None)
    with pytest.raises(shadow.ShadowError,match='not owned'):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=_poster(service))
    assert uid not in tracker['accounts']
    assert service['accounts'][uid]['customAttributes']=={'preserve':True}
    shadow.cleanup('http://127.0.0.1:1',shadow.shadow_budget(),tracker,poster=_poster(service))
    assert uid in service['accounts']
    assert responsibility.summary(tracker)['existingAccounts']==1
    assert responsibility.summary(tracker)['unknownCreates']==0
    responsibility.close(tracker)


@pytest.mark.parametrize('flag',[None,0,1,'true'])
def test_ambiguous_custom_creation_flag_keeps_unknown_responsibility(tmp_path,monkeypatch,flag):
    tracker,root=setup(tmp_path);service=_service();original=service['sender']
    def sender(base,path,body,owner,timeout):
        status,raw=original(base,path,body,owner,timeout)
        if 'signInWithCustomToken' in path and status==200:
            value=json.loads(raw);value['isNewUser']=flag;raw=json.dumps(value).encode()
        return status,raw
    service['sender']=sender;monkeypatch.setattr(shadow,'_rest',lambda *a:None)
    with pytest.raises(shadow.ShadowError,match='unconfirmed'):
        shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=_poster(service))
    assert 'custom-'+tracker['nonce'] not in tracker['accounts']
    assert responsibility.summary(tracker)['unknownCreates']==1
    responsibility.close(tracker)


def test_normal_lifecycle_keeps_hash_chain_private_and_no_secrets(tmp_path,monkeypatch):
    tracker,root=setup(tmp_path);service=_service();monkeypatch.setattr(shadow,'_rest',lambda *a:None)
    rows={};shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,rows,poster=_poster(service))
    assert shadow._agreement(list(rows.values()))['unexpected']==[]
    shadow.cleanup('http://127.0.0.1:1',shadow.shadow_budget(),tracker,poster=_poster(service))
    assert cleanup_report(tracker)['cleanupComplete'] is True
    previous=None
    for index,p in enumerate(sorted(root.glob('*.json'))):
        raw=p.read_bytes();record=json.loads(raw)
        assert record['previousSha256']==previous and record['sequence']==index
        assert p.stat().st_mode&0o777==0o600
        previous=hashlib.sha256(raw).hexdigest()
        assert shadow.PASSWORD.encode() not in raw
        assert b'idToken' not in raw and b'refreshToken' not in raw
    report=responsibility.summary(tracker)
    assert report['unknownCreates']==0 and report['confirmedCreates']==3
    assert report['authorizesCleanup'] is False
    assert 'known-uid' not in json.dumps(report) and '@' not in json.dumps(report)
    responsibility.close(tracker)


def test_response_record_failure_does_not_stop_other_owned_cleanup(tmp_path,monkeypatch):
    tracker,root=setup(tmp_path);service=_service();monkeypatch.setattr(shadow,'_rest',lambda *a:None)
    shadow.run_cases('http://127.0.0.1:1',shadow.shadow_budget(),tracker,{},poster=_poster(service))
    def fail(_):raise OSError('journal unavailable')
    monkeypatch.setattr(tracker['_responsibilityJournal'],'append',fail)
    shadow.cleanup('http://127.0.0.1:1',shadow.shadow_budget(),tracker,poster=_poster(service))
    assert not service['accounts']
    assert responsibility.summary(tracker)['recordingComplete'] is False
    responsibility.close(tracker)


def test_journal_directory_replacement_is_refused(tmp_path):
    tracker,root=setup(tmp_path);root.rename(tmp_path/'old');root.mkdir(mode=0o700)
    with pytest.raises(responsibility.JournalFailure):responsibility.begin(tracker,'signup',email='owned@example.invalid')
    assert not list(root.iterdir())
    responsibility.close(tracker)


def test_killing_process_after_intent_does_not_erase_it(tmp_path):
    root=tmp_path/'journal'
    code=f'''import sys,time
sys.path.insert(0,{str(HERE.resolve())!r})
from pathlib import Path
from credential_collector import new_tracker
import credential_responsibility as r
t=new_tracker("d"*32)
r.attach(t,Path({str(root)!r}),{{"artifactSha256":"a"*64}})
r.begin(t,"signup",email="owned@example.invalid")
print("intent-durable",flush=True)
time.sleep(60)
'''
    p=subprocess.Popen([sys.executable,'-I','-S','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        # File-based readiness and finite polling avoids blocking on a child's stdout.
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not (root/'0001.json').exists():
            if p.poll() is not None:break
            time.sleep(.01)
        assert (root/'0001.json').exists()
    finally:
        p.kill() if p.poll() is None else None
        p.communicate(timeout=3)
    assert records(root)[-1]['event']['state']=='unknown'


def test_close_is_idempotent_and_new_creation_after_close_is_refused(tmp_path):
    tracker,root=setup(tmp_path);responsibility.close(tracker);responsibility.close(tracker)
    with pytest.raises(responsibility.JournalFailure):responsibility.begin(tracker,'signup',email='owned@example.invalid')
    assert responsibility.summary(tracker)['recordingComplete'] is False
