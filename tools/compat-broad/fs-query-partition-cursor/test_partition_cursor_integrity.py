"""Partition/cursor evidence integrity through the actual local collector.

Synthetic API responses, not a running fireemu or production observation.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import pytest
import partition_cursor_collector as collector
from partition_cursor_offline_fixture import plan, Transport, TIME, partition_cursor
from partition_cursor_shadow import residual_documents, validate_shadow


def receipt(body, status=200):
    raw = json.dumps(body, allow_nan=False).encode()
    return dict(status=status, body=body, rawBody=raw, byteCount=len(raw), complete=True,
                contentType="application/json")


def run_mutation(tmp_path, kind, mutate):
    value = plan()
    class Changed(Transport):
        def __call__(self, request):
            result = super().__call__(request)
            if request["kind"] == kind:
                result = mutate(result)
            return result
    transport = Changed(value)
    return collector.collect_local(value, transport, tmp_path / "run"), transport


def alter_body(change):
    def mutate(r):
        change(r["body"])
        return receipt(r["body"], r["status"])
    return mutate


@pytest.mark.parametrize("partitions", [0, 1])
@pytest.mark.parametrize("change", ["value", "type", "extra-field", "deleted-field", "error-row"])
def test_reconstruction_requires_identical_values_not_only_names(tmp_path, partitions, change):
    value = plan()
    class Changed(Transport):
        def _body(self, request):
            status, body = super()._body(request)
            if request["kind"] == "partition-reconstruction-range-0":
                fields = body[0]["document"]["fields"]
                if change == "value": fields["n"] = {"integerValue": "999"}
                elif change == "type": fields["n"] = {"integerValue": 0}
                elif change == "extra-field": fields["extra"] = {"booleanValue": True}
                elif change == "deleted-field": fields.pop("g")
                else: body.append({"error": {"status": "INTERNAL"}})
            return status, body
    result = collector.collect_local(value, Changed(value, partitions=partitions), tmp_path/'run')
    assert result['status'] == 'incomplete'
    assert result['reconstruction']['matches'] is not True
    assert result['cleanup']['complete'] is True


def test_readtime_and_document_version_metadata_are_not_value_differences(tmp_path):
    def change(body):
        for row in body:
            if 'document' in row:
                row['document']['updateTime'] = '2026-09-20T00:00:00Z'
                row['readTime'] = '2026-09-20T00:00:01Z'
    result, _ = run_mutation(tmp_path, 'partition-reconstruction-range-0', alter_body(change))
    assert result['status'] == 'pass'


@pytest.mark.parametrize('mutation', ['different-body', 'duplicate-key', 'float-code', 'bad-media',
                                     'incomplete', 'float-count', 'oversized', 'no-raw'])
def test_unusable_raw_preflight_never_allows_writes(tmp_path, mutation):
    def mutate(r):
        if mutation == 'different-body': r['rawBody'] = b'{"error":{"code":403,"status":"PERMISSION_DENIED"}}'
        elif mutation == 'duplicate-key': r['rawBody'] = b'{"error":{},"error":{"code":404,"status":"NOT_FOUND"}}'
        elif mutation == 'float-code': r['rawBody'] = b'{"error":{"code":404.0,"status":"NOT_FOUND"}}'
        elif mutation == 'bad-media': r['contentType'] = 'text/html'
        elif mutation == 'incomplete': r['complete'] = False
        elif mutation == 'oversized': r['rawBody'] = b' ' * 65537
        elif mutation == 'no-raw': r.pop('rawBody')
        r['byteCount'] = len(r.get('rawBody',b''))
        if mutation == 'float-count': r['byteCount'] = float(r['byteCount'])
        return r
    result, transport = run_mutation(tmp_path, 'preflight-typed-absence', mutate)
    assert result['status'] == 'incomplete'
    assert result['rows'][0]['status'] == 'failed'
    assert validate_shadow(result, plan())['status'] == 'INDETERMINATE'
    assert not any(r['method'] in ('PATCH','DELETE') or r['kind'] in ('seed-commit','cleanup-seed-delete')
                   for r in transport.sent)


@pytest.mark.parametrize('body,status', [
    ({'error':{'code':404.0,'status':'NOT_FOUND'}},404),
    ({'error':{'code':404,'status':'NOT_FOUND'},'name':'unrelated'},404),
    ({'error':{'code':404,'status':'PERMISSION_DENIED'}},404),
    ({},404), ({'name':'already-present'},200),
])
def test_invalid_preflight_stops_setup_but_attempts_readonly_recovery(tmp_path, body, status):
    result, transport = run_mutation(tmp_path,'preflight-typed-absence', lambda r: receipt(body,status))
    assert result['status'] == 'incomplete'
    assert all(r['method'] != 'PATCH' and r['kind'] != 'seed-commit' for r in transport.sent)
    assert any(r['phase'] == 'recovery' for r in transport.sent)


@pytest.mark.parametrize('timestamp', ['2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z',
                                     '2026-09-18T00:00:00.0000000001Z', 'version', None])
def test_invalid_creation_version_grants_no_delete(tmp_path,timestamp):
    result, transport = run_mutation(tmp_path,'create-only-patch',alter_body(lambda b: b.update(updateTime=timestamp)))
    assert result['rows'][1]['status'] == 'mismatch'
    assert 'seed-commit' not in [r['kind'] for r in transport.sent]
    assert not any(r['kind'] in ('cleanup-root-delete','cleanup-seed-delete') for r in transport.sent)


@pytest.mark.parametrize('kind', ['create-only-patch', 'seed-commit', 'cleanup-ownership-read'])
def test_success_with_top_level_error_never_grants_cleanup(tmp_path,kind):
    result, transport = run_mutation(tmp_path,kind,alter_body(lambda b: b.update(error={'code':403,'status':'PERMISSION_DENIED'})))
    assert not result['cleanup']['complete']
    assert 'cleanup-seed-delete' not in [r['kind'] for r in transport.sent]
    if kind != 'seed-commit':
        assert 'cleanup-root-delete' not in [r['kind'] for r in transport.sent]


@pytest.mark.parametrize('kind', ['cleanup-verify-group-absence','cleanup-verify-collection-absence'])
@pytest.mark.parametrize('body', [[{}], [{'error':{'code':500,'status':'INTERNAL'}}],
                                 [{'readTime':TIME,'error':{'code':403,'status':'PERMISSION_DENIED'}}],
                                 [{'readTime':'2026-02-30T00:00:00Z'}]])
def test_error_or_malformed_query_stream_is_not_empty_cleanup(tmp_path, kind, body):
    result, _ = run_mutation(tmp_path,kind,lambda r: receipt(body))
    assert result['status'] == 'incomplete'
    assert result['cleanup']['complete'] is False


@pytest.mark.parametrize('body', [{'error':{'status':'INTERNAL'}}, {'ignored':True}, [], None])
def test_delete_success_requires_empty_object(tmp_path,body):
    result, _ = run_mutation(tmp_path,'cleanup-root-delete',lambda r:receipt(body))
    assert result['cleanup']['complete'] is False


@pytest.mark.parametrize('change', ['int-before','null-before','wrong-value','foreign-reference','duplicate-value'])
def test_unusable_partition_cursor_does_not_bind_range(tmp_path,change):
    def mutate(r):
        c=partition_cursor(plan()['ownedResources'][2])
        if change=='int-before':c['before']=1
        elif change=='null-before':c['before']=None
        elif change=='wrong-value':c['values']=[{'integerValue':'1'}]
        elif change=='foreign-reference':c['values'][0]['referenceValue']='projects/other/databases/(default)/documents/a/b'
        else:c['values'].append(copy.deepcopy(c['values'][0]))
        return receipt({'partitions':[c]})
    result, transport = run_mutation(tmp_path,'partition-count-1',mutate)
    assert result['status']=='incomplete'
    assert not any(r['kind'].startswith('partition-reconstruction') for r in transport.sent)
    assert result['cleanup']['complete'] is True


@pytest.mark.parametrize('mode', ['short','zero'])
def test_publication_handles_short_write_without_claiming_truncated_success(tmp_path,monkeypatch,mode):
    real=os.write
    monkeypatch.setattr(collector.os,'write',lambda fd,payload: real(fd,payload[:7]) if mode=='short' else 0)
    value=plan(); transport=Transport(value)
    result=collector.collect_local(value,transport,tmp_path/'run')
    if mode=='short':
        assert result['status']=='pass'
        assert json.loads((tmp_path/'run/collection.json').read_bytes())==result
        for binding in json.loads((tmp_path/'run/raw/manifest.json').read_bytes())['bindings']:
            raw=(tmp_path/'run/raw'/binding['path']).read_bytes()
            assert len(raw)==binding['byteCount']
            assert hashlib.sha256(raw).hexdigest()==binding['sha256']
    else:
        assert result['status']=='incomplete'
        assert result['publication']['complete'] is False
        assert result['cleanup']['complete'] is True


@pytest.mark.parametrize('mode',['fifo','directory','oversized'])
def test_raw_verification_cannot_block_on_special_or_overlarge_files(tmp_path,mode):
    target=tmp_path/'sidecar.raw'
    if mode=='fifo':os.mkfifo(target)
    elif mode=='directory':target.mkdir()
    else:target.write_bytes(b'x'*65537)
    fd=os.open(tmp_path,os.O_RDONLY)
    try:
        assert collector._verify_raw(fd,[dict(path=target.name,byteCount=0,sha256=hashlib.sha256(b'').hexdigest())]) is False
    finally:os.close(fd)


def residual_transport(root_body=None):
    def send(r):
        if r['kind']=='residual-root':return receipt(root_body or {'error':{'status':'NOT_FOUND','code':404}},404)
        return receipt([{'readTime':TIME}])
    return send


@pytest.mark.parametrize('kind', ['residual-root','residual-scan','residual-cursor'])
@pytest.mark.parametrize('mutation', ['incomplete','wrong-raw','error','bad-count'])
def test_residual_zero_requires_typed_complete_bound_responses(kind,mutation):
    original=residual_transport()
    def send(r):
        result=original(r)
        if r['kind']==kind:
            if mutation=='incomplete':result['complete']=False
            elif mutation=='wrong-raw':result['rawBody']=b'{}';result['byteCount']=2
            elif mutation=='bad-count':result['byteCount']=float(result['byteCount'])
            else:result=receipt({'error':{'code':403,'status':'PERMISSION_DENIED'}},404) if kind=='residual-root' else receipt([{'error':{'code':500,'status':'INTERNAL'}}])
        return result
    assert residual_documents(send,plan()) is None


def test_positive_residual_zero_from_complete_streams_and_typed_404():
    assert residual_documents(residual_transport(),plan()) == 0


@pytest.mark.parametrize('status',[False,True,200.0,404.0])
def test_transport_status_type_is_not_coerced(tmp_path,status):
    result,transport=run_mutation(tmp_path,'preflight-typed-absence',lambda r:{**r,'status':status})
    assert result['rows'][0]['status'] != 'pass'
    assert not any(r['method'] == 'PATCH' or r['kind'] == 'seed-commit' for r in transport.sent)
