"""Compare actual retained fixture bundles; source bytes are the authority."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from test_partition_cursor_comparator import bundle
from partition_cursor_comparator import compare_evidence, verify_retained_bytes


def selected(value):
    return next(r for r in value['rows'] if r.get('raw', {}).get('present') is True)


def rewrite(root, row, payload, decoded=None):
    p = root / 'raw' / row['raw']['path']
    p.chmod(0o600)
    p.write_bytes(payload)
    row['raw']['sha256'] = hashlib.sha256(payload).hexdigest()
    row['raw']['byteCount'] = len(payload)
    row['receipt']['byteCount'] = len(payload)
    if decoded is not None:
        row['receipt']['body'] = decoded


def test_normal_retained_pair_is_verified(tmp_path):
    left, right = bundle(tmp_path, 'a'), bundle(tmp_path, 'b')
    result = compare_evidence(left, right, production_directory=tmp_path/'a', local_directory=tmp_path/'b')
    assert result['classification'] == 'EQUIVALENT'
    assert result['retainedBytesVerified'] is True


def test_projection_only_comparison_is_explicitly_unverified(tmp_path):
    result = compare_evidence(bundle(tmp_path, 'a'), bundle(tmp_path, 'b'))
    assert result['classification'] == 'EQUIVALENT'
    assert result['retainedBytesVerified'] is False
    assert result['acquisitionValidated'] is False


@pytest.mark.parametrize('kind', ['absolute', 'parent', 'symlink', 'hardlink', 'raw-symlink'])
def test_sidecar_cannot_escape_its_private_raw_directory(tmp_path, kind):
    value = bundle(tmp_path, 'a'); row = selected(value)
    original = tmp_path/'a/raw'/row['raw']['path']
    outside = tmp_path/'outside.raw'; outside.write_bytes(original.read_bytes()); outside.chmod(0o600)
    if kind == 'absolute': row['raw']['path'] = str(outside)
    elif kind == 'parent': row['raw']['path'] = '../../outside.raw'
    elif kind in ('symlink', 'hardlink'):
        original.unlink()
        if kind == 'symlink': original.symlink_to(outside)
        else: os.link(outside, original)
    else:
        raw = tmp_path/'a/raw'; raw.rename(tmp_path/'elsewhere'); raw.symlink_to(tmp_path/'elsewhere', target_is_directory=True)
    assert verify_retained_bytes(value, tmp_path/'a')


@pytest.mark.parametrize('where', ['binding', 'receipt'])
@pytest.mark.parametrize('value', [False, 0.0, -1, 1, '123'])
def test_lengths_are_typed_and_must_match_the_bytes(tmp_path, where, value):
    data = bundle(tmp_path,'a'); row=selected(data)
    row['raw' if where=='binding' else 'receipt']['byteCount']=value
    assert verify_retained_bytes(data,tmp_path/'a')


@pytest.mark.parametrize(('raw','body'), [
    (b'{"ok":0,"ok":1}', {'ok':1}),
    ('{"ok":1}'.encode('utf-16'), {'ok':1}),
    (b'{"ok":NaN}', {'ok':float('nan')}),
    (b'{"ok":Infinity}', {'ok':float('inf')}),
    (b'{"ok":0}', {'ok':False}),
    (b'{"ok":1}', {'ok':1.0}),
    (b'{"ok":[false]}', {'ok':[0]}),
])
def test_strict_decoding_and_typed_body_equality(tmp_path,raw,body):
    data=bundle(tmp_path,'a');row=selected(data);rewrite(tmp_path/'a',row,raw,body)
    assert verify_retained_bytes(data,tmp_path/'a')


def test_oversized_regular_file_is_rejected_without_unbounded_read(tmp_path):
    data=bundle(tmp_path,'a');row=selected(data)
    rewrite(tmp_path/'a',row,b' '*65537,{})
    assert verify_retained_bytes(data,tmp_path/'a')


def test_fifo_is_refused_without_waiting_for_a_writer(tmp_path):
    data=bundle(tmp_path,'a');row=selected(data);p=tmp_path/'a/raw'/row['raw']['path'];p.unlink();os.mkfifo(p,0o600)
    assert verify_retained_bytes(data,tmp_path/'a')


@pytest.mark.parametrize('bad',[None,False,[],{},'row'])
def test_malformed_row_is_a_named_failure_not_an_exception(tmp_path,bad):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b');right['rows'][0]=bad
    assert compare_evidence(left,right,local_directory=tmp_path/'b')['classification']=='INDETERMINATE'


@pytest.mark.parametrize('field',['index','phase','kind'])
def test_row_must_stay_bound_to_its_compiled_slot(tmp_path,field):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b')
    for data in (left,right):
        data['rows'][0][field] = {'index':False,'phase':'recovery','kind':'invented'}[field]
    assert compare_evidence(left,right)['classification']=='INDETERMINATE'


@pytest.mark.parametrize(('a','b'),[(False,0),(True,1),(1,1.0),([False],[0])])
def test_pair_comparison_preserves_json_types(tmp_path,a,b):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b')
    left['rows'][0]['receipt']['body']={'probe':a};right['rows'][0]['receipt']['body']={'probe':b}
    assert compare_evidence(left,right)['classification']=='SEMANTIC_MISMATCH'

@pytest.mark.parametrize('field,value', [
    ('status',[]),('status',{}),('skipReason',[]),('skipReason',{}),
    ('extra',float('nan')),('extra',{1:'invalid JSON'}),('extra',1 << 15000),
], ids=['status-list','status-map','reason-list','reason-map','nan','bad-key','huge-int'])
def test_malformed_semantic_row_is_indeterminate_not_an_exception(tmp_path,field,value):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b')
    left['rows'][0][field]=value
    assert compare_evidence(left,right)['classification']=='INDETERMINATE'


def test_cyclic_semantic_row_cannot_recurse_indefinitely(tmp_path):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b')
    left['rows'][0]['cycle']=left['rows'][0]
    assert compare_evidence(left,right)['classification']=='INDETERMINATE'

@pytest.mark.parametrize('value',[0,1,None,'false'])
def test_production_flag_is_a_boolean(tmp_path,value):
    left,right=bundle(tmp_path,'a'),bundle(tmp_path,'b')
    left['productionExecuted']=value
    assert compare_evidence(left,right)['classification']=='INDETERMINATE'
