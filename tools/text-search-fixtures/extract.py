#!/usr/bin/env python3
"""Reconstruct the corpus state and extract every recorded text-search response.

Usage: extract.py OUT.json RUN_DIR [RUN_DIR ...]

Each RUN_DIR is one private production recording (journal.jsonl plus <step>.request.body and
<step>.response.body files). The runs are replayed in the order of their first sent request:
document writes and index creates/deletes update the reconstructed state, and every
executePipeline with a search stage is written out with the corpus and active text index at that
moment. The recordings are private; only the fixtures built from this output are committed
(order_fixture.py, membership_fixture.py).
"""
import json, os, sys, re


def first_time(d):
    for l in open(d + '/journal.jsonl'):
        j = json.loads(l)
        if 'sentAtUnix' in j:
            return j['sentAtUnix']
    return 0


DIRS = [d.rstrip('/') for d in sys.argv[2:] if os.path.exists(d.rstrip('/') + '/journal.jsonl')]
DIRS.sort(key=first_time)

store = {}  # full doc name -> {'fields':..., 'createTime':...}
indexes = {}  # (db, cg) -> {index_name_or_step: fields}
out = []


def load(d, step, kind):
    p = f'{d}/{step}.{kind}.body'
    if not os.path.exists(p):
        return None
    raw = open(p, 'rb').read()
    try:
        return json.loads(raw)
    except Exception:
        return None


def strs(fields):
    o = {}
    for k, v in (fields or {}).items():
        if 'stringValue' in v:
            o[k] = v['stringValue']
        else:
            o[k] = v
    return o


def apply_doc(name, fields, t):
    prev = store.get(name)
    store[name] = {'fields': fields, 'createTime': prev['createTime'] if prev else t}


for d in DIRS:
    run = os.path.basename(d)
    steps = []
    statuses = {}
    for l in open(d + '/journal.jsonl'):
        j = json.loads(l)
        if j.get('phase') == 'before-send':
            steps.append(j)
        if j.get('phase') == 'response-persisted':
            statuses[j['step']] = j.get('status')
    for j in steps:
        step, m, url = j['step'], j['method'], j['url']
        st = statuses.get(step)
        path0 = url.split('?')[0]
        if m == 'POST' and path0.endswith('/indexes') and st in (200, 409):
            mdb0 = re.search(r'/databases/([^/:]+)', path0).group(1)
            cg0 = path0.split('/collectionGroups/')[1].split('/')[0]
            if st == 200 or (mdb0, cg0) not in indexes:
                indexes[(mdb0, cg0)] = {'active': load(d, step, 'request')}
            continue
        if m == 'DELETE' and '/indexes/' in path0 and st == 200:
            mdb0 = re.search(r'/databases/([^/:]+)', path0).group(1)
            cg0 = path0.split('/collectionGroups/')[1].split('/')[0]
            indexes.pop((mdb0, cg0), None)
            continue
        if st != 200:
            continue
        req = load(d, step, 'request')
        res = load(d, step, 'response')
        path = url.split('?')[0]
        mdb = re.search(r'/databases/([^/:]+)', path)
        db = mdb.group(1) if mdb else None
        if m == 'GET' and '/documents/' in path and res and isinstance(res, dict) and 'name' in res:
            store[res['name']] = {'fields': res.get('fields', {}), 'createTime': res.get('createTime')}
        elif m == 'POST' and path.endswith(':commit') or path.endswith(':batchWrite'):
            if not req:
                continue
            wr = (res or {}).get('writeResults', [])
            ct = (res or {}).get('commitTime')
            for i, w in enumerate(req.get('writes', [])):
                if res and 'status' in res and i < len(res['status']) and res['status'][i].get('code', 0) != 0:
                    continue
                t = (wr[i].get('updateTime') if i < len(wr) else None) or ct
                if 'update' in w:
                    apply_doc(w['update']['name'], w['update'].get('fields', {}), t)
                elif 'delete' in w:
                    store.pop(w['delete'], None)
        elif m == 'POST' and '/documents/' in path and ':' not in path.split('/')[-1] and res and 'name' in res:
            store[res['name']] = {'fields': res.get('fields', {}), 'createTime': res.get('createTime')}
        elif m == 'DELETE' and '/documents/' in path:
            store.pop(path.split('/v1/')[1], None)
        elif m == 'POST' and path.endswith('/indexes') and req:
            cg = path.split('/collectionGroups/')[1].split('/')[0]
            idxname = (res or {}).get('metadata', {}).get('index') or step
            indexes.setdefault((db, cg), {})[idxname] = req
        elif m == 'POST' and path.endswith(':executePipeline') and req:
            stages = req.get('structuredPipeline', {}).get('pipeline', {}).get('stages', [])
            if not any(s.get('name') == 'search' for s in stages):
                continue
            results = []
            if isinstance(res, list):
                for chunk in res:
                    results.extend(chunk.get('results', []))
            coll = None
            for s in stages:
                if s['name'] == 'collection':
                    coll = s['args'][0]['referenceValue']
            prefix = f'projects/' + path.split('/v1/projects/')[1].split('/documents')[0] + '/documents' + coll + '/'
            corpus = [
                {'name': n.split('/')[-1], 'createTime': v['createTime'], 'fields': strs(v['fields'])}
                for n, v in store.items() if n.startswith(prefix) and '/' not in n[len(prefix):]
            ]
            corpus.sort(key=lambda x: (x['createTime'] or '', x['name']))
            cg = coll.strip('/').split('/')[-1]
            out.append({
                'run': run, 'step': step, 'db': db, 'collection': coll,
                'stages': stages,
                'results': [{'name': r['name'].split('/')[-1], 'createTime': r.get('createTime'),
                             'fields': strs(r.get('fields', {}))} for r in results],
                'corpus': corpus,
                'indexes': list(indexes.get((db, cg), {}).values()),
            })

json.dump(out, open(sys.argv[1], 'w'), indent=1)
print(len(out), 'searches')
