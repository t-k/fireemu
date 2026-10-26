#!/usr/bin/env python3
"""Build crates/fireemu-core-firestore/tests/fixtures/production_text_order.json.

Usage: order_fixture.py INV.json OUT.json  (INV.json is the output of extract.py)

Keeps the responses with two or more results, in production response order. Every repeated
recording of the same case (same reconstructed corpus, query and sort) must return the same
ordered list; the script stops if two recordings disagree.
"""
import json, sys, hashlib
from datetime import datetime, timezone

inv = json.load(open(sys.argv[1]))


def nanos(ts):
    base, frac = ts.rstrip('Z').split('.') if '.' in ts else (ts.rstrip('Z'), '0')
    dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 10**9 + int(frac.ljust(9, '0')[:9])


corpora = {}
cases = {}
problems = []
for s in inv:
    if len(s['results']) < 2:
        continue
    o = [x for x in s['stages'] if x['name'] == 'search'][0].get('options', {})
    if not s['indexes']:
        sys.exit(f"no reconstructed text index for {s['run']}/{s['step']}: pass every recorded text run "
                 "directory to extract.py (index creates live in runs without searches); see README.md")
    idx = s['indexes'][0]
    fields = [f['fieldPath'] for f in idx['fields']]
    override = (idx.get('searchIndexOptions') or {}).get('textLanguageOverrideFieldPath')
    docs = []
    t0 = min(nanos(d['createTime']) for d in s['corpus'])
    for d in s['corpus']:
        sf = {k: v for k, v in d['fields'].items() if isinstance(v, str)}
        docs.append({'id': d['name'], 'created': nanos(d['createTime']) - t0, 'fields': sf})
    byid = {d['name']: d for d in s['corpus']}
    for r in s['results']:
        c = byid.get(r['name'])
        rf = {k: v for k, v in r['fields'].items() if isinstance(v, str)}
        cf = {k: v for k, v in c['fields'].items() if isinstance(v, str)} if c else None
        if cf != rf or (c and c['createTime'] != r['createTime']):
            problems.append((s['run'], s['step'], r['name']))
    corpus = {'collection': s['collection'].strip('/'), 'fields': fields, 'languageOverride': override, 'documents': docs}
    key = hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest()[:12]
    corpora.setdefault(key, corpus)
    query = o['query']['functionValue']['args'][0]['stringValue']
    sorted_ = 'sort' in o
    expected = [r['name'] for r in s['results']]
    ck = (key, query, sorted_, json.dumps(expected))
    case = cases.setdefault(ck, {'corpus': key, 'query': query, 'scoreSort': sorted_, 'expected': expected, 'recordings': []})
    case['recordings'].append(f"{s['run']}/{s['step']}")

# stable corpus names
names = {}
for i, k in enumerate(corpora):
    c = corpora[k]
    names[k] = f"{c['collection']}#{sum(1 for kk in list(names) if corpora[kk]['collection'] == c['collection'])}"
out = {
    'about': 'Production Firestore Enterprise text-search responses with two or more results, '
             'replayed offline. Corpus state is reconstructed from the recorded writes; expected '
             'lists are the production response order. Only string fields are kept.',
    'corpora': {names[k]: v for k, v in corpora.items()},
    'cases': [dict(v, corpus=names[v['corpus']]) for v in cases.values()],
}
groups = {}
for (key, query, sorted_, expected) in cases:
    groups.setdefault((key, query, sorted_), set()).add(expected)
disagreeing = {k: v for k, v in groups.items() if len(v) > 1}
if disagreeing:
    sys.exit(f'repeated recordings disagree: {disagreeing}')
json.dump(out, open(sys.argv[2], 'w'), indent=1, ensure_ascii=False)
print('corpora', len(corpora), 'cases', len(cases), 'sorted', sum(c['scoreSort'] for c in cases.values()), 'problems', len(problems), problems[:5])
