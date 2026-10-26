#!/usr/bin/env python3
"""Build crates/fireemu-core-firestore/tests/fixtures/production_text_membership.json.

Usage: membership_fixture.py INV.json OUT.json  (INV.json is the output of extract.py)

Every recorded production search response, any result count, as the sorted set of returned
document ids. Every repeated recording of the same case (same reconstructed corpus and query)
must return the same set; the script stops if two recordings disagree.
"""
import json, sys, hashlib
from datetime import datetime, timezone
inv = json.load(open(sys.argv[1]))
def nanos(ts):
    base, frac = ts.rstrip('Z').split('.') if '.' in ts else (ts.rstrip('Z'), '0')
    dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 10**9 + int(frac.ljust(9, '0')[:9])
corpora, cases = {}, {}
for s in inv:
    o = [x for x in s['stages'] if x['name'] == 'search'][0].get('options', {})
    idx = s['indexes'][0]
    fields = [f['fieldPath'] for f in idx['fields']]
    override = (idx.get('searchIndexOptions') or {}).get('textLanguageOverrideFieldPath')
    t0 = min((nanos(d['createTime']) for d in s['corpus']), default=0)
    docs = [{'id': d['name'], 'created': nanos(d['createTime']) - t0,
             'fields': {k: v for k, v in d['fields'].items() if isinstance(v, str)}} for d in s['corpus']]
    corpus = {'collection': s['collection'].strip('/'), 'fields': fields, 'languageOverride': override, 'documents': docs}
    key = hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest()[:12]
    corpora.setdefault(key, corpus)
    query = o['query']['functionValue']['args'][0]['stringValue']
    expected = sorted(r['name'] for r in s['results'])
    ck = (key, query, json.dumps(expected))
    cases.setdefault(ck, {'corpus': key, 'query': query, 'expected': expected, 'responses': 0})['responses'] += 1
names, seen = {}, {}
for k, c in corpora.items():
    n = seen.get(c['collection'], 0); seen[c['collection']] = n + 1
    names[k] = f"{c['collection']}#{n}"
out = {'about': 'Every recorded production Firestore Enterprise text-search REST response (any number of results), '
                'as the set of returned document ids. Corpus state is reconstructed from the recorded writes; only '
                'string fields are kept. Order is checked by production_text_order.json.',
       'responses': sum(c['responses'] for c in cases.values()),
       'corpora': {names[k]: v for k, v in corpora.items()},
       'cases': [dict(v, corpus=names[v['corpus']]) for v in cases.values()]}
groups = {}
for (key, query, expected) in cases:
    groups.setdefault((key, query), set()).add(expected)
disagreeing = {k: v for k, v in groups.items() if len(v) > 1}
if disagreeing:
    sys.exit(f'repeated recordings disagree: {disagreeing}')
json.dump(out, open(sys.argv[2], 'w'), indent=1, ensure_ascii=False)
print('responses', out['responses'], 'corpora', len(corpora), 'cases', len(cases), 'empty', sum(1 for c in cases.values() if not c['expected']))
