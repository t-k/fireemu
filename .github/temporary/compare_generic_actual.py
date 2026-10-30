import json
from pathlib import Path

root=Path('/tmp/generic-evidence')
cases=json.loads(Path('/tmp/generic-expected.json').read_text())
results=[]
for profile in ('strict','emulator'):
    data=json.loads((root/f'{profile}.json').read_text())
    raw=next(iter(data['results'].values()))['raw']
    ids=[]
    for case in cases:
        item=raw[case['id']]['response']
        if item['status']!=200: raise AssertionError((profile,case['id'],item))
        body=json.loads(item['text'])
        value=body[0]['results'][0]['fields']['value']
        if case['id']=='autogen-document-id':
            text=value.get('stringValue','')
            assert len(text)==20 and text.isascii() and text.isalnum(),(profile,value)
            ids.append(text)
        else:
            expected=case['expected']
            if 'referenceValue' in expected:
                expected={'referenceValue': expected['referenceValue'].replace('entpipe2-20261031','entpipe1')}
            assert value==expected,(profile,case['id'],value,expected)
        results.append({'profile':profile,'id':case['id'],'status':item['status'],'value':value})
(root/'comparison.json').write_text(json.dumps(results,indent=2)+'\n')
print('38 profile/case values verified')
