import json
from pathlib import Path
raw=json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
groups=json.loads(Path('.ci-helper/.github/temporary/o5_unknown_groups.json').read_text())
rows=set(groups['unknown-precedence']+groups['name-plain'])
assert len(rows)==35
programs=[]
for original in raw['programs']:
 steps=[step for step in original['steps'] if f"{original['id']}#{step['id']}" in rows]
 if steps:
  programs.append({**original,'steps':steps+[{**step,'id':step['id']+'-grpc','transport':'grpc'} for step in steps]})
assert sum(len(p['steps']) for p in programs)==70
original=next(p for p in raw['programs'] if p['id']=='fs-ent-pipeline/o4/stages')
step=next(s for s in original['steps'] if s['id']=='select-empty-then-unknown-function')
programs.append({**original,'steps':[step,{**step,'id':step['id']+'-grpc','transport':'grpc'}]})
Path('/tmp/o5-unknown-programs.json').write_text(json.dumps(programs))
