import json
from pathlib import Path
prod=json.loads(Path('conformance/fs-ent-pipeline-production.json').read_text())['programs']
release=json.loads(Path('conformance/fs-ent-pipeline-release-v040.json').read_text())['rows']
actual=json.loads(Path('/tmp/fs-strict-arity-fireemu.json').read_text())
rows=[]
for entry in release:
 if entry['status'] != 'MISMATCH': continue
 pid,sid=entry['row'].split('#',1)
 expected=prod.get(pid,{}).get('steps',{}).get(sid,{})
 if expected.get('status') != 400: continue
 observed=actual['results'][pid]
 rows.append({'id':entry['row'],'production':expected,'local':observed['steps'][sid],'raw':observed['raw'][sid]})
assert len(rows)==122,len(rows)
Path('/tmp/fs-strict-arity-comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
