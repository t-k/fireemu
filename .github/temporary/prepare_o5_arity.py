import json
from pathlib import Path
names={'get_field','offset','sum','minimum','maximum','negate','cmp','reverse','length','storage_size','coalesce','namespace','has_ancestor','reference_slice','autogen_document_id','replace_document_id','string_concat'}
raw=json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
original=next(p for p in raw['programs'] if p['id']=='fs-ent-pipeline/o5/function-names')
steps=[s for s in original['steps'] if s['id'] in {'fn-'+n for n in names}]
if len(steps)!=17: raise RuntimeError(f'expected 17 got {len(steps)}')
programs=[{**original,'steps':steps+[{**s,'id':s['id']+'-grpc','transport':'grpc'} for s in steps]}]
Path('/tmp/o5-arity-programs.json').write_text(json.dumps(programs))
