import json
from pathlib import Path

ids = {'map-one-argument', 'proposed-n76-map-add-then-empty'}
raw = json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
programs = []
for original in raw['programs']:
    if not original['id'].startswith('fs-ent-pipeline/o5/'):
        continue
    steps = [step for step in original['steps'] if step['id'] in ids]
    if steps:
        programs.append({**original, 'steps': steps})
seen = [step['id'] for program in programs for step in program['steps']]
if len(seen) != 2 or set(seen) != ids:
    raise RuntimeError(f'expected 2 exact steps, got {seen}')
Path('/tmp/map-request-programs.json').write_text(json.dumps(programs))
