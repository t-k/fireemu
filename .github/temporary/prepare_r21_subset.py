import json
from pathlib import Path

raw = json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
selected = {
    'fs-ent-pipeline/o6/sort-wire-errors': 'expression-unknown-fn',
    'fs-ent-pipeline/o7/aggregate-args': 'accumulator-unknown',
}
programs = []
for program in raw['programs']:
    target = selected.get(program['id'])
    if target is None:
        continue
    ids = {target}
    if program['id'] == 'fs-ent-pipeline/o7/aggregate-args':
        ids.add('nested-aggregate')
    steps = [step for step in program['steps'] if step['id'] in ids]
    assert len(steps) == len(ids)
    programs.append({**program, 'steps': steps + [{**step, 'id': step['id'] + '-grpc', 'transport': 'grpc'} for step in steps]})
assert len(programs) == 2 and sum(len(p['steps']) for p in programs) == 6
Path('/tmp/r21-programs.json').write_text(json.dumps(programs))
