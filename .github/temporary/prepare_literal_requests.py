import json
from pathlib import Path

ids = {
    'where-vector-of-integer', 'vector-of-integer', 'vector-of-double-and-integer',
    'vector-without-value', 'vector-with-extra-key', 'vector-value-not-array',
    'proposed-type-tag-integer', 'proposed-type-tag-boolean', 'proposed-type-tag-null',
    'proposed-type-tag-double', 'proposed-type-tag-map', 'proposed-type-tag-array',
    'proposed-type-tag-nested', 'proposed-type-tag-where', 'proposed-type-tag-function-argument',
    'proposed-reference-collection', 'proposed-reference-empty-segment', 'proposed-reference-garbage',
}
raw = json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
programs = []
for original in raw['programs']:
    if not original['id'].startswith('fs-ent-pipeline/o5/'):
        continue
    steps = [step for step in original['steps'] if step['id'] in ids]
    if steps:
        programs.append({**original, 'steps': steps})
seen = [step['id'] for program in programs for step in program['steps']]
if len(seen) != 18 or set(seen) != ids:
    raise RuntimeError(f'expected 18 exact steps, got {seen}')
Path('/tmp/literal-request-programs.json').write_text(json.dumps(programs))
