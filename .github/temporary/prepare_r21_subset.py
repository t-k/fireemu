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

# Local counterexamples reuse the recorded request and vary only data or one extra stage.
import copy
source = next(p for p in raw['programs'] if p['id'] == 'fs-ent-pipeline/o7/aggregate-args')
nested = next(step for step in source['steps'] if step['id'] == 'nested-aggregate')
for variant in ('long', 'array', 'string', 'empty', 'other-shape'):
    case = copy.deepcopy(source)
    case['id'] = 'fs-ent-pipeline/local-counter-' + variant
    step = copy.deepcopy(nested)
    if variant == 'empty':
        case['seed'] = []
    elif variant != 'other-shape':
        value = {'integerValue': '77'} if variant == 'long' else ({'arrayValue': {'values': [{'integerValue': '7'}]}} if variant == 'array' else {'stringValue': 'x'})
        for _, fields in case['seed']:
            fields['n'] = copy.deepcopy(value)
    if variant == 'other-shape':
        step['body']['structuredPipeline']['pipeline']['stages'].append({'name': 'limit', 'args': [{'integerValue': '1'}]})
    case['steps'] = [step, {**step, 'id': step['id'] + '-grpc', 'transport': 'grpc'}]
    programs.append(case)
Path('/tmp/r21-programs.json').write_text(json.dumps(programs))
