import json
from pathlib import Path
import subprocess

adapter = 'crates/fireemu-adapter-grpc/src/pipeline.rs'
core = 'crates/fireemu-core-firestore/src/pipeline_exec.rs'
cases = [
    ('arity_classification', core, 'if function.arity == Arity::Pairs {\n                return Err(ExprError::Arity(format!(', 'if function.arity == Arity::Pairs {\n                return Err(ExprError::Invalid(format!(', 'recorded_map_constructor_refusals'),
    ('add_fields_key_check', adapter, '.find_map(|alias| map_key_error(&fields[alias]))\n    {\n        return Err(error);\n    }\n    Ok(aliases)', '.find_map(|_| None::<Status>)\n    {\n        return Err(error);\n    }\n    Ok(aliases)', 'recorded_map_add_fields_refusal_precedes_empty_select'),
    ('validation_priority', adapter, 'deferred_name.get_or_insert(error);\n                                continue;\n                            }\n                            Err(error) => return Err(error),', 'return Err(error);\n                            }\n                            Err(error) => return Err(error),', 'generated_map_refusal_precedence_cases'),
]
out = Path('/tmp/map-mutants')
out.mkdir(exist_ok=True)
results = []
for name, file, old, new, test in cases:
    path = Path(file)
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f'{name}: anchor count {original.count(old)}')
    cmd = ['cargo', 'nextest', 'run', '--profile', 'pr', '--locked', '-p', 'fireemu-adapter-grpc', '-E', f'test({test})']
    try:
        noop = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / f'{name}-noop.log').write_text(noop.stdout)
        if noop.returncode != 0:
            raise RuntimeError(f'{name}: noop failed')
        path.write_text(original.replace(old, new, 1))
        mutant = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / f'{name}-mutant.log').write_text(mutant.stdout)
        killed = mutant.returncode != 0 and 'FAIL [' in mutant.stdout and test in mutant.stdout
        results.append({'name': name, 'noop': noop.returncode, 'mutant': mutant.returncode, 'killed': killed})
        if not killed:
            raise RuntimeError(f'{name}: no target test failure')
    finally:
        path.write_text(original)
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results))
