import json
import pathlib
import subprocess
import sys

root = pathlib.Path.cwd()
out = pathlib.Path('/tmp/fs-r21-mutants')
out.mkdir(exist_ok=False)
adapter = root / 'crates/fireemu-adapter-grpc/src/pipeline.rs'
core = root / 'crates/fireemu-core-firestore/src/pipeline_exec.rs'
original = {p: p.read_text() for p in (adapter, core)}
expr = 'test(recorded_sort_and_accumulator_unknown_candidates) | test(nested_sum_uses_actual_row_type) | test(nested_sum_long_requires_admission) | test(admitted_nested_sum_evaluates_child_once) | test(nested_sum_admission_requires_recorded_shape_and_strict_profile) | test(generated_refusal_partition_table)'
command = ['cargo', 'nextest', 'run', '--manifest-path', 'Cargo.toml', '--locked', '--profile', 'pr', '-p', 'fireemu-core-firestore', '-p', 'fireemu-adapter-grpc', '-E', expr]
cases = [
    ('noop', None, None, None, 0),
    ('sort-name', adapter, 'if function.name == "nope"\n', 'if function.name == "never"\n', 100),
    ('accumulator-name', adapter, 'if function.name == "nope" && function.args.len()', 'if function.name == "never" && function.args.len()', 100),
    ('optin-disabled', core, 'if recorded_nested_sum_wrong_type\n', 'if false && recorded_nested_sum_wrong_type\n', 100),
    ('optin-always', core, 'if recorded_nested_sum_wrong_type\n', 'if true\n', 100),
    ('wrong-input-type', core, 'matches!(arg, Eval::Value(Value::Integer(_)))', 'matches!(arg, Eval::Value(Value::Double(_)))', 100),
    ('child-evaluated-twice', core, 'let arg = args[0].eval_at(row, unrecorded, false, runtime);', 'let _ = args[0].eval_at(row, unrecorded, false, runtime);\n                let arg = args[0].eval_at(row, unrecorded, false, runtime);', 100),
]
results = []
try:
    for name, path, old, new, expected in cases:
        if path:
            assert original[path].count(old) == 1, name
            path.write_text(original[path].replace(old, new, 1))
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / f'{name}.log').write_text(result.stdout)
        semantic = expected == 0 or (' FAIL ' in result.stdout and 'test run failed' in result.stdout)
        results.append({'name': name, 'returncode': result.returncode, 'expected': expected, 'semantic_failure': semantic})
        (out / 'results.json').write_text(json.dumps(results, indent=2))
        if path:
            path.write_text(original[path])
        if result.returncode != expected or not semantic:
            sys.exit(1)
finally:
    for path, contents in original.items():
        path.write_text(contents)
