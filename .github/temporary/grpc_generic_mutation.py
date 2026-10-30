import json, pathlib, subprocess
path = pathlib.Path('crates/fireemu-adapter-grpc/src/pipeline_shape.rs')
original = path.read_text()
old = '    request.pipeline_type.as_ref()?;'
new = '    if request.pipeline_type.is_some() { return None; }\n    request.pipeline_type.as_ref()?;'
if original.count(old) != 1: raise RuntimeError('anchor must match once')
out = pathlib.Path('/tmp/grpc-generic-mutant'); out.mkdir(exist_ok=True)
cmd = ['cargo', 'nextest', 'run', '--profile', 'pr', '--locked', '-p', 'fireemu-adapter-grpc', '-E', 'test(recorded_literal_refusal_gate_matrix)']
result = {}
try:
    noop = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    (out / 'noop.log').write_text(noop.stdout); result['noop'] = noop.returncode
    if noop.returncode != 0: raise RuntimeError('noop failed')
    path.write_text(original.replace(old, new, 1))
    mutant = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    (out / 'mutant.log').write_text(mutant.stdout); result['mutant'] = mutant.returncode
    result['killed'] = mutant.returncode != 0 and 'FAIL [' in mutant.stdout and 'recorded_literal_refusal_gate_matrix' in mutant.stdout
    if not result['killed']: raise RuntimeError('expected test did not kill mutant')
finally:
    path.write_text(original)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
