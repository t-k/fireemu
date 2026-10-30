import json
import pathlib
import subprocess

path = pathlib.Path('crates/fireemu-adapter-grpc/src/pipeline.rs')
original = path.read_text()
old = '(direct && recorded_direct) || walk(value)'
new = 'recorded_direct || walk(value)'
if original.count(old) != 1:
    raise RuntimeError('mutation anchor must match exactly once')
output = pathlib.Path('/tmp/nested-infinity-mutant')
output.mkdir(exist_ok=True)
cmd = ['cargo', 'nextest', 'run', '--profile', 'pr', '--locked', '-p', 'fireemu-adapter-grpc', '-E', 'test(infinity_vector_admission_depends_on_expression_position)']
result = {}
try:
    noop = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    (output / 'noop.log').write_text(noop.stdout)
    result['noop'] = noop.returncode
    if noop.returncode != 0:
        raise RuntimeError('unmodified control failed')
    path.write_text(original.replace(old, new, 1))
    mutant = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    (output / 'mutant.log').write_text(mutant.stdout)
    result['mutant'] = mutant.returncode
    result['killed'] = mutant.returncode != 0 and 'FAIL [' in mutant.stdout and 'infinity_vector_admission_depends_on_expression_position' in mutant.stdout
    if not result['killed']:
        raise RuntimeError('mutant was not killed by the expected test')
finally:
    path.write_text(original)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
