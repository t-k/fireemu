import json
from pathlib import Path
import subprocess
core='crates/fireemu-core-firestore/src/pipeline_exec.rs'
adapter='crates/fireemu-adapter-grpc/src/pipeline_shape.rs'
cases=[
 ('signature_metadata',core,'"get_field(map: map[string, any], key: string): any?"','""','recorded_registered_function_arities_match_both_transports'),
 ('unbounded_overload',core,'if *high == usize::MAX {','if *high == 0 {','recorded_registered_function_arities_match_both_transports'),
 ('variadic_signature',core,'"coalesce(x: any?*): any?"','""','recorded_registered_function_arities_match_both_transports'),
 ('unrecorded_gate',adapter,'if error.code() != tonic::Code::InvalidArgument {','if error.code() == tonic::Code::InvalidArgument {','registered_function_arity_unrecorded_shapes_remain_refused'),
]
out=Path('/tmp/o5-arity-mutants');out.mkdir(exist_ok=True);results=[]
for name,file,old,new,test in cases:
 path=Path(file);original=path.read_text()
 if original.count(old)!=1:raise RuntimeError(f'{name}: anchor {original.count(old)}')
 cmd=['cargo','nextest','run','--profile','pr','--locked','-p','fireemu-adapter-grpc','-E',f'test({test})']
 try:
  noop=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900);(out/f'{name}-noop.log').write_text(noop.stdout)
  if noop.returncode:raise RuntimeError(f'{name}: noop failed')
  path.write_text(original.replace(old,new,1))
  mutant=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900);(out/f'{name}-mutant.log').write_text(mutant.stdout)
  killed=mutant.returncode!=0 and 'FAIL [' in mutant.stdout and test in mutant.stdout
  results.append({'name':name,'noop':noop.returncode,'mutant':mutant.returncode,'killed':killed})
  if not killed:raise RuntimeError(f'{name}: no target failure')
 finally:
  path.write_text(original);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results))
