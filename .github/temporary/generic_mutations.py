import json
from pathlib import Path
import subprocess

adapter='crates/fireemu-adapter-grpc/src/pipeline.rs'
core='crates/fireemu-core-firestore/src/pipeline_exec.rs'
cases=[
 ('autogen_runtime',adapter,'\n                        | "autogen_document_id"','', 'autogen_document_id_uses_request_runtime'),
 ('coalesce_lazy',adapter,'\n                                    | "coalesce"','', 'coalesce_skips_failing_constant_but_validates_static_errors'),
 ('coalesce_registration',core,'array_access_function("coalesce",','array_access_function("mutated_coalesce",','coalesce_skips_failing_constant_but_validates_static_errors'),
]
out=Path('/tmp/generic-mutants');out.mkdir(exist_ok=True);results=[]
for name,file,old,new,test in cases:
    path=Path(file);original=path.read_text()
    if original.count(old)!=1: raise RuntimeError(f'{name}: anchor {original.count(old)}')
    cmd=['cargo','nextest','run','--profile','pr','--locked','-p','fireemu-adapter-grpc','-E',f'test({test})']
    try:
        noop=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900)
        (out/f'{name}-noop.log').write_text(noop.stdout)
        if noop.returncode: raise RuntimeError(f'{name}: noop failed')
        path.write_text(original.replace(old,new,1))
        mutant=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=900)
        (out/f'{name}-mutant.log').write_text(mutant.stdout)
        killed=mutant.returncode!=0 and 'FAIL [' in mutant.stdout and test in mutant.stdout
        results.append({'name':name,'noop':noop.returncode,'mutant':mutant.returncode,'killed':killed})
        if not killed: raise RuntimeError(f'{name}: no target test failure')
    finally:
        path.write_text(original)
        (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results))
