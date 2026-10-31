import json
from pathlib import Path
import subprocess
adapter='crates/fireemu-adapter-grpc/src/pipeline.rs'
gate='crates/fireemu-adapter-grpc/src/pipeline_shape.rs'
cases=[
 ('unknown_candidate',adapter,"The function '{name}' does not exist.\"","The function '{name}' is absent.\"",'recorded_unknown_function_refusals_follow_shape_gate'),
 ('case_suggestion',adapter,'if titlecase && pipeline_exec::function(&lowercase).is_some() {','if false && titlecase && pipeline_exec::function(&lowercase).is_some() {','unknown_function_candidates_preserve_unrecorded_and_emulator_boundaries'),
 ('stage_precedence',adapter,'if position == 2\n            && pipeline.stages[position].name == "aggregate"','if position == usize::MAX\n            && pipeline.stages[position].name == "aggregate"','unknown_add_fields_precedes_later_stage_arity_on_both_transports'),
 ('deferred_candidate',adapter,'Some(text) => crate::pipeline_shape::retain_unknown_candidate(error, &text),','Some(_) => error,','recorded_unknown_after_empty_select_matches_both_profiles'),
 ('ordinary_admission',gate,'Self::Recorded(shape, database) | Self::Ordinary(shape, database) => {\n                    Self::Recorded(shape.clone(), database.clone()).answer(computed)\n                }','Self::Recorded(shape, database) => {\n                    Self::Recorded(shape.clone(), database.clone()).answer(computed)\n                }\n                Self::Ordinary(_, _) => Status::unimplemented("mutated"),','recorded_unknown_refusals_match_both_profiles_and_transports'),
 ('fallback_status',gate,'Self::Open | Self::Ordinary(_, _) => fallback,','Self::Open | Self::Ordinary(_, _) => Status::unimplemented("mutated"),','unknown_candidate_gate_preserves_exact_fallback_status'),
 ('candidate_pb_depth',adapter,'if depth > MAX_DEPTH {','if false && depth > MAX_DEPTH {','candidate_shape_eligibility_bounds_nested_function_options'),
 ('candidate_json_depth',gate,'if depth > MAX_DEPTH {','if false && depth > MAX_DEPTH {','candidate_json_eligibility_bounds_depth_and_width'),
]
out=Path('/tmp/o5-unknown-dual-mutants');out.mkdir(exist_ok=True);results=[]
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
