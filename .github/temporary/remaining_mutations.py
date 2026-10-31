import json
from pathlib import Path
import subprocess
adapter='crates/fireemu-adapter-grpc/src/pipeline.rs'
service='crates/fireemu-adapter-grpc/src/service.rs'
rest='crates/fireemu-adapter-grpc/src/rest/mod.rs'
core='crates/fireemu-core-firestore/src/pipeline_exec.rs'
cases=[
 ('docid_stage',adapter,'position == 1 && pipeline.stages.len() == 2','true','document_id_unrecorded_option_shapes_remain_closed'),
 ('docid_alias',adapter,'recorded_docid_options && entries.len() == 1','recorded_docid_options && true','document_id_unrecorded_option_shapes_remain_closed'),
 ('docid_type',adapter,'recorded_options && is_recorded_docid_options(value)','recorded_options && true','document_id_unrecorded_option_shapes_remain_closed'),
 ('later_refusal',adapter,'.or(later)','.or(None)','recorded_docid_order_matches_original_rest'),
 ('geo_range',service,'Some(V::GeoPointValue(point)) if (-90.0..=90.0).contains(&point.latitude)\n                && (-180.0..=180.0).contains(&point.longitude)','Some(V::GeoPointValue(_))','recorded_geo_shape_rejects_invalid_coordinates'),
 ('geo_profile',service,'} else if self.gateway.production_refusals()\n                            && recorded_geo_select(request.get_ref(), &error)','} else if recorded_geo_select(request.get_ref(), &error)','recorded_geo_select_grpc_refusal_is_search_only_in_strict'),
 ('ordered_optin',rest,'if recorded_select_first {','if false && recorded_select_first {','recorded_error_info_matches_original_rest'),
 ('ordered_default',core,'recorded_select_first_wrong_type: false,','recorded_select_first_wrong_type: true,','ordered_select_first_refusal_is_default_off_and_type_bounded'),
 ('reference_offset','crates/fireemu-adapter-grpc/tests/pipeline_replay.rs','Some(resource[..=empty].encode_utf16().count())','Some(resource[..empty + 2].encode_utf16().count())','reference_environment_comparison_checks_both_offsets_and_suffix'),
 ('ordered_type',core,'function: "collection_id",\n                                            expected: "Reference",\n                                            got: "STRING"','function: "collection_id",\n                                            expected: _,\n                                            got: _','ordered_select_first_refusal_is_default_off_and_type_bounded'),
]
out=Path('/tmp/o5-remaining-mutants');out.mkdir(exist_ok=True);results=[]
for name,file,old,new,test in cases:
 path=Path(file);original=path.read_text()
 if original.count(old)!=1:raise RuntimeError(f'{name}: anchor {original.count(old)}')
 package = 'fireemu-core-firestore' if test == 'ordered_select_first_refusal_is_default_off_and_type_bounded' else 'fireemu-adapter-grpc'
 cmd=['cargo','nextest','run','--profile','pr','--locked','-p',package,'-E',f'test({test})']
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
