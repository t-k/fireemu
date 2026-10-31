import json
from pathlib import Path
raw=json.loads(Path('conformance/fs-ent-pipeline-requests.json').read_text())
selection={'fs-ent-pipeline/o5/function-names':{'fn-bit_not','fn-bit_left_shift','fn-bit_right_shift','fn-document_matches','fn-matches','fn-geo_distance','fn-score'},'fs-ent-pipeline/o5/value-shapes':{'document-id-with-options'},'fs-ent-pipeline/o5/appendix':{'proposed-n14-docid-where-then-empty','proposed-n15-docid-add-then-empty','proposed-n78-docid-double-then-limit','proposed-reference-empty-segment','original-m4242-00731'}}
programs=[]
for original in raw['programs']:
 if original['id'] not in selection: continue
 steps=[s for s in original['steps'] if s['id'] in selection[original['id']]]
 programs.append({**original,'steps':steps+[{**s,'id':s['id']+'-grpc','transport':'grpc'} for s in steps]})
assert sum(len(p['steps']) for p in programs)==26
native_steps=[]
for round_number in [1,2]:
 for name,values in [('bit_not',[5]),('bit_left_shift',[5,1]),('bit_right_shift',[8,1]),('geo_distance',None)]:
  args=[{'geoPointValue':{}},{'geoPointValue':{'longitude':1}}] if values is None else [{'integerValue':str(v)} for v in values]
  body={'structuredPipeline':{'pipeline':{'stages':[{'name':'collection','args':[{'referenceValue':'/positive'}]},{'name':'select','args':[{'mapValue':{'fields':{'value':{'functionValue':{'name':name,'args':args}}}}}]}]}}}
  native_steps.append({'id':f'{name}-round-{round_number}','transport':'grpc','rpc':'executePipeline','body':body})
programs.append({'id':'fs-ent-pipeline/native-negative-replay','seed':[['positive/d1',{'n':{'integerValue':'1'}}]],'steps':native_steps})
Path('/tmp/o5-unknown-programs.json').write_text(json.dumps(programs))
