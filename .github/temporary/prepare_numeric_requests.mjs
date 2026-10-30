import { cases, seed } from './numeric_corpus.mjs';
import { writeFileSync } from 'node:fs';
const names = new Set(['minimum-array', 'minimum-variadic', 'maximum-array', 'maximum-variadic', 'sum-array', 'negate-int']);
const selected = cases({project:'fireemu-oracle-query', database:'entpipe1'}).filter(item => names.has(item.id));
if (selected.length !== 6 || new Set(selected.map(item => item.id)).size !== 6) throw new Error('missing exact numeric forms');
const programs = [{id:'fs-ent-pipeline/numeric-positive-local',seed:seed.map(({path,fields})=>[path,fields]),steps:selected.map(({id,request})=>({id,rpc:'executePipeline',body:{structuredPipeline:request.structuredPipeline}}))}];
for (const name of ['minimum', 'maximum', 'sum', 'negate']) {
  const body = structuredClone(selected[0].request.structuredPipeline);
  body.pipeline.stages[1].args[0].mapValue.fields.value.functionValue = {name, args: []};
  programs[0].steps.push({id: `zero-${name}`, rpc:'executePipeline', body:{structuredPipeline:body}});
}
writeFileSync('/tmp/numeric-request-programs.json', JSON.stringify(programs));
