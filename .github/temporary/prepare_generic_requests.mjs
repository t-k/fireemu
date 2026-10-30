import { cases, seed } from './generic_corpus.mjs';
import { writeFileSync } from 'node:fs';
const names = new Set(['cmp-int','storage-size-string','coalesce-null-string','namespace-reference','has-ancestor-reference','reference-slice','autogen-document-id','replace-document-id','get-field-map','offset-array','reverse-string','reverse-bytes','reverse-array','length-string','length-bytes','length-array','length-map','length-vector','string-concat']);
const selected = cases({project:'fireemu-oracle-query', database:'entpipe1'}).filter(item => names.has(item.id));
if (selected.length !== 19 || new Set(selected.map(item => item.id)).size !== 19) throw new Error('missing captured forms');
const programs = [{id:'fs-ent-pipeline/generic-positive-local',seed:seed.map(({path,fields})=>[path,fields]),steps:selected.map(({id,request})=>({id,rpc:'executePipeline',body:{structuredPipeline:request.structuredPipeline}}))}];
writeFileSync('/tmp/generic-request-programs.json', JSON.stringify(programs));
