import { PROGRAMS } from '../conformance/src/fs-ent-pipeline/corpus.mjs';
import { writeFileSync } from 'node:fs';
const ids = new Set(['fs-ent-pipeline/o4/stages','fs-ent-pipeline/o5/function-order','fs-ent-pipeline/o5/stage-order','fs-ent-pipeline/o5/value-shapes','fs-ent-pipeline/o5/function-names','fs-ent-pipeline/o5/appendix','fs-ent-pipeline/o6/sort-wire-errors','fs-ent-pipeline/o7/aggregate-args']);
const selected = PROGRAMS.filter(p => ids.has(p.id));
if (selected.length !== ids.size) throw Error('missing selected program');
writeFileSync('/tmp/fs-strict-arity-programs.json', JSON.stringify(selected));
