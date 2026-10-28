import test from 'node:test';
import assert from 'node:assert/strict';
import { serverValueRequest } from './orchestrator.mjs';
import { serverValueCases } from './server-values.mjs';
const prefix = 'rnext1_0123456789abcdef01234567', base = 'https://demo-instance.firebaseio.com';
test('only exact scoped seed, read, and typed server-value requests are admitted', () => {
 for (const round of ['r1','r2']) for (const item of serverValueCases()) {
  const path = `/${prefix}/${round}/${item.id}.json`;
  for (const req of [{step:'sv-seed',method:'PUT',path,body:JSON.stringify(item.seed),phase:'normal'}, {step:'sv-before',method:'GET',path,phase:'normal'}, {step:'sv-write',method:item.method,path,body:JSON.stringify(item.body),phase:'normal'}, {step:'sv-after',method:'GET',path,phase:'normal'}]) assert.equal(serverValueRequest(base,prefix,req).url,`${base}${path}`);
  assert.throws(() => serverValueRequest(base,prefix,{step:'sv-write',method:item.method,path,body:'{}',phase:'normal'}));
 }
 assert.throws(() => serverValueRequest(base,prefix,{step:'sv-before',method:'GET',path:`/${prefix}/r1/timestamp-single.json?x=1`,phase:'normal'}));
 assert.throws(() => serverValueRequest('https://example.invalid',prefix,{step:'sv-before',method:'GET',path:`/${prefix}/r1/timestamp-single.json`,phase:'normal'}));
});
