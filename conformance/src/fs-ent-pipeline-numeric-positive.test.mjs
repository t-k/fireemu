import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { numericPositiveRecipes } from './fs-ent-pipeline/numeric-positive-corpus.mjs';

const require=createRequire(import.meta.url);

test('27 fixed recipes cover every generated function/arity/partition without writes',()=>{
  const recipes=numericPositiveRecipes();
  const table=readFileSync(new URL('./fs-ent-pipeline/fixtures/numeric-positive-pict.tsv',import.meta.url),'utf8').trim().split('\n').slice(1).map(x=>x.split('\t'));
  assert.equal(recipes.length,27);assert.equal(new Set(recipes.map(x=>x.id)).size,27);assert.equal(table.length,27);
  for(const [name,arity,partition] of table) {
    const matching=recipes.filter(x=>x.name===name && x.arity===arity && x.partition===partition);assert.equal(matching.length,1);
    const recipe=matching[0];assert.equal(recipe.step.rpc,'executePipeline');assert.equal(recipe.step.transport,'grpc');
    const stages=recipe.step.body.structuredPipeline.pipeline.stages;assert.equal(stages.length,2);assert.equal(stages[0].name,'documents');assert.equal(stages[0].args[0].referenceValue,'/numeric-probe/d1');assert.equal(stages[1].name,'select');
    const expr=stages[1].args[0].mapValue.fields.v.functionValue;assert.equal(expr.name,name);assert.equal(expr.args.length,arity==='one'?1:2);assert.deepEqual(Object.keys(stages[1].args[0].mapValue.fields),['v']);
  }
});

test('each fixed expression uses SDK 8.7.1 protobuf value schema and exact argument order',()=>{
  const sdk=require('@google-cloud/firestore');const packagePath=require.resolve('@google-cloud/firestore');
  const expressions=require(join(dirname(packagePath),'pipelines/expression.js'));
  const db=new sdk.Firestore({projectId:'demo-local'});
  const normalize=x=>Array.isArray(x)?x.map(normalize):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,k==='integerValue'?String(v):normalize(v)])):x;
  for(const recipe of numericPositiveRecipes()) {
    const sdkExpression=new expressions.FunctionExpression(recipe.name,recipe.args.map(x=>expressions.constant(x)));
    const sdkProto=normalize(sdkExpression._toProto(db._serializer));
    const actual=recipe.step.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.v;
    assert.deepEqual(actual,sdkProto,recipe.id);
  }
});

test('sensitive arities, numeric values and JSON scalar types are fixed',()=>{
  const recipes=numericPositiveRecipes(),byId=id=>recipes.find(x=>x.id===id);
  assert.deepEqual(byId('log-positive-two').args,[100,10]);assert.deepEqual(byId('log-positive-one').args,[1]);
  assert.deepEqual(byId('trunc-positive-one').args,[-15.5]);assert.deepEqual(byId('trunc-positive-two').args,[15.48924,2]);
  assert.deepEqual(byId('sqrt-domain-one').args,[-1]);assert.deepEqual(byId('ln-null-one').args,[null]);
  assert.deepEqual(byId('log10-wrong-one').args,['not-a-number']);
  assert.equal(numericPositiveRecipes().some(x=>x.step.rpc==='commit'),false);
});

test('all 27 complete gRPC requests encode and decode with typed oneof arguments',()=>{
  const sdk=require('@google-cloud/firestore');const client=new sdk.v1.FirestoreClient({projectId:'demo-local'});
  const type=client._protos.google.firestore.v1.ExecutePipelineRequest;
  for(const recipe of numericPositiveRecipes()) {
    const request={database:'projects/demo-local/databases/demo-db',...recipe.step.body};
    const bytes=type.serialize(request),decoded=type.deserialize(bytes);
    assert.deepEqual(type.serialize(decoded),bytes,recipe.id);
    const fn=decoded.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.v.functionValue;
    assert.equal(fn.name,recipe.name);assert.equal(fn.args.length,recipe.args.length);
    for(let i=0;i<recipe.args.length;i++) {
      const x=recipe.args[i],expected=x===null?'nullValue':typeof x==='string'?'stringValue':Number.isInteger(x)?'integerValue':'doubleValue';
      assert.equal(fn.args[i].valueType,expected,recipe.id);
    }
  }
});

test('each documented domain boundary and wrong-type case uses a discriminating operand',()=>{
  const recipes=numericPositiveRecipes(),byId=id=>recipes.find(x=>x.id===id);
  for(const [id,args] of [['ln-domain-one',[0]],['log-domain-two',[10,1]],['log10-domain-one',[0]],['sqrt-domain-one',[-1]]])assert.deepEqual(byId(id).args,args,id);
  for(const name of ['exp','ln','log','log10','trunc','sqrt']) {
    assert.deepEqual(byId(`${name}-null-one`).args,[null]);
    assert.deepEqual(byId(`${name}-wrong-one`).args,['not-a-number']);
  }
});

test('positive witnesses use the chosen finite documented inputs',()=>{
  const recipes=numericPositiveRecipes(),byId=id=>recipes.find(x=>x.id===id);
  for(const [id,args] of [['exp-positive-one',[0]],['ln-positive-one',[1]],['log-positive-one',[1]],['log-positive-two',[100,10]],['log10-positive-one',[100]],['trunc-positive-one',[-15.5]],['trunc-positive-two',[15.48924,2]],['sqrt-positive-one',[25]]])assert.deepEqual(byId(id).args,args,id);
});

test('trunc delta appends three cases while original 24 JSON and wire bytes stay exact',()=>{
  const {createHash}=require('node:crypto'),sdk=require('@google-cloud/firestore'),type=new sdk.v1.FirestoreClient({projectId:'demo-local'})._protos.google.firestore.v1.ExecutePipelineRequest;
  const recipes=numericPositiveRecipes();assert.equal(recipes.length,27);
  assert.equal(createHash('sha256').update(JSON.stringify(recipes.slice(0,24))).digest('hex'),'4d1a90996d68ceae6ab9f22ea31fb48333fe6945c3ce95bda1030368c7956bf9');
  const h=createHash('sha256');for(const r of recipes.slice(0,24)){const bytes=type.serialize({database:'projects/demo-local/databases/demo-db',...r.step.body}),n=Buffer.alloc(4);n.writeUInt32BE(bytes.length);h.update(n);h.update(bytes);}assert.equal(h.digest('hex'),'98c2fc914c6198c68c0c4670d399ff937fca5b8ae725bafc2f9b099fce8bdc85');
  assert.deepEqual(recipes.slice(24).map(x=>x.id),['trunc_029_p2','trunc_115_p2','trunc_min_subnormal_p309']);
  const expected=[[0.29,2],[1.15,2],[Number.MIN_VALUE,309]];
  for(let i=0;i<3;i++){
    const r=recipes[24+i];assert.deepEqual(r.args,expected[i]);const bytes=type.serialize({database:'projects/demo-local/databases/demo-db',...r.step.body}),decoded=type.deserialize(bytes);assert.deepEqual(type.serialize(decoded),bytes);
    const args=decoded.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.v.functionValue.args;assert.equal(args[0].valueType,'doubleValue');assert.equal(args[1].valueType,'integerValue');assert.equal(String(args[1].integerValue),String(expected[i][1]));
    if(i===2){const bits=Buffer.alloc(8);bits.writeDoubleLE(args[0].doubleValue);assert.equal(bits.readBigUInt64LE(),1n);assert.equal(args[0].doubleValue,Number.MIN_VALUE);}
  }
});
