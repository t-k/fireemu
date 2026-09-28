import assert from 'node:assert/strict';
import test from 'node:test';
import { collectFunctions, exportNamespace, DISCOVERY_LIMITS, DiscoveryError } from './discovery.mjs';

function fn() { const value = () => {}; value.__endpoint = { platform: 'gcfv2', scheduleTrigger: {} }; return value; }
function names(result) { return [...result.functions.keys()]; }
function bad(error) { return { enumerable: true, get() { throw error; } }; }

for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
  test(`own export ${key} is not inherited or lost during namespace merge`, () => {
    const value = fn();
    for (const module of [{ [key]: value }, { default: { [key]: value } }]) {
      const merged = exportNamespace(module);
      assert.equal(Object.getPrototypeOf(merged), null);
      assert.equal(merged[key], value);
      assert.deepEqual(names(collectFunctions(merged)), [key]);
    }
    assert.equal(Object.prototype.polluted, undefined);
  });
}

test('CommonJS order/precedence, named fallbacks and interop alias omission are retained', () => {
  const primary = { z: fn(), a: fn(), default: fn(), ['module.exports']: fn() };
  const module = { a: fn(), other: fn(), default: primary, ['module.exports']: primary };
  const merged = exportNamespace(module);
  assert.deepEqual(Object.keys(merged), ['z', 'a', 'other']);
  assert.equal(merged.a, primary.a);
  assert.deepEqual(names(collectFunctions(merged)), ['z', 'a', 'other']);
});

test('root getters are lazy, use their original receiver and are read once per export path', () => {
  let calls = 0;
  const value = fn();
  const primary = Object.defineProperty({}, 'alias', { enumerable: true, get() { assert.equal(this, primary); calls++; return value; } });
  const merged = exportNamespace({ default: primary, alias: fn() });
  assert.equal(calls, 0);
  assert.deepEqual(names(collectFunctions(merged)), ['alias']);
  assert.equal(calls, 1);
});

test('throwing CommonJS root getter is not retried through the named fallback', () => {
  let reads = 0; const primary = Object.defineProperty({}, 'broken', { enumerable:true, get() { reads++; throw new Error('fixture'); } });
  const result = collectFunctions(exportNamespace({ default: primary, broken: fn(), healthy: fn() }));
  assert.equal(reads, 1); assert.deepEqual(names(result), ['healthy']);
  assert.match(result.broken.get('broken'), /fixture/);
});

for (const shape of ['self', 'mutual', 'root', 'normalized-root']) {
  test(`cycle ${shape} is reported without hiding healthy peers or recursing`, () => {
    let root = { healthy: fn() };
    if (shape === 'self') { const group = { leaf: fn() }; group.self = group; root.group = group; }
    if (shape === 'mutual') { const a = {leaf:fn()}, b = {back:a}; a.next=b; root.group=a; }
    if (shape === 'root' || shape === 'normalized-root') root.self = root;
    if (shape === 'normalized-root') root=exportNamespace({default:root});
    const result=collectFunctions(root);
    assert.ok(result.functions.has('healthy'));
    assert.equal(result.broken.size, 1);
    assert.match([...result.broken.values()][0], /cyclic export group/);
    assert.equal(result.functions.has('self-healthy'), false);
  });
}

test('shared acyclic groups are exported at every distinct alias, not globally deduplicated', () => {
  const shared={leaf:fn()}; const result=collectFunctions({left:shared, right:shared});
  assert.deepEqual(names(result),['left-leaf','right-leaf']); assert.equal(result.broken.size,0);
});

for (const kind of ['getter', 'endpoint', 'trigger', 'ownKeys', 'revoked', 'describe-error-shape']) {
  test(`isolates ${kind} inspection failures, even with unformattable thrown values`, () => {
    const thrown = Object.defineProperties({}, {message:{get(){throw null;}},stack:{get(){throw null;}},toString:{value(){throw null;}}});
    const group = { before:fn() };
    if(kind==='getter') Object.defineProperty(group,'broken',bad(thrown));
    if(kind==='endpoint'||kind==='trigger') { const value=()=>{}; Object.defineProperty(value,kind==='endpoint'?'__endpoint':'__trigger',bad(thrown)); group.broken=value; }
    if(kind==='ownKeys') group.broken=new Proxy({}, {ownKeys(){throw thrown;}});
    if(kind==='revoked') { const proxy=Proxy.revocable({},{}); proxy.revoke(); group.broken=proxy.proxy; }
    if(kind==='describe-error-shape') { const proxy=Proxy.revocable({},{});proxy.revoke();group.broken=new Proxy({}, {ownKeys(){throw proxy.proxy;}}); }
    group.after=fn(); const result=collectFunctions(group);
    assert.deepEqual(names(result),['before','after']); assert.equal(result.broken.size,1);
    assert.match(result.broken.get('broken'),/export could not be read/);
  });
}

for(const reversed of [false,true]) {
  test(`flat names colliding with nested names have no winner (reversed=${reversed})`,()=>{
    const nested={api:{user:fn()}}; const flat={'api-user':fn()};
    const result=collectFunctions(reversed?{...flat,...nested,healthy:fn()}:{...nested,...flat,healthy:fn()});
    assert.deepEqual(names(result),['healthy']); assert.equal(result.broken.size,1);
    assert.match(result.broken.get('api-user'),/ambiguous/);
  });
  test(`a broken export colliding with a valid one cannot leave an executable winner (${reversed})`,()=>{
    const nested={api:Object.defineProperty({},'user',bad(null))}; const flat={'api-user':fn()};
    const result=collectFunctions(reversed?{...flat,...nested}:{...nested,...flat});
    assert.equal(result.functions.size,0); assert.equal(result.broken.size,1);
    assert.match(result.broken.get('api-user'),/ambiguous/);
  });
}

test('three ambiguous origins, including the same callback identity, never resurrect a winner',()=>{
  const f=fn(); const result=collectFunctions({'a-b-c':f,a:{'b-c':f},'a-b':{c:f}});
  assert.equal(result.functions.size,0); assert.equal(result.broken.size,1);
});

test('nonenumerable, inherited, symbol, array, utility and scalar exports remain non-functions',()=>{
  const root=Object.create({inherited:fn()});Object.defineProperty(root,'hidden',{value:fn()});
  Object.assign(root,{good:fn(),nil:null,off:false,number:1,text:'x',list:[fn()],utility:()=>{}});root[Symbol('ignored')]=fn();
  assert.deepEqual(names(collectFunctions(root)),['good']);
});

test('traversal limit counts graph paths, stopping exponential alias expansion',()=>{
  let group={leaf:fn()};for(let i=0;i<15;i++)group={left:group,right:group};
  assert.throws(()=>collectFunctions(group), e=> e instanceof DiscoveryError && /entry limit/.test(e.message));
});

test('depth boundary is inclusive and overflow is explicit, not a partial inventory',()=>{
  for(const [depth,pass] of [[DISCOVERY_LIMITS.maxDepth,true],[DISCOVERY_LIMITS.maxDepth+1,false]]){
    let root={leaf:fn()};for(let i=0;i<depth;i++)root={g:root};
    if(pass)assert.equal(collectFunctions(root).functions.size,1);
    else assert.throws(()=>collectFunctions({healthy:fn(),...root}),/depth limit/);
  }
});

test('name byte limit counts UTF-8 bytes rather than UTF-16 code units',()=>{
  assert.equal(collectFunctions({['x'.repeat(DISCOVERY_LIMITS.maxNameBytes)]:fn()}).functions.size,1);
  assert.throws(()=>collectFunctions({['x'.repeat(DISCOVERY_LIMITS.maxNameBytes+1)]:fn()}),/name limit/);
  assert.throws(()=>collectFunctions({['語'.repeat(Math.floor(DISCOVERY_LIMITS.maxNameBytes/3)+1)]:fn()}),/name limit/);
});

test('entry limit rejects large namespaces in both merge and traversal',()=>{
  const root=Object.fromEntries(Array.from({length:DISCOVERY_LIMITS.maxEntries},(_,i)=>['f'+i,fn()]));
  assert.equal(collectFunctions(root).functions.size,DISCOVERY_LIMITS.maxEntries);
  root.extra=fn();assert.throws(()=>collectFunctions(root),/entry limit/);
  assert.throws(()=>exportNamespace({default:root}),/entry limit/);
});

for (const normalized of [false, true]) {
  for (const mutation of ['delete', 'hide']) {
    test(`stale enumerated keys never resolve an inherited/nonenumerable callback (${normalized}, ${mutation})`, () => {
      const wrong=fn(), correct=fn();
      const root=Object.create({later:wrong});
      Object.defineProperty(root,'first',{enumerable:true,get(){
        if(mutation==='delete') delete root.later;
        else Object.defineProperty(root,'later',{enumerable:false});
        return correct;
      }});
      Object.defineProperty(root,'later',{value:wrong,configurable:true,enumerable:true});
      const result=collectFunctions(normalized?exportNamespace({default:root,later:wrong}):root);
      assert.deepEqual(names(result),['first']);assert.equal(result.functions.get('first'),correct);
      assert.equal(result.broken.size,0);
    });
  }
}

test('a descriptor trap that starts failing on one key is isolated after enumeration',()=>{
  let calls=0;
  const proxy=new Proxy({bad:fn(),good:fn()},{getOwnPropertyDescriptor(target,key){
    if(key==='bad' && ++calls>1)throw new Error('descriptor failure');
    return Reflect.getOwnPropertyDescriptor(target,key);
  }});
  const result=collectFunctions(proxy);
  assert.deepEqual(names(result),['good']);assert.match(result.broken.get('bad'),/descriptor failure/);
});
