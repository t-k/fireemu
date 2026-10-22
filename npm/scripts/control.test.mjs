import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createControlClient } from '../fireemu/control.mjs';

async function server(t, handler) {
  const instance = createServer(handler);
  t.after(async () => { instance.closeAllConnections(); await new Promise(resolve => instance.close(resolve)); });
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  return `http://127.0.0.1:${instance.address().port}`;
}

async function echo(t) {
  return server(t, async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({url:req.url,method:req.method,authorization:req.headers.authorization,contentType:req.headers['content-type'],body}));
  });
}

test('origin, API base and environment clients resolve identical authenticated requests', async t => {
  const origin = await echo(t);
  const env = {FIREEMU_CONTROL_URL:`${origin}/v1/`,FIREEMU_CONTROL_TOKEN:'test-capability'};
  const original = {...env};
  const clients = [
    createControlClient({origin,token:'test-capability'}),
    createControlClient({apiBaseUrl:`${origin}/v1/`,token:'test-capability'}),
    createControlClient({env}),
    createControlClient({env:{...env,FIREEMU_CONTROL_URL:origin}}),
  ];
  env.FIREEMU_CONTROL_URL = 'http://wrong.invalid/v1/';
  env.FIREEMU_CONTROL_TOKEN = 'wrong-token';
  for (const client of clients) {
    assert.equal(client.origin,origin);
    assert.equal(client.apiBaseUrl,`${origin}/v1/`);
    assert.equal(Object.isFrozen(client),true);
    for (const path of ['sessions/default:awaitIdle','/v1/sessions/default:awaitIdle']) {
      assert.deepEqual(await client.request('POST',path,{budget:3}),{url:'/v1/sessions/default:awaitIdle',method:'POST',authorization:`Bearer ${original.FIREEMU_CONTROL_TOKEN}`,contentType:'application/json',body:'{"budget":3}'});
    }
    const health = await client.request('GET','/health/ready');
    assert.equal(health.url,'/health/ready');
    assert.equal(health.body,'');
    assert.equal(health.contentType,undefined);
  }
});

test('generated encoded routes preserve path/query and have exactly one API base', async t => {
  const origin = await echo(t), client = createControlClient({origin,token:'test'});
  let seed = 0x12345678;
  for (let index=0; index<64; index++) {
    seed = (Math.imul(seed,1664525)+1013904223) >>> 0;
    const id = encodeURIComponent(`session ${seed}/日本語?%`);
    const route = `sessions/${id}?limit=${index}&label=a%2Fb`;
    const relative = await client.request('GET',route);
    const absolute = await client.request('GET',`/v1/${route}`);
    assert.equal(relative.url,`/v1/${route}`);
    assert.deepEqual(relative,absolute);
  }
});

test('external request targets cannot receive the capability', async t => {
  let received = 0;
  const origin = await server(t, (_req,res) => { received++; res.end('{}'); });
  const client = createControlClient({origin,token:'secret'});
  for (const path of [`${origin}/v1/sessions`,`//127.0.0.1:${new URL(origin).port}/v1/`,'\\\\other.invalid/v1/','/\\other.invalid/v1/','https://other.invalid/','\n//other.invalid/',' /v1/sessions']) {
    await assert.rejects(client.request('GET',path), /path/);
  }
  assert.equal(received,0);
});

test('redirects are refused without reaching the redirected endpoint', async t => {
  let received = 0;
  const sink = await server(t, (_req,res) => { received++; res.end('{}'); });
  const origin = await server(t, (_req,res) => { res.writeHead(307,{location:`${sink}/v1/`});res.end(); });
  await assert.rejects(createControlClient({origin,token:'secret'}).request('GET','sessions'));
  assert.equal(received,0);
});

test('HTTP errors preserve status and daemon diagnostics, including non-JSON failures', async t => {
  const origin = await server(t, (req,res) => {
    if(req.url.endsWith('/empty')){res.writeHead(204);res.end();return;}
    if(req.url.endsWith('/bad-json')){res.end('not JSON');return;}
    res.writeHead(403,{'content-type':'application/json'});
    res.end(req.url.endsWith('/text') ? 'denied' : JSON.stringify({error:{message:'capability refused'}}));
  });
  const client = createControlClient({origin,token:'wrong'});
  await assert.rejects(client.request('POST','sessions'), error => error.status===403 && /capability refused/.test(error.message));
  await assert.rejects(client.request('GET','text'), error => error.status===403 && /403/.test(error.message));
  await assert.rejects(client.request('GET','bad-json'), /JSON/);
  assert.equal(await client.request('DELETE','empty'),undefined);
});

test('timeout and caller cancellation abort requests', {timeout:3000}, async t => {
  const origin = await server(t, () => {});
  const client = createControlClient({origin,token:'test',requestTimeoutMs:25});
  await assert.rejects(client.request('GET','sessions'), {name:'TimeoutError'});
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client.request('GET','sessions',undefined,{signal:controller.signal}), {name:'AbortError'});
});

test('configuration names origin and API base explicitly and rejects ambiguous or unsafe values', () => {
  const origin = 'http://127.0.0.1:9999';
  for (const options of [
    {env:{}}, {origin}, {origin,token:''}, {origin,token:'bad\ntoken'},
    {origin,apiBaseUrl:`${origin}/v1/`,token:'test'},
    {origin:`${origin}/v1/`,token:'test'},
    ...['file:///tmp/','http://user:password@localhost/','http://localhost/?token=x','http://localhost/#x'].map(origin=>({origin,token:'test'})),
    {apiBaseUrl:`${origin}/wrong/`,token:'test'},
    ...[0,-1,1.5,NaN,Infinity].map(requestTimeoutMs=>({origin,token:'test',requestTimeoutMs})),
  ]) assert.throws(()=>createControlClient(options),TypeError);
  for(const value of ['http://[::1]:9099','https://localhost:9099/']) {
    const client = createControlClient({origin:value,token:'test'});
    assert.equal(client.origin,new URL(value).origin);
    assert.equal(client.apiBaseUrl,`${new URL(value).origin}/v1/`);
  }
});

test('the public package exports and publishes the shared client', async () => {
  const manifest = JSON.parse(await readFile(new URL('../fireemu/package.json',import.meta.url),'utf8'));
  assert.deepEqual(manifest.exports['./control'],{types:'./control.d.mts',default:'./control.mjs'});
  assert.ok(manifest.files.includes('control.mjs'));
  assert.ok(manifest.files.includes('control.d.mts'));
});


test('fireemu exec provides the unchanged base URL to the public control client', {skip:!process.env.FIREEMU_TEST_BINARY,timeout:30_000}, async t => {
  const cwd = await mkdtemp(join(tmpdir(),'fireemu-control-exec-'));
  t.after(()=>rm(cwd,{recursive:true,force:true}));
  await writeFile(join(cwd,'fireemu.json'),JSON.stringify({schemaVersion:1,profile:'strict'}));
  const module = new URL('../fireemu/control.mjs',import.meta.url).href;
  const script = `import {createControlClient} from ${JSON.stringify(module)};
    const client=createControlClient();
    if(client.apiBaseUrl!==process.env.FIREEMU_CONTROL_URL)throw Error('base changed');
    const a=await client.request('GET','sessions/default');
    const b=await client.request('GET','/v1/sessions/default');
    if(JSON.stringify(a)!==JSON.stringify(b))throw Error('routes differ');
    console.log('control-client-ok');`;
  const ports = ['firestore','http','storage','functions','eventarc','tasks','pubsub','hub','ui','logging'].flatMap(name=>[`--${name}-port`,'0']);
  const result = await promisify(execFile)(process.env.FIREEMU_TEST_BINARY,['exec','--config','fireemu.json','--project','demo-control-client','--only','auth',...ports,'--',process.execPath,'--input-type=module','-e',script],{cwd,timeout:25_000});
  assert.match(result.stdout,/control-client-ok/);
});
