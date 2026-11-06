// Real runner/discovery and framed IPC, with metadata models and a required cached SDK gate.
// These local checks do not stand in for production trigger routing or recordings.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const frame = value => {
  const data = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${data.length}\n`), data]);
};

async function start(t, sdkSource, profile) {
  const dir = await mkdtemp(join(tmpdir(), 'fireemu-event-resource-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ private: true, main: 'index.cjs' }));
  await writeFile(join(dir, 'index.cjs'), sdkSource);
  const prefix = sdkSource && process.env.FE_SOURCE_RUNNER_PREFIX
    ? JSON.parse(process.env.FE_SOURCE_RUNNER_PREFIX) : [process.execPath];
  const child = spawn(prefix[0], [...prefix.slice(1), runner, '--source', dir], {
    detached: process.platform !== 'win32',
    env: { PATH: process.env.PATH, GCLOUD_PROJECT: 'demo-app', ...(profile ? { FIREEMU_HTTP_PROFILE: profile } : {}), ...(sdkSource ? { NODE_PATH: join(sdkRoot, '..'), FE_SOURCE_RECEIPTS: process.env.FE_SOURCE_RECEIPTS } : {}) },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const frames = [];
  const identity = () => execFileSync('ps', ['-p', String(child.pid), '-o', 'pid=,comm=,lstart=,args='], { encoding: 'utf8' }).trim();
  const ownedIdentity = process.platform === 'win32' ? undefined : identity();
  let buffer = Buffer.alloc(0), stderr = '', outcome, parseError;
  child.stdin.on('error', () => {});
  const exited = once(child, 'exit').then(([code, signal]) => (outcome = { code, signal }));
  child.stderr.on('data', chunk => { if (stderr.length < 65536) stderr += chunk.toString(); });
  child.stdout.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    while (!parseError) {
      const at = buffer.indexOf(10);
      if (at < 0) break;
      const n = Number(buffer.subarray(0, at).toString());
      if (!Number.isSafeInteger(n) || n < 1 || n > 16 * 1024 * 1024) { parseError = Error('invalid output length'); break; }
      if (buffer.length < at + 1 + n) break;
      try { frames.push(JSON.parse(buffer.subarray(at + 1, at + 1 + n).toString('utf8'))); }
      catch { parseError = Error('invalid output JSON'); }
      buffer = buffer.subarray(at + 1 + n);
    }
  });
  async function wait(predicate) {
    const until = Date.now() + 5000;
    while (Date.now() < until) {
      if (parseError) throw parseError;
      const found = predicate();
      if (found) return found;
      if (outcome) throw Error(`runner exited ${JSON.stringify(outcome)}: ${stderr.slice(-500)}`);
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    throw Error('runner response timeout');
  }
  t.after(async () => {
    if (!outcome) {
      child.stdin.write(frame({ type: 'shutdown' }));
      await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 3000).unref())]);
    }
    if (!outcome) {
      // The still-live ChildProcess owns this isolated group; never signal a discovered PID.
      if (process.platform === 'win32') child.kill('SIGKILL');
      else {
        assert.equal(identity(), ownedIdentity, 'verify owned PID, command and start time before group cleanup');
        assert(ownedIdentity.includes(runner));
        process.kill(-child.pid, 'SIGKILL');
      }
    }
    await exited;
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await rm(dir, { recursive: true, force: true });
    assert.equal(outcome.code, 0, `runner shutdown failed: ${stderr.slice(-1000)}`);
  });
  const hello = await wait(() => frames.find(x => x.type === 'hello'));
  let sequence = 0;
  return {
    manifest: hello.manifest,
    async invoke(name, trigger, event, extra = {}) {
      const invocationId = `resource-${++sequence}`;
      child.stdin.write(frame({ type: 'invoke', invocationId, function: name, entryPoint: name, trigger, event, ...extra }));
      return wait(() => frames.find(x => x.type === 'result' && x.invocationId === invocationId));
    },
    async calls() {
      try { return (await readFile(join(dir, 'calls.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
      catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    },
  };
}

const sdkRoot = fileURLToPath(new URL('../../conformance/functions-events/fixtures/node_modules/firebase-functions', import.meta.url));


const corpus = JSON.parse(await readFile(process.env.FE_FIRESTORE_CORPUS, 'utf8'));
for (const profile of ['strict', 'emulator']) {
  test(`Rust Firestore bytes through the real SDK: ${profile}`, { timeout: 30000 }, async t => {
    assert.equal(JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8')).version, '7.3.2');
    const source = `
const {appendFileSync}=require('node:fs');
const assert=require('node:assert/strict');
const sdk=require(${JSON.stringify(join(sdkRoot,'lib/v2/providers/firestore.js'))});
const v1=require(${JSON.stringify(join(sdkRoot,'lib/v1/providers/firestore.js'))});
function snapshot(s) {
 if (!s || !s.exists) return null;
 const d=s.data();
 assert.equal(Object.keys(d).length,12);
 assert.equal(d.null,null); assert.equal(d.boolean,true); assert.equal(d.double,1.5);
 assert.equal(d.string,'é snow 雪'); assert.equal(d.bytes.toString('base64'),'AAH/');
 assert.equal(d.reference.path,'items/ref'); assert.equal(d.geo.latitude,-90); assert.equal(d.geo.longitude,180);
 assert.deepEqual(d.array,[d.integer,{nested:'value'}]); assert.deepEqual(d.map,{'a.b':[false]});
 assert.deepEqual(d.vector.toArray(),[1,-2.5]);
 assert.equal(d.timestamp.seconds,-1); assert.equal(d.timestamp.nanoseconds,123456789);
 return {integer:d.integer,path:s.ref.path};
}
for (const kind of ['Created','Updated','Deleted','Written']) for (const auth of [false,true]) {
 const name=kind+(auth?'Auth':'');
 exports[name]=sdk['onDocument'+kind+(auth?'WithAuthContext':'')]('items/{id}',e=>{
  const changed=kind==='Updated'||kind==='Written';
  const output={name,before:changed?snapshot(e.data.before):kind==='Deleted'?snapshot(e.data):null,
   after:changed?snapshot(e.data.after):kind==='Created'?snapshot(e.data):null};
  assert.equal(e.params.id,'a');
  if(auth){assert.equal(e.authType,'system');assert.equal(e.authId,'local');}
  appendFileSync(__dirname+'/calls.jsonl',JSON.stringify(output)+'\\n');
 });
}
`;
    const f = await start(t, source + `
for (const [kind,method] of [['Created','onCreate'],['Updated','onUpdate'],['Deleted','onDelete'],['Written','onWrite']]) {
 const name='V1'+kind;
 exports[name]=v1.document('items/{id}')[method]((data,context)=>{
  const changed=kind==='Updated'||kind==='Written';
  assert.equal(context.params.id,'a');
  appendFileSync(__dirname+'/calls.jsonl',JSON.stringify({name,
   before:changed?snapshot(data.before):kind==='Deleted'?snapshot(data):null,
   after:changed?snapshot(data.after):kind==='Created'?snapshot(data):null})+'\\n');
 });
}
`, profile);
    for (const generation of [1,2]) for (const row of corpus) for (const auth of generation===1?[false]:[false,true]) {
      const kind = row.kind.split('-')[0];
      const name = (generation===1?'V1':'')+kind[0].toUpperCase()+kind.slice(1)+(auth?'Auth':'');
      const event = {
        params:{id:'a'},specversion:'1.0',id:'local-test',time:'2026-01-01T00:00:00.000Z',
        type:`google.cloud.firestore.document.v1.${kind}${auth?'.withAuthContext':''}`,
        source:'//firestore.googleapis.com/projects/demo-proj/databases/(default)',
        subject:'documents/items/a',project:'demo-proj',database:'(default)',namespace:'(default)',location:'local',document:'items/a',
        datacontenttype:profile==='strict'&&generation===2?'application/protobuf':'application/json',
        data:row[profile==='strict'&&generation===2?'protobuf':'json'],
        ...(auth?{authtype:'system',authid:'local'}:{}),
      };
      const result = await f.invoke(name,'firestore',event);
      assert.equal(result.ok,true,`${row.kind} auth=${auth}: ${JSON.stringify(result)}`);
      const last=(await f.calls()).at(-1);
      assert.deepEqual(last.before,row.json.oldValue?{integer:41,path:'items/a'}:null);
      assert.deepEqual(last.after,row.json.value?{integer:42,path:'items/a'}:null);
      if(generation===2) console.log(`PICT\tNode\t${profile}\t${row.kind}\t${auth?'context':'ordinary'}`);
    }
  });
}
