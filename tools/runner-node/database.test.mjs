// Exercises the codebase's installed SDK wrappers, including real DataSnapshots.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const smoke = process.env.FIREEMU_SDK_SMOKE_DIR || resolve(here, "../sdk-smoke");
const installed = existsSync(join(smoke, "node_modules/firebase-functions/package.json"));
const required = process.env.FIREEMU_REQUIRE_SDK === "1";
const fixture = `
const v1 = require('firebase-functions/v1');
const v2 = require('firebase-functions/v2/database');
const snap = s => ({key:s.key,exists:s.exists(),value:s.val(),child:s.child('nested').val(),ref:s.ref.toString()});
const emit = value => console.log(JSON.stringify(value));
for (const [suffix,method] of [['Write','onWrite'],['Create','onCreate'],['Update','onUpdate'],['Delete','onDelete']]) {
  exports['v1'+suffix] = v1.database.instance('app-first').ref('/users/{uid}')[method]((data,context) => {
    emit({generation:1,kind:suffix,params:context.params,authType:context.authType,auth:context.auth,
      eventId:context.eventId,resource:context.resource,
      data: data.before ? {before:snap(data.before),after:snap(data.after)} : snap(data)});
  });
}
for (const [suffix,method] of [['Write','onValueWritten'],['Create','onValueCreated'],['Update','onValueUpdated'],['Delete','onValueDeleted']]) {
  exports['v2'+suffix] = v2[method]({ref:'/users/{uid=*-test}',instance:'app-*',region:'us-central1'}, event => {
    emit({generation:2,kind:suffix,params:event.params,authType:event.authType,authId:event.authId,
      eventId:event.id,instance:event.instance,ref:event.ref,
      data: event.data.before ? {before:snap(event.data.before),after:snap(event.data.after)} : snap(event.data)});
  });
}
exports.v2All = v2.onValueWritten('/all/{uid}', () => {});
exports.v1Default = v1.database.ref('/default/{uid}').onWrite(() => {});
`;
function frame(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${bytes.length}\n`), bytes]);
}
async function stopRunner(child, exited, wait, remove) {
  try {
    if (!exited()) {
      child.stdin.end();
      try { await wait(exited, "clean exit", 1000); }
      catch {
        child.kill("SIGTERM");
        try { await wait(exited, "terminated exit", 1000); }
        catch { child.kill("SIGKILL"); await wait(exited, "killed exit", 3000); }
      }
    }
  } finally {
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await remove();
  }
}

async function start(t) {
  assert.ok(installed, "firebase-functions is required but is not installed in the SDK fixture");
  const dir = await mkdtemp(join(tmpdir(), "fireemu-database-runner-"));
  await writeFile(join(dir, "package.json"), JSON.stringify({main:"index.cjs"}));
  await writeFile(join(dir, "index.cjs"), fixture);
  await symlink(join(smoke, "node_modules"), join(dir, "node_modules"), "dir");
  const child = spawn(process.execPath, [process.env.FIREEMU_TEST_RUNNER || join(here,"index.mjs"), "--source",dir], {
    env:{PATH:process.env.PATH,GCLOUD_PROJECT:"demo-db",FIREBASE_CONFIG:JSON.stringify({projectId:"demo-db",databaseURL:"https://app-default.firebaseio.com"})},
    stdio:["pipe","pipe","pipe"],
  });
  const messages = []; let pending = Buffer.alloc(0), result, stderr = "", invalid;
  child.on("exit", (code,signal) => { result={code,signal}; });
  child.stdin.on("error", () => {});
  child.stderr.on("data", b => { stderr = (stderr+b).slice(-8192); });
  child.stdout.on("data", b => {
    pending=Buffer.concat([pending,b]);
    while (!invalid) {
      const nl=pending.indexOf(10); if(nl<0)return;
      const n=Number(pending.subarray(0,nl).toString());
      if(!Number.isSafeInteger(n)||n<1||n>16*1024*1024){invalid="invalid frame size";return;}
      if(pending.length<nl+1+n)return;
      try { messages.push(JSON.parse(pending.subarray(nl+1,nl+1+n))); }
      catch { invalid="invalid JSON frame";return; }
      pending=pending.subarray(nl+1+n);
    }
  });
  async function wait(predicate,label,timeout=8000) {
    const until=Date.now()+timeout;
    while(Date.now()<until){const value=predicate();if(value)return value;await delay(10);}
    throw new Error(`${label}: exit=${JSON.stringify(result)} invalid=${invalid} stderr=${stderr}`);
  }
  t.after(() => stopRunner(child, () => result, wait, () => rm(dir,{recursive:true,force:true})));
  const hello=await wait(()=>messages.find(m=>m.type==="hello"),"hello");
  return {hello,messages,async invoke(name,event) {
    child.stdin.write(frame({type:"invoke",invocationId:name,function:name,entryPoint:name,trigger:"database",event}));
    const result=await wait(()=>messages.find(m=>m.type==="result"&&m.invocationId===name),name);
    assert.equal(result.ok,true,JSON.stringify(result));
    const log=messages.find(m=>m.type==="log"&&m.invocationId===name);
    assert.ok(log, `${name} handler did not emit a snapshot`);
    return JSON.parse(log.message);
  }};
}
const options = {skip:!installed&&!required?"firebase-functions is not installed under tools/sdk-smoke":false,timeout:20000};
test("database SDK discovery preserves v1 default instance and v2 path/instance patterns", options, async t => {
  const runner=await start(t);
  const functions=runner.hello.manifest.functions;
  assert.equal(functions.length,10,JSON.stringify(runner.hello.manifest));
  assert.deepEqual(functions.find(f=>f.name==="v2Write").trigger,{type:"database",eventType:"google.firebase.database.ref.v1.written",instance:"app-*",ref:"/users/{uid=*-test}"});
  assert.equal(functions.find(f=>f.name==="v1Default").trigger.instance,"app-default");
  assert.equal(functions.find(f=>f.name==="v2All").trigger.instance,"*");
  assert.equal(runner.hello.httpPort,undefined,"database functions need no HTTP listener");
});
test("v1 and v2 database wrappers build actual before/after and single DataSnapshots", options, async t => {
  const runner=await start(t);
  assert.equal(runner.hello.manifest.functions.length,10);
  for(const generation of [1,2])for(const [suffix,type,before,delta] of [
    ["Write","written",{nested:1},{nested:2}],
    ["Update","updated",{nested:1},{nested:2}],
    ["Create","created",null,{nested:2}],
    ["Delete","deleted",{nested:1},null],
  ]) {
    const event={specversion:"1.0",id:`event-${generation}-${suffix}`,type:`google.firebase.database.ref.v1.${type}`,
      source:"//firebasedatabase.googleapis.com/projects/demo-db/locations/us-central1/instances/app-first",
      time:"2026-10-24T00:00:00.000Z",instance:"app-first",ref:"users/a-test",location:"us-central1",
      firebasedatabasehost:"firebaseio.com",authtype:"app_user",authid:"verified-user",
      auth:{uid:"verified-user",token:{role:"member"}},data:{data:before,delta}};
    const actual=await runner.invoke(`v${generation}${suffix}`,event);
    assert.deepEqual(actual.params,{uid:"a-test"});
    assert.equal(actual.authType,generation===1?"USER":"app_user");
    assert.equal(actual.eventId,event.id);
    if(generation===1)assert.deepEqual(actual.auth,event.auth);else assert.equal(actual.authId,"verified-user");
    const snap=actual.data.after||actual.data;
    assert.equal(snap.key,"a-test");
    assert.equal(snap.ref,"https://app-first.firebaseio.com/users/a-test");
    assert.deepEqual(snap.value,{nested:suffix==="Delete"?1:2});
    assert.equal(snap.child,suffix==="Delete"?1:2);
    if(actual.data.before)assert.deepEqual(actual.data.before.value,{nested:1});
  }
});

test("normal wrappers distinguish administrator and unauthenticated principals without fabricated users", options, async t => {
  const runner=await start(t);
  for(const [name,authtype,expected] of [["v1Write","admin","ADMIN"],["v2Write","unauthenticated","unauthenticated"]]) {
    const actual=await runner.invoke(name,{id:`principal-${name}`,type:"google.firebase.database.ref.v1.written",
      time:"2026-10-24T00:00:00.000Z",instance:"app-first",ref:"users/a-test",
      firebasedatabasehost:"europe-west1.firebasedatabase.app",authtype,data:{data:1,delta:2}});
    assert.equal(actual.authType,expected);
    assert.equal(Object.hasOwn(actual,"auth"),false);
    assert.equal(Object.hasOwn(actual,"authId"),false);
    assert.equal(actual.data.after.ref,"https://app-first.europe-west1.firebasedatabase.app/users/a-test");
  }
});

test("database runner teardown escalates to KILL and reaps before final cleanup", async () => {
  const calls=[]; let exited=false;
  const stream=name=>({end(){calls.push(name+".end");},destroy(){calls.push(name+".destroy");}});
  const child={stdin:stream("stdin"),stdout:stream("stdout"),stderr:stream("stderr"),kill(signal){calls.push(signal);if(signal==="SIGKILL")exited=true;}};
  await stopRunner(child,()=>exited,async(predicate,label)=>{calls.push(label);if(!predicate())throw new Error("timeout");},async()=>{calls.push("remove");});
  assert.deepEqual(calls,["stdin.end","clean exit","SIGTERM","terminated exit","SIGKILL","killed exit","stdin.destroy","stdout.destroy","stderr.destroy","remove"]);
});
test("database runner teardown preserves reap failure and still cleans streams and fixture", async () => {
  const calls=[];
  const stream=name=>({end(){},destroy(){calls.push(name);}});
  const child={stdin:stream("stdin"),stdout:stream("stdout"),stderr:stream("stderr"),kill(signal){calls.push(signal);}};
  await assert.rejects(stopRunner(child,()=>false,async()=>{throw new Error("reap timeout");},async()=>{calls.push("remove");}),/reap timeout/);
  assert.deepEqual(calls,["SIGTERM","SIGKILL","stdin","stdout","stderr","remove"]);
});
