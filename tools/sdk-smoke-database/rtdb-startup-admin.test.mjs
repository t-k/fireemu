import test from 'node:test';
import assert from 'node:assert/strict';
import { createRtdbAdmin } from './rtdb-admin.mjs';
import { createStartupStrictClient } from './rtdb-residual.mjs';

const caps={observe:2,cleanup:1,mutations:2,pollsPerOperation:2};
const setup=(options={})=>{
 const rows=[],wire=[];const client=createStartupStrictClient({caps,allowed:(url)=>url==='https://owned.test/a',journal:(row)=>rows.push(row),fetchImpl:async(url,init)=>{wire.push({url,method:init.method});return new Response('{"ok":true}',{status:200})},...options});return {client,rows,wire};
};
test('strict client journals before and complete response, rejects foreign target and latches unknown',async()=>{
 const {client,rows,wire}=setup();await client.call('first','GET','https://owned.test/a');assert.equal(rows[0].kind,'before');assert.equal(rows[1].body,'{"ok":true}');
 await assert.rejects(client.call('foreign','GET','https://foreign.test/a'),/target/i);await assert.rejects(client.call('later','GET','https://owned.test/a'),/stop|unknown|latched/i);assert.equal(wire.length,1);
});
test('failed journal or unknown response prevents later sends even in cleanup',async()=>{
 for(const fail of ['before','after','network']){let count=0;const {client,wire}=setup({journal:(r)=>{if(r.kind===fail)throw Error('disk')},fetchImpl:async()=>{count++;if(fail==='network')throw Error('network');return new Response('{}')}});await client.call('one','PUT','https://owned.test/a').catch(()=>{});client.cleanup();await assert.rejects(client.call('later','DELETE','https://owned.test/a'),/stop|unknown|latched/i);assert.equal(count,fail==='before'?0:1);assert.equal(wire.length,0);}
});
test('strict cleanup stops after first failed cleanup step',async()=>{
 const a=createRtdbAdmin({instance:'x',location:'y',caps,propagationMs:0,fireGraceMs:0,rulesFor:()=>({}),strictStartup:true});const calls=[];
 const run={admin:{cleanup(){}},state:{data:'ours',rules:'ours',instance:'baseline',api:'baseline'},u:{data:(p)=>p},call:async(step)=>{calls.push(step);return {outcome:'unknown'}},errors:[],unresolved:[]};
 await a.cleanup(run,{mode:'local',prefix:'owned'},async()=>{});assert.deepEqual(calls,['prefix-delete']);
});
test('strict propagation never retries 401 or 403',async()=>{
 const a=createRtdbAdmin({instance:'x',location:'y',caps,propagationMs:1000,fireGraceMs:0,rulesFor:()=>({}),strictStartup:true});for(const status of [401,403]){let calls=0;const run={propagation:true,propagationWaited:0,sleep:async()=>{},call:async()=>{calls++;return {outcome:'refused',status}}};await assert.rejects(a.read(run,'read','GET','x',()=>true));assert.equal(calls,1);}
});

test('PICT strict client failure latch and send bounds',async()=>{
 if(!process.env.ADMIN_PICT)return;
 const {readFileSync}=await import('node:fs');const lines=readFileSync(process.env.ADMIN_PICT,'utf8').trim().split(/\r?\n/).slice(1);
 for(const line of lines){const [phase,journalState,outcome,target]=line.split('\t');let sends=0;const {client}=setup({journal:(r)=>{if((r.kind==='before'&&journalState==='before-fail')||(r.kind==='after'&&journalState==='after-fail'))throw Error('disk')},fetchImpl:async()=>{sends++;if(outcome==='unknown')throw Error('network');return new Response('{}',{status:outcome==='refusal'?403:200})}});if(phase==='cleanup')client.cleanup();const result=await client.call('one','GET',target==='owned'?'https://owned.test/a':'https://foreign.test/a').catch(()=>null);if(target==='foreign'||journalState!=='ok'||outcome!=='ok'){assert.ok(!result||result.outcome==='unknown');await assert.rejects(client.call('later','GET','https://owned.test/a'));}else assert.equal(result.outcome,'ok');assert.ok(sends<=1);}
});

test('strict cap is shared across observe and cleanup with mutation as subset',async()=>{
 const {client,wire}=setup({caps:{observe:2,cleanup:1,mutations:1}});
 await client.call('read','GET','https://owned.test/a');await client.call('put','PUT','https://owned.test/a');client.cleanup();await assert.rejects(client.call('delete','DELETE','https://owned.test/a'),/cap/);assert.equal(wire.length,2);assert.equal(client.counts.mutations,1);
});

test('private admin journal retains full body and refuses secrets',async()=>{
 const {mkdtempSync,readFileSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {createPrivateAdminJournal}=await import('./rtdb-residual.mjs');
 const d=mkdtempSync(join(tmpdir(),'sdk-admin-test-'));try{const p=join(d,'journal');const journal=createPrivateAdminJournal(p,['secret-token']);const body='x'.repeat(5000);journal({kind:'after',body});assert.equal(JSON.parse(readFileSync(p,'utf8')).body,body);assert.throws(()=>journal({body:'secret-token'}),/secret/);}finally{rmSync(d,{recursive:true,force:true})}
});

test('strict cleanup stops after known response with mismatched readback',async()=>{
 const a=createRtdbAdmin({instance:'x',location:'y',caps,propagationMs:0,fireGraceMs:0,rulesFor:()=>({}),strictStartup:true});const calls=[];
 const run={admin:{cleanup(){}},state:{data:'ours',rules:'ours',instance:'baseline',api:'baseline'},u:{data:(p)=>p},call:async(step)=>{calls.push(step);return {outcome:'ok',value:step==='prefix-delete'?null:{foreign:true},text:'{}'}},errors:[],unresolved:[]};
 await a.cleanup(run,{mode:'local',prefix:'owned'},async()=>{});assert.deepEqual(calls,['prefix-delete','prefix-null']);
});
