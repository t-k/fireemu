import test from 'node:test';
import assert from 'node:assert/strict';
import { lifecycle } from './lifecycle.mjs';

test('successful lifecycle runs corpus between prefix-only rules and exact restore', async () => {
 const calls=[]; const io=async (step,method,path,body) => { calls.push({step,method,path,body}); return {
 'api-before': {name:'service',state:'DISABLED'}, 'api-enable': {name:'operations/a',done:true}, 'api-enabled': {name:'service',state:'ENABLED'},
 'instance-before': {name:'instance',type:'USER_DATABASE',state:'DELETED'}, 'active-before': {instances:[]},
 'undelete': {name:'instance',type:'USER_DATABASE',state:'DISABLED'}, 'reenable': {name:'instance',type:'USER_DATABASE',state:'ACTIVE'}, 'instance-active': {name:'instance',type:'USER_DATABASE',state:'ACTIVE'},
 'rules-before': 'BASELINE', 'prefix-before': null, 'rules-install': {status:'ok'}, 'rules-installed': {rules:{owned:{'.read':true,'.write':true}}},
 'prefix-delete': null, 'prefix-after': null, 'rules-restore': {status:'ok'}, 'rules-restored': 'BASELINE',
 'disable': {name:'instance',type:'USER_DATABASE',state:'DISABLED'}, 'instance-disabled': {name:'instance',type:'USER_DATABASE',state:'DISABLED'}, 'delete': {name:'instance',type:'USER_DATABASE',state:'DELETED'}, 'instance-deleted': {name:'instance',type:'USER_DATABASE',state:'DELETED'}, 'active-after': {instances:[]}, 'api-disable': {name:'operations/b',done:true}, 'api-disabled': {name:'service',state:'DISABLED'} }[step]; };
 const result=await lifecycle(io,{prefix:'owned', instanceName:'instance', serviceName:'service', baselineHash:'678bf03b47ad96012e4b7cf24f90a91aefc5c921863940998e65e28463f45cb0'},async()=>{calls.push({step:'corpus'});});
 assert.equal(result,'closed'); assert.ok(calls.findIndex(x=>x.step==='corpus')<calls.findIndex(x=>x.step==='rules-restore'));
});

test('unknown rules mutation stops without automatic cleanup writes', async () => {
 let mutations=0;
 const io=async (step,method) => { if (method !== 'GET') mutations++; if(step==='api-before')return {name:'service',state:'DISABLED'}; if(step==='api-enable')return {name:'operations/a',done:true}; if(step==='api-enabled')return {name:'service',state:'ENABLED'}; if(step==='instance-before')return {name:'instance',type:'USER_DATABASE',state:'DELETED'}; if(step==='active-before')return {instances:[]}; if(step==='undelete'||step==='instance-active')return {name:'instance',type:'USER_DATABASE',state:'ACTIVE'}; if(step==='rules-before')return 'BASELINE'; if(step==='prefix-before')return null; if(step==='rules-install')throw Error('unknown'); throw Error(step); };
 await assert.rejects(lifecycle(io,{prefix:'owned',instanceName:'instance',serviceName:'service',baselineHash:'678bf03b47ad96012e4b7cf24f90a91aefc5c921863940998e65e28463f45cb0'},async()=>{}),/unknown/);
 assert.equal(mutations,3);
});

test('pending API operation is polled only within fixed bound',async()=>{
 const calls=[];const io=async(step,method)=>{calls.push([step,method]);if(step==='api-before')return {name:'service',state:'DISABLED'};if(step==='api-enable')return {name:'operations/a',done:false};if(step.startsWith('api-enable-poll-'))return {name:'operations/a',done:false};throw Error(step);};
 await assert.rejects(lifecycle(io,{prefix:'owned',instanceName:'instance',serviceName:'service',baselineHash:'678bf03b47ad96012e4b7cf24f90a91aefc5c921863940998e65e28463f45cb0'},async()=>{}),/operation unresolved/);
 assert.equal(calls.filter(x=>x[0].startsWith('api-enable-poll-')).length,3);assert.equal(calls.filter(x=>x[1]==='POST').length,1);
});

test('wrong Rules baseline blocks rules mutation',async()=>{
 const steps=[];const io=async(step)=>{steps.push(step);return {'api-before':{name:'service',state:'DISABLED'},'api-enable':{name:'operations/a',done:true},'api-enabled':{name:'service',state:'ENABLED'},'instance-before':{name:'instance',type:'USER_DATABASE',state:'DELETED'},'active-before':{instances:[]},undelete:{name:'instance',type:'USER_DATABASE',state:'ACTIVE'},'instance-active':{name:'instance',type:'USER_DATABASE',state:'ACTIVE'},'rules-before':'WRONG'}[step];};
 await assert.rejects(lifecycle(io,{prefix:'owned',instanceName:'instance',serviceName:'service',baselineHash:'678bf03b47ad96012e4b7cf24f90a91aefc5c921863940998e65e28463f45cb0'},async()=>{}),/rules-before: guard/);assert.equal(steps.includes('rules-install'),false);
});
