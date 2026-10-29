import {createHash} from 'node:crypto';import {isDeepStrictEqual} from 'node:util';import {buildGrpcRequest,guardGrpcRequest} from './harness.mjs';import {readConsistencyStep} from './read-consistency-corpus.mjs';
// The generic guard validates the entire fixed request before the single selector is attached.
export function prepareReadConsistency(step,ctx,selector){
 if(!isDeepStrictEqual(step,readConsistencyStep())||!selector||!['readTime','transaction','strong'].includes(selector.kind))throw Error('unapproved consistency request');
 const keys=Object.keys(selector);if(selector.kind==='strong'&&(keys.length!==1))throw Error('unexpected selector');
 const built=buildGrpcRequest(step,ctx,new Map());guardGrpcRequest(built,ctx);let evidence={kind:selector.kind};
 if(selector.kind==='transaction'){
  if(keys.some(k=>!['kind','token'].includes(k))||!Buffer.isBuffer(selector.token)||selector.token.length<1||selector.token.length>4096)throw Error('invalid transaction selector');
  built.request.transaction=Buffer.from(selector.token);evidence.sha256=createHash('sha256').update(selector.token).digest('hex');
 }else if(selector.kind==='readTime'){
  if(keys.some(k=>!['kind','timestamp','now'].includes(k))||typeof selector.timestamp!=='string'||!Number.isFinite(selector.now))throw Error('invalid readTime selector');
  const match=/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(selector.timestamp);if(!match)throw Error('invalid captured timestamp');
  const nanos=Number((match[2]??'').padEnd(9,'0'));if(nanos%1000!==0)throw Error('sub-microsecond timestamp');const ms=Date.parse(selector.timestamp),normal=Number.isFinite(ms)?new Date(ms).toISOString().slice(0,19):'';if(normal!==match[1]||selector.now<ms||selector.now-ms>3600000)throw Error('stale captured timestamp');
  built.request.readTime={seconds:String(Math.floor(ms/1000)),nanos};evidence.timestamp=selector.timestamp;
 }
 return {built,evidence};
}
