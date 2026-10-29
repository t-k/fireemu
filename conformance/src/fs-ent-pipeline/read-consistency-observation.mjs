import {createRequire} from 'node:module';import {createHash} from 'node:crypto';import {PRODUCTION_GRPC} from './harness.mjs';import {readConsistencyStep} from './read-consistency-corpus.mjs';import {prepareReadConsistency} from './read-consistency-selector.mjs';
const require=createRequire(import.meta.url);
export async function observeReadConsistency(ctx,selector,{id,activeToken,claim,journal,clientFactory,timeoutMs=60000}={}){
 if(typeof claim!=='function'||typeof journal!=='function'||!Buffer.isBuffer(activeToken)||activeToken.length===0||activeToken.length>4096||!['tx-anchor','strong','read-time','tx-snapshot'].includes(id))throw Error('observation admission missing');
 if((id==='tx-anchor'||id==='tx-snapshot')!== (selector?.kind==='transaction')||id==='strong'&&selector?.kind!=='strong'||id==='read-time'&&selector?.kind!=='readTime')throw Error('selector binding mismatch');
 if(selector?.kind==='transaction'&&(!Buffer.isBuffer(selector.token)||!selector.token.equals(activeToken)))throw Error('active transaction mismatch');
 const {built,evidence}=prepareReadConsistency(readConsistencyStep(),ctx,selector),grpc=require('@grpc/grpc-js'),{v1}=require('@google-cloud/firestore'),gapic=new v1.FirestoreClient({projectId:ctx.project});const bytes=gapic._protos.google.firestore.v1.ExecutePipelineRequest.serialize(built.request);if(bytes.length>1048576)throw Error('request exceeds bound');
 const secrets=[...(ctx.target.kind==='production'?[Buffer.from(ctx.target.token)]:[]),activeToken];if(selector.kind!=='transaction'&&(bytes.includes(activeToken)||bytes.includes(Buffer.from(activeToken.toString('base64')))))throw Error('secret in request; retain claims');await claim(id);await journal({phase:'attempt',id,requestSha256:createHash('sha256').update(bytes).digest('hex'),selector:evidence,...(selector.kind==='transaction'?{}:{requestBase64:bytes.toString('base64')})});
  const target = ctx.target.kind === 'production' ? `${PRODUCTION_GRPC.host}:${PRODUCTION_GRPC.port}` : `${ctx.target.grpcHost}:${ctx.target.grpcPort}`;
  const credentials = ctx.target.kind === 'production' ? grpc.credentials.createSsl() : grpc.credentials.createInsecure();
  const client = clientFactory ? clientFactory(target, credentials) : new grpc.Client(target, credentials, {'grpc.enable_retries':0});
  const metadata = new grpc.Metadata();
  metadata.set('authorization', `Bearer ${ctx.target.kind === 'production' ? ctx.target.token : 'owner'}`);
  if (ctx.target.kind === 'production') metadata.set('x-goog-user-project', ctx.target.quotaProject);
  metadata.set('x-goog-request-params', `database=${encodeURIComponent(built.request.database)}`);
  return new Promise((resolve, reject) => {
    const frames=[]; let length=0; let overflow=false; let streamError=false; let journalError=false; let queue=Promise.resolve();
    let call;
    try { call = client.makeServerStreamRequest('/google.firestore.v1.Firestore/ExecutePipeline', () => bytes, b => b, built.request, metadata, {deadline:new Date(Date.now()+timeoutMs)}); }
    catch { client.close(); gapic.close().finally(() => reject(new Error('unknown gRPC start; retain claims'))); return; }
    call.on('metadata', () => { queue=queue.then(() => journal({phase:'headers', id:id})).catch(() => {journalError=true; call.cancel();}); });
    call.on('data', frame => { if (secrets.some(secret=>Buffer.from(frame).includes(secret)||Buffer.from(frame).includes(Buffer.from(secret.toString('base64'))))) {overflow=true; call.cancel(); return;} try{const decoded=gapic._protos.google.firestore.v1.ExecutePipelineResponse.deserialize(Buffer.from(frame));if(decoded.transaction?.length){overflow=true;call.cancel();return;}}catch{overflow=true;call.cancel();return;} length+=frame.length; if (length>1024*1024 || frames.length>=1024) {overflow=true; call.cancel(); return;} frames.push(Buffer.from(frame).toString('base64')); });
    call.on('error', () => {streamError=true;});
    call.on('status', status => {
      queue.then(async () => {
        try {
          const details = typeof status.details === 'string' ? status.details : '';
          const statusBytes = status.metadata?.get?.('grpc-status-details-bin')?.[0];
          const detailBytes = statusBytes ? Buffer.from(statusBytes) : Buffer.alloc(0);
          if (secrets.some(secret=>details.includes(secret.toString())||details.includes(secret.toString('base64'))||detailBytes.includes(secret)||detailBytes.includes(Buffer.from(secret.toString('base64'))))) throw new Error('secret in status; retain claims');
          await journal({phase:'status', id:id, code:status.code, details, statusDetailsBase64:detailBytes.toString('base64'), frames});
          if (journalError || overflow || [2,4,8,13,14].includes(status.code) || (streamError && status.code === 0)) throw new Error('unknown observation; retain claims');
          let anchorVerified=false;if(id==='tx-anchor'&&status.code===0){const proto=gapic._protos.google.firestore.v1.ExecutePipelineResponse,rows=frames.flatMap(frame=>proto.deserialize(Buffer.from(frame,'base64')).results??[]);anchorVerified=rows.length===1&&Object.keys(rows[0].fields??{}).length===1&&rows[0].fields?.v?.valueType==='integerValue'&&String(rows[0].fields.v.integerValue)==='1';}return {known:true,ok:status.code===0,code:status.code,frames,...(id==='tx-anchor'?{anchorVerified}:{})};
        } finally { client.close(); await gapic.close(); }
      }).then(resolve,reject);
    });
  });
}
