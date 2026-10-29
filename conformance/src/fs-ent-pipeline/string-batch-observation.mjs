// One fixed read-only ExecutePipeline observation, with a bounded raw stream.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { isMainThread } from 'node:worker_threads';
import { buildGrpcRequest, guardGrpcRequest, PRODUCTION_GRPC } from './harness.mjs';
import { stringBatchRecipes } from './string-batch-corpus.mjs';

const require = createRequire(import.meta.url);
export async function observeString(ctx, step, {claim, journal, clientFactory, timeoutMs = 60000} = {}) {
  const fixed = stringBatchRecipes().map(x => x.step).find(x => x.id === step?.id);
  if (!fixed || !isDeepStrictEqual(fixed, step) || ctx.stageContextDatabase !== ctx.database) throw new Error('unapproved observation corpus or target');
  if (typeof claim !== 'function' || typeof journal !== 'function') throw new Error('observation admission missing');
  const deep = /^chain-(48|100)-grpc$/.test(step.id);
  if (deep && isMainThread) throw new Error('deep observation requires an isolated worker');
  if (deep) {
    const firestoreRequire = createRequire(require.resolve('@google-cloud/firestore'));
    const gaxRequire = createRequire(firestoreRequire.resolve('google-gax'));
    const loaderRequire = createRequire(gaxRequire.resolve('@grpc/proto-loader'));
    const protobuf = loaderRequire('protobufjs');
    protobuf.util.recursionLimit = 1024; protobuf.Reader.recursionLimit = 1024;
  }
  const grpc = require('@grpc/grpc-js');
  const {v1} = require('@google-cloud/firestore');
  const built = buildGrpcRequest(step, ctx, new Map());
  guardGrpcRequest(built, ctx);
  const gapic = new v1.FirestoreClient({projectId:ctx.project});
  const bytes = gapic._protos.google.firestore.v1.ExecutePipelineRequest.serialize(built.request);
  if (bytes.length > 1024 * 1024) throw new Error('request exceeds bound');
  await claim(step.id);
  await journal({phase:'attempt', id:step.id, requestSha256:createHash('sha256').update(bytes).digest('hex'), requestBase64:bytes.toString('base64')});
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
    call.on('metadata', () => { queue=queue.then(() => journal({phase:'headers', id:step.id})).catch(() => {journalError=true; call.cancel();}); });
    call.on('data', frame => { if (ctx.target.kind === 'production' && ctx.target.token && Buffer.from(frame).includes(Buffer.from(ctx.target.token))) {overflow=true; call.cancel(); return;} length+=frame.length; if (length>1024*1024 || frames.length>=1024) {overflow=true; call.cancel(); return;} frames.push(Buffer.from(frame).toString('base64')); });
    call.on('error', () => {streamError=true;});
    call.on('status', status => {
      queue.then(async () => {
        try {
          const details = typeof status.details === 'string' ? status.details : '';
          const statusBytes = status.metadata?.get?.('grpc-status-details-bin')?.[0];
          const detailBytes = statusBytes ? Buffer.from(statusBytes) : Buffer.alloc(0);
          const token = ctx.target.kind === 'production' ? ctx.target.token : '';
          if (token && (details.includes(token) || detailBytes.includes(Buffer.from(token)))) throw new Error('secret in status; retain claims');
          await journal({phase:'status', id:step.id, code:status.code, details, statusDetailsBase64:detailBytes.toString('base64'), frames});
          if (journalError || overflow || [2,4,8,13,14].includes(status.code) || (streamError && status.code === 0)) throw new Error('unknown observation; retain claims');
          return {known:true,ok:status.code===0,code:status.code,frames};
        } finally { client.close(); await gapic.close(); }
      }).then(resolve,reject);
    });
  });
}
