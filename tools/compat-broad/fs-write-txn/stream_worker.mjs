// Private finite worker. Configuration and short-lived metadata arrive only on its inherited socket.
import net from 'node:net';
import { createHash } from 'node:crypto';
import { collectWithApi } from './stream_collector.mjs';
import { buildUnaryRequest, createFixedTlsTransport } from './transport_internal.mjs';
import { runUnary, runWrite } from './stream_node_transport.mjs';

const PROTOCOL = 'firestore-grpc-stream-v1';
const MAX_BYTES = 4 * 1024 * 1024;
const canonical = value => {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('base64');
  if (value?.type === 'Buffer' && Array.isArray(value.data)) return Buffer.from(value.data).toString('base64');
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    if ('seconds' in value && 'nanos' in value) return { nanos: value.nanos, seconds: String(value.seconds) };
    return Object.fromEntries(Object.keys(value).filter(key => key !== 'valueType' && value[key] !== undefined).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
};
// Python's digest uses ASCII JSON, including surrogate pairs.
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const encoded = value => JSON.stringify(sorted(JSON.parse(JSON.stringify(value)))).replace(/[\u007f-\uffff]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
const digest = value => createHash('sha256').update(encoded(value)).digest('hex');
const fail = () => { throw new Error('private stream protocol rejected'); };
const fd = Number(process.env.STREAM_CHANNEL_FD);
if (!Number.isInteger(fd) || fd < 3) fail();
const channel = new net.Socket({ fd, readable: true, writable: true });
let buffer = Buffer.alloc(0);
let waiting;
let closed = false;
const messages = [];
channel.on('data', chunk => {
  buffer = Buffer.concat([buffer, chunk]);
  if (buffer.length > MAX_BYTES + 4) return channel.destroy(new Error('bounded private message required'));
  while (buffer.length >= 4) {
    const size = buffer.readUInt32BE(0);
    if (size === 0 || size > MAX_BYTES) return channel.destroy(new Error('bounded private message required'));
    if (buffer.length < size + 4) break;
    let message;
    try { message = JSON.parse(buffer.subarray(4, size + 4).toString()); } catch { return channel.destroy(new Error('invalid private message')); }
    buffer = buffer.subarray(size + 4);
    if (waiting) { const resolve = waiting; waiting = undefined; resolve(message); }
    else { messages.push(message); if (messages.length > 1) channel.destroy(new Error('unsolicited private message')); }
  }
});
channel.on('error', () => { closed = true; if (waiting) { const resolve = waiting; waiting = undefined; resolve({ type: 'denied' }); } });
channel.on('close', () => { closed = true; if (waiting) { const resolve = waiting; waiting = undefined; resolve({ type: 'denied' }); } });
const receive = () => {
  if (closed) fail();
  if (messages.length) return Promise.resolve(messages.shift());
  if (waiting) fail();
  return new Promise(resolve => { waiting = resolve; });
};
const send = value => {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > MAX_BYTES || closed) fail();
  const length = Buffer.alloc(4); length.writeUInt32BE(body.length);
  channel.write(Buffer.concat([length, body]));
};
const main = async () => {
  const init = await receive();
  if (init.type !== 'init' || init.protocol !== PROTOCOL || init.job !== 'stream' || digest(init.plan) !== init.planDigest || !['local', 'fixed-tls'].includes(init.mode)) fail();
  const plan = init.plan;
  const options = { host: '127.0.0.1', port: init.mode === 'local' ? init.port : 443, projectId: plan.projectId, documentPrefix: plan.documentPrefix, nonce: plan.nonce, deadlineMs: 30000, maxFrames: 32, maxMessageBytes: 1048576 };
  let id = 0;
  let observation = 0;
  let busy = false;
  const rpc = async (phase, index, operation) => {
    if (busy) fail();
    busy = true;
    const binding = { protocol: PROTOCOL, planDigest: init.planDigest, job: 'stream', id: ++id, phase, index };
    send({ ...binding, type: 'request', operation });
    const grant = await receive();
    if (Object.entries(binding).some(([key, value]) => grant[key] !== value)) fail();
    if (grant.type === 'recorded' && grant.skipped) { busy = false; return { skipped: true, operation: grant.operation }; }
    if (grant.type !== 'grant' || digest(grant.operation) !== grant.requestDigest || (operation && digest(operation) !== grant.requestDigest) || grant.deadlineMs !== 30000) fail();
    const request = grant.operation.request;
    const method = grant.operation.method;
    const input = method === 'GetDocument'
      ? { path: request.name.split('/documents/')[1], ...(request.transaction ? { transaction: request.transaction } : {}) }
      : Object.fromEntries(Object.entries(request).filter(([key]) => key !== 'database'));
    const ready = () => {
      if (closed || Date.now() + 31000 > Math.min(grant.metadataExpiresAt, grant.permissionExpiresAt, grant.phaseDeadlineAt)) fail();
    };
    ready();
    let raw;
    if (init.mode === 'local') {
      const local = { ...options, metadata: grant.metadata };
      raw = method === 'Write' ? await runWrite(request, local) : await runUnary(method, local, input);
    } else {
      const transport = createFixedTlsTransport({ ...Object.fromEntries(Object.entries(options).filter(([key]) => !['host', 'port', 'nonce'].includes(key))), metadata: grant.metadata, metadataExpiresAt: grant.metadataExpiresAt, phaseDeadlineAt: Math.min(grant.permissionExpiresAt, grant.phaseDeadlineAt) }, { admit: ready });
      raw = method === 'Write' ? await transport.runWrite(request) : await transport.runUnary(method, input);
    }
    const receipt = { protocol: PROTOCOL, requestDigest: grant.requestDigest, raw: canonical(raw), wireRaw: raw };
    send({ ...binding, type: 'receipt', receipt });
    const ack = await receive();
    if (ack.type !== 'recorded' || Object.entries(binding).some(([key, value]) => ack[key] !== value) || ack.receiptDigest !== digest(receipt)) fail();
    busy = false;
    return { raw: receipt.raw, operation: grant.operation };
  };
  const observe = async (method, request) => {
    const template = plan.jobs.stream.observation[observation];
    if (!template) fail();
    const operation = { service: 'firestore', protocol: PROTOCOL, slot: template.slot, method, request: canonical(request) };
    const result = await rpc('observation', observation++, operation);
    return result.raw;
  };
  const recoveryObservations = [];
  const api = {
    runUnary: (method, _options, input) => observe(method, buildUnaryRequest(method, options, input)),
    runWrite: requests => observe('Write', requests),
    recover: async () => {
      const cleanup = [];
      const byRole = new Map();
      for (let index = 0; index < plan.jobs.stream.recovery.length; index++) {
        const result = await rpc('recovery', index, null);
        recoveryObservations.push({ index, phase: result.operation.slot, receipt: result.raw, skipped: result.skipped === true });
        if (result.operation.slot.startsWith('owned-read-')) byRole.set(result.operation.slot.slice('owned-read-'.length), { ownedRead: result.raw });
        if (result.operation.slot.startsWith('conditional-delete-')) {
          const entry = byRole.get(result.operation.slot.slice('conditional-delete-'.length));
          entry.deleted = result.raw; entry.skipped = result.skipped === true;
        }
        if (result.operation.slot.startsWith('typed-absence-')) {
          const absent = result.raw?.kind === 'grpc_status' && result.raw?.complete === true && result.raw?.status?.code === 5;
          const entry = byRole.get(result.operation.slot.slice('typed-absence-'.length));
          cleanup.push({ path: result.operation.request.name.split('/documents/')[1], skipped: entry.skipped, complete: absent, absent, ...(entry.skipped ? { receipt: entry.ownedRead } : { ownedRead: entry.ownedRead, receipt: entry.deleted }), absence: result.raw });
        }
      }
      return cleanup;
    },
  };
  const result = await collectWithApi(options, api, plan.ownerId);
  result.recoveryObservations = recoveryObservations;
  send({ type: 'done', protocol: PROTOCOL, planDigest: init.planDigest, job: 'stream', id, result });
  if ((await receive()).type !== 'shutdown') fail();
  // The parent has consumed done and every receipt before granting shutdown.
  // Fully close: end() would keep our readable half alive while the parent waits.
  channel.destroy();
};
const watchdog = setTimeout(() => { channel.destroy(); process.exitCode = 1; }, 1_100_000);
try { await main(); } catch { channel.destroy(); process.exitCode = 1; } finally { clearTimeout(watchdog); }
