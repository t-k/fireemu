/** One bounded native unary RPC per worker; no GAPIC calls or credential discovery. */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const grpc = require('@grpc/grpc-js');
const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
if (require('@grpc/grpc-js/package.json').version !== '1.14.4' || require('@google-cloud/firestore/package.json').version !== '8.7.1') throw new Error('P10-A dependency pin differs');
const descriptorClient = new FirestoreClient({ projectId: 'demo-descriptors' });
const protos = descriptorClient._protos;
const firestore = protos.google.firestore.v1;
const empty = protos.google.protobuf.Empty;
const RESPONSES = { BeginTransaction: firestore.BeginTransactionResponse, GetDocument: firestore.Document, Commit: firestore.CommitResponse, Rollback: empty, DeleteDocument: empty };
export const CHANNEL_OPTIONS = Object.freeze({ 'grpc.enable_retries': 0, 'grpc.max_send_message_length': 16384, 'grpc.max_receive_message_length': 65536 });

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function keys(value, required, optional = []) {
  if (!plain(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => ![...required, ...optional].includes(key))) throw new Error('P10-A closed schema differs');
}
function bytes(value) {
  if (typeof value !== 'string' || !value.length || value.length > 2048 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('P10-A canonical token required');
  const decoded = Buffer.from(value, 'base64');
  if (!decoded.length || decoded.length > 1024 || decoded.toString('base64') !== value) throw new Error('P10-A canonical token required');
}
function timestamp(value) {
  keys(value, ['seconds', 'nanos']);
  if (typeof value.seconds !== 'string' || !/^[0-9]{1,12}$/.test(value.seconds) || !Number.isInteger(value.nanos) || value.nanos < 0 || value.nanos > 999999999) throw new Error('P10-A canonical updateTime required');
}

export function validateCall(spec) {
  keys(spec, ['kind', 'target', 'projectId', 'nonce', 'ownerId', 'method', 'request', 'bearer', 'deadlineMs']);
  if (spec.kind !== 'txn-p10-grpc-call-v1' || !/^[a-f0-9]{32}$/.test(spec.nonce) || !/^[a-f0-9]{32}$/.test(spec.ownerId)) throw new Error('P10-A identity differs');
  if (!Number.isInteger(spec.deadlineMs) || spec.deadlineMs < 1 || spec.deadlineMs > 10000 || typeof spec.bearer !== 'string' || !/^[A-Za-z0-9._~+\/-]{1,8192}$/.test(spec.bearer)) throw new Error('P10-A deadline or bearer differs');
  if (spec.target?.kind === 'production') {
    keys(spec.target, ['kind']);
    if (spec.projectId !== 'fireemu-oracle-sbx') throw new Error('P10-A production project differs');
  } else {
    keys(spec.target, ['kind', 'host', 'port']);
    if (spec.target.kind !== 'local' || spec.target.host !== '127.0.0.1' || !Number.isInteger(spec.target.port) || spec.target.port < 1 || spec.target.port > 65535 || !/^demo-[a-z0-9-]{1,48}$/.test(spec.projectId) || spec.bearer !== 'owner') throw new Error('P10-A local target differs');
  }
  if (!Object.hasOwn(RESPONSES, spec.method)) throw new Error('P10-A RPC differs');
  const database = `projects/${spec.projectId}/databases/(default)`;
  const name = `${database}/documents/oracle/${spec.nonce}/txn-p10/control`;
  const request = spec.request;
  switch (spec.method) {
    case 'BeginTransaction': {
      keys(request, ['database', 'options']);
      if (request.database !== database) throw new Error('P10-A database differs');
      if (Object.keys(request.options ?? {}).length !== 1) throw new Error('P10-A transaction mode differs');
      keys(request.options, ['readWrite']); keys(request.options.readWrite, [], ['retryTransaction']); if (request.options.readWrite.retryTransaction !== undefined) bytes(request.options.readWrite.retryTransaction);
      break;
    }
    case 'GetDocument':
      keys(request, ['name'], ['transaction']);
      if (request.name !== name) throw new Error('P10-A document differs');
      if (request.transaction !== undefined) bytes(request.transaction);
      break;
    case 'Rollback':
      keys(request, ['database', 'transaction']);
      if (request.database !== database) throw new Error('P10-A database differs');
      bytes(request.transaction);
      break;
    case 'Commit': {
      keys(request, ['database', 'writes'], ['transaction']);
      if (request.database !== database || !Array.isArray(request.writes) || request.writes.length !== 1) throw new Error('P10-A writes differ');
      if (request.transaction !== undefined) bytes(request.transaction);
      const write = request.writes[0];
      keys(write, ['update', 'currentDocument']); keys(write.update, ['name', 'fields']); keys(write.currentDocument, ['exists']);
      if (write.update.name !== name || typeof write.currentDocument.exists !== 'boolean') throw new Error('P10-A write scope differs');
      keys(write.update.fields, ['owner', 'nonce', 'role', 'state']);
      for (const [key, expected] of Object.entries({ owner: spec.ownerId, nonce: spec.nonce, role: 'control' })) {
        keys(write.update.fields[key], ['stringValue']);
        if (write.update.fields[key].stringValue !== expected) throw new Error('P10-A write owner differs');
      }
      keys(write.update.fields.state, ['stringValue']);
      if (!['created', 'committed-before-idle', 'attempted-after-idle', 'after-rollback-first', 'after-get-first'].includes(write.update.fields.state.stringValue)) throw new Error('P10-A state differs');
      break;
    }
    case 'DeleteDocument':
      keys(request, ['name', 'currentDocument']); keys(request.currentDocument, ['updateTime']);
      if (request.name !== name) throw new Error('P10-A delete scope differs');
      timestamp(request.currentDocument.updateTime);
      break;
  }
  if (Buffer.byteLength(JSON.stringify(spec)) > 16384) throw new Error('P10-A request capacity exceeded');
}

export function serviceDefinitions() {
  return Object.fromEntries(Object.entries(RESPONSES).map(([method, response]) => [method, { path: `/google.firestore.v1.Firestore/${method}`, requestStream: false, responseStream: false, requestSerialize: firestore[`${method}Request`].serialize, requestDeserialize: firestore[`${method}Request`].deserialize, responseSerialize: response.serialize, responseDeserialize: response.deserialize }]));
}

function normalize(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('base64');
  if (Array.isArray(value)) return value.map(normalize);
  if (plain(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalize(item)]));
  return value;
}

export async function runUnary(spec, localFactory) {
  validateCall(spec);
  const production = spec.target.kind === 'production';
  if (localFactory !== undefined && (production || typeof localFactory !== 'function')) throw new Error('P10-A test factory requires a local target');
  const createClient = localFactory ?? ((endpoint, credentials, options) => new grpc.Client(endpoint, credentials, options));
  const client = createClient(production ? 'firestore.googleapis.com:443' : `${spec.target.host}:${spec.target.port}`, production ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(), CHANNEL_OPTIONS);
  const metadata = new grpc.Metadata();
  metadata.set('authorization', `Bearer ${spec.bearer}`);
  if (production) metadata.set('x-goog-user-project', 'fireemu-oracle-sbx');
  const routing = spec.request.database ? 'database' : 'name';
  metadata.set('x-goog-request-params', `${routing}=${encodeURIComponent(spec.request[routing])}`);
  let call;
  let timer;
  try {
    return await new Promise(resolve => {
      let settled = false;
      const finish = (code, details, response) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const safeDetails = String(details ?? '').split(spec.bearer).join('[credential-redacted]').slice(0, 4096);
        const result = { kind: 'txn-p10-grpc-receipt-v1', complete: Number.isInteger(code) && ![1, 2, 4, 13, 14].includes(code), code, details: safeDetails, response: response === undefined ? null : normalize(response), dispatchedRequests: 1 };
        if (Buffer.byteLength(JSON.stringify(result)) > 65536) resolve({ ...result, complete: false, response: null, details: 'response capacity exceeded' });
        else resolve(result);
      };
      timer = setTimeout(() => { finish(4, 'worker deadline exceeded'); call?.cancel(); }, spec.deadlineMs + 25);
      try {
        call = client.makeUnaryRequest(`/google.firestore.v1.Firestore/${spec.method}`, firestore[`${spec.method}Request`].serialize, RESPONSES[spec.method].deserialize, spec.request, metadata, { deadline: new Date(Date.now() + spec.deadlineMs) }, (error, response) => finish(error?.code ?? 0, error?.details ?? '', response));
      } catch { finish(2, 'native dispatch failed'); }
    });
  } finally { clearTimeout(timer); client.close(); await descriptorClient.close(); }
}

export function runtimeInfo() {
  const dependencies = {};
  const modules = realpathSync(new URL('../../../conformance/node_modules', import.meta.url));
  const resolveRoot = (name, resolver) => {
    let entry;
    try { entry = resolver.resolve(`${name}/package.json`); } catch { entry = resolver.resolve(name); }
    let root = dirname(realpathSync(entry));
    while (!statSync(join(root, 'package.json'), { throwIfNoEntry: false })?.isFile() || typeof JSON.parse(readFileSync(join(root, 'package.json'))).name !== 'string') {
      const parent = dirname(root);
      if (parent === root) throw new Error(`P10-A dependency root missing: ${name}`);
      root = parent;
    }
    if (relative(modules, root).startsWith('..')) throw new Error('P10-A dependency escaped its checkout');
    return root;
  };
  const pending = ['@grpc/grpc-js', '@google-cloud/firestore'].map(name => resolveRoot(name, require));
  while (pending.length) {
    const root = pending.pop();
    const key = relative(modules, root);
    if (Object.hasOwn(dependencies, key)) continue;
    const manifest = JSON.parse(readFileSync(join(root, 'package.json')));
    const resolver = createRequire(join(root, 'package.json'));
    const requires = {};
    for (const name of Object.keys({ ...manifest.dependencies, ...manifest.optionalDependencies }).sort()) {
      let child;
      try { child = resolveRoot(name, resolver); }
      catch (error) { if (!Object.hasOwn(manifest.optionalDependencies ?? {}, name)) throw error; requires[name] = null; continue; }
      requires[name] = relative(modules, child); pending.push(child);
    }
    const rows = [];
    const scan = relative => {
      for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
        if (entry.name === 'node_modules') continue;
        const child = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isDirectory()) scan(child);
        else if (entry.isFile()) rows.push([child, createHash('sha256').update(readFileSync(join(root, child))).digest('hex')]);
        else throw new Error('P10-A dependency tree contains a non-regular entry');
      }
    };
    scan(''); rows.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    dependencies[key] = { root, name: manifest.name, version: manifest.version, requires, fileCount: rows.length, treeSha256: createHash('sha256').update(rows.map(([path, digest]) => `${path}\0${digest}\n`).join('')).digest('hex') };
  }
  return { nodeVersion: process.version, dependencies };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === '--runtime-info') {
    process.stdout.write(`${JSON.stringify(runtimeInfo())}\n`);
  } else {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16384) throw new Error('P10-A IPC request capacity exceeded');
    chunks.push(chunk);
  }
  const result = await runUnary(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  }
}
