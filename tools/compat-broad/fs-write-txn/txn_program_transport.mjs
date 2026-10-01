/** One bounded unary Firestore call per worker, over REST or native gRPC; no GAPIC calls or credential discovery. */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import http from 'node:http';
import https from 'node:https';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const grpc = require('@grpc/grpc-js');
const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
if (require('@grpc/grpc-js/package.json').version !== '1.14.4' || require('@google-cloud/firestore/package.json').version !== '8.7.1') throw new Error('program dependency pin differs');
const descriptorClient = new FirestoreClient({ projectId: 'demo-descriptors' });
const protos = descriptorClient._protos;
const firestore = protos.google.firestore.v1;
const empty = protos.google.protobuf.Empty;
const RESPONSES = { BeginTransaction: firestore.BeginTransactionResponse, GetDocument: firestore.Document, BatchGetDocuments: firestore.BatchGetDocumentsResponse, Commit: firestore.CommitResponse, Rollback: empty, DeleteDocument: empty };
const REST_METHODS = ['BeginTransaction', 'GetDocument', 'BatchGetDocuments', 'Commit', 'Rollback'];
export const MAX_BATCH_FRAMES = 16;
export const CHANNEL_OPTIONS = Object.freeze({ 'grpc.enable_retries': 0, 'grpc.max_send_message_length': 16384, 'grpc.max_receive_message_length': 65536 });
export const RECEIPT_KIND = 'txn-program-receipt-v1';
export const MAX_DEADLINE_MS = 30000;
export const DEFAULT_DEADLINE_MS = 10000;
const UNKNOWN_CODES = [1, 2, 4, 13, 14];
// google.rpc.Code by the `status` name a REST error carries.
const STATUS_CODES = { OK: 0, CANCELLED: 1, UNKNOWN: 2, INVALID_ARGUMENT: 3, DEADLINE_EXCEEDED: 4, NOT_FOUND: 5, ALREADY_EXISTS: 6, PERMISSION_DENIED: 7, RESOURCE_EXHAUSTED: 8, FAILED_PRECONDITION: 9, ABORTED: 10, OUT_OF_RANGE: 11, UNIMPLEMENTED: 12, INTERNAL: 13, UNAVAILABLE: 14, DATA_LOSS: 15, UNAUTHENTICATED: 16 };
const LABEL = /^[a-z0-9][a-z0-9-]{0,47}$/;
// The sandbox projects a production call may name: the shared one and the one FS-TRANSACTION owns alone.
export const SANDBOX_PROJECTS = Object.freeze(['fireemu-oracle-sbx', 'fireemu-oracle-txn']);

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function keys(value, required, optional = []) {
  if (!plain(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => ![...required, ...optional].includes(key))) throw new Error('program closed schema differs');
}
function bytes(value) {
  if (typeof value !== 'string' || !value.length || value.length > 2048 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('program canonical token required');
  const decoded = Buffer.from(value, 'base64');
  if (!decoded.length || decoded.length > 1024 || decoded.toString('base64') !== value) throw new Error('program canonical token required');
}
function timestamp(value) {
  keys(value, ['seconds', 'nanos']);
  if (typeof value.seconds !== 'string' || !/^[0-9]{1,12}$/.test(value.seconds) || !Number.isInteger(value.nanos) || value.nanos < 0 || value.nanos > 999999999) throw new Error('program canonical updateTime required');
}

export function validateCall(spec) {
  keys(spec, ['kind', 'transport', 'target', 'projectId', 'nonce', 'ownerId', 'slug', 'documents', 'states', 'method', 'request', 'bearer', 'deadlineMs']);
  if (spec.kind !== 'txn-program-call-v1' || !['rest', 'grpc'].includes(spec.transport) || !/^[a-f0-9]{32}$/.test(spec.nonce) || !/^[a-f0-9]{32}$/.test(spec.ownerId)) throw new Error('program identity differs');
  if (typeof spec.slug !== 'string' || !LABEL.test(spec.slug) || !Array.isArray(spec.documents) || !spec.documents.length || spec.documents.length > 8 || spec.documents.some(role => typeof role !== 'string' || !LABEL.test(role)) || new Set(spec.documents).size !== spec.documents.length) throw new Error('program document scope differs');
  if (!Array.isArray(spec.states) || !spec.states.length || spec.states.length > 32 || spec.states.some(state => typeof state !== 'string' || !LABEL.test(state))) throw new Error('program states differ');
  // Only an outside writer's commit (no transaction) may wait 30 s; every other call is capped at 10 s.
  const writer = spec.method === 'Commit' && plain(spec.request) && spec.request.transaction === undefined;
  if (!Number.isInteger(spec.deadlineMs) || spec.deadlineMs < 1 || spec.deadlineMs > (writer ? MAX_DEADLINE_MS : DEFAULT_DEADLINE_MS) || typeof spec.bearer !== 'string' || !/^[A-Za-z0-9._~+\/-]{1,8192}$/.test(spec.bearer)) throw new Error('program deadline or bearer differs');
  if (spec.target?.kind === 'production') {
    keys(spec.target, ['kind']);
    if (!SANDBOX_PROJECTS.includes(spec.projectId)) throw new Error('program production project differs');
  } else {
    keys(spec.target, ['kind', 'host', 'port']);
    if (spec.target.kind !== 'local' || spec.target.host !== '127.0.0.1' || !Number.isInteger(spec.target.port) || spec.target.port < 1 || spec.target.port > 65535 || !/^demo-[a-z0-9-]{1,48}$/.test(spec.projectId) || spec.bearer !== 'owner') throw new Error('program local target differs');
  }
  if (!Object.hasOwn(RESPONSES, spec.method)) throw new Error('program RPC differs');
  if (spec.transport === 'rest' && !REST_METHODS.includes(spec.method)) throw new Error('program REST surface differs');
  const database = `projects/${spec.projectId}/databases/(default)`;
  const prefix = `${database}/documents/oracle/${spec.nonce}/${spec.slug}/`;
  const owned = name => typeof name === 'string' && name.startsWith(prefix) && spec.documents.includes(name.slice(prefix.length));
  const request = spec.request;
  switch (spec.method) {
    case 'BeginTransaction': {
      keys(request, ['database', 'options']);
      if (request.database !== database) throw new Error('program database differs');
      if (Object.keys(request.options ?? {}).length !== 1) throw new Error('program transaction mode differs');
      // A fresh transaction, read-write or read-only at its own time. A read-write begin over REST may name one earlier token
      // (`retryTransaction`) as the attempt it retries; a retry over gRPC, with a read-only begin or with any other key is refused.
      const mode = Object.keys(request.options)[0];
      if (!['readWrite', 'readOnly'].includes(mode)) throw new Error('program transaction mode differs');
      keys(request.options, [mode]);
      if (mode === 'readOnly') { keys(request.options.readOnly, [], ['readTime']); if (request.options.readOnly.readTime !== undefined) timestamp(request.options.readOnly.readTime); } else {
        keys(request.options.readWrite, [], ['retryTransaction']);
        if (request.options.readWrite.retryTransaction !== undefined) {
          if (spec.transport !== 'rest') throw new Error('program retry is a REST begin only');
          bytes(request.options.readWrite.retryTransaction);
        }
      }
      break;
    }
    case 'GetDocument':
      keys(request, ['name'], ['transaction', 'readTime']);
      if (!owned(request.name)) throw new Error('program document differs');
      if (request.transaction !== undefined && request.readTime !== undefined) throw new Error('program read names a transaction and a time');
      if (request.transaction !== undefined) bytes(request.transaction);
      if (request.readTime !== undefined) timestamp(request.readTime);
      break;
    case 'BatchGetDocuments': {
      keys(request, ['database', 'documents'], ['transaction', 'readTime', 'newTransaction']);
      if (['transaction', 'readTime', 'newTransaction'].filter(key => request[key] !== undefined).length > 1) throw new Error('program batch names more than one consistency selector');
      if (request.readTime !== undefined) timestamp(request.readTime);
      if (request.newTransaction !== undefined) {
        if (!plain(request.newTransaction) || Object.keys(request.newTransaction).length !== 1 || !['readWrite', 'readOnly'].includes(Object.keys(request.newTransaction)[0])) throw new Error('program batch transaction mode differs');
        keys(request.newTransaction[Object.keys(request.newTransaction)[0]], []);
      }
      if (request.database !== database || !Array.isArray(request.documents) || !request.documents.length || request.documents.length > spec.documents.length || new Set(request.documents).size !== request.documents.length || !request.documents.every(owned)) throw new Error('program batch documents differ');
      if (request.transaction !== undefined) bytes(request.transaction);
      break;
    }
    case 'Rollback':
      keys(request, ['database', 'transaction']);
      if (request.database !== database) throw new Error('program database differs');
      bytes(request.transaction);
      break;
    case 'Commit': {
      keys(request, ['database', 'writes'], ['transaction']);
      // An empty commit is a transaction's own: it must name the transaction.
      if (request.database !== database || !Array.isArray(request.writes) || request.writes.length > spec.documents.length || (!request.writes.length && request.transaction === undefined)) throw new Error('program writes differ');
      if (request.transaction !== undefined) bytes(request.transaction);
      const seen = new Set();
      for (const write of request.writes) {
        keys(write, ['update', 'currentDocument']); keys(write.update, ['name', 'fields']); keys(write.currentDocument, ['exists']);
        if (!owned(write.update.name) || seen.has(write.update.name) || typeof write.currentDocument.exists !== 'boolean') throw new Error('program write scope differs');
        seen.add(write.update.name);
        keys(write.update.fields, ['owner', 'nonce', 'role', 'state']);
        for (const [key, expected] of Object.entries({ owner: spec.ownerId, nonce: spec.nonce, role: write.update.name.slice(prefix.length) })) {
          keys(write.update.fields[key], ['stringValue']);
          if (write.update.fields[key].stringValue !== expected) throw new Error('program write owner differs');
        }
        keys(write.update.fields.state, ['stringValue']);
        if (!spec.states.includes(write.update.fields.state.stringValue)) throw new Error('program state differs');
      }
      break;
    }
    case 'DeleteDocument':
      keys(request, ['name', 'currentDocument']); keys(request.currentDocument, ['updateTime']);
      if (!owned(request.name)) throw new Error('program delete scope differs');
      timestamp(request.currentDocument.updateTime);
      break;
  }
  if (Buffer.byteLength(JSON.stringify(spec)) > 16384) throw new Error('program request capacity exceeded');
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

function receipt(spec, code, details, response, http = null) {
  const safeDetails = String(details ?? '').split(spec.bearer).join('[credential-redacted]').slice(0, 4096);
  const result = { kind: RECEIPT_KIND, transport: spec.transport, complete: Number.isInteger(code) && !UNKNOWN_CODES.includes(code), code, details: safeDetails, response: response === undefined ? null : response, http, dispatchedRequests: 1 };
  if (Buffer.byteLength(JSON.stringify(result)) > 65536) return { ...result, complete: false, response: null, details: 'response capacity exceeded' };
  return result;
}

/** The logical call as one REST request: method, path, query and JSON body. */
/** A read time as REST spells it: RFC 3339 with all nine digits of the fraction. */
export function rfc3339(time) {
  return `${new Date(Number(time.seconds) * 1000).toISOString().slice(0, 19)}.${String(time.nanos).padStart(9, '0')}Z`;
}

export function restRequest(spec) {
  const database = `projects/${spec.projectId}/databases/(default)`;
  const request = spec.request;
  switch (spec.method) {
    case 'BeginTransaction': {
      const options = request.options.readOnly?.readTime === undefined ? request.options : { readOnly: { readTime: rfc3339(request.options.readOnly.readTime) } };
      return { method: 'POST', path: `/v1/${database}/documents:beginTransaction`, body: { options } };
    }
    case 'Commit': return { method: 'POST', path: `/v1/${database}/documents:commit`, body: { writes: request.writes, ...(request.transaction === undefined ? {} : { transaction: request.transaction }) } };
    case 'Rollback': return { method: 'POST', path: `/v1/${database}/documents:rollback`, body: { transaction: request.transaction } };
    case 'BatchGetDocuments': return { method: 'POST', path: `/v1/${database}/documents:batchGet`, body: { documents: request.documents, ...(request.transaction === undefined ? {} : { transaction: request.transaction }), ...(request.readTime === undefined ? {} : { readTime: rfc3339(request.readTime) }), ...(request.newTransaction === undefined ? {} : { newTransaction: request.newTransaction }) } };
    default: return { method: 'GET', path: `/v1/${request.name}${request.transaction === undefined ? '' : `?transaction=${encodeURIComponent(request.transaction)}`}${request.readTime === undefined ? '' : `?readTime=${encodeURIComponent(rfc3339(request.readTime))}`}`, body: undefined };
  }
}

/** The real REST exchange: one connection, one request, a bounded answer; the caller times it out. */
export function restHeaders(spec) {
  const headers = { authorization: `Bearer ${spec.bearer}`, accept: 'application/json' };
  if (spec.target.kind === 'production') headers['x-goog-user-project'] = spec.projectId;
  return headers;
}

export function httpExchange(spec, prepared, signal) {
  const production = spec.target.kind === 'production';
  const module = production ? https : http;
  const headers = restHeaders(spec);
  const payload = prepared.body === undefined ? undefined : Buffer.from(JSON.stringify(prepared.body));
  if (payload) { headers['content-type'] = 'application/json'; headers['content-length'] = String(payload.length); }
  return new Promise((resolve, reject) => {
    const req = module.request({ host: production ? 'firestore.googleapis.com' : spec.target.host, port: production ? 443 : spec.target.port, method: prepared.method, path: prepared.path, headers, agent: false, signal }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) { res.destroy(); resolve({ status: res.statusCode, text: null, oversize: true }); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(payload);
  });
}

async function runRest(spec, exchange) {
  const controller = new AbortController();
  let timer;
  try {
    const answer = await Promise.race([
      exchange(spec, restRequest(spec), controller.signal),
      new Promise((_resolve, reject) => { timer = setTimeout(() => { controller.abort(); reject(Object.assign(new Error('worker deadline exceeded'), { deadline: true })); }, spec.deadlineMs + 25); }),
    ]);
    if (answer.oversize) return receipt(spec, 2, 'response capacity exceeded', null, answer.status);
    let body;
    try { body = JSON.parse(answer.text); } catch { return receipt(spec, 2, 'REST answer is not JSON', null, answer.status); }
    const batch = spec.method === 'BatchGetDocuments';
    // A batch answers with an array of entries; an error may arrive as the first entry.
    if (batch && Array.isArray(body) && body.length && plain(body[0]) && plain(body[0].error)) body = body[0];
    if (answer.status >= 200 && answer.status < 300) {
      if (batch) return Array.isArray(body) && body.length <= MAX_BATCH_FRAMES && body.every(plain) ? receipt(spec, 0, '', { responses: body }, answer.status) : receipt(spec, 2, 'REST batch answer is not a bounded list of entries', null, answer.status);
      return plain(body) ? receipt(spec, 0, '', body, answer.status) : receipt(spec, 2, 'REST success is not an object', null, answer.status);
    }
    const status = body?.error?.status;
    // A non-2xx answer is never OK, whatever its status name says.
    const code = typeof status === 'string' && Object.hasOwn(STATUS_CODES, status) && STATUS_CODES[status] !== 0 ? STATUS_CODES[status] : 2;
    return receipt(spec, code, body?.error?.message ?? 'REST error without a status', null, answer.status);
  } catch (error) {
    return error?.deadline ? receipt(spec, 4, 'worker deadline exceeded', null) : receipt(spec, 14, 'REST exchange failed', null);
  } finally { clearTimeout(timer); }
}

/** The gRPC call metadata: the credential, the user project in production only, and the routing parameter. */
export function grpcMetadata(spec) {
  const metadata = new grpc.Metadata();
  metadata.set('authorization', `Bearer ${spec.bearer}`);
  if (spec.target.kind === 'production') metadata.set('x-goog-user-project', spec.projectId);
  const routing = spec.request.database ? 'database' : 'name';
  metadata.set('x-goog-request-params', `${routing}=${encodeURIComponent(spec.request[routing])}`);
  return metadata;
}

async function runGrpc(spec, createClientOverride) {
  const production = spec.target.kind === 'production';
  const createClient = createClientOverride ?? ((endpoint, credentials, options) => new grpc.Client(endpoint, credentials, options));
  const client = createClient(production ? 'firestore.googleapis.com:443' : `${spec.target.host}:${spec.target.port}`, production ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(), CHANNEL_OPTIONS);
  const metadata = grpcMetadata(spec);
  let call;
  let timer;
  try {
    return await new Promise(resolve => {
      let settled = false;
      const finish = (code, details, response) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(receipt(spec, code, details, response === undefined || response === null ? null : normalize(response)));
      };
      timer = setTimeout(() => { finish(4, 'worker deadline exceeded'); call?.cancel(); }, spec.deadlineMs + 25);
      try {
        if (spec.method === 'BatchGetDocuments') {
          // A server stream: collect a bounded number of entries; an error after entries is still the call's answer.
          call = client.makeServerStreamRequest(`/google.firestore.v1.Firestore/${spec.method}`, firestore[`${spec.method}Request`].serialize, RESPONSES[spec.method].deserialize, spec.request, metadata, { deadline: new Date(Date.now() + spec.deadlineMs) });
          const entries = [];
          call.on('data', entry => { entries.push(entry); if (entries.length > MAX_BATCH_FRAMES) { finish(2, 'batch stream over the frame cap'); call.cancel(); } });
          // A batch that begins a transaction may already have handed it over: an error after entries is unknown.
          call.on('error', error => (entries.length && spec.request.newTransaction !== undefined) ? finish(2, 'batch stream failed after entries that may carry a new transaction') : finish(error?.code ?? 2, error?.details ?? ''));
          call.on('end', () => finish(0, '', { responses: entries }));
        } else {
          call = client.makeUnaryRequest(`/google.firestore.v1.Firestore/${spec.method}`, firestore[`${spec.method}Request`].serialize, RESPONSES[spec.method].deserialize, spec.request, metadata, { deadline: new Date(Date.now() + spec.deadlineMs) }, (error, response) => finish(error?.code ?? 0, error?.details ?? '', response));
        }
      } catch { finish(2, 'native dispatch failed'); }
    });
  } finally { clearTimeout(timer); client.close(); }
}

/** `injected` replaces the network for a local target only: a gRPC client factory or a REST exchange. */
export async function runUnary(spec, injected) {
  validateCall(spec);
  if (injected !== undefined && (spec.target.kind === 'production' || typeof injected !== 'function')) throw new Error('program test injection requires a local target');
  try {
    return spec.transport === 'rest' ? await runRest(spec, injected ?? httpExchange) : await runGrpc(spec, injected);
  } finally { await descriptorClient.close(); }
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
      if (parent === root) throw new Error(`program dependency root missing: ${name}`);
      root = parent;
    }
    if (relative(modules, root).startsWith('..')) throw new Error('program dependency escaped its checkout');
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
        else throw new Error('program dependency tree contains a non-regular entry');
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
      if (size > 16384) throw new Error('program IPC request capacity exceeded');
      chunks.push(chunk);
    }
    const result = await runUnary(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
}
