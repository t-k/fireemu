// A bounded proof checker for the collector's single finite stream experiment.
// Comparison is deliberately not acquisition or promotion authority.
const PHASES = Object.freeze([
  ['preflight-create-absence', 'GetDocument'], ['preflight-create-absence', 'GetDocument'],
  ['setup-control', 'Write'], ['setup-locked', 'Write'], ['positive-uncontended-stream', 'Write'],
  ['readback-control', 'GetDocument'], ['begin-rw-transaction', 'BeginTransaction'],
  ['get-locked-with-transaction', 'GetDocument'], ['preflight-suffix-absence', 'GetDocument'],
  ['contended-multiwrite-stream', 'Write'], ['readback-contention', 'GetDocument'],
  ['rollback', 'Rollback'], ['post-rollback-positive-stream', 'Write'],
  ['readback-post-rollback', 'GetDocument'], ['cleanup', 'Cleanup'],
]);
const TIME = Symbol('protocol timestamp');
const ABSENT = 5;
const ABORTED = 10;
const ROLES = ['control', 'locked', 'suffix'];
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const stable = v => Array.isArray(v) ? v.map(stable) : object(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v;
const json = v => JSON.stringify(stable(v));
const equal = (a, b) => json(a) === json(b);
const requireProof = (condition, detail) => { if (!condition) throw new Error(detail); };
const keys = (v, allowed) => object(v) && Object.keys(v).every(k => allowed.includes(k));
const exact = (actual, expected, detail) => requireProof(equal(actual, expected), detail);
const pathValid = p => typeof p === 'string' && p.length > 0 && p.split('/').every(s => s && s !== '.' && s !== '..');

const sideContract = (expected, side) => {
  requireProof(object(expected) && expected.version === 1, 'expected.version must be 1');
  const c = { ...expected, ...(expected[side] ?? {}) };
  requireProof(typeof c.projectId === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{4,62}$/.test(c.projectId), 'invalid projectId');
  c.database ??= `projects/${c.projectId}/databases/(default)`;
  requireProof(c.database === `projects/${c.projectId}/databases/(default)` && pathValid(c.documentPrefix), 'invalid database or prefix');
  requireProof(Array.isArray(c.resources) && c.resources.length === 3, 'exactly three resources required');
  c.paths = {};
  for (const resource of c.resources) {
    const role = typeof resource === 'string' ? resource : resource?.role;
    let path = typeof resource === 'string' ? resource : resource?.path ?? resource?.suffix;
    requireProof(ROLES.includes(role) && !Object.hasOwn(c.paths, role) && pathValid(path), 'invalid resource role/path');
    if (expected.documentPrefix && path.startsWith(`${expected.documentPrefix}/`)) path = `${c.documentPrefix}/${path.slice(expected.documentPrefix.length + 1)}`;
    if (!path.startsWith(`${c.documentPrefix}/`)) path = `${c.documentPrefix}/${path}`;
    requireProof(pathValid(path) && path.startsWith(`${c.documentPrefix}/`), 'resource outside prefix');
    c.paths[role] = path;
  }
  requireProof(new Set(Object.values(c.paths)).size === 3, 'resource paths must be distinct');
  c.maxRpc ??= 24;
  c.maxFramesPerRpc ??= 32;
  requireProof(Number.isInteger(c.maxRpc) && c.maxRpc > 0 && c.maxRpc <= 25, 'invalid finite RPC budget');
  requireProof(Number.isInteger(c.maxFramesPerRpc) && c.maxFramesPerRpc > 0 && c.maxFramesPerRpc <= 256, 'invalid frame budget');
  return c;
};

const byteToken = v => typeof v === 'string'
  ? v.length > 0 && v.length <= 87384 && /^[A-Za-z0-9+/]+={0,2}$/.test(v) && Buffer.from(v, 'base64').length <= 65536 && Buffer.from(v, 'base64').toString('base64') === v
  : keys(v, ['type', 'data']) && v.type === 'Buffer' && Array.isArray(v.data) && v.data.length > 0 && v.data.length <= 65536 && v.data.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
const timestamp = value => {
  requireProof(keys(value, ['seconds', 'nanos']), 'timestamp must be a typed protobuf timestamp');
  let seconds = value.seconds;
  if (object(seconds)) {
    requireProof(keys(seconds, ['low', 'high', 'unsigned']) && Number.isInteger(seconds.low) && seconds.low >= -2147483648 && seconds.low <= 2147483647 && Number.isInteger(seconds.high) && seconds.high >= -2147483648 && seconds.high <= 2147483647 && typeof seconds.unsigned === 'boolean', 'invalid protobuf Long timestamp');
    seconds = (BigInt(seconds.high) << 32n) + BigInt(seconds.low >>> 0);
    if (value.seconds.unsigned) seconds = BigInt.asUintN(64, seconds);
  } else {
    requireProof(typeof seconds === 'string' && /^-?(0|[1-9][0-9]*)$/.test(seconds), 'invalid timestamp seconds');
    seconds = BigInt(seconds);
  }
  const nanos = value.nanos ?? 0;
  requireProof(seconds >= -62135596800n && seconds <= 253402300799n && Number.isInteger(nanos) && nanos >= 0 && nanos <= 999999999, 'timestamp out of range');
  return seconds * 1000000000n + BigInt(nanos);
};
const typedStatus = v => {
  requireProof(object(v) && Number.isInteger(v.code) && v.code >= 0 && v.code <= 16, 'missing or invalid gRPC status');
  for (const key of ['details', 'message']) requireProof(v[key] === undefined || typeof v[key] === 'string', 'invalid status text');
};

// Every literal is tagged, so protocol tags cannot collide with user JSON.
const literal = v => Array.isArray(v) ? ['array', v.map(literal)] : object(v) ? ['object', Object.keys(v).sort().map(k => [k, literal(v[k])])] : [v === null ? 'null' : typeof v, v];
const mapObject = (v, overrides = {}) => ['object', Object.keys(v).sort().map(k => [k, Object.hasOwn(overrides, k) ? overrides[k] : literal(v[k])])];
const newContext = (c, receipt) => ({ ...c, owner: receipt.ownerId, rpc: 0, times: [], identities: [c.database, c.paths, receipt.ownerId], deviations: [], latest: {}, name: role => `${c.database}/documents/${c.paths[role]}` });
const timeProjection = (value, ctx) => {
  const ns = timestamp(value);
  ctx.times.push(ns);
  return { [TIME]: ns.toString() };
};
const tokenProjection = (value, registry, kind) => {
  requireProof(byteToken(value), `invalid ${kind} bytes`);
  const key = json(value);
  if (!registry.has(key)) registry.set(key, registry.size);
  return [kind, registry.get(key)];
};
const semantic = (ctx, condition, detail) => { if (!condition) ctx.deviations.push(detail); };
const tick = ctx => { ctx.rpc += 1; requireProof(ctx.rpc <= ctx.maxRpc, 'finite RPC budget exceeded'); };
const markerFields = (ctx, role, value) => ({ owner: { stringValue: `o3-stream:${ctx.owner}` }, role: { stringValue: role }, ...(value === undefined ? {} : { value: { stringValue: value } }) });
const documentFields = fields => Object.fromEntries(Object.entries(fields).map(([k, value]) => {
  if (object(value) && value.valueType === 'stringValue') { const { valueType: _type, ...rest } = value; return [k, rest]; }
  return [k, value];
}));
const docProjection = (doc, role, ctx) => {
  requireProof(object(doc) && doc.name === ctx.name(role) && object(doc.fields) && doc.updateTime !== undefined && doc.createTime !== undefined, 'missing or wrong-target document proof');
  const update = timeProjection(doc.updateTime, ctx);
  const create = timeProjection(doc.createTime, ctx);
  semantic(ctx, timestamp(doc.createTime) <= timestamp(doc.updateTime), 'document createTime is after updateTime');
  const owner = doc.fields.owner;
  const projectedFields = mapObject(doc.fields, owner?.stringValue === `o3-stream:${ctx.owner}` ? { owner: mapObject(owner, { stringValue: ['owner-marker'] }) } : {});
  return mapObject(doc, { name: ['resource', role], fields: projectedFields, updateTime: update, createTime: create });
};
const checkDocument = (receipt, role, value, ctx, expectedTime) => {
  semantic(ctx, receipt.status === undefined, `${role} document read did not succeed`);
  if (receipt.response) {
    semantic(ctx, equal(documentFields(receipt.response.fields), markerFields(ctx, role, value)), `${role} document fields differ`);
    if (expectedTime !== undefined) semantic(ctx, timestamp(receipt.response.updateTime) === timestamp(expectedTime), `${role} document version differs from acknowledged write`);
  }
};

const unary = (receipt, operation, request, ctx, role) => {
  tick(ctx);
  requireProof(object(receipt) && receipt.kind === 'grpc_status' && receipt.complete === true && receipt.operation === operation, 'incomplete unary receipt');
  exact(receipt.request, request, `${operation} request differs from the frozen request`);
  if (receipt.status !== undefined) {
    typedStatus(receipt.status);
    requireProof(receipt.status.code !== 0 && object(receipt.error) && receipt.error.code === receipt.status.code && receipt.response === undefined, 'inconsistent unary error proof');
    for (const key of ['details', 'message']) if (receipt.status[key] !== undefined) requireProof(receipt.error[key] === receipt.status[key], 'unary error disagrees with status');
    return { operation, status: literal(receipt.status), error: literal(receipt.error) };
  }
  requireProof(object(receipt.response) && receipt.error === undefined, 'successful unary lacks response');
  if (operation === 'GetDocument') return { operation, response: docProjection(receipt.response, role, ctx) };
  if (operation === 'BeginTransaction') {
    requireProof(byteToken(receipt.response.transaction), 'begin lacks a typed transaction token');
    return { operation, response: mapObject(receipt.response, { transaction: ['transaction', 0] }) };
  }
  return { operation, response: literal(receipt.response) };
};
const read = (r, role, ctx, transaction) => unary(r, 'GetDocument', { name: ctx.name(role), ...(transaction ? { transaction } : {}) }, ctx, role);
const absence = (r, role, ctx) => {
  const projected = read(r, role, ctx);
  requireProof(r.status?.code === ABSENT, 'cleanup lacks a typed absence');
  return projected;
};

const write = (receipt, writes, ctx) => {
  tick(ctx);
  requireProof(object(receipt) && receipt.kind === 'grpc_status' && receipt.complete === true && receipt.transportReceiptVersion === 2 && Array.isArray(receipt.events), 'incomplete v2 stream receipt');
  typedStatus(receipt.status);
  const events = receipt.events;
  const sends = events.filter(e => e?.type === 'send');
  const data = events.filter(e => e?.type === 'data');
  requireProof(sends.length === 2 && data.length >= 1 && data.length <= 2 && receipt.sentFrames === sends.length && receipt.completedSendFrames === sends.length && receipt.receivedFrames === data.length, 'stream frame counts do not prove two completed sends');
  requireProof(sends.length + data.length <= ctx.maxFramesPerRpc, 'finite frame budget exceeded');
  requireProof(events[0]?.type === 'send' && events[1]?.type === 'data' && events[2]?.type === 'send', 'handshake/data/write order is invalid');
  exact(sends[0].value, { database: ctx.database }, 'handshake differs from frozen request');
  const handshake = data[0].value;
  requireProof(object(handshake) && byteToken(handshake.streamToken) && Array.isArray(handshake.writeResults) && handshake.writeResults.length === 0 && typeof handshake.streamId === 'string' && handshake.streamId.length > 0, 'incomplete handshake response');
  requireProof(handshake.commitTime === undefined || handshake.commitTime === null, 'handshake has an unexpected commit timestamp');
  const frame = sends[1].value;
  requireProof(keys(frame, ['database', 'writes', 'streamToken']) && (frame.database === undefined || frame.database === ctx.database), 'unexpected write frame fields or database');
  exact(frame.writes, writes, 'write payload differs from frozen request');
  exact(frame.streamToken, handshake.streamToken, 'write did not use the latest received stream token');
  let terminalSeen = false;
  let statusSeen = false;
  let closeSeen = false;
  let errorSeen = false;
  for (const event of events.slice(3)) {
    requireProof(!(statusSeen && closeSeen), 'events after completed terminal proof');
    requireProof(keys(event, ['type', 'value']) && object(event.value), 'invalid stream event');
    if (event.type === 'data') {
      requireProof(!terminalSeen && !closeSeen, 'response after terminal event');
    } else if (event.type === 'status') {
      requireProof(!statusSeen, 'duplicate status event');
      typedStatus(event.value);
      exact(event.value, receipt.status, 'terminal status differs from summary');
      statusSeen = true; terminalSeen = true;
    } else if (event.type === 'error') {
      requireProof(!errorSeen && Number.isInteger(event.value.code) && event.value.code === receipt.status.code && receipt.status.code !== 0, 'error conflicts with final status');
      for (const k of ['details', 'message']) requireProof(event.value[k] === undefined || typeof event.value[k] === 'string', 'invalid error text');
      if (event.value.details !== undefined && receipt.status.details !== undefined) exact(event.value.details, receipt.status.details, 'error details disagree with status');
      errorSeen = true; terminalSeen = true;
    } else if (event.type === 'end' || event.type === 'close') {
      requireProof(!closeSeen, 'duplicate terminal closure');
      requireProof(keys(event.value, ['status']), 'unexpected closure fields');
      if (event.value.status !== undefined) exact(event.value.status, receipt.status, 'closure status differs from final status');
      // runWriteCore permits end/close before status; a status may follow it.
      closeSeen = true; terminalSeen = true;
    } else requireProof(false, 'unknown or extra stream event');
  }
  requireProof(statusSeen && closeSeen, 'raw status and end/close are required');
  if (receipt.error !== undefined) requireProof(errorSeen && events.some(e => e.type === 'error' && equal(e.value, receipt.error)), 'unbound summarized stream error');
  if (receipt.status.code === 0) requireProof(data.length === 2 && data[1].value?.writeResults?.length === writes.length, 'successful write lacks required write results');
  ctx.identities.push(data.map(e => ({ streamId: e.value.streamId, streamToken: e.value.streamToken })));
  const tokens = new Map();
  const projectData = (response, index) => {
    requireProof(object(response) && Array.isArray(response.writeResults) && byteToken(response.streamToken), 'invalid write response');
    const overrides = { streamToken: tokenProjection(response.streamToken, tokens, 'stream-token') };
    if (response.streamId !== undefined) {
      requireProof(typeof response.streamId === 'string', 'invalid stream ID');
      overrides.streamId = response.streamId === '' ? literal('') : response.streamId === handshake.streamId ? ['stream-id', 0] : ['stream-id', 1];
    }
    if (response.commitTime !== undefined && response.commitTime !== null) overrides.commitTime = timeProjection(response.commitTime, ctx);
    overrides.writeResults = ['array', response.writeResults.map((result, i) => {
      requireProof(object(result), 'invalid write result');
      const normalized = {};
      if (result.updateTime !== undefined && result.updateTime !== null) normalized.updateTime = timeProjection(result.updateTime, ctx);
      if (index === 1 && receipt.status.code === 0 && writes[i]?.update) requireProof(result.updateTime !== undefined && result.updateTime !== null, 'successful update lacks updateTime');
      if (result.transformResults !== undefined) {
        requireProof(Array.isArray(result.transformResults), 'invalid transform results');
        semantic(ctx, result.transformResults.length === 0, 'unexpected transform results for non-transform write');
      }
      return mapObject(result, normalized);
    })];
    return mapObject(response, overrides);
  };
  const projected = events.filter(e => e.type !== 'send').map(e => ({ type: e.type, value: e.type === 'data' ? projectData(e.value, data.findIndex(d => d === e)) : literal(e.value) }));
  if (receipt.status.code === 0) writes.forEach((w, i) => {
    if (w.update) {
      const role = ROLES.find(role => ctx.name(role) === w.update.name);
      ctx.latest[role] = data[1].value.writeResults[i].updateTime;
    }
  });
  return { events: projected, status: literal(receipt.status) };
};
const update = (ctx, role, value, create = false) => ({ update: { name: ctx.name(role), fields: markerFields(ctx, role, value) }, ...(create ? { currentDocument: { exists: false } } : {}) });

const validate = (receipt, c) => {
  requireProof(object(receipt) && typeof receipt.ownerId === 'string' && receipt.ownerId.length > 0 && Array.isArray(receipt.observations) && receipt.observations.length === PHASES.length, 'invalid receipt, owner or finite observation sequence');
  const ctx = newContext(c, receipt);
  const obs = receipt.observations;
  obs.forEach((o, i) => requireProof(object(o) && o.phase === PHASES[i][0] && o.complete === true, `incomplete or unexpected observation ${i}`));
  const r = i => obs[i].receipt;
  const projection = [];
  const get = (i, role, transaction) => projection.push(read(r(i), role, ctx, transaction));
  const performWrite = (i, writes, expectedCode = 0) => {
    projection.push(write(r(i), writes, ctx));
    semantic(ctx, r(i).status.code === expectedCode, `unexpected ${obs[i].phase} status`);
  };
  get(0, 'control'); semantic(ctx, r(0).status?.code === ABSENT, 'control preflight was not absent');
  get(1, 'locked'); semantic(ctx, r(1).status?.code === ABSENT, 'locked preflight was not absent');
  performWrite(2, [update(ctx, 'control', undefined, true)]);
  performWrite(3, [update(ctx, 'locked', 'before', true)]);
  performWrite(4, [update(ctx, 'control', 'accepted')]);
  get(5, 'control'); checkDocument(r(5), 'control', 'accepted', ctx, ctx.latest.control);
  projection.push(unary(r(6), 'BeginTransaction', { database: ctx.database, options: { readWrite: {} } }, ctx));
  requireProof(byteToken(r(6).response?.transaction), 'missing transaction token prevents request binding');
  const transaction = r(6).response.transaction;
  ctx.identities.push(transaction);
  get(7, 'locked', transaction); checkDocument(r(7), 'locked', 'before', ctx, ctx.latest.locked);
  get(8, 'suffix'); semantic(ctx, r(8).status?.code === ABSENT, 'suffix preflight was not absent');
  performWrite(9, [update(ctx, 'locked', 'must-not-commit'), update(ctx, 'suffix', 'must-not-commit', true)], ABORTED);
  requireProof(keys(r(10), ['locked', 'suffix']) && r(10).locked && r(10).suffix, 'contention requires locked and suffix readbacks');
  projection.push({ locked: read(r(10).locked, 'locked', ctx), suffix: read(r(10).suffix, 'suffix', ctx) });
  semantic(ctx, r(10).suffix.status?.code === ABSENT, 'contention created suffix');
  semantic(ctx, r(10).locked.status === undefined && r(7).status === undefined && equal(r(10).locked.response, r(7).response), 'contention changed locked document');
  projection.push(unary(r(11), 'Rollback', { database: ctx.database, transaction }, ctx));
  semantic(ctx, r(11).status === undefined && equal(r(11).response, {}), 'rollback did not succeed');
  performWrite(12, [update(ctx, 'locked', 'after-rollback')]);
  get(13, 'locked'); checkDocument(r(13), 'locked', 'after-rollback', ctx, ctx.latest.locked);
  const cleanup = obs[14].cleanup;
  requireProof(Array.isArray(cleanup) && cleanup.length === 3 && new Set(cleanup.map(i => i?.path)).size === 3, 'cleanup must cover three distinct resources');
  if (receipt.cleanup !== undefined) exact(receipt.cleanup, cleanup, 'redundant cleanup journal disagrees');
  const projectedCleanup = [];
  for (const role of ROLES) {
    const item = cleanup.find(i => i?.path === ctx.paths[role]);
    requireProof(object(item) && item.complete === true && item.absent === true && typeof item.skipped === 'boolean', 'incomplete resource cleanup');
    if (item.skipped) {
      semantic(ctx, ctx.latest[role] === undefined, 'acknowledged document unexpectedly absent at cleanup');
      requireProof(item.ownedRead === undefined, 'skipped cleanup has extra ownership read proof');
      projectedCleanup.push({ role, skipped: true, receipt: absence(item.receipt, role, ctx), ...(item.absence === undefined ? {} : { absence: absence(item.absence, role, ctx) }) });
    } else {
      const owned = read(item.ownedRead, role, ctx);
      const doc = item.ownedRead.response;
      requireProof(object(doc) && doc.fields.owner?.stringValue === `o3-stream:${ctx.owner}` && doc.fields.role?.stringValue === role, 'cleanup has no owned document proof');
      requireProof(ctx.latest[role] !== undefined && timestamp(doc.updateTime) === timestamp(ctx.latest[role]), 'cleanup version is not the last acknowledged write');
      checkDocument(item.ownedRead, role, role === 'control' ? 'accepted' : role === 'locked' ? 'after-rollback' : 'must-not-commit', ctx, ctx.latest[role]);
      const removed = write(item.receipt, [{ delete: ctx.name(role), currentDocument: { updateTime: doc.updateTime } }], ctx);
      requireProof(item.receipt.status.code === 0, 'cleanup delete was not acknowledged');
      projectedCleanup.push({ role, ownedRead: owned, receipt: removed, absence: absence(item.absence, role, ctx) });
    }
  }
  if (receipt.recoveryObservations !== undefined) {
    const recovery = receipt.recoveryObservations;
    requireProof(Array.isArray(recovery) && recovery.length === 10, 'Gate recovery journal must contain ten slots');
    const slots = [{ phase: 'rollback-finally', skipped: true }];
    for (const role of ROLES) {
      const item = cleanup.find(i => i.path === ctx.paths[role]);
      requireProof(item.absence !== undefined, 'Gate recovery requires a distinct final absence RPC');
      slots.push({ phase: `owned-read-${role}`, skipped: false, receipt: item.skipped ? item.receipt : item.ownedRead });
      slots.push({ phase: `conditional-delete-${role}`, skipped: item.skipped, ...(item.skipped ? {} : { receipt: item.receipt }) });
      slots.push({ phase: `typed-absence-${role}`, skipped: false, receipt: item.absence });
    }
    slots.forEach((slot, index) => exact(recovery[index], { index, ...slot }, 'Gate recovery slot does not bind the canonical cleanup receipt'));
  }
  projection.push(projectedCleanup);
  // Rank actual instants, preserving every equality and order relation. Only
  // generated timestamp tags are visited; literal user JSON is separately tagged.
  const times = [...new Set(ctx.times.map(String))].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
  const ranks = new Map(times.map((t, i) => [t, i]));
  const rank = value => {
    if (object(value) && Object.hasOwn(value, TIME)) return ['timestamp', ranks.get(value[TIME])];
    if (Array.isArray(value)) return value.map(rank);
    return object(value) ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, rank(v)])) : value;
  };
  return { projection: rank(projection), identities: [...ctx.identities, ctx.times.map(String)], deviations: ctx.deviations, rpc: ctx.rpc };
};

const jsonNumbers = (value, seen = new Set()) => {
  if (typeof value === 'number') requireProof(Number.isFinite(value), 'nonfinite JSON number');
  requireProof(!['bigint', 'function', 'symbol'].includes(typeof value), 'non-JSON value');
  if (value && typeof value === 'object') {
    requireProof(!seen.has(value), 'cyclic receipt');
    seen.add(value);
    for (const child of Object.values(value)) jsonNumbers(child, seen);
    seen.delete(value);
  }
};

export const compareStreamReceipts = (input = {}) => {
  const { production, local, expected } = object(input) ? input : {};
  const result = { acquisitionValidated: false, promotionReady: false };
  const sides = {};
  const reasons = {};
  for (const [side, receipt] of Object.entries({ production, local })) {
    try {
      // Receipts are a JSON wire-artifact contract; snapshotting also fails closed
      // on cycles and strips only actual transport-owned undefined defaults.
      jsonNumbers(receipt);
      sides[side] = validate(JSON.parse(JSON.stringify(receipt)), sideContract(expected, side));
    } catch (error) { reasons[side] = [{ code: 'proof', detail: error.message }]; }
  }
  if (Object.keys(reasons).length) return { ...result, classification: 'INDETERMINATE', reasons };
  const p = sides.production; const l = sides.local;
  if (p.deviations.length || l.deviations.length || !equal(p.projection, l.projection)) return { ...result, classification: 'SEMANTIC_MISMATCH', differences: { production: p.projection, local: l.projection }, reasons: { production: p.deviations, local: l.deviations } };
  return { ...result, classification: equal(p.identities, l.identities) ? 'MATCH' : 'EXPECTED_NONDETERMINISM' };
};
export const streamComparisonPhases = PHASES;
export const streamComparisonConstants = Object.freeze({ ABSENT, ABORTED });
