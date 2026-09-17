const PHASES = Object.freeze([
  ['preflight-create-absence', 'GetDocument'], ['preflight-create-absence', 'GetDocument'],
  ['setup-control', 'Write'], ['setup-locked', 'Write'], ['positive-uncontended-stream', 'Write'],
  ['readback-control', 'GetDocument'], ['begin-rw-transaction', 'BeginTransaction'],
  ['get-locked-with-transaction', 'GetDocument'], ['preflight-suffix-absence', 'GetDocument'],
  ['contended-multiwrite-stream', 'Write'], ['readback-contention', 'GetDocument'],
  ['rollback', 'Rollback'], ['post-rollback-positive-stream', 'Write'],
  ['readback-post-rollback', 'GetDocument'], ['cleanup', 'Cleanup'],
]);
const WRITE_PHASES = new Set(['setup-control', 'setup-locked', 'positive-uncontended-stream', 'contended-multiwrite-stream', 'post-rollback-positive-stream']);
const RESOURCE_ROLES = new Set(['control', 'locked', 'suffix']);
const ABSENT = 5;
const ABORTED = 10;

const stable = value => {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
};
const json = value => JSON.stringify(stable(value));
const isObject = value => value && typeof value === 'object' && !Array.isArray(value);
const tokenKey = value => value && typeof value === 'object' && value.type === 'Buffer' && Array.isArray(value.data) ? json(value) : undefined;
const documentPath = (database, value) => typeof value === 'string' && value.startsWith(`${database}/documents/`) ? value.slice(`${database}/documents/`.length) : undefined;
const error = (code, detail) => ({ code, detail });

const sideContract = (expected, side) => {
  const override = isObject(expected?.[side]) ? expected[side] : {};
  const projectId = override.projectId ?? expected?.projectId;
  const documentPrefix = override.documentPrefix ?? expected?.documentPrefix;
  const database = override.database ?? expected?.database ?? (typeof projectId === 'string' ? `projects/${projectId}/databases/(default)` : undefined);
  const sourceResources = override.resources ?? expected?.resources;
  const resources = Array.isArray(sourceResources) ? sourceResources.map(resource => {
    if (typeof resource === 'string') return { path: `${documentPrefix}/${resource}`, role: resource };
    const path = resource?.path ?? (typeof resource?.suffix === 'string' ? `${documentPrefix}/${resource.suffix}` : undefined);
    const relative = typeof path === 'string' && typeof expected?.documentPrefix === 'string' && path.startsWith(`${expected.documentPrefix}/`) ? path.slice(expected.documentPrefix.length + 1) : path;
    return { ...resource, path: typeof relative === 'string' && !relative.startsWith(`${documentPrefix}/`) ? `${documentPrefix}/${relative}` : relative };
  }) : sourceResources;
  return { ...expected, ...override, projectId, database, documentPrefix, resources };
};

const contractErrors = expected => {
  if (!isObject(expected) || expected.version !== 1) return [error('contract', 'expected.version must be 1')];
  const sides = expected.production || expected.local ? ['production', 'local'] : ['local'];
  const errors = [];
  for (const side of sides) {
    const view = sideContract(expected, side);
    if (typeof view.projectId !== 'string' || typeof view.database !== 'string' || typeof view.documentPrefix !== 'string') return [error('contract', `${side} projectId, database, and documentPrefix are required`)];
    if (view.database !== `projects/${view.projectId}/databases/(default)`) return [error('contract', `${side} database does not match projectId`)];
    if (!Array.isArray(view.resources) || view.resources.length !== 3) return [error('contract', `${side} requires exactly three resources` )];
    errors.push(...validateResources(view));
  }
  return errors;
};

const validateResources = expected => {
  const seen = new Set();
  for (const resource of expected.resources) {
    if (!isObject(resource) || typeof resource.path !== 'string' || !RESOURCE_ROLES.has(resource.role) || seen.has(resource.role)) return [error('contract', 'resources must declare the three distinct allowed roles')];
    if (!resource.path.startsWith(`${expected.documentPrefix}/`) || resource.path.includes('..')) return [error('contract', 'resource is outside documentPrefix')];
    seen.add(resource.role);
  }
  return seen.size === 3 ? [] : [error('contract', 'all three resource roles are required')];
};

const phaseReceipts = receipt => Array.isArray(receipt?.observations) ? receipt.observations : [];
const responseEvents = receipt => (receipt?.events ?? []).filter(event => event?.type === 'data').map(event => event.value);
const sendEvents = receipt => (receipt?.events ?? []).filter(event => event?.type === 'send').map(event => event.value);

const markerRole = (value, ownerId) => {
  const marker = value?.fields?.owner?.stringValue;
  if (typeof marker !== 'string' || marker !== `o3-stream:${ownerId}`) return undefined;
  return value?.fields?.role?.stringValue;
};

const validateWrite = (phase, receipt, context, issues) => {
  if (!receipt || receipt.complete !== true || receipt.transportReceiptVersion !== 2 || !Array.isArray(receipt.events)) return issues.push(error('request-proof', `${phase} write receipt lacks transport receipt version 2 or is incomplete`));
  const sends = sendEvents(receipt);
  const data = responseEvents(receipt);
  if (sends.length !== 2) issues.push(error('request-proof', `${phase} must contain one handshake and one write send`));
  if (data.length < 1) issues.push(error('stream', `${phase} has no response data`));
  if (receipt.sentFrames !== sends.length || receipt.completedSendFrames !== sends.length || receipt.receivedFrames !== data.length) issues.push(error('stream', `${phase} frame counters do not match captured events`));
  const handshake = sends[0];
  if (!isObject(handshake) || handshake.database !== context.database || Object.hasOwn(handshake, 'writes') || Object.hasOwn(handshake, 'streamToken')) issues.push(error('handshake', `${phase} handshake is not exact`));
  const request = sends[1];
  if (!isObject(request) || request.database !== context.database || !Array.isArray(request.writes)) issues.push(error('request-proof', `${phase} write frame is missing`));
  const writeSendIndex = (receipt.events ?? []).findIndex(event => event?.type === 'send' && event?.value?.writes);
  const precedingData = writeSendIndex >= 0 ? [...(receipt.events ?? [])].slice(0, writeSendIndex).reverse().find(event => event?.type === 'data')?.value : undefined;
  if (precedingData?.streamToken !== undefined && request?.streamToken !== undefined && json(precedingData.streamToken) !== json(request.streamToken)) issues.push(error('token-relation', `${phase} request token is not the immediately preceding response token`));
  if (data.length > 1 && tokenKey(data[0]?.streamToken) === tokenKey(data[1]?.streamToken)) issues.push(error('token-freshness', `${phase} response stream token was reused`));
  if (receipt.sentFrames !== undefined && receipt.sentFrames > context.maxFrames) issues.push(error('budget', `${phase} exceeds frame budget`));
  const allowed = new Set(context.paths);
  const writes = request?.writes ?? [];
  const expectedCounts = { 'setup-control': 1, 'setup-locked': 1, 'positive-uncontended-stream': 1, 'contended-multiwrite-stream': 2, 'post-rollback-positive-stream': 1 };
  if (expectedCounts[phase] !== undefined && writes.length !== expectedCounts[phase]) issues.push(error('request-proof', `${phase} has an unexpected write cardinality`));
  const expectedValues = {
    'setup-control': ['control', undefined],
    'setup-locked': ['locked', 'before'],
    'positive-uncontended-stream': ['control', 'accepted'],
    'post-rollback-positive-stream': ['locked', 'after-rollback'],
  };
  for (const [index, write] of writes.entries()) {
    const path = documentPath(context.database, write?.update?.name ?? write?.delete);
    if (!path || !allowed.has(path)) issues.push(error('resource', `${phase} targets an undeclared resource`));
    const fields = write?.update?.fields;
    if (fields && markerRole({ fields }, context.ownerId) === undefined) issues.push(error('owner', `${phase} write lacks the receipt owner marker`));
    if (expectedValues[phase] && index === 0) {
      const [role, value] = expectedValues[phase];
      if (path !== context.rolePaths[role] || fields?.role?.stringValue !== role || (value === undefined ? fields?.value !== undefined : fields?.value?.stringValue !== value) || (phase.startsWith('setup-') && write?.currentDocument?.exists !== false)) issues.push(error('request-proof', `${phase} payload is not exact`));
    }
    if (phase === 'contended-multiwrite-stream') {
      const expected = index === 0 ? ['locked', 'must-not-commit'] : ['suffix', 'must-not-commit'];
      if (path !== context.rolePaths[expected[0]] || fields?.role?.stringValue !== expected[0] || fields?.value?.stringValue !== expected[1] || (index === 1 && write?.currentDocument?.exists !== false)) issues.push(error('request-proof', `${phase} payload is not exact`));
    }
  }
};

const validateReceipt = (receipt, expected) => {
  const issues = [];
  if (!isObject(receipt)) return [error('receipt', 'receipt must be an object')];
  if (typeof receipt.ownerId !== 'string' || receipt.ownerId.length === 0) issues.push(error('owner', 'ownerId is required'));
  const observations = phaseReceipts(receipt);
  if (observations.length !== PHASES.length) issues.push(error('sequence', 'observation sequence length is invalid'));
  const paths = expected.resources.map(resource => resource.path);
  const context = { database: expected.database, paths, rolePaths: Object.fromEntries(expected.resources.map(resource => [resource.role, resource.path])), ownerId: receipt.ownerId, maxFrames: expected.maxFramesPerRpc ?? 32 };
  for (let index = 0; index < Math.max(observations.length, PHASES.length); index += 1) {
    const observation = observations[index];
    const expectedPhase = PHASES[index];
    if (!observation || !expectedPhase || observation.phase !== expectedPhase[0]) {
      issues.push(error('sequence', `unexpected phase at index ${index}`));
      continue;
    }
    const phase = expectedPhase[0];
    const inner = observation.receipt;
    const aggregateReadback = phase === 'readback-contention' && isObject(inner) && isObject(inner.locked) && isObject(inner.suffix);
    if (observation.complete !== true || (phase !== 'cleanup' && phase !== 'readback-contention' && inner?.complete !== true)) issues.push(error('incomplete', `${phase} is incomplete`));
    if (aggregateReadback && (inner.locked.complete !== true || inner.suffix.complete !== true)) issues.push(error('incomplete', `${phase} contains an incomplete readback`));
    if (WRITE_PHASES.has(phase)) validateWrite(phase, inner, context, issues);
    if (expectedPhase[1] !== 'Write' && expectedPhase[1] !== 'Cleanup' && inner?.operation !== expectedPhase[1] && phase !== 'readback-contention') issues.push(error('operation', `${phase} operation is invalid`));
    if (phase === 'cleanup') {
      if (!Array.isArray(observation.cleanup) || observation.cleanup.length !== 3) issues.push(error('cleanup', 'cleanup must cover all three resources'));
      for (const item of observation.cleanup ?? []) {
        if (!allResourcePath(item.path, paths) || item.complete !== true || item.absent !== true) issues.push(error('cleanup', 'cleanup item is not a confirmed typed absence'));
        if (item.skipped === true) {
          if (item.receipt?.complete !== true || item.receipt?.operation !== 'GetDocument' || item.receipt?.status?.code !== ABSENT) issues.push(error('cleanup', 'skipped cleanup lacks a typed absence read'));
        } else {
          const sends = sendEvents(item.receipt);
          const request = sends[1];
          if (sends.length !== 2 || !Array.isArray(request?.writes) || request.writes.length !== 1 || request.writes[0]?.delete === undefined || request.writes[0]?.currentDocument?.updateTime === undefined) issues.push(error('cleanup', 'conditional cleanup request proof is incomplete'));
          validateWrite('conditional-delete', item.receipt, context, issues);
          if (documentPath(context.database, request?.writes?.[0]?.delete) !== item.path) issues.push(error('cleanup', 'conditional cleanup targets the wrong resource'));
        }
        if (item.absence?.complete !== true || item.absence?.status?.code !== ABSENT) issues.push(error('cleanup', 'cleanup absence is not a typed NOT_FOUND'));
      }
    }
  }
  const allPaths = new Set(paths);
  const check = value => {
    if (Array.isArray(value)) return value.forEach(check);
    if (!isObject(value)) return;
    for (const [key, child] of Object.entries(value)) {
      if ((key === 'name' || key === 'path') && typeof child === 'string') {
        const path = key === 'name' ? documentPath(expected.database, child) : child;
        if (key === 'name' && child.includes('/documents/') && (path === undefined || !allPaths.has(path))) issues.push(error('resource', `undeclared resource path ${path ?? child}`));
        else if (path !== undefined && !allPaths.has(path)) issues.push(error('resource', `undeclared resource path ${path}`));
      }
      if (key === 'fields' && isObject(child) && typeof child.owner?.stringValue === 'string' && child.owner.stringValue.startsWith('o3-stream:') && child.owner.stringValue !== `o3-stream:${receipt.ownerId}`) issues.push(error('owner', 'receipt contains a foreign owner marker'));
      check(child);
    }
  };
  check(receipt);
  const begin = observations.find(item => item?.phase === 'begin-rw-transaction')?.receipt?.response?.transaction;
  const rollback = observations.find(item => item?.phase === 'rollback')?.receipt?.request?.transaction;
  if (!tokenKey(begin) || !tokenKey(rollback) || tokenKey(begin) !== tokenKey(rollback)) issues.push(error('token-relation', 'rollback token does not equal begin token'));
  const statuses = observations.filter(item => item?.receipt?.status?.code !== undefined).map(item => item.receipt.status.code);
  if (statuses.length > 24) issues.push(error('budget', 'receipt exceeds the finite RPC budget'));
  return issues;
};

const allResourcePath = (path, paths) => typeof path === 'string' && paths.includes(path);

const normalize = (value, context, state = { tokens: new Map(), timestamps: new Map() }, key = '') => {
  if (Array.isArray(value)) return value.map(item => normalize(item, context, state, key));
  if (!isObject(value)) {
    if (typeof value === 'string') {
      if (value === context.ownerId) return '<owner>';
      const path = documentPath(context.database, value);
      if (path !== undefined && context.pathRoles?.[path]) return `<resource:${context.pathRoles[path]}>`;
    }
    return value;
  }
  const token = tokenKey(value);
  if (token && (key === 'transaction' || key === 'streamToken')) {
    if (!state.tokens.has(token)) state.tokens.set(token, `<${key}:${state.tokens.size}>`);
    return state.tokens.get(token);
  }
  if (['updateTime', 'createTime', 'commitTime'].includes(key) && (Object.hasOwn(value, 'seconds') || Object.hasOwn(value, 'nanos'))) {
    const timestamp = json(value);
    if (!state.timestamps.has(timestamp)) state.timestamps.set(timestamp, `<timestamp:${state.timestamps.size}>`);
    return state.timestamps.get(timestamp);
  }
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([childKey, child]) => {
    if (childKey === 'owner' && child?.stringValue === `o3-stream:${context.ownerId}`) return [childKey, { stringValue: '<owner-marker>' }];
    return [childKey, normalize(child, context, state, childKey)];
  }));
};

const semanticProjection = (receipt, expected) => normalize(receipt, { database: expected.database, paths: expected.resources.map(resource => resource.path), pathRoles: Object.fromEntries(expected.resources.map(resource => [resource.path, resource.role])), ownerId: receipt.ownerId });

export const compareStreamReceipts = ({ production, local, expected } = {}) => {
  const contractIssues = contractErrors(expected);
  if (contractIssues.length > 0) return { classification: 'INDETERMINATE', acquisitionValidated: false, promotionReady: false, reasons: contractIssues };
  const productionExpected = sideContract(expected, 'production');
  const localExpected = sideContract(expected, 'local');
  const productionIssues = validateReceipt(production, productionExpected);
  const localIssues = validateReceipt(local, localExpected);
  if (productionIssues.length > 0 || localIssues.length > 0) return { classification: 'INDETERMINATE', acquisitionValidated: false, promotionReady: false, reasons: { production: productionIssues, local: localIssues } };
  const productionProjection = semanticProjection(production, productionExpected);
  const localProjection = semanticProjection(local, localExpected);
  const normalizedEqual = json(productionProjection) === json(localProjection);
  const rawEqual = json(production) === json(local);
  const classification = normalizedEqual ? (rawEqual ? 'MATCH' : 'EXPECTED_NONDETERMINISM') : 'SEMANTIC_MISMATCH';
  return { classification, acquisitionValidated: false, promotionReady: false, ...(classification === 'SEMANTIC_MISMATCH' ? { differences: { production: productionProjection, local: localProjection } } : {}) };
};

export const streamComparisonPhases = PHASES;
export const streamComparisonConstants = Object.freeze({ ABSENT, ABORTED });
