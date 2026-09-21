// Local expectation checking only: no SDK, network, production admission, or
// assertion that this receipt was produced by the current source/binary.
// Usage: node local_shadow_check.mjs [--legacy-lifecycle] <receipt.json>
// Old immutable receipts without lifecycle evidence require the explicit flag,
// and O6_LISTEN_CATALOG_PATH must name the catalog of their era
// (spec/compatibility/fs-listen-sdk-cases-historical.json).
import { constants, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const empty = value => Array.isArray(value) && value.length === 0;
const count = value => Number.isSafeInteger(value) && value >= 0;
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const equal = isDeepStrictEqual;
const sortedKeys = value => Object.keys(value).sort();
// The owned resources are whatever the catalog's cases declare: five documents
// for the single-principal catalog, six once the second principal's private
// document joined it.
const resourcesOf = catalog => [...new Set(catalog.cases.flatMap(row => row.documents ?? []))].sort();
const budgetKinds = ['deletes', 'listeners', 'reads', 'snapshots', 'writes'];
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : object(value) ? Object.fromEntries(sortedKeys(value).map(key => [key, canonical(value[key])])) : value;
const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))
  .replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)).digest('hex');

export const parseEvidence = text => {
  const parsed = JSON.parse(text);
  // JSON.parse has already checked the grammar. This second, bounded scan
  // rejects repeated *decoded* object keys that it would silently replace.
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; }
      const parent = stack.at(-1);
      if (parent?.keys && parent.nextKey) {
        const key = JSON.parse(text.slice(start, i + 1));
        if (parent.keys.has(key)) throw new Error('duplicate-key');
        parent.keys.add(key); parent.nextKey = false;
      }
    } else if (c === '{' || c === '[') {
      stack.push(c === '{' ? { keys: new Set(), nextKey: true } : {});
      if (stack.length > 128) throw new Error('json-depth-limit');
    } else if (c === '}' || c === ']') stack.pop();
    else if (c === ',' && stack.at(-1)?.keys) stack.at(-1).nextKey = true;
  }
  const finite = value => {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('non-finite-json');
    if (value && typeof value === 'object') Object.values(value).forEach(finite);
  };
  finite(parsed);
  return parsed;
};

const readEvidence = filename => {
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 8 * 1024 * 1024) throw new Error('invalid-evidence-file');
    const buffer = Buffer.alloc(info.size + 1);
    let length = 0, received;
    while (length < buffer.length && (received = readSync(fd, buffer, length, buffer.length - length, null)) > 0) length += received;
    if (length !== info.size || fstatSync(fd).size !== info.size) throw new Error('evidence-size-changed');
    return parseEvidence(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)));
  } finally { closeSync(fd); }
};

export const checkShadow = (receipt, catalog, { legacyLifecycle = false } = {}) => {
  const issues = [];
  const require = (ok, issue) => { if (!ok) issues.push(issue); return ok; };
  const result = () => ({ kind: 'local-listen-expectation-check', complete: issues.length === 0,
    currentArtifactVerified: false, productionCompatibilityVerified: false,
    legacyLifecycle: !Object.hasOwn(receipt ?? {}, 'lifecycle'), issues });
  if (!require(object(receipt) && object(catalog), 'object-input-required')) return result();
  if (!require(catalog.schema === 'o6-listen-sdk-cases-v1' &&
      Array.isArray(catalog.cases) && catalog.cases.length > 0, 'catalog-invalid')) return result();
  const { catalogDigest, ...payload } = catalog;
  require(hex(catalogDigest) && digest(payload) === catalogDigest, 'catalog-digest-mismatch');
  require(receipt.schema === 'o6-listen-observation-v1' && receipt.caseId === 'FS-LISTEN-SDK', 'receipt-contract');
  require(receipt.productionExecuted === false && receipt.environment?.kind === 'local-fireemu', 'not-local-evidence');
  require(receipt.complete === true && receipt.thrown === null, 'collection-incomplete');
  require(receipt.catalogDigest === catalogDigest, 'receipt-catalog-mismatch');
  const expectedIds = catalog.cases.map(row => row.caseId);
  if (!require(expectedIds.every(id => typeof id === 'string' && id.length > 0) &&
      new Set(expectedIds).size === expectedIds.length && Array.isArray(receipt.cases) &&
      equal(receipt.cases.map(row => row?.caseId), expectedIds), 'case-set-or-order')) return result();
  for (let i = 0; i < catalog.cases.length; i++) {
    const spec = catalog.cases[i], row = receipt.cases[i];
    const fields = spec.comparedFields;
    require(object(row) && row.complete === true && row.listenersClosed === true &&
      empty(row.failures) && empty(row.invariantViolations), `case-${i}-incomplete`);
    require(row.role === spec.role && row.comparison === spec.comparison, `case-${i}-identity`);
    if (!require(Array.isArray(fields) && fields.length > 0 &&
        fields.every(f => typeof f === 'string') && new Set(fields).size === fields.length &&
        Array.isArray(spec.expectedLocal) && Array.isArray(row.observed), `case-${i}-shape`)) continue;
    require(equal(row.comparedFields, fields), `case-${i}-fields`);
    const projection = rows => rows.map(event => object(event) && fields.every(f => Object.hasOwn(event, f))
      ? Object.fromEntries(fields.map(f => [f, event[f]])) : undefined);
    const actual = projection(row.observed), expected = projection(spec.expectedLocal);
    require(!actual.includes(undefined) && !expected.includes(undefined) && equal(actual, expected), `case-${i}-mismatch`);
  }
  for (const key of ['budget', 'cleanupBudget']) {
    const b = receipt[key];
    require(object(b) && object(b.used) && object(b.limits) && equal(sortedKeys(b.used), budgetKinds) &&
      equal(sortedKeys(b.limits), budgetKinds) && b.exhausted === false && empty(b.exceeded) &&
      Number.isFinite(b.deadlineMs) && b.deadlineMs > 0 && budgetKinds.every(k =>
        count(b.used[k]) && count(b.limits[k]) && b.used[k] <= b.limits[k]), `${key}-invalid-or-exhausted`);
  }
  const resources = resourcesOf(catalog);
  const cleanupValid = value => object(value) && value.complete === true && Array.isArray(value.rows) &&
    equal(value.rows.map(row => row?.name).sort(), resources) && value.rows.every(row =>
      hex(row.pathDigest) && row.detail === null &&
      ['not-created', 'deleted-and-absent', 'already-deleted-earlier'].includes(row.outcome));
  require(cleanupValid(receipt.cleanup) && empty(receipt.cleanup?.unproven) &&
    count(receipt.cleanup?.deleted) && receipt.cleanup.deleted === receipt.cleanup.rows.filter(r => r.outcome === 'deleted-and-absent').length,
    'cleanup-unproven');
  const passes = receipt.cleanupPasses;
  if (require(Array.isArray(passes) && equal(passes.map(p => p?.pass), [...expectedIds, 'final']), 'cleanup-passes-incomplete')) {
    require(passes.every(p => cleanupValid(p) && count(p.deleted) &&
      p.deleted === p.rows.filter(r => r.outcome === 'deleted-and-absent').length), 'cleanup-pass-unproven');
    require(count(receipt.totalDeleted) && receipt.totalDeleted === passes.reduce((sum, p) => sum + p.deleted, 0), 'cleanup-count-mismatch');
    require(equal(receipt.cleanup?.rows, passes.at(-1).rows), 'final-cleanup-mismatch');
    const finalRows = receipt.cleanup?.rows;
    if (Array.isArray(finalRows)) require(passes.every(p => Array.isArray(p.rows) &&
      p.rows.every(r => r.pathDigest === finalRows.find(f => f.name === r.name)?.pathDigest)), 'cleanup-resource-changed');
  }
  if (Object.hasOwn(receipt, 'lifecycle')) {
    const l = receipt.lifecycle;
    require(object(l) && l.complete === true && l.failure === null && l.accountCleanup?.complete === true &&
      l.clients?.complete === true, 'lifecycle-incomplete');
  } else require(legacyLifecycle === true, 'missing-lifecycle-use-explicit-legacy-mode');
  return result();
};

export const main = (args = process.argv.slice(2), env = process.env) => {
  const legacyLifecycle = args[0] === '--legacy-lifecycle';
  if (legacyLifecycle) args = args.slice(1);
  if (args.length !== 1) { console.error('Usage: local_shadow_check.mjs [--legacy-lifecycle] <receipt.json>'); return 2; }
  try {
    const report = checkShadow(readEvidence(args[0]), readEvidence(env.O6_LISTEN_CATALOG_PATH ??
      'spec/compatibility/fs-listen-sdk-cases.json'), { legacyLifecycle });
    console.log(JSON.stringify(report));
    return report.complete ? 0 : 1;
  } catch {
    // Do not publish file contents, raw exceptions, paths, or token-bearing rows.
    console.error('Invalid or unreadable local expectation evidence.'); return 2;
  }
};
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = main();
