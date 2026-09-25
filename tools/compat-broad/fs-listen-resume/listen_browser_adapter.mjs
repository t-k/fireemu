// Real-browser bindings for the FS-LISTEN-SDK collector.
//
// The Node adapter (`listen_sdk_adapter.mjs`) runs the catalog through the Node
// build of the firebase JS SDK, whose Firestore transport is gRPC. This adapter
// runs the same frozen catalog through the browser build, whose transport is
// WebChannel, inside a headless Chromium that this process owns. The collector
// itself (`listen_collector.mjs`) is served to the page byte-identical and runs
// there; this file only owns what a browser origin cannot do:
//
//   - the local account namespace preflight and the account deletion through
//     the emulator's management route,
//   - the responsibility journal (single-mode runs only),
//   - the receipt, in the same shape as the Node receipt plus the transport
//     evidence: the page's own WebChannel request log and the digests of the
//     SDK bundles the browser actually executed.
//
// Modes are real WebChannel variants: `long-polling` forces long polling (every
// backchannel response closes immediately, `CI=1`); `streaming` disables the
// buffering-proxy auto-detection so the backchannel stays open and chunked
// (`CI=0`). Both run against the same owned `fireemu exec` child, one account
// each, sequentially.
//
// Production is refused exactly as in the Node adapter. Secrets never appear
// in argv, in a log line, in the page URL or in the receipt: the throwaway
// password is read from a private descriptor (or generated) and handed to the
// page in memory through `page.evaluate`.

import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { createLifecycleJournal } from './listen_journal.mjs';
import {
  LOCAL_ADMIN_REQUEST_LIMIT,
  MODE_LOCAL,
  admitMode,
  artifactDigest,
  localAccountRequest,
  localEmulatorEndpoint,
  readPasswordFromFd,
  secondaryAccountFor,
  sourceDigests,
} from './listen_sdk_adapter.mjs';
import { argvIsClean, buildReceipt, redact } from './listen_collector.mjs';
import {
  REQUEST_ROW_COLUMNS,
  captureWebChannel,
  closeAll,
  compactWebChannelRows,
  launchChromium,
  serveStatic,
} from '../../sdk-smoke-browser/browser_harness.mjs';

export const SCHEMA = 'o6-listen-browser-shadow-v1';
export const TRANSPORT = 'browser-webchannel';
export const MODES = Object.freeze(['long-polling', 'streaming']);
export const SDK_BUNDLE_ORIGIN = 'https://www.gstatic.com/firebasejs/';
/** Browser-only sources bound by the receipt in addition to the campaign's list. */
export const BROWSER_BOUND_SOURCES = Object.freeze([
  'tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs',
  'tools/sdk-smoke-browser/browser_harness.mjs',
  'tools/sdk-smoke/web/listen-catalog.html',
  'tools/sdk-smoke/web/listen-catalog.js',
  'tools/sdk-smoke/web/listen-catalog-sha256.js',
]);
const MAX_REQUEST_ROWS = 4000;
/** The lane directory, decoded from the module URL so spaces, `%` and non-ASCII in the checkout path survive. */
export const LANE_DIR = path.dirname(fileURLToPath(import.meta.url));

const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const lifecycleFailure = error =>
  typeof error?.code === 'string' && /^[a-zA-Z0-9_/-]{1,80}$/.test(error.code)
    ? error.code : 'local-lifecycle-operation-failed';

export const parseModes = value => {
  const modes = (value ?? MODES.join(',')).split(',').map(item => item.trim()).filter(Boolean);
  if (!modes.length || modes.some(mode => !MODES.includes(mode)) || new Set(modes).size !== modes.length) {
    throw new Error(`browser modes must be a unique subset of ${MODES.join(',')}`);
  }
  return modes;
};

// Same typed lookup as the Node adapter: the response must be the emulator's
// own shape and must name exactly the account this run owns.
export const accountLookup = (response, email, uid = null) => {
  if (!plainObject(response) || response.status !== 200 || !plainObject(response.body)) {
    throw new Error('account lookup unavailable');
  }
  const body = response.body;
  if (Object.keys(body).some(key => key !== 'kind' && key !== 'users') ||
      ('kind' in body && body.kind !== 'identitytoolkit#GetAccountInfoResponse')) {
    throw new Error('account lookup ambiguous');
  }
  const users = 'users' in body ? body.users :
    Object.keys(body).length === 1 && body.kind === 'identitytoolkit#GetAccountInfoResponse' ? [] : null;
  if (!Array.isArray(users) || users.length > 1) throw new Error('typed account lookup required');
  if (!users.length) return null;
  const user = users[0];
  if (!plainObject(user) || typeof user.localId !== 'string' || !user.localId ||
      user.email !== email || (uid !== null && user.localId !== uid)) {
    throw new Error('owned account identity mismatch');
  }
  return user.localId;
};

/** The page result must be the plain shape `listen-catalog.js` returns. */
export const validatePageResult = (result, catalog) => {
  if (!plainObject(result)) throw new Error('page returned no result');
  if (result.pageError) throw Object.assign(new Error('page lifecycle failed'), { code: result.pageError });
  const required = ['sdkVersion', 'mode', 'principals', 'caseRecords', 'cleanup',
    'cleanupPasses', 'totalDeleted', 'thrown', 'lifecycle', 'budget', 'cleanupBudget'];
  for (const key of required) {
    if (!Object.hasOwn(result, key)) throw new Error(`page result missing ${key}`);
  }
  const principal = value => plainObject(value) && typeof value.signupAttempted === 'boolean' &&
    (value.uid === null || typeof value.uid === 'string');
  if (!Array.isArray(result.caseRecords) || !plainObject(result.budget) ||
      !plainObject(result.cleanupBudget) || !plainObject(result.lifecycle) ||
      !plainObject(result.principals) || !principal(result.principals.primary) ||
      !principal(result.principals.secondary)) {
    throw new Error('page result has the wrong shape');
  }
  if (result.caseRecords.length > catalog.cases.length) throw new Error('page returned extra cases');
  return result;
};

/** Assemble one mode's receipt in the Node receipt shape plus transport evidence. */
export const assembleReceipt = ({ env, repoRoot, campaignRecord, catalog, boundSources, projectId,
  nonce, mode, pageResult, accountCleanup, localAdminRequests, browser, webchannel, sdkBundleDigests }) => {
  const lifecycle = {
    failure: pageResult.lifecycle.failure ?? null,
    accountCleanup,
    clients: pageResult.lifecycle.clients,
    localAdminRequests,
    localAdminRequestLimit: LOCAL_ADMIN_REQUEST_LIMIT,
  };
  lifecycle.complete = lifecycle.failure === null && accountCleanup.complete === true &&
    pageResult.lifecycle.clients?.complete === true;
  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: campaignRecord.campaignDigest,
    catalogDigest: catalog.catalogDigest ?? null,
    environment: {
      kind: 'local-fireemu',
      transport: TRANSPORT,
      webchannelMode: mode,
      browser: { name: browser.name, version: browser.version },
      node: process.versions.node,
      sourceCommit: env.O6_LISTEN_SOURCE_COMMIT ?? null,
      firebaseSdk: env.O6_LISTEN_SDK_VERSION ?? null,
      firebaseSdkReportedByPage: pageResult.sdkVersion ?? null,
      sdkSource: `${SDK_BUNDLE_ORIGIN}${env.O6_LISTEN_SDK_VERSION ?? ''}`,
      sdkBundleDigests,
      fireemuBinary: env.O6_LISTEN_FIREEMU_BINARY
        ? path.relative(repoRoot, env.O6_LISTEN_FIREEMU_BINARY) : null,
      fireemuBinaryDigest: artifactDigest(env.O6_LISTEN_FIREEMU_BINARY),
      fireemuSourceCommit: env.O6_LISTEN_FIREEMU_COMMIT ?? null,
      rulesPath: env.O6_LISTEN_RULES_PATH ? path.relative(repoRoot, env.O6_LISTEN_RULES_PATH) : null,
      rulesDigest: artifactDigest(env.O6_LISTEN_RULES_PATH),
      projectId,
      nonceDigest: createHash('sha256').update(nonce).digest('hex'),
    },
    caseRecords: pageResult.caseRecords,
    cleanup: pageResult.cleanup,
    cleanupPasses: pageResult.cleanupPasses,
    totalDeleted: pageResult.totalDeleted,
    budget: { snapshot: () => pageResult.budget },
    cleanupBudget: { snapshot: () => pageResult.cleanupBudget },
    thrown: pageResult.thrown,
    productionExecuted: false,
  });
  receipt.permission = campaignRecord.campaign.permission ?? null;
  receipt.sdkResolved = campaignRecord.campaign.sdk;
  receipt.transport = TRANSPORT;
  receipt.webchannel = redact({ mode, summary: webchannel.summary(),
    columns: [...REQUEST_ROW_COLUMNS], rows: compactWebChannelRows(webchannel.rows, MAX_REQUEST_ROWS) });
  receipt.transportTimeline = pageResult.caseRecords
    .flatMap(record => (record.transportTimeline ?? []).map(entry => ({ ...entry, caseId: record.caseId })))
    .sort((left, right) => left.atMs - right.atMs);
  receipt.sourceDigests = sourceDigests(repoRoot, [...boundSources, ...BROWSER_BOUND_SOURCES]);
  receipt.lifecycle = lifecycle;
  receipt.complete = receipt.complete && lifecycle.complete &&
    pageResult.caseRecords.length === catalog.cases.length &&
    pageResult.caseRecords.every((row, index) => row.caseId === catalog.cases[index].caseId);
  return receipt;
};

const withDeadline = (promise, ms, label) => {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(label), { code: 'page-deadline' })), ms);
    }),
  ]).finally(() => clearTimeout(timer));
};

/** Drive one transport mode through a fresh page; always closes the page. */
export const runMode = async ({ env, repoRoot, chromium, serverOrigin, firestore, auth, projectId,
  nonce, account, secondaryAccount, catalog, campaignRecord, budgetSpec, boundSources, mode,
  stepTimeoutMs, deadlineMs, request = localAccountRequest, checkpoint = null }) => {
  let accountCalls = 0;
  const call = async (operation, body) => {
    if (accountCalls >= LOCAL_ADMIN_REQUEST_LIMIT) throw new Error('local account request budget exhausted');
    accountCalls++;
    return request(auth.raw, projectId, operation, body, 12000);
  };
  const accounts = { primary: account, secondary: secondaryAccount };
  for (const row of Object.values(accounts)) {
    const found = accountLookup(await call('lookup', { email: [row.email] }), row.email);
    if (found !== null) throw new Error('local account namespace occupied');
  }
  // The page may only revoke a principal this run owns: the uid it names must
  // resolve, through the management route, to one of the run's two emails.
  const ownedEmails = new Set(Object.values(accounts).map(row => row.email));
  const revoke = async (uid, email) => {
    if (typeof uid !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(uid) || !ownedEmails.has(email)) {
      throw new Error('revocation outside this run');
    }
    if (accountLookup(await call('lookup', { localId: [uid] }), email, uid) !== uid) {
      throw new Error('revocation target is not this run\'s account');
    }
    const validSince = String(Math.floor(Date.now() / 1000));
    const updated = await call('update', { localId: uid, validSince });
    if (!plainObject(updated) || updated.status !== 200 || !plainObject(updated.body) ||
        'error' in updated.body || updated.body.localId !== uid) throw new Error('revocation unconfirmed');
  };
  const context = await chromium.browser.newContext();
  const page = await context.newPage();
  const webchannel = captureWebChannel(page, firestore.port);
  const sdkBundleDigests = {};
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(lifecycleFailure(error)));
  page.on('response', response => {
    const url = response.url();
    if (!url.startsWith(SDK_BUNDLE_ORIGIN) || response.status() !== 200) return;
    response.body().then(body => {
      sdkBundleDigests[url.slice(SDK_BUNDLE_ORIGIN.length)] =
        createHash('sha256').update(body).digest('hex');
    }, () => {});
  });
  let pageResult;
  let accountCleanup = { complete: false, outcome: 'not-attempted' };
  try {
    if (checkpoint) {
      await page.exposeFunction('__o6Checkpoint', (phase, value) => {
        checkpoint(phase, value === undefined ? {} : value);
      });
    }
    await page.exposeFunction('__o6Revoke', revoke);
    await page.goto(`${serverOrigin}/listen-catalog.html`, { waitUntil: 'load' });
    await page.waitForSelector('body[data-catalog-ready="true"]', { timeout: 30000 });
    const config = { projectId, firestorePort: firestore.port, authPort: auth.port, account,
      secondaryAccount, nonce, catalog, budgetSpec, mode, stepTimeoutMs, deadlineMs };
    const raw = await withDeadline(
      page.evaluate(value => window.__o6RunCatalog(value), config),
      deadlineMs + budgetSpec.cleanupReserveSeconds * 1000 + 30000,
      'browser catalog run exceeded its deadline',
    );
    pageResult = validatePageResult(raw, catalog);
    accountCleanup = await cleanupAccounts({ call, accounts, pageResult });
    if (checkpoint) {
      checkpoint('lifecycle-result', {
        complete: pageResult.lifecycle.failure === null && accountCleanup.complete === true &&
          pageResult.lifecycle.clients?.complete === true && pageResult.cleanup?.complete === true,
        accountCleanupComplete: accountCleanup.complete === true,
        clientsComplete: pageResult.lifecycle.clients?.complete === true,
        documentsCleanupComplete: pageResult.cleanup?.complete === true,
      });
    }
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
  }
  const receipt = assembleReceipt({ env, repoRoot, campaignRecord, catalog, boundSources, projectId,
    nonce, mode, pageResult, accountCleanup, localAdminRequests: accountCalls,
    browser: chromium, webchannel, sdkBundleDigests });
  if (pageErrors.length) {
    receipt.complete = false;
    receipt.thrown = receipt.thrown ?? `page-error:${pageErrors[0]}`;
  }
  return receipt;
};

const cleanupOne = async ({ call, account, principal, documentsComplete }) => {
  const { uid, signupAttempted } = principal;
  if (!signupAttempted) return { complete: true, outcome: 'not-created-by-this-run' };
  if (uid !== null && !documentsComplete) {
    return { complete: false, outcome: 'retained-for-document-recovery' };
  }
  const selector = uid ? { localId: [uid] } : { email: [account.email] };
  const found = accountLookup(await call('lookup', selector), account.email, uid);
  if (uid === null) return { complete: false, outcome: 'creation-unconfirmed', observedAbsent: found === null };
  if (found === null) return { complete: true, outcome: 'server-confirmed-absent' };
  const deleted = await call('delete', { localId: uid });
  if (!plainObject(deleted) || deleted.status !== 200 || !plainObject(deleted.body) ||
      'error' in deleted.body || 'users' in deleted.body) throw new Error('account delete unconfirmed');
  const after = accountLookup(await call('lookup', { localId: [uid] }), account.email, uid);
  return { complete: after === null, outcome: after === null ? 'deleted-and-absent' : 'still-present' };
};

/** Same combined row as the Node adapter: every account attempted, first incomplete outcome named. */
export const cleanupAccounts = async ({ call, accounts, pageResult }) => {
  const rows = {};
  let failure = null;
  for (const [name, account] of Object.entries(accounts)) {
    try {
      rows[name] = await cleanupOne({ call, account, principal: pageResult.principals[name],
        documentsComplete: pageResult.cleanup?.complete === true });
    } catch (error) {
      rows[name] = { complete: false, outcome: 'account-cleanup-unconfirmed', failure: lifecycleFailure(error) };
      failure = failure ?? error;
    }
  }
  const values = Object.values(rows);
  const complete = values.every(row => row.complete === true);
  const outcomes = new Set(values.map(row => row.outcome));
  const combined = { complete, outcome: complete && outcomes.size === 1 ? values[0].outcome
    : complete ? 'complete' : values.find(row => row.complete !== true).outcome, accounts: rows };
  if (failure) combined.failure = lifecycleFailure(failure);
  return combined;
};

export const main = async ({ env = process.env, argv = process.argv,
  emit = value => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) } = {}) => {
  if (!argvIsClean(argv)) {
    throw new Error('refusing to start: a secret-shaped value was passed on the command line');
  }
  const admitted = admitMode(env.O6_LISTEN_MODE ?? MODE_LOCAL, { permission: env.O6_LISTEN_PERMISSION });
  if (!admitted.ok) {
    process.stderr.write(`${admitted.error}\n`);
    process.exitCode = 2;
    return null;
  }
  const firestoreHost = env.FIRESTORE_EMULATOR_HOST;
  const authHost = env.FIREBASE_AUTH_EMULATOR_HOST;
  if (!firestoreHost || !authHost) {
    throw new Error('local mode requires FIRESTORE_EMULATOR_HOST and FIREBASE_AUTH_EMULATOR_HOST');
  }
  const firestore = localEmulatorEndpoint(firestoreHost);
  const auth = { ...localEmulatorEndpoint(authHost), raw: authHost };
  // The page can only reach IPv4 loopback by the address it is given.
  if (firestore.host !== '127.0.0.1' || auth.host !== '127.0.0.1') {
    throw new Error('the browser lane requires 127.0.0.1 emulator endpoints');
  }
  const repoRoot = env.O6_REPO_ROOT ?? process.cwd();
  const playwrightDir = env.O6_PLAYWRIGHT_MODULE_DIR ?? path.join(repoRoot, 'tools/sdk-smoke-browser');
  const webDir = path.join(repoRoot, 'tools/sdk-smoke/web');
  const laneDir = LANE_DIR;
  const modes = parseModes(env.O6_LISTEN_BROWSER_MODES);
  const projectId = env.GOOGLE_CLOUD_PROJECT ?? 'demo-app';

  const catalog = JSON.parse(readFileSync(
    env.O6_LISTEN_CATALOG_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-cases.json'), 'utf8'));
  if (!env.O6_LISTEN_CAMPAIGN_PATH) throw new Error('set O6_LISTEN_CAMPAIGN_PATH to a compiled campaign record');
  const campaignRecord = JSON.parse(readFileSync(env.O6_LISTEN_CAMPAIGN_PATH, 'utf8'));
  const { budget: budgetSpec, boundSources } = JSON.parse(readFileSync(
    env.O6_LISTEN_BUDGET_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-budget.json'), 'utf8'));
  const nonce = env.O6_LISTEN_NONCE ?? campaignRecord.nonce ?? randomBytes(16).toString('hex');
  if (!/^[0-9a-f]{32}$/.test(nonce) || !/^[a-zA-Z0-9_-]{1,128}$/.test(projectId) ||
      (typeof campaignRecord.nonce === 'string' && campaignRecord.nonce !== nonce) ||
      !Array.isArray(catalog.cases) || catalog.cases.length === 0 ||
      catalog.cases.some(row => typeof row?.caseId !== 'string' || !row.caseId) ||
      new Set(catalog.cases.map(row => row.caseId)).size !== catalog.cases.length ||
      !plainObject(campaignRecord.campaign) || !plainObject(budgetSpec) ||
      !Array.isArray(boundSources) || boundSources.some(value => typeof value !== 'string')) {
    throw new Error('invalid local campaign configuration');
  }
  const deadlineMs = Number(env.O6_LISTEN_DEADLINE_MS ?? '300000');
  const stepTimeoutMs = Number(env.O6_LISTEN_STEP_TIMEOUT_MS ?? '15000');
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0 ||
      !Number.isSafeInteger(stepTimeoutMs) || stepTimeoutMs <= 0) {
    throw new Error('positive finite local timeouts required');
  }
  if (env.O6_LISTEN_JOURNAL_DIR && modes.length !== 1) {
    throw new Error('the responsibility journal covers one account lifecycle: run one mode per journal');
  }
  const checkpoint = env.O6_LISTEN_JOURNAL_DIR
    ? createLifecycleJournal(env.O6_LISTEN_JOURNAL_DIR, { nonce, projectId }) : null;
  const password = readPasswordFromFd(env.O6_LISTEN_PASSWORD_FD) ?? randomBytes(24).toString('hex');
  const account = { name: 'throwaway', email: `o6-${nonce}@example.test`, password };
  const secondaryAccount = secondaryAccountFor(nonce,
    readPasswordFromFd(env.O6_LISTEN_SECONDARY_PASSWORD_FD) ?? randomBytes(24).toString('hex'));

  const receipts = {};
  const startedAt = performance.now();
  const server = await serveStatic({ '/': webDir, '/collector/': laneDir });
  let chromium = null;
  try {
    chromium = await launchChromium(playwrightDir);
    for (const mode of modes) {
      receipts[mode] = await runMode({ env, repoRoot, chromium, serverOrigin: server.origin,
        firestore, auth, projectId, nonce, account, secondaryAccount, catalog, campaignRecord,
        budgetSpec, boundSources, mode, stepTimeoutMs, deadlineMs, checkpoint });
    }
  } finally {
    await closeAll([server.close, ...(chromium ? [chromium.close] : [])]);
  }
  const document = {
    schema: SCHEMA,
    transport: TRANSPORT,
    productionExecuted: false,
    modes,
    elapsedMs: Math.trunc(performance.now() - startedAt),
    receipts,
    complete: modes.every(mode => receipts[mode]?.complete === true),
  };
  await emit(document);
  if (!document.complete) process.exitCode = 2;
  return document;
};

const invokedDirectly = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (invokedDirectly) {
  main().catch(error => {
    process.stderr.write(`${lifecycleFailure(error)}\n`);
    process.exitCode = 1;
  });
}
