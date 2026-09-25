// Real firebase JS SDK bindings for the FS-LISTEN-SDK collector.
//
// This file owns every effect. It is the only place that imports the SDK, and
// it runs in one of two modes:
//
//   local       against an owned fireemu instance, using the emulator hosts the
//               parent `fireemu exec` child environment provides. This is the
//               local shadow.
//   production  refused. A production run needs a campaign-scoped permission
//               that this repository does not contain, so the adapter exits
//               before constructing a client.
//
// Secrets never appear in argv, in a log line or in the receipt. The password
// for the throwaway account is read from a private file descriptor when one is
// supplied, held in a local binding and never returned.

import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { createLifecycleJournal } from './listen_journal.mjs';
import { parseEvidence } from './local_shadow_check.mjs';

import {
  argvIsClean,
  buildReceipt,
  createBudget,
  createRecoveryBudget,
  classifyCleanup,
  runCleanup,
  ownedPaths,
  runCatalog,
  secondaryPaths,
} from './listen_collector.mjs';

/** Client names and the account each one signs in as. */
export const CLIENT_ACCOUNTS = Object.freeze({ primary: 'account', witness: 'account',
  secondary: 'secondaryAccount' });
/** Cleanup of the second principal's document goes through its own client. */
export const CLEANUP_CLIENT_FOR = Object.freeze({ privateB: 'secondary' });
/** Local management calls per run: two preflights, at most two for one revocation
 * (the browser lane confirms the target first), three per account cleanup. */
export const LOCAL_ADMIN_REQUEST_LIMIT = 10;

export const MODE_LOCAL = 'local';
export const MODE_PRODUCTION = 'production';

export const resolveSdk = async moduleDir => {
  const require = createRequire(path.join(moduleDir, 'noop.cjs'));
  const load = async specifier =>
    import(pathToFileURL(require.resolve(specifier, { paths: [moduleDir] })).href);
  const [app, firestore, auth] = await Promise.all([
    load('firebase/app'),
    load('firebase/firestore'),
    load('firebase/auth'),
  ]);
  return { ...app, ...firestore, ...auth };
};

/** Reject a production run: no campaign permission exists in this repository. */
export const admitMode = (mode, { permission } = {}) => {
  if (mode === MODE_LOCAL) return { ok: true, value: MODE_LOCAL };
  if (mode !== MODE_PRODUCTION) return { ok: false, error: `unknown-mode:${mode}` };
  if (!permission) {
    return {
      ok: false,
      error:
        'production is BLOCKED_OWNER: supply a campaign-scoped o6-listen-sdk permission and a ' +
        'reviewed prepared manifest before any oracle run',
    };
  }
  return { ok: false, error: 'production execution is not implemented in this preparation lane' };
};

export const readPasswordFromFd = fd => {
  if (fd === undefined || fd === null || fd === '') return null;
  const text = String(fd);
  const parsed = /^[1-9][0-9]*$/.test(text) ? Number(text) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 3) throw new Error('password fd must be a private descriptor');
  return readFileSync(parsed, 'utf8').trim();
};

const nameOfFactory = paths => {
  const names = new Map(Object.entries(paths).map(([name, value]) => [value, name]));
  return value => names.get(value) ?? String(value).split('/').at(-1);
};

export const createDeps = (sdk, clients, { revoke = null } = {}) => ({
  // Transport timeline timestamps are part of the cross-language receipt
  // contract, whose schema represents elapsed milliseconds as integers.
  now: () => Math.trunc(performance.now()),
  sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
  firestore: {
    async setDoc(client, docPath, fields) {
      await sdk.setDoc(sdk.doc(clients[client].db, docPath), fields);
    },
    async deleteDoc(client, docPath, precondition = null) {
      if (precondition !== null) {
        throw new Error('client SDK cannot apply an updateTime delete precondition');
      }
      // Ordinary observation steps intentionally exercise client deleteDoc.
      await sdk.deleteDoc(sdk.doc(clients[client].db, docPath));
    },
    async deleteOwnedDoc(client, docPath, condition) {
      if (!condition || typeof condition.owner !== 'string' || !condition.owner ||
          Object.keys(condition).length !== 1) throw new Error('owned cleanup marker required');
      const db = clients[client].db;
      const ref = sdk.doc(db, docPath);
      // The transaction binds its delete to the version it reads. One attempt
      // keeps the additional ownership read within the collector's reservation.
      return sdk.runTransaction(db, async transaction => {
        const snapshot = await transaction.get(ref);
        const exists = snapshot.exists();
        if (typeof exists !== 'boolean') throw new Error('typed transaction presence required');
        if (!exists) return;
        if (snapshot.data()?.owner !== condition.owner) {
          throw Object.assign(new Error('owned marker changed'), { code: 'failed-precondition' });
        }
        transaction.delete(ref);
      }, { maxAttempts: 1 });
    },
    async getDoc(client, docPath) {
      const snapshot = await sdk.getDocFromServer(sdk.doc(clients[client].db, docPath));
      if (snapshot.metadata?.fromCache !== false || snapshot.metadata?.hasPendingWrites !== false) {
        throw new Error('server-confirmed cleanup snapshot required');
      }
      const exists = snapshot.exists();
      if (typeof exists !== 'boolean') throw new Error('typed document presence required');
      return { exists, fields: exists ? snapshot.data() : null, updateTime: null };
    },
    onDocSnapshot(client, docPath, options, onNext, onError) {
      return sdk.onSnapshot(sdk.doc(clients[client].db, docPath), options, {
        next: snapshot =>
          onNext({
            path: docPath,
            exists: snapshot.exists(),
            fromCache: snapshot.metadata.fromCache,
            hasPendingWrites: snapshot.metadata.hasPendingWrites,
          }),
        error: onError,
      });
    },
    onQuerySnapshot(client, spec, options, onNext, onError) {
      const collection = sdk.collection(clients[client].db, `${spec.parent}/${spec.target}`);
      const constraints = [
        sdk.where(spec.where[0], spec.where[1], spec.where[2]),
        sdk.orderBy(spec.orderBy?.[0] ?? spec.where[0], spec.orderBy?.[1] ?? 'asc'),
        sdk.limit(spec.limit ?? 10),
      ];
      return sdk.onSnapshot(sdk.query(collection, ...constraints), options, {
        next: snapshot =>
          onNext({
            docs: snapshot.docs.map(entry => entry.ref.path),
            changes: snapshot.docChanges().map(change => ({
              type: change.type,
              path: change.doc.ref.path,
              oldIndex: change.oldIndex,
              newIndex: change.newIndex,
            })),
            fromCache: snapshot.metadata.fromCache,
            hasPendingWrites: snapshot.metadata.hasPendingWrites,
          }),
        error: onError,
      });
    },
    async disableNetwork(client) {
      await sdk.disableNetwork(clients[client].db);
    },
    async enableNetwork(client) {
      await sdk.enableNetwork(clients[client].db);
    },
  },
  auth: {
    async signIn(client, account) {
      const target = clients[client];
      if (account && account !== target.account.name) {
        throw new Error(`unknown sign-in account: ${account}`);
      }
      await sdk.signInWithEmailAndPassword(target.auth, target.account.email, target.account.password);
    },
    async signOut(client) {
      await sdk.signOut(clients[client].auth);
    },
    // Revoke the sessions of whoever this client is signed in as, through the
    // management route the adapter owns. The SDK itself has no such API.
    async revoke(client) {
      const uid = clients[client].auth.currentUser?.uid;
      if (typeof uid !== 'string' || !uid) throw new Error('revoke needs a signed-in client');
      if (typeof revoke !== 'function') throw new Error('session revocation is unavailable');
      await revoke(uid);
    },
  },
});

/** The second principal's account: derived from the nonce like the first one. */
export const secondaryAccountFor = (nonce, password) =>
  ({ name: 'second', email: `o6-${nonce}-b@example.test`, password });

/** Digest of the runtime under test, so a receipt names the binary that produced it. */
export const artifactDigest = absolutePath => {
  if (!absolutePath) return null;
  try {
    return createHash('sha256').update(readFileSync(absolutePath)).digest('hex');
  } catch {
    return 'unreadable';
  }
};

export const sourceDigests = (repoRoot, relativePaths) =>
  Object.fromEntries(
    relativePaths.map(relative => {
      const absolute = path.join(repoRoot, relative);
      try {
        return [relative, createHash('sha256').update(readFileSync(absolute)).digest('hex')];
      } catch {
        return [relative, 'missing'];
      }
    }),
  );

/** Only explicit numeric loopback host:port strings can start a local SDK. */
export const localEmulatorEndpoint = value => {
  if (typeof value !== 'string') throw new Error('numeric loopback emulator endpoint required');
  const match = /^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/.exec(value);
  const port = match ? Number(match[2]) : NaN;
  if (!match || port < 1 || port > 65535) throw new Error('numeric loopback emulator endpoint required');
  return { host: match[1] === '[::1]' ? '::1' : match[1], port, origin: `http://${value}` };
};

const buildClients = async (sdk, { projectId, firestoreHost, authHost, account, secondaryAccount,
  nonce, clients }) => {
  const firestoreEndpoint = localEmulatorEndpoint(firestoreHost);
  const authEndpoint = localEmulatorEndpoint(authHost);
  const accounts = { account, secondaryAccount };
  for (const [name, accountKey] of Object.entries(CLIENT_ACCOUNTS)) {
    const account = accounts[accountKey];
    const app = sdk.initializeApp({ projectId, apiKey: 'fake-api-key' }, `o6-${nonce}-${name}`);
    // Register ownership before any subsequent initializer can throw.
    clients[name] = { app, account };
    const db = sdk.getFirestore(app);
    clients[name].db = db;
    sdk.connectFirestoreEmulator(db, firestoreEndpoint.host, firestoreEndpoint.port);
    const auth = sdk.getAuth(app);
    clients[name].auth = auth;
    sdk.connectAuthEmulator(auth, authEndpoint.origin, { disableWarnings: true });
    clients[name] = { app, db, auth, account };
  }
  return clients;
};

// Diagnostic codes are deliberately not raw SDK exception messages.
const lifecycleFailure = error =>
  typeof error?.code === 'string' && /^[a-zA-Z0-9_/-]{1,80}$/.test(error.code)
    ? error.code : 'local-lifecycle-operation-failed';
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Local-only management request: fixed route, no redirects/proxy, whole-call
 * deadline and a 64 KiB response bound. No real-cloud credential is accepted.
 */
export const localAccountRequest = (endpoint, projectId, operation, body, timeoutMs = 12000) => {
  const parsed = localEmulatorEndpoint(endpoint);
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(projectId) ||
      !['lookup', 'delete', 'update'].includes(operation) || !plainObject(body) ||
      !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 12000) {
    throw new Error('invalid local account request');
  }
  const raw = Buffer.from(JSON.stringify(body));
  if (raw.length > 16384) throw new Error('local account request too large');
  return new Promise((resolve, reject) => {
    let timer;
    const fail = () => Object.assign(new Error('local account transport failed'),
      { code: 'local-account-transport' });
    const req = httpRequest({ hostname: parsed.host, port: parsed.port, method: 'POST',
      path: `/identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:${operation}`,
      headers: { 'Content-Type': 'application/json', 'Content-Length': raw.length,
        Authorization: 'Bearer owner' }, agent: false,
    }, res => {
      const chunks = []; let length = 0;
      res.on('data', chunk => {
        length += chunk.length;
        if (length > 65536) req.destroy(fail());
        else chunks.push(chunk);
      });
      res.on('error', () => { clearTimeout(timer); reject(fail()); });
      res.on('aborted', () => { clearTimeout(timer); reject(fail()); });
      res.on('end', () => {
        clearTimeout(timer);
        try {
          const lengths = res.rawHeaders.filter((_, index, all) =>
            index % 2 === 1 && all[index - 1].toLowerCase() === 'content-length');
          if (!res.complete || length > 65536 || lengths.length > 1 ||
              (lengths.length && (!/^[0-9]+$/.test(lengths[0]) || Number(lengths[0]) !== length)) ||
              (res.headers['transfer-encoding'] && lengths.length) ||
              !/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] ?? '')) throw fail();
          const value = parseEvidence(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
          if (!plainObject(value) || !Number.isInteger(res.statusCode)) throw fail();
          resolve({ status: res.statusCode, body: value });
        } catch { reject(fail()); }
      });
    });
    req.on('error', () => { clearTimeout(timer); reject(fail()); });
    timer = setTimeout(() => req.destroy(fail()), Math.ceil(timeoutMs));
    req.end(raw);
  });
};

const accountLookup = (response, email, uid = null) => {
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

const teardownClients = async (sdk, clients) => {
  const rows = [];
  // Finalize every client even when an earlier finalizer rejected. Do not claim
  // cancellation: an SDK finalizer that never settles still needs supervision.
  for (const [name, client] of Object.entries(clients)) {
    const row = { client: name, databaseTerminated: !client.db, appDeleted: false, failures: [] };
    rows.push(row);
    if (client.db) {
      try { await sdk.terminate(client.db); row.databaseTerminated = true; }
      catch (error) { row.failures.push(lifecycleFailure(error)); }
    }
    try { await sdk.deleteApp(client.app); row.appDeleted = true; }
    catch (error) { row.failures.push(lifecycleFailure(error)); }
  }
  return { complete: rows.every(row => row.databaseTerminated && row.appDeleted), rows };
};

/** Effects behind the already validated local entry. Dependencies can be
 * instrumented by tests; the CLI has no switch that supplies a remote transport.
 */
export const executeLocalLifecycle = async (sdk, config, {
  request = localAccountRequest, run = runCatalog, checkpoint = () => {},
} = {}) => {
  const { projectId, firestoreHost, authHost, account, secondaryAccount, nonce, catalog,
    budget, cleanupBudget, stepTimeoutMs } = config;
  localEmulatorEndpoint(firestoreHost); localEmulatorEndpoint(authHost);
  if (!/^[0-9a-f]{32}$/.test(nonce) || !/^[a-zA-Z0-9_-]{1,128}$/.test(projectId)) {
    throw new Error('local namespace required');
  }
  if (!plainObject(secondaryAccount) || secondaryAccount.email === account.email) {
    throw new Error('two distinct throwaway accounts required');
  }
  const clients = {};
  // Both principals share one lifecycle: A is the case client, B owns privateB.
  const principals = {
    primary: { account, uid: null, signupAttempted: false, preflightAbsent: false },
    secondary: { account: secondaryAccount, uid: null, signupAttempted: false, preflightAbsent: false },
  };
  let paths = null;
  let catalogStarted = false;
  let catalogReturned = false;
  let accountCalls = 0;
  let outcome = { caseRecords: [], cleanup: classifyCleanup([]), cleanupPasses: [],
    totalDeleted: 0, thrown: null };
  const lifecycle = { failure: null, accountCleanup: { complete: false, outcome: 'not-attempted' },
    clients: null, localAdminRequests: 0, localAdminRequestLimit: LOCAL_ADMIN_REQUEST_LIMIT };
  const call = async (operation, body, recovery) => {
    if (accountCalls >= LOCAL_ADMIN_REQUEST_LIMIT) throw new Error('local account request budget exhausted');
    const remaining = recovery ? cleanupBudget.remainingMs() : budget.remainingMs();
    if (remaining <= 0) throw new Error('local account phase expired');
    accountCalls++;
    const response = await request(authHost, projectId, operation, body, Math.min(12000, remaining));
    if ((recovery ? cleanupBudget : budget).remainingMs() <= 0) throw new Error('late account response');
    return response;
  };
  const cleanupOne = async ({ account, uid, signupAttempted, preflightAbsent }) => {
    if (!signupAttempted) return { complete: true, outcome: 'not-created-by-this-run' };
    if (paths && !outcome.cleanup?.complete) {
      return { complete: false, outcome: 'retained-for-document-recovery' };
    }
    const selector = uid ? { localId: [uid] } : { email: [account.email] };
    const found = accountLookup(await call('lookup', selector, true), account.email, uid);
    // Absence at one instant cannot resolve an unacknowledged creation that
    // might still finish later. It is diagnostic, never a release proof.
    if (!preflightAbsent || uid === null) return {
      complete: false, outcome: 'creation-unconfirmed', observedAbsent: found === null,
    };
    if (found === null) return { complete: true, outcome: 'server-confirmed-absent' };
    const deleted = await call('delete', { localId: uid }, true);
    if (!plainObject(deleted) || deleted.status !== 200 || !plainObject(deleted.body) ||
        'error' in deleted.body || 'users' in deleted.body) throw new Error('account delete unconfirmed');
    const after = accountLookup(await call('lookup', { localId: [uid] }, true), account.email, uid);
    return { complete: after === null, outcome: after === null ? 'deleted-and-absent' : 'still-present' };
  };
  // Every account is attempted even when an earlier one failed; the combined
  // row is complete only when each one is, and names the first incomplete outcome.
  const cleanupAccount = async () => {
    const accounts = {};
    let failure = null;
    for (const [name, principal] of Object.entries(principals)) {
      try { accounts[name] = await cleanupOne(principal); }
      catch (error) {
        accounts[name] = { complete: false, outcome: 'account-cleanup-unconfirmed',
          failure: lifecycleFailure(error) };
        failure = failure ?? error;
      }
    }
    const rows = Object.values(accounts);
    const complete = rows.every(row => row.complete === true);
    const outcomes = new Set(rows.map(row => row.outcome));
    const combined = { complete, outcome: complete && outcomes.size === 1 ? rows[0].outcome
      : complete ? 'complete' : rows.find(row => row.complete !== true).outcome, accounts };
    if (failure) combined.failure = lifecycleFailure(failure);
    return combined;
  };
  const revoke = async uid => {
    // validSince is a whole second: sessions issued strictly before it are revoked.
    const validSince = String(Math.floor(Date.now() / 1000));
    const updated = await call('update', { localId: uid, validSince }, false);
    if (!plainObject(updated) || updated.status !== 200 || !plainObject(updated.body) ||
        'error' in updated.body || updated.body.localId !== uid) throw new Error('revocation unconfirmed');
  };
  try {
    for (const principal of Object.values(principals)) {
      const found = accountLookup(await call('lookup', { email: [principal.account.email] }, false),
        principal.account.email);
      if (found !== null) throw new Error('local account namespace occupied');
      principal.preflightAbsent = true;
    }
    const admitObservation = () => {
      if (budget.remainingMs() <= 0) throw new Error('observation phase expired');
    };
    admitObservation();
    await buildClients(sdk, { projectId, firestoreHost, authHost, account, secondaryAccount, nonce, clients });
    admitObservation();
    checkpoint('account-create-intent');
    const signUp = async (name, principal) => {
      principal.signupAttempted = true;
      const { email, password } = principal.account;
      const credential = await sdk.createUserWithEmailAndPassword(clients[name].auth, email, password);
      const user = credential?.user;
      if (!user || typeof user.uid !== 'string' || !user.uid || user.email !== email ||
          clients[name].auth.currentUser?.uid !== user.uid) throw new Error('signup identity unconfirmed');
      principal.uid = user.uid;
    };
    await signUp('primary', principals.primary);
    await signUp('secondary', principals.secondary);
    const uid = principals.primary.uid;
    const secondaryUid = principals.secondary.uid;
    if (secondaryUid === uid) throw new Error('second principal is not distinct');
    paths = { ...ownedPaths(nonce, uid), ...secondaryPaths(nonce, secondaryUid) };
    checkpoint('account-created', { uid, paths: ownedPaths(nonce, uid), secondaryUid,
      secondaryPaths: secondaryPaths(nonce, secondaryUid) });
    admitObservation();
    const witness = await sdk.signInWithEmailAndPassword(clients.witness.auth, account.email, account.password);
    if (witness?.user?.uid !== uid) throw new Error('witness identity mismatch');
    admitObservation();
    const deps = createDeps(sdk, clients, { revoke });
    // Both clients of the first principal are re-signed between cases: the
    // revocation case invalidates every session that principal held.
    const restore = async () => {
      for (const name of ['primary', 'witness']) {
        const signed = await sdk.signInWithEmailAndPassword(clients[name].auth, account.email, account.password);
        if (signed?.user?.uid !== uid) throw new Error('cleanup principal changed');
      }
      if (clients.secondary.auth.currentUser?.uid !== secondaryUid) {
        const signed = await sdk.signInWithEmailAndPassword(clients.secondary.auth,
          secondaryAccount.email, secondaryAccount.password);
        if (signed?.user?.uid !== secondaryUid) throw new Error('second principal changed');
      }
    };
    checkpoint('documents-at-risk');
    catalogStarted = true;
    outcome = await run(deps, {
      catalog, budget, cleanupBudget, paths, nonce, client: 'primary', clientFor: CLEANUP_CLIENT_FOR,
      contextFor: () => ({ client: 'primary',
        clients: { primary: 'primary', witness: 'witness', secondary: 'secondary' },
        nonce, paths, nameOf: nameOfFactory(paths), stepTimeoutMs, pollMs: 25, budget }),
      betweenCases: restore, beforeFinalCleanup: restore,
    });
    catalogReturned = true;
  } catch (error) {
    lifecycle.failure = lifecycleFailure(error);
    outcome.thrown = lifecycle.failure;
  } finally {
    // Catch failures outside the catalog's own recovery boundary as well.
    if (catalogStarted && !catalogReturned) {
      try {
        outcome.cleanup = await cleanupBudget.withPhase(async () => {
          const signed = await sdk.signInWithEmailAndPassword(clients.primary.auth, account.email, account.password);
          if (signed?.user?.uid !== principals.primary.uid) throw new Error('cleanup principal changed');
          const second = await sdk.signInWithEmailAndPassword(clients.secondary.auth,
            secondaryAccount.email, secondaryAccount.password);
          if (second?.user?.uid !== principals.secondary.uid) throw new Error('second principal changed');
          return runCleanup(createDeps(sdk, clients), {
            client: 'primary', paths, nonce, budget: cleanupBudget, clientFor: CLEANUP_CLIENT_FOR,
          });
        });
      } catch (error) {
        outcome.cleanup = classifyCleanup([{ name: 'outer-recovery', pathDigest: null,
          outcome: 'cleanup-threw', detail: lifecycleFailure(error) }]);
      }
    }
    try { lifecycle.accountCleanup = await cleanupBudget.withPhase(cleanupAccount); }
    catch (error) { lifecycle.accountCleanup = { complete: false,
      outcome: 'account-cleanup-unconfirmed', failure: lifecycleFailure(error) }; }
    lifecycle.clients = await teardownClients(sdk, clients);
    lifecycle.localAdminRequests = accountCalls;
  }
  lifecycle.complete = lifecycle.failure === null && lifecycle.accountCleanup.complete &&
    lifecycle.clients.complete;
  checkpoint('lifecycle-result', { complete: lifecycle.complete === true,
    accountCleanupComplete: lifecycle.accountCleanup.complete === true,
    clientsComplete: lifecycle.clients?.complete === true,
    documentsCleanupComplete: outcome.cleanup?.complete === true });
  return { ...outcome, lifecycle };
};

export const main = async ({ env = process.env, argv = process.argv,
  sdkLoader = resolveSdk, request = localAccountRequest,
  emit = value => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`),
} = {}) => {
  if (!argvIsClean(argv)) {
    throw new Error('refusing to start: a secret-shaped value was passed on the command line');
  }
  const mode = env.O6_LISTEN_MODE ?? MODE_LOCAL;
  const admitted = admitMode(mode, { permission: env.O6_LISTEN_PERMISSION });
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
  // Reject remote or URL-shaped inputs before resolving/importing the SDK or
  // creating either client. "local" must not just be a label on remote I/O.
  localEmulatorEndpoint(firestoreHost);
  localEmulatorEndpoint(authHost);
  const moduleDir = env.O6_FIREBASE_MODULE_DIR;
  if (!moduleDir) throw new Error('set O6_FIREBASE_MODULE_DIR to a directory holding the pinned firebase SDK');
  const repoRoot = env.O6_REPO_ROOT ?? process.cwd();
  const nonce = env.O6_LISTEN_NONCE ?? randomBytes(16).toString('hex');
  const projectId = env.GOOGLE_CLOUD_PROJECT ?? 'demo-app';

  const catalog = JSON.parse(
    readFileSync(
      env.O6_LISTEN_CATALOG_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-cases.json'),
      'utf8',
    ),
  );
  const campaignRecord = env.O6_LISTEN_CAMPAIGN_PATH
    ? JSON.parse(readFileSync(env.O6_LISTEN_CAMPAIGN_PATH, 'utf8'))
    : null;
  if (!campaignRecord) {
    throw new Error('set O6_LISTEN_CAMPAIGN_PATH to a compiled campaign record');
  }
  const { budget: limitsSpec, boundSources } = JSON.parse(
    readFileSync(
      env.O6_LISTEN_BUDGET_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-budget.json'),
      'utf8',
    ),
  );

  if (!/^[0-9a-f]{32}$/.test(nonce) || !/^[a-zA-Z0-9_-]{1,128}$/.test(projectId) ||
      !Array.isArray(catalog.cases) || catalog.cases.length === 0 ||
      catalog.cases.some(row => typeof row?.caseId !== 'string' || !row.caseId) ||
      new Set(catalog.cases.map(row => row.caseId)).size !== catalog.cases.length ||
      !plainObject(campaignRecord.campaign) || !Array.isArray(boundSources) ||
      boundSources.some(value => typeof value !== 'string')) {
    throw new Error('invalid local campaign configuration');
  }
  const duration = Number(env.O6_LISTEN_DEADLINE_MS ?? '300000');
  const stepTimeoutMs = Number(env.O6_LISTEN_STEP_TIMEOUT_MS ?? '15000');
  if (!Number.isSafeInteger(duration) || duration <= 0 ||
      !Number.isSafeInteger(stepTimeoutMs) || stepTimeoutMs <= 0) {
    throw new Error('positive finite local timeouts required');
  }
  const budget = createBudget({
    now: () => performance.now(),
    deadlineMs: Math.min(
      duration,
      limitsSpec.maxDurationSeconds * 1000,
    ),
    limits: {
      reads: limitsSpec.maxReads,
      writes: limitsSpec.maxWrites,
      deletes: limitsSpec.maxDeletes,
      snapshots: limitsSpec.maxSnapshots,
      listeners: limitsSpec.maxListenerRegistrations,
    },
  });

  // Cleanup has its own reserve. An exhausted observation budget or an expired
  // observation deadline must never leave an owned document behind.
  const cleanupBudget = createRecoveryBudget({
    now: () => performance.now(),
    deadlineMs: limitsSpec.cleanupReserveSeconds * 1000,
    limits: {
      reads: limitsSpec.cleanupReserveReads,
      writes: 0,
      deletes: limitsSpec.cleanupReserveDeletes,
      snapshots: 0,
      listeners: 0,
    },
  });

  // All file parsing and finite budget validation above is inert. A missing
  // campaign or malformed limit must not strand a newly created account.
  const checkpoint = env.O6_LISTEN_JOURNAL_DIR
    ? createLifecycleJournal(env.O6_LISTEN_JOURNAL_DIR, { nonce, projectId }) : () => {};
  const password = readPasswordFromFd(env.O6_LISTEN_PASSWORD_FD) ?? randomBytes(24).toString('hex');
  const account = { name: 'throwaway', email: `o6-${nonce}@example.test`, password };
  const secondaryAccount = secondaryAccountFor(nonce,
    readPasswordFromFd(env.O6_LISTEN_SECONDARY_PASSWORD_FD) ?? randomBytes(24).toString('hex'));
  const sdk = await sdkLoader(moduleDir);
  const outcome = await executeLocalLifecycle(sdk, { projectId, firestoreHost, authHost,
    account, secondaryAccount, nonce, catalog, budget, cleanupBudget, stepTimeoutMs }, { request, checkpoint });
  const { caseRecords, cleanup } = outcome;

  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: campaignRecord.campaignDigest,
    catalogDigest: catalog.catalogDigest ?? null,
    environment: {
      kind: 'local-fireemu',
      node: process.versions.node,
      sourceCommit: env.O6_LISTEN_SOURCE_COMMIT ?? null,
      firebaseSdk: env.O6_LISTEN_SDK_VERSION ?? null,
      // The runtime under test. A shadow is only evidence about the binary it
      // actually ran, so the receipt names that binary and the commit it was
      // built from rather than trusting whatever was on the path.
      // Recorded relative to the repository root: an absolute path would put a
      // personal directory into a receipt that ships with the repository.
      fireemuBinary: env.O6_LISTEN_FIREEMU_BINARY
        ? path.relative(repoRoot, env.O6_LISTEN_FIREEMU_BINARY)
        : null,
      fireemuBinaryDigest: artifactDigest(env.O6_LISTEN_FIREEMU_BINARY),
      fireemuSourceCommit: env.O6_LISTEN_FIREEMU_COMMIT ?? null,
      rulesPath: env.O6_LISTEN_RULES_PATH
        ? path.relative(repoRoot, env.O6_LISTEN_RULES_PATH)
        : null,
      rulesDigest: artifactDigest(env.O6_LISTEN_RULES_PATH),
      projectId,
      nonceDigest: createHash('sha256').update(nonce).digest('hex'),
    },
    caseRecords,
    cleanup,
    cleanupPasses: outcome.cleanupPasses,
    totalDeleted: outcome.totalDeleted,
    budget,
    cleanupBudget,
    thrown: outcome.thrown,
    productionExecuted: false,
  });
  receipt.permission = campaignRecord.campaign.permission ?? null;
  receipt.sdkResolved = campaignRecord.campaign.sdk;
  receipt.transportTimeline = caseRecords
    .flatMap(record =>
      (record.transportTimeline ?? []).map(entry => ({ ...entry, caseId: record.caseId })),
    )
    .sort((left, right) => left.atMs - right.atMs);
  // The bound-source list comes from the published contract, never from a
  // literal here: widening the contract must break the collector loudly.
  receipt.sourceDigests = sourceDigests(repoRoot, boundSources);

  receipt.lifecycle = outcome.lifecycle;
  receipt.complete = receipt.complete && outcome.lifecycle.complete &&
    caseRecords.length === catalog.cases.length && caseRecords.every((row, index) =>
      row.caseId === catalog.cases[index].caseId);
  await emit(receipt);
  if (!receipt.complete) process.exitCode = 2;
  return receipt;
};

const invokedDirectly =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (invokedDirectly) {
  main().catch(error => {
    process.stderr.write(`${lifecycleFailure(error)}\n`);
    process.exitCode = 1;
  });
}
