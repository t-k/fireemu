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
import path from 'node:path';

import {
  argvIsClean,
  buildReceipt,
  createBudget,
  ownedPaths,
  runCase,
  runCleanup,
} from './listen_collector.mjs';

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
  const parsed = Number.parseInt(String(fd), 10);
  if (!Number.isInteger(parsed) || parsed < 3) throw new Error('password fd must be a private descriptor');
  return readFileSync(parsed, 'utf8').trim();
};

const nameOfFactory = paths => {
  const names = new Map(Object.entries(paths).map(([name, value]) => [value, name]));
  return value => names.get(value) ?? String(value).split('/').at(-1);
};

export const createDeps = (sdk, clients) => ({
  now: () => Date.now(),
  sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
  firestore: {
    async setDoc(client, docPath, fields) {
      await sdk.setDoc(sdk.doc(clients[client].db, docPath), fields);
    },
    async deleteDoc(client, docPath) {
      await sdk.deleteDoc(sdk.doc(clients[client].db, docPath));
    },
    async getDoc(client, docPath) {
      const snapshot = await sdk.getDoc(sdk.doc(clients[client].db, docPath));
      return {
        exists: snapshot.exists(),
        fields: snapshot.exists() ? snapshot.data() : null,
        updateTime: null,
      };
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
    async signIn(client) {
      const target = clients[client];
      await sdk.signInWithEmailAndPassword(target.auth, target.account.email, target.account.password);
    },
    async signOut(client) {
      await sdk.signOut(clients[client].auth);
    },
  },
});

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

const buildClients = async (sdk, { projectId, firestoreHost, authHost, account }) => {
  const clients = {};
  for (const name of ['primary', 'witness']) {
    const app = sdk.initializeApp({ projectId, apiKey: 'fake-api-key' }, `o6-${name}`);
    const db = sdk.getFirestore(app);
    const [host, port] = firestoreHost.split(':');
    sdk.connectFirestoreEmulator(db, host, Number.parseInt(port, 10));
    const auth = sdk.getAuth(app);
    sdk.connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
    clients[name] = { app, db, auth, account };
  }
  return clients;
};

export const main = async ({ env = process.env, argv = process.argv } = {}) => {
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
  const moduleDir = env.O6_FIREBASE_MODULE_DIR;
  if (!moduleDir) throw new Error('set O6_FIREBASE_MODULE_DIR to a directory holding the pinned firebase SDK');
  const repoRoot = env.O6_REPO_ROOT ?? process.cwd();
  const nonce = env.O6_LISTEN_NONCE ?? randomBytes(16).toString('hex');
  const projectId = env.GOOGLE_CLOUD_PROJECT ?? 'demo-app';

  const sdk = await resolveSdk(moduleDir);
  const password = readPasswordFromFd(env.O6_LISTEN_PASSWORD_FD) ?? randomBytes(24).toString('hex');
  const account = { email: `o6-${nonce}@example.test`, password };

  const clients = await buildClients(sdk, { projectId, firestoreHost, authHost, account });
  const deps = createDeps(sdk, clients);

  await sdk.createUserWithEmailAndPassword(clients.primary.auth, account.email, password);
  const uid = clients.primary.auth.currentUser.uid;
  await sdk.signInWithEmailAndPassword(clients.witness.auth, account.email, password);

  const paths = ownedPaths(nonce, uid);

  const catalog = JSON.parse(
    readFileSync(
      env.O6_LISTEN_CATALOG_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-cases.json'),
      'utf8',
    ),
  );
  const { budget: limitsSpec } = JSON.parse(
    readFileSync(
      env.O6_LISTEN_BUDGET_PATH ?? path.join(repoRoot, 'spec/compatibility/fs-listen-sdk-budget.json'),
      'utf8',
    ),
  );

  const budget = createBudget({
    now: () => Date.now(),
    deadlineMs: Math.min(
      Number.parseInt(env.O6_LISTEN_DEADLINE_MS ?? '300000', 10),
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
  const cleanupBudget = createBudget({
    now: () => Date.now(),
    deadlineMs: Number.MAX_SAFE_INTEGER,
    limits: {
      reads: limitsSpec.cleanupReserveReads,
      writes: 0,
      deletes: limitsSpec.cleanupReserveDeletes,
      snapshots: 0,
      listeners: 0,
    },
  });

  const caseRecords = [];
  for (const caseSpec of catalog.cases) {
    const record = await runCase(deps, caseSpec, {
      client: 'primary',
      clients: { primary: 'primary', witness: 'witness' },
      nonce,
      paths,
      nameOf: nameOfFactory(paths),
      stepTimeoutMs: Number.parseInt(env.O6_LISTEN_STEP_TIMEOUT_MS ?? '15000', 10),
      pollMs: 25,
      budget,
    });
    caseRecords.push(record);
    await runCleanup(deps, { client: 'primary', paths, nonce, budget: cleanupBudget });
    await sdk.signInWithEmailAndPassword(clients.primary.auth, account.email, password);
  }

  const cleanup = await runCleanup(deps, {
    client: 'primary',
    paths,
    nonce,
    budget: cleanupBudget,
  });
  const receipt = buildReceipt({
    campaign: { caseId: 'FS-LISTEN-SDK' },
    campaignDigest: env.O6_LISTEN_CAMPAIGN_DIGEST ?? null,
    catalogDigest: catalog.catalogDigest ?? null,
    environment: {
      kind: 'local-fireemu',
      node: process.versions.node,
      sourceCommit: env.O6_LISTEN_SOURCE_COMMIT ?? null,
      firebaseSdk: env.O6_LISTEN_SDK_VERSION ?? null,
      // The runtime under test. A shadow is only evidence about the binary it
      // actually ran, so the receipt names that binary and the commit it was
      // built from rather than trusting whatever was on the path.
      fireemuBinary: env.O6_LISTEN_FIREEMU_BINARY ?? null,
      fireemuBinaryDigest: artifactDigest(env.O6_LISTEN_FIREEMU_BINARY),
      fireemuSourceCommit: env.O6_LISTEN_FIREEMU_COMMIT ?? null,
      projectId,
      nonceDigest: createHash('sha256').update(nonce).digest('hex'),
    },
    caseRecords,
    cleanup,
    budget,
    cleanupBudget,
    productionExecuted: false,
  });
  receipt.transportTimeline = caseRecords
    .flatMap(record =>
      (record.transportTimeline ?? []).map(entry => ({ ...entry, caseId: record.caseId })),
    )
    .sort((left, right) => left.atMs - right.atMs);
  receipt.sourceDigests = sourceDigests(repoRoot, [
    'tools/compat-broad/fs-listen-resume/listen_collector.mjs',
    'tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs',
  ]);

  for (const client of Object.values(clients)) {
    await sdk.terminate(client.db).catch(() => {});
    await sdk.deleteApp(client.app).catch(() => {});
  }
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
};

const invokedDirectly =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (invokedDirectly) {
  main().catch(error => {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  });
}
