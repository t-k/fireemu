// One Web SDK 12.18.0 client in its own process (AUTH-FS-CROSS stage 2). The parent sends one
// JSON command per line on stdin and reads one JSON event per line on stdout. Every request the
// SDK makes goes through the wire guard; a request is attributed to the uid whose ID token it
// carried (by hash), never by the token itself. Secrets arrive on stdin, never in argv.
//
//   config (env AFC_SDK_CONFIG): { mode: "production" | "local", web: { apiKey, projectId,
//     authDomain }, authEmulator?: "http://host:port", firestoreEmulator?: { host, port },
//     wireCap }
//   commands: { id, op, ... }; each is answered by { event: "result", id, ok, ... }.

// Must stay the first import: it installs the wire guard before Firebase loads.
import { config, emit, local, sha256, tokenOwner } from "./sdk-driver-wire.mjs";

import { createInterface } from "node:readline";

import { initializeApp } from "firebase/app";
import {
  connectAuthEmulator,
  getAuth,
  onIdTokenChanged,
  signInWithEmailAndPassword,
  signOut,
} from "firebase/auth";
import {
  collection,
  connectFirestoreEmulator,
  deleteDoc,
  disableNetwork,
  doc,
  enableNetwork,
  getFirestore,
  onSnapshot,
  query,
  runTransaction,
  setDoc,
  where,
} from "firebase/firestore";

const app = initializeApp(config.web, `afc-${process.pid}`);
const auth = getAuth(app);
const db = getFirestore(app);
if (local) {
  connectAuthEmulator(auth, config.authEmulator, { disableWarnings: true });
  connectFirestoreEmulator(db, config.firestoreEmulator.host, config.firestoreEmulator.port);
}
onIdTokenChanged(auth, async (user) => {
  if (!user) return emit({ event: "auth", uid: null });
  const token = await user.getIdToken();
  tokenOwner.set(sha256(token), user.uid);
  // The token's times, never the token: the parent schedules its expiry probes from them.
  const { iat, exp } = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  emit({ event: "auth", uid: user.uid, tenant: user.tenantId ?? null, iat, exp });
});

const listeners = new Map();
const pausedTransactions = new Map();
const pendingWrites = new Map();

const plainDoc = (snapshot) => ({
  path: snapshot.ref.path,
  exists: snapshot.exists(),
  data: snapshot.exists() ? snapshot.data() : null,
  hasPendingWrites: snapshot.metadata.hasPendingWrites,
});

function listen({ name, path, collection: collectionPath, where: filters = [] }) {
  const target = path
    ? doc(db, path)
    : query(collection(db, collectionPath), ...filters.map(([f, op, v]) => where(f, op, v)));
  const stop = onSnapshot(
    target,
    { includeMetadataChanges: true },
    (snapshot) =>
      emit({
        event: "snapshot",
        name,
        fromCache: snapshot.metadata.fromCache,
        hasPendingWrites: snapshot.metadata.hasPendingWrites,
        docs: path ? [plainDoc(snapshot)] : snapshot.docs.map(plainDoc),
      }),
    (error) => emit({ event: "listen-error", name, code: error.code, message: error.message }),
  );
  listeners.set(name, stop);
}

async function transact({ name, reads, write, pauseAttempts = 1 }) {
  let attempts = 0;
  let committed;
  try {
    committed = await runTransaction(db, async (transaction) => {
      attempts += 1;
      const docs = [];
      for (const path of reads) docs.push(plainDoc(await transaction.get(doc(db, path))));
      emit({ event: "transaction-read", name, attempt: attempts, docs });
      // The parent changes the Auth state, then lets the commit go. A retry runs straight through,
      // so the parent sees how many times the SDK called the update function.
      if (attempts <= pauseAttempts)
        await new Promise((resolve) => pausedTransactions.set(name, resolve));
      transaction.set(doc(db, write.path), write.data);
      return attempts;
    });
  } catch (error) {
    // A failed transaction still reports how many times the update function ran.
    throw Object.assign(error, { attempts });
  }
  return { attempts: committed };
}

const operations = {
  signIn: async ({ email, password, tenantId }) => {
    auth.tenantId = tenantId ?? null;
    const { user } = await signInWithEmailAndPassword(auth, email, password);
    return { uid: user.uid };
  },
  signOut: async () => {
    await signOut(auth);
    return {};
  },
  refreshToken: async () => {
    await auth.currentUser.getIdToken(true);
    return { uid: auth.currentUser.uid };
  },
  listen: async (command) => {
    listen(command);
    return {};
  },
  unlisten: async ({ name }) => {
    listeners.get(name)?.();
    listeners.delete(name);
    return {};
  },
  write: async ({ path, data }) => {
    await setDoc(doc(db, path), data);
    return {};
  },
  /** A write whose promise the parent watches later (it may stay pending while offline). */
  writeLater: async ({ writeId, path, data }) => {
    const promise = setDoc(doc(db, path), data).then(
      () => emit({ event: "write-settled", writeId, ok: true }),
      (error) => emit({ event: "write-settled", writeId, ok: false, code: error.code }),
    );
    pendingWrites.set(writeId, promise);
    return {};
  },
  remove: async ({ path }) => {
    await deleteDoc(doc(db, path));
    return {};
  },
  offline: async () => {
    await disableNetwork(db);
    return {};
  },
  online: async () => {
    await enableNetwork(db);
    return {};
  },
  transaction: async (command) => transact(command),
  continueTransaction: async ({ name }) => {
    const resume = pausedTransactions.get(name);
    if (!resume)
      throw Object.assign(new Error(`transaction ${name} is not paused`), { code: "harness" });
    pausedTransactions.delete(name);
    resume();
    return {};
  },
  shutdown: async () => {
    for (const stop of listeners.values()) stop();
    setTimeout(() => process.exit(0), 50);
    return {};
  },
};

// Commands run concurrently: a paused transaction must not block the command that resumes it.
createInterface({ input: process.stdin }).on("line", (line) => {
  let command;
  try {
    command = JSON.parse(line);
  } catch {
    return emit({ event: "result", id: null, ok: false, error: "unparsable command" });
  }
  const run = operations[command.op];
  if (!run)
    return emit({ event: "result", id: command.id, ok: false, error: `unknown op ${command.op}` });
  run(command).then(
    (value) => emit({ event: "result", id: command.id, ok: true, ...value }),
    (error) =>
      emit({
        event: "result",
        id: command.id,
        ok: false,
        code: error.code ?? null,
        error: error.message,
        ...(error.attempts === undefined ? {} : { attempts: error.attempts }),
      }),
  );
});
emit({ event: "ready" });
