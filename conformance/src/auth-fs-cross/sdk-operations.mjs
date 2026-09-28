// The operations of an AUTH-FS-CROSS stage-2 SDK client, shared by the Node driver and the
// browser page so both run the same Web SDK calls. No imports: the caller passes the Web SDK
// 12.18.0 functions (`fb`), the app's `auth` and `db`, `emit` for events, `onToken(token, uid)`
// to attribute later requests to a principal (the token never leaves the client), and `exit`.

/** The token's times, never the token: the parent schedules its expiry probes from them. */
function tokenTimes(token, decodeBase64Url) {
  const { iat, exp } = JSON.parse(decodeBase64Url(token.split(".")[1]));
  return { iat, exp };
}

/** How long an operation waits for the event that completes it (a snapshot, a token change). */
const WAIT_MS = 20_000;

export function createOperations({
  fb,
  auth,
  db,
  emit,
  onToken,
  decodeBase64Url,
  exit,
  waitMs = WAIT_MS,
}) {
  // Each reported token change, numbered: an operation that changes the Auth state answers
  // after the report of its own change, so every client (Node and browser alike) has reported
  // it before the parent's next step. The report stays among the events.
  let authReports = 0;
  const authWaiters = [];
  const reportAuth = (event) => {
    authReports += 1;
    emit(event);
    for (const waiter of authWaiters.splice(0)) waiter(event.uid);
  };
  fb.onIdTokenChanged(auth, async (user) => {
    if (!user) return reportAuth({ event: "auth", uid: null });
    const token = await user.getIdToken();
    await onToken(token, user.uid);
    return reportAuth({
      event: "auth",
      uid: user.uid,
      tenant: user.tenantId ?? null,
      ...tokenTimes(token, decodeBase64Url),
    });
  });
  /** Resolves `true` at the first report of `uid` after report number `after`, or `false`. */
  function authReported(uid, after) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), waitMs);
      const check = (reported) => {
        if (authReports > after && reported === uid) {
          clearTimeout(timer);
          resolve(true);
        } else authWaiters.push(check);
      };
      if (authReports > after) check(uid);
      else authWaiters.push(check);
    });
  }

  const listeners = new Map();
  const pausedTransactions = new Map();
  const pendingWrites = new Map();

  const plainDoc = (snapshot) => ({
    path: snapshot.ref.path,
    exists: snapshot.exists(),
    data: snapshot.exists() ? snapshot.data() : null,
    hasPendingWrites: snapshot.metadata.hasPendingWrites,
  });

  /**
   * Starts a listener and resolves with how its first answer from the server came: its first
   * snapshot not from the cache, its error, or nothing within the wait. Every snapshot and the
   * error are events, the awaited one included.
   */
  function listen({ name, path, collection: collectionPath, where: filters = [] }) {
    const target = path
      ? fb.doc(db, path)
      : fb.query(
          fb.collection(db, collectionPath),
          ...filters.map(([f, op, v]) => fb.where(f, op, v)),
        );
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve("timeout"), waitMs);
      const settle = (first) => {
        clearTimeout(timer);
        resolve(first);
      };
      const stop = fb.onSnapshot(
        target,
        { includeMetadataChanges: true },
        (snapshot) => {
          emit({
            event: "snapshot",
            name,
            fromCache: snapshot.metadata.fromCache,
            hasPendingWrites: snapshot.metadata.hasPendingWrites,
            docs: path ? [plainDoc(snapshot)] : snapshot.docs.map(plainDoc),
          });
          if (!snapshot.metadata.fromCache) settle("snapshot");
        },
        (error) => {
          emit({ event: "listen-error", name, code: error.code, message: error.message });
          settle("error");
        },
      );
      listeners.set(name, stop);
    });
  }

  async function transact({ name, reads, write, pauseAttempts = 1 }) {
    let attempts = 0;
    let committed;
    try {
      committed = await fb.runTransaction(db, async (transaction) => {
        attempts += 1;
        const docs = [];
        for (const path of reads) docs.push(plainDoc(await transaction.get(fb.doc(db, path))));
        emit({ event: "transaction-read", name, attempt: attempts, docs });
        // The parent changes the Auth state, then lets the commit go. A retry runs straight
        // through, so the parent sees how many times the SDK called the update function.
        if (attempts <= pauseAttempts)
          await new Promise((resolve) => pausedTransactions.set(name, resolve));
        transaction.set(fb.doc(db, write.path), write.data);
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
      const before = authReports;
      const { user } = await fb.signInWithEmailAndPassword(auth, email, password);
      return { uid: user.uid, authReported: await authReported(user.uid, before) };
    },
    /**
     * A read that uses the API key from this client's origin (the password policy), before the
     * run writes anything: a key restricted by referrer or application refuses it.
     */
    probeKey: async () => {
      await fb.validatePassword(auth, "afc-probe-password-1");
      return {};
    },
    signOut: async () => {
      const before = authReports;
      await fb.signOut(auth);
      return { authReported: await authReported(null, before) };
    },
    refreshToken: async () => {
      const before = authReports;
      await auth.currentUser.getIdToken(true);
      const { uid } = auth.currentUser;
      return { uid, authReported: await authReported(uid, before) };
    },
    listen: async (command) => ({ first: await listen(command) }),
    unlisten: async ({ name }) => {
      listeners.get(name)?.();
      listeners.delete(name);
      return {};
    },
    write: async ({ path, data }) => {
      await fb.setDoc(fb.doc(db, path), data);
      return {};
    },
    /** A write whose promise the parent watches later (it may stay pending while offline). */
    writeLater: async ({ writeId, path, data }) => {
      const promise = fb.setDoc(fb.doc(db, path), data).then(
        () => emit({ event: "write-settled", writeId, ok: true }),
        (error) => emit({ event: "write-settled", writeId, ok: false, code: error.code }),
      );
      pendingWrites.set(writeId, promise);
      return {};
    },
    remove: async ({ path }) => {
      await fb.deleteDoc(fb.doc(db, path));
      return {};
    },
    offline: async () => {
      await fb.disableNetwork(db);
      return {};
    },
    online: async () => {
      await fb.enableNetwork(db);
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
      setTimeout(exit, 50);
      return {};
    },
  };

  /** Runs one command; its result (or error) is emitted, never thrown. */
  return function run(command) {
    const operation = operations[command.op];
    if (!operation)
      return emit({
        event: "result",
        id: command.id,
        ok: false,
        error: `unknown op ${command.op}`,
      });
    return operation(command).then(
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
  };
}
