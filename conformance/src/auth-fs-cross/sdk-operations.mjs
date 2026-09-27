// The operations of an AUTH-FS-CROSS stage-2 SDK client, shared by the Node driver and the
// browser page so both run the same Web SDK calls. No imports: the caller passes the Web SDK
// 12.18.0 functions (`fb`), the app's `auth` and `db`, `emit` for events, `onToken(token, uid)`
// to attribute later requests to a principal (the token never leaves the client), and `exit`.

/** The token's times, never the token: the parent schedules its expiry probes from them. */
function tokenTimes(token, decodeBase64Url) {
  const { iat, exp } = JSON.parse(decodeBase64Url(token.split(".")[1]));
  return { iat, exp };
}

export function createOperations({ fb, auth, db, emit, onToken, decodeBase64Url, exit }) {
  fb.onIdTokenChanged(auth, async (user) => {
    if (!user) return emit({ event: "auth", uid: null });
    const token = await user.getIdToken();
    await onToken(token, user.uid);
    emit({
      event: "auth",
      uid: user.uid,
      tenant: user.tenantId ?? null,
      ...tokenTimes(token, decodeBase64Url),
    });
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
      ? fb.doc(db, path)
      : fb.query(
          fb.collection(db, collectionPath),
          ...filters.map(([f, op, v]) => fb.where(f, op, v)),
        );
    const stop = fb.onSnapshot(
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
      const { user } = await fb.signInWithEmailAndPassword(auth, email, password);
      return { uid: user.uid };
    },
    signOut: async () => {
      await fb.signOut(auth);
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
