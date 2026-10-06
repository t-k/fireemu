// The catalog adapter's dependencies for a browser page (FS-LISTEN-SDK packet L2). The same
// functions as `createDeps` of tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs, which
// cannot be loaded in a page because its module imports Node built-ins; a test drives both over a
// recording fake SDK and requires the same calls and the same answers. This file imports nothing.

export const createPageDeps = (sdk, clients, { revoke = null } = {}) => ({
  // Transport timeline timestamps are part of the cross-language receipt
  // contract, whose schema represents elapsed milliseconds as integers.
  now: () => Math.trunc(performance.now()),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  firestore: {
    async setDoc(client, docPath, fields) {
      await sdk.setDoc(sdk.doc(clients[client].db, docPath), fields);
    },
    async deleteDoc(client, docPath, precondition = null) {
      if (precondition !== null) {
        throw new Error("client SDK cannot apply an updateTime delete precondition");
      }
      // Ordinary observation steps intentionally exercise client deleteDoc.
      await sdk.deleteDoc(sdk.doc(clients[client].db, docPath));
    },
    async deleteOwnedDoc(client, docPath, condition) {
      if (
        !condition ||
        typeof condition.owner !== "string" ||
        !condition.owner ||
        Object.keys(condition).length !== 1
      )
        throw new Error("owned cleanup marker required");
      const db = clients[client].db;
      const ref = sdk.doc(db, docPath);
      // The transaction binds its delete to the version it reads. One attempt
      // keeps the additional ownership read within the collector's reservation.
      return sdk.runTransaction(
        db,
        async (transaction) => {
          const snapshot = await transaction.get(ref);
          const exists = snapshot.exists();
          if (typeof exists !== "boolean") throw new Error("typed transaction presence required");
          if (!exists) return;
          if (snapshot.data()?.owner !== condition.owner) {
            throw Object.assign(new Error("owned marker changed"), { code: "failed-precondition" });
          }
          transaction.delete(ref);
        },
        { maxAttempts: 1 },
      );
    },
    async getDoc(client, docPath) {
      const snapshot = await sdk.getDocFromServer(sdk.doc(clients[client].db, docPath));
      if (snapshot.metadata?.fromCache !== false || snapshot.metadata?.hasPendingWrites !== false) {
        throw new Error("server-confirmed cleanup snapshot required");
      }
      const exists = snapshot.exists();
      if (typeof exists !== "boolean") throw new Error("typed document presence required");
      return { exists, fields: exists ? snapshot.data() : null, updateTime: null };
    },
    onDocSnapshot(client, docPath, options, onNext, onError) {
      return sdk.onSnapshot(sdk.doc(clients[client].db, docPath), options, {
        next: (snapshot) =>
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
        sdk.orderBy(spec.orderBy?.[0] ?? spec.where[0], spec.orderBy?.[1] ?? "asc"),
        sdk.limit(spec.limit ?? 10),
      ];
      return sdk.onSnapshot(sdk.query(collection, ...constraints), options, {
        next: (snapshot) =>
          onNext({
            docs: snapshot.docs.map((entry) => entry.ref.path),
            changes: snapshot.docChanges().map((change) => ({
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
      await sdk.signInWithEmailAndPassword(
        target.auth,
        target.account.email,
        target.account.password,
      );
    },
    async signOut(client) {
      await sdk.signOut(clients[client].auth);
    },
    // Revoke the sessions of whoever this client is signed in as, through the
    // management route the adapter owns. The SDK itself has no such API.
    async revoke(client) {
      const uid = clients[client].auth.currentUser?.uid;
      if (typeof uid !== "string" || !uid) throw new Error("revoke needs a signed-in client");
      if (typeof revoke !== "function") throw new Error("session revocation is unavailable");
      await revoke(uid);
    },
  },
});
