import { initializeApp } from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  connectAuthEmulator,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import {
  getDatabase,
  connectDatabaseEmulator,
  forceLongPolling,
  goOffline,
  onDisconnect,
  ref,
  runTransaction,
  set,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js";

// Long polling, one signed-in user, four writes: a set, two transactions (an update and a create) and an
// onDisconnect pair (a remove and a set) that the server runs when this connection ends. A transaction
// returns the whole target value whatever it was shown, so the first attempt (which sees no cached data)
// and its retry write the same node and only one write reaches the server.
let auth, db, expectedUid;
window.__breadth = async ({ action, config, email, password, uid, nonce }) => {
  if (action === "signIn") {
    if (auth) throw Error("already initialized");
    const app = initializeApp(config);
    auth = getAuth(app);
    if (config.emulator) connectAuthEmulator(auth, config.emulator.auth, { disableWarnings: true });
    const user = await signInWithEmailAndPassword(auth, email, password);
    if (!uid || user.user.uid !== uid) throw Error("owned user mismatch");
    expectedUid = uid;
    forceLongPolling();
    db = getDatabase(app);
    if (config.emulator) connectDatabaseEmulator(db, config.emulator.host, config.emulator.dbPort);
    return { outcome: "ok" };
  }
  if (!db?.app || db.app !== auth?.app || !expectedUid || auth.currentUser?.uid !== expectedUid)
    throw Error("owned user changed or signed out");
  const item = (id) => ref(db, `k9-rtdb/gs/items/${id}`);
  if (action === "k18") await set(item("s1"), { value: 1, run: nonce });
  else if (action === "k19") await runTransaction(item("s1"), () => ({ value: 2, run: nonce }));
  else if (action === "k20") await runTransaction(item("s2"), () => ({ value: 1, run: nonce }));
  else if (action === "k21") {
    await onDisconnect(item("s1")).remove();
    await onDisconnect(item("s3")).set({ value: 3, run: nonce });
    goOffline(db);
  } else throw Error("invalid write");
  return { outcome: "ok" };
};
