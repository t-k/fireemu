import { initializeApp } from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  connectAuthEmulator,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import {
  getDatabase,
  connectDatabaseEmulator,
  forceWebSockets,
  ref,
  set,
  update,
  remove,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js";

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
    forceWebSockets();
    db = getDatabase(app);
    if (config.emulator) connectDatabaseEmulator(db, config.emulator.host, config.emulator.dbPort);
    return { outcome: "ok" };
  }
  if (!db?.app || db.app !== auth?.app || !expectedUid || auth.currentUser?.uid !== expectedUid)
    throw Error("owned user changed or signed out");
  const parent = ref(db, "g9-rtdb/gu");
  if (action === "w10")
    await set(parent, { items: { a: { value: 1, run: nonce }, b: { value: 1, run: nonce } } });
  else if (action === "w11") await update(parent, { "items/a/value": 2, "items/b/value": 2 });
  else if (action === "w12") await remove(parent);
  else throw Error("invalid write");
  return { outcome: "ok" };
};
