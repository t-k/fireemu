// The page of the AUTH-FS-CROSS stage-2 browser client: the Web SDK 12.18.0 browser bundles
// (the gstatic URLs below are answered by the driver from the pinned npm package, never fetched)
// running the operations shared with the Node driver. The driver passes the configuration in
// `window.afcConfig` and receives events through `window.afcEmit`; a token is hashed here and
// only its hash leaves the page (`window.afcToken`).

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import * as auth from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import * as firestore from "https://www.gstatic.com/firebasejs/12.18.0/firebase-firestore.js";

import { createOperations } from "./sdk-operations.mjs";

const config = window.afcConfig;
const app = initializeApp(config.web, "afc-browser");
const clientAuth = auth.getAuth(app);
const db = firestore.getFirestore(app);
if (config.mode === "local") {
  auth.connectAuthEmulator(clientAuth, config.authEmulator, { disableWarnings: true });
  firestore.connectFirestoreEmulator(
    db,
    config.firestoreEmulator.host,
    config.firestoreEmulator.port,
  );
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeBase64Url(text) {
  const padded = text.replaceAll("-", "+").replaceAll("_", "/");
  const bytes = Uint8Array.from(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4)), (c) =>
    c.charCodeAt(0),
  );
  return new TextDecoder().decode(bytes);
}

const run = createOperations({
  fb: { ...auth, ...firestore },
  auth: clientAuth,
  db,
  emit: (event) => window.afcEmit(event),
  onToken: async (token, uid) => window.afcToken(await sha256Hex(token), uid),
  decodeBase64Url,
  exit: () => window.afcEmit({ event: "page-closed" }),
});

window.afcRun = (command) => {
  run(command);
};
window.afcEmit({ event: "ready" });
