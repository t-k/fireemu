// One Web SDK 12.18.0 client in its own process (AUTH-FS-CROSS stage 2). The parent sends one
// JSON command per line on stdin and reads one JSON event per line on stdout. Every request the
// SDK makes goes through the wire guard; a request is attributed to the uid whose ID token it
// carried (by hash), never by the token itself. Secrets arrive on stdin, never in argv.
//
//   config (env AFC_SDK_CONFIG): { mode: "production" | "local", web: { apiKey, projectId,
//     authDomain }, authEmulator?: "http://host:port", firestoreEmulator?: { host, port },
//     wireCap }
//   commands: { id, op, ... }; each is answered by { event: "result", id, ok, ... }. The
//   operations are those of sdk-operations.mjs, shared with the browser page.

// Must stay the first import: it installs the wire guard before Firebase loads.
import { config, emit, local, sha256, tokenOwner } from "./sdk-driver-wire.mjs";

import { createInterface } from "node:readline";

import { initializeApp } from "firebase/app";
import * as auth from "firebase/auth";
import * as firestore from "firebase/firestore";

import { createOperations } from "./sdk-operations.mjs";

const app = initializeApp(config.web, `afc-${process.pid}`);
const clientAuth = auth.getAuth(app);
const db = firestore.getFirestore(app);
if (local) {
  auth.connectAuthEmulator(clientAuth, config.authEmulator, { disableWarnings: true });
  firestore.connectFirestoreEmulator(
    db,
    config.firestoreEmulator.host,
    config.firestoreEmulator.port,
  );
}

const run = createOperations({
  fb: { ...auth, ...firestore },
  auth: clientAuth,
  db,
  emit,
  onToken: (token, uid) => tokenOwner.set(sha256(token), uid),
  decodeBase64Url: (text) => Buffer.from(text, "base64url").toString("utf8"),
  exit: () => process.exit(0),
});

// Commands run concurrently: a paused transaction must not block the command that resumes it.
createInterface({ input: process.stdin }).on("line", (line) => {
  let command;
  try {
    command = JSON.parse(line);
  } catch {
    return emit({ event: "result", id: null, ok: false, error: "unparsable command" });
  }
  return run(command);
});
emit({ event: "ready" });
