// Records the official import / export fixtures under
// `crates/fireemu/tests/fixtures/export/`.
//
// The fixtures are what pins the Local Emulator Suite artifact format: they are real
// directories written by `firebase emulators:export` with the pinned `firebase-tools`
// (15.28.2) and the pinned Firestore emulator jar, seeded with a corpus that reaches every
// value shape and every Auth and Storage member fireemu has to preserve.
//
// Usage (Java is required, as for the rest of the oracle side):
//
//     node src/record-export.mjs            # rewrite both fixtures
//     node src/record-export.mjs --check    # record into a temporary directory and diff
//
// The recorded files carry the wall-clock timestamps and generated identifiers of the run
// that produced them, so re-recording always changes them; `--check` only reports whether
// the *shape* still matches (the same file names and the same document count).

import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  cpSync,
  readdirSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const conformance = path.resolve(here, "..");
const fixtures = path.resolve(conformance, "../crates/fireemu/tests/fixtures/export");
const cli = path.resolve(conformance, "node_modules/.bin/firebase");

const FIREBASE_JSON = {
  firestore: { rules: "firestore.rules" },
  storage: { rules: "storage.rules" },
  emulators: {
    singleProjectMode: true,
    firestore: { host: "127.0.0.1", port: 33080 },
    auth: { host: "127.0.0.1", port: 33099 },
    storage: { host: "127.0.0.1", port: 33199 },
    hub: { host: "127.0.0.1", port: 33400 },
    logging: { host: "127.0.0.1", port: 33500 },
    ui: { enabled: false },
  },
};

const OPEN_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if true; }
  }
}
`;

const OPEN_STORAGE_RULES = `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} { allow read, write: if true; }
  }
}
`;

/** The multi-product corpus: Firestore documents, Auth accounts and Storage objects. */
const SEED_MULTIPRODUCT = `
import { initializeApp } from "firebase-admin/app";
import { getFirestore, Timestamp, GeoPoint } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";
import { getStorage } from "firebase-admin/storage";

const projectId = process.env.GCLOUD_PROJECT;
initializeApp({ projectId, storageBucket: \`\${projectId}.appspot.com\` });
const db = getFirestore();
const auth = getAuth();

await db.collection("cities").doc("SF").set({
  name: "San Francisco", state: "CA", country: "USA", capital: false,
  population: 860000, density: 7272.5,
  regions: ["west_coast", "norcal"],
  location: new GeoPoint(37.7749, -122.4194),
  founded: Timestamp.fromMillis(1700000000000),
  nickname: null,
  blob: Buffer.from([0, 1, 2, 253, 254, 255]),
  ref: db.collection("cities").doc("LA"),
  nested: { a: 1, b: { c: "deep", d: [1, "two", true] } },
});
await db.collection("cities").doc("LA").set({
  name: "Los Angeles", state: "CA", country: "USA", capital: false, population: 3900000,
});
await db.collection("cities").doc("SF").collection("landmarks").doc("golden-gate")
  .set({ name: "Golden Gate Bridge", type: "bridge" });
await db.collection("empty-ish").doc("only-doc").set({});
await db.collection("unicode").doc("nihongo").set({ text: "こんにちは", emoji: "ok" });
for (let i = 0; i < 25; i++) {
  await db.collection("bulk").doc(\`doc-\${String(i).padStart(3, "0")}\`).set({ i, even: i % 2 === 0 });
}

await auth.createUser({
  uid: "user-password", email: "alice@example.com", emailVerified: true,
  password: "s3cret-password", displayName: "Alice Example",
  photoURL: "https://example.com/alice.png", phoneNumber: "+15555550100", disabled: false,
});
await auth.setCustomUserClaims("user-password", { role: "admin", tier: 3 });
await auth.createUser({
  uid: "user-disabled", email: "bob@example.com", password: "another-password",
  displayName: "Bob Example", disabled: true,
});
await auth.importUsers([{
  uid: "user-federated", email: "carol@example.com", emailVerified: true,
  displayName: "Carol Example",
  providerData: [{
    uid: "google-carol", email: "carol@example.com",
    displayName: "Carol Example", providerId: "google.com",
  }],
}]);
await auth.createUser({
  uid: "user-mfa", email: "dave@example.com", emailVerified: true,
  password: "mfa-password", phoneNumber: "+15555550101",
  multiFactor: { enrolledFactors: [{
    phoneNumber: "+15555550102", displayName: "personal phone", factorId: "phone",
  }] },
});
await auth.createUser({ uid: "user-anon" });

const bucket = getStorage().bucket();
await bucket.file("images/hello.txt").save(Buffer.from("hello storage\\n"), {
  contentType: "text/plain",
  metadata: { metadata: { custom: "value", n: "1" }, cacheControl: "public, max-age=60" },
});
await bucket.file("binary/blob.bin").save(Buffer.from([0, 1, 2, 3, 250, 251, 252, 253]), {
  contentType: "application/octet-stream",
});
await bucket.file("nested/deep/path/file.json").save(Buffer.from(JSON.stringify({ a: 1 })), {
  contentType: "application/json",
});
console.log("seeded");
`;

/** The Firestore value corpus: the shapes whose Datastore encoding is not obvious. */
const SEED_VALUES = `
import { initializeApp } from "firebase-admin/app";
import { getFirestore, Timestamp, GeoPoint, FieldValue } from "firebase-admin/firestore";

initializeApp({ projectId: process.env.GCLOUD_PROJECT });
const db = getFirestore();

await db.collection("edge").doc("empty-doc").set({});
await db.collection("edge").doc("empty-array").set({ arr: [], other: 1 });
await db.collection("edge").doc("empty-map").set({ m: {}, other: 2 });
await db.collection("edge").doc("specials").set({
  nan: Number.NaN, inf: Number.POSITIVE_INFINITY, ninf: Number.NEGATIVE_INFINITY,
  zero: 0, negzero: -0,
  maxint: Number.MAX_SAFE_INTEGER, minint: -Number.MAX_SAFE_INTEGER,
  emptystring: "", longstring: "x".repeat(2000),
});
await db.collection("edge").doc("nested-arrays").set({
  arr: [{ a: 1 }, { b: [1, 2] }], mapofarray: { inner: ["a", "b"] },
});
await db.collection("edge").doc("times").set({
  epoch: Timestamp.fromMillis(0),
  precise: new Timestamp(1700000000, 123456000),
  server: FieldValue.serverTimestamp(),
});
await db.collection("edge").doc("emptybytes").set({ b: Buffer.alloc(0) });
await db.collection("edge").doc("geo").set({ g: new GeoPoint(0, 0) });
await db.doc("edge/deep/a/1/b/2/c/3").set({ leaf: true });
await db.doc("edge/missing-parent/sub/child").set({ x: 1 });
console.log("seeded");
`;

const RECORDINGS = [
  {
    name: "official-multiproduct",
    project: "demo-export",
    only: "auth,firestore,storage",
    seed: SEED_MULTIPRODUCT,
  },
  {
    name: "official-firestore-values",
    project: "demo-edge",
    only: "firestore",
    seed: SEED_VALUES,
  },
];

function record(recording, into) {
  const work = mkdtempSync(path.join(tmpdir(), "fireemu-record-"));
  writeFileSync(path.join(work, "firebase.json"), JSON.stringify(FIREBASE_JSON, undefined, 2));
  writeFileSync(path.join(work, "firestore.rules"), OPEN_RULES);
  writeFileSync(path.join(work, "storage.rules"), OPEN_STORAGE_RULES);
  writeFileSync(path.join(work, "package.json"), JSON.stringify({ type: "module" }));
  writeFileSync(path.join(work, "seed.mjs"), recording.seed);
  // The seed script resolves `firebase-admin` from the pinned conformance install.
  spawnSync("ln", [
    "-sfn",
    path.join(conformance, "node_modules"),
    path.join(work, "node_modules"),
  ]);

  const out = path.join(work, "export");
  const result = spawnSync(
    cli,
    [
      "emulators:exec",
      "--project",
      recording.project,
      "--only",
      recording.only,
      "--export-on-exit",
      out,
      "node seed.mjs",
    ],
    { cwd: work, stdio: "inherit" },
  );
  if (result.status !== 0) {
    throw new Error(`recording ${recording.name} failed with status ${result.status}`);
  }
  rmSync(into, { recursive: true, force: true });
  mkdirSync(path.dirname(into), { recursive: true });
  cpSync(out, into, { recursive: true });
  rmSync(work, { recursive: true, force: true });
}

function tree(dir) {
  const out = [];
  const walk = (at, prefix) => {
    for (const entry of readdirSync(at).sort()) {
      const full = path.join(at, entry);
      if (statSync(full).isDirectory()) walk(full, `${prefix}${entry}/`);
      else out.push(`${prefix}${entry}`);
    }
  };
  walk(dir, "");
  return out;
}

const check = process.argv.includes("--check");
for (const recording of RECORDINGS) {
  const target = path.join(fixtures, recording.name);
  if (!check) {
    record(recording, target);
    console.log(`recorded ${recording.name}: ${tree(target).length} files`);
    continue;
  }
  const staged = path.join(mkdtempSync(path.join(tmpdir(), "fireemu-check-")), recording.name);
  record(recording, staged);
  const before = tree(target).join("\n");
  const after = tree(staged).join("\n");
  if (before !== after) {
    console.error(
      `${recording.name}: the recorded file set changed\n--- kept\n${before}\n--- new\n${after}`,
    );
    process.exitCode = 1;
  } else {
    console.log(`${recording.name}: the recorded file set is unchanged`);
  }
  rmSync(path.dirname(staged), { recursive: true, force: true });
}
