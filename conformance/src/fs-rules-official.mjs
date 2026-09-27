// What the pinned official Firestore emulator answers on the FS-RULES cases where fireemu's
// emulator profile changed along with production (committed evidence for R9: the emulator
// profile adds no refusal the official emulator does not make).
//
//   npx firebase emulators:exec --only firestore --project demo-fs-rules-official \
//     --config <dir>/firebase.json "node src/fs-rules-official.mjs record"
//
// writes conformance/fs-rules-official.json. The official emulator is local; nothing here
// reaches production. The test (fs-rules-official.test.mjs) compares it with the production
// fixture.

import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { COMPILE_CASES } from "./fs-rules/programs/limits.mjs";

const PROJECT = "demo-fs-rules-official";
const OUT = fileURLToPath(new URL("../fs-rules-official.json", import.meta.url));
const DB = "/databases/$(database)/documents";

const balanced = (n) =>
  n === 1 ? "true" : `(${balanced(Math.floor(n / 2))} && ${balanced(n - Math.floor(n / 2))})`;

/**
 * Runtime cases: one ruleset each, one request, and the production row it stands beside
 * (`[program, step]` in conformance/fs-rules-production.json).
 */
export const RUNTIME_CASES = [
  {
    name: "terms-334",
    rules: `match /c/{d} { allow get: if ${balanced(334)}; }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/runtime-limits/evaluation", "terms-334"],
  },
  {
    name: "terms-335",
    rules: `match /c/{d} { allow get: if ${balanced(335)}; }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/runtime-limits/evaluation", "terms-335"],
  },
  {
    name: "terms-500-then-true",
    rules: `match /c/{d} { allow get: if ${balanced(500)}; allow get: if true; }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/runtime-limits/evaluation", "terms-500-then-true"],
  },
  {
    name: "error-then-true",
    rules: `match /c/{d} { allow get: if get(${DB}/src/missing).data.n == 1; allow get: if true; }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/runtime-limits/evaluation", "error-then-true"],
  },
  {
    name: "exists-after-in-a-read",
    rules: `match /c/{d} { allow get: if existsAfter(${DB}/src/present); }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/runtime-limits/evaluation", "exists-after-runtime-read"],
  },
  {
    name: "get-of-a-missing-document-is-null",
    rules: `match /c/{d} { allow get: if get(${DB}/src/missing) == null; }`,
    request: { method: "GET", path: "c/d" },
    production: ["fs-rules/document-access/reads-and-writes", "get-missing-is-null"],
  },
  {
    name: "end-user-batch-write",
    rules: "match /{document=**} { allow read, write: if true; }",
    request: {
      method: "POST",
      path: ":batchWrite",
      user: "u1",
      body: (docs) => ({ writes: [{ update: { name: `${docs}/bw/one`, fields: {} } }] }),
    },
    production: ["fs-rules/atomic/commit-and-batch-write", "batch-write-all-allowed"],
  },
  {
    name: "delete-sees-a-null-request-resource",
    rules: "match /c/{d} { allow read: if true; allow delete: if request.resource == null; }",
    request: { method: "DELETE", path: "c/gone", user: "u1" },
    production: ["fs-rules/request-resource/writes", "delete-no-request-resource"],
  },
  {
    name: "create-on-an-existing-document-denied-by-rules-first",
    rules: "match /c/{d} { allow read: if true; allow create: if false; allow update: if true; }",
    request: { method: "POST", path: "c?documentId=d", user: "u1", body: () => ({ fields: {} }) },
    production: ["fs-rules/principals/separation", "verified-create-in-b"],
  },
  {
    name: "create-on-an-existing-document-allowed-then-refused-as-existing",
    rules: "match /c/{d} { allow read: if true; allow create: if true; allow update: if false; }",
    request: { method: "POST", path: "c?documentId=d", user: "u1", body: () => ({ fields: {} }) },
    production: ["fs-rules/document-access/reads-and-writes", "write-get-before-partner-existing"],
  },
  {
    name: "query-keys-has-only-the-documented-three",
    rules:
      "match /q/{d} { allow list: if request.query.keys().hasOnly(['limit', 'offset', 'orderBy']); }",
    request: { method: "POST", path: ":runQuery", query: "q" },
    production: ["fs-rules/query/constraints", "shape-keys"],
  },
  {
    name: "query-keys-has-all-the-documented-three",
    rules:
      "match /q/{d} { allow list: if request.query.keys().hasAll(['limit', 'offset', 'orderBy']); }",
    request: { method: "POST", path: ":runQuery", query: "q" },
    production: ["fs-rules/query/constraints", "shape-keys-all"],
  },
  {
    name: "query-order-by-is-an-empty-map",
    rules:
      "match /q/{d} { allow list: if request.query.orderBy is map && request.query.orderBy.size() == 0; }",
    request: { method: "POST", path: ":runQuery", query: "q" },
    production: ["fs-rules/query/constraints", "shape-order-empty"],
  },
  {
    name: "query-has-nine-keys",
    rules: "match /q/{d} { allow list: if request.query.size() == 9; }",
    request: { method: "POST", path: ":runQuery", query: "q" },
    // Not a recorded row: the exploratory probes found nine keys (see the closure note).
    production: null,
  },
  {
    name: "list-reads-20-documents",
    rules: `match /q/{d} { allow list: if ${Array.from({ length: 20 }, (_, i) => `!exists(${DB}/src/m${i})`).join(" && ")}; }`,
    request: { method: "POST", path: ":runQuery", query: "q" },
    production: ["fs-rules/budgets/access-calls", "list-empty-20"],
  },
  {
    name: "list-reads-21-documents",
    rules: `match /q/{d} { allow list: if ${Array.from({ length: 21 }, (_, i) => `!exists(${DB}/src/m${i})`).join(" && ")}; }`,
    request: { method: "POST", path: ":runQuery", query: "q" },
    production: ["fs-rules/budgets/access-calls", "list-empty-21"],
  },
];

const source = (rules) =>
  `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    ${rules}\n  }\n}\n`;

function mockToken(uid) {
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  return `${b64({ alg: "none", typ: "JWT" })}.${b64({
    iss: `https://securetoken.google.com/${PROJECT}`,
    aud: PROJECT,
    sub: uid,
    user_id: uid,
    iat: now,
    exp: now + 3600,
    auth_time: now,
    firebase: { sign_in_provider: "password", identities: {} },
  })}.`;
}

async function record() {
  const host = process.env.FIRESTORE_EMULATOR_HOST;
  if (!host) throw new Error("run under firebase emulators:exec (FIRESTORE_EMULATOR_HOST)");
  const base = `http://${host}`;
  const docs = `projects/${PROJECT}/databases/(default)/documents`;
  const load = async (rules) => {
    const response = await fetch(`${base}/emulator/v1/projects/${PROJECT}:securityRules`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: rules }] } }),
    });
    return { status: response.status, body: await response.json().catch(() => null) };
  };
  const compile = {};
  for (const [name, rules] of COMPILE_CASES) {
    const { status } = await load(rules);
    compile[name] = { accepted: status === 200 };
  }
  // Seed as the owner, which the official emulator lets bypass rules.
  const owner = { authorization: "Bearer owner", "content-type": "application/json" };
  for (const path of ["c/d", "c/gone", "src/present", "q/one"]) {
    await fetch(`${base}/v1/${docs}/${path}`, {
      method: "PATCH",
      headers: owner,
      body: JSON.stringify({ fields: { n: { integerValue: "1" } } }),
    });
  }
  const runtime = {};
  for (const { name, rules, request } of RUNTIME_CASES) {
    const loaded = await load(source(rules));
    if (loaded.status !== 200) {
      runtime[name] = { compiled: false };
      continue;
    }
    const headers = {
      "content-type": "application/json",
      ...(request.user ? { authorization: `Bearer ${mockToken(request.user)}` } : {}),
    };
    const url = request.path.startsWith(":")
      ? `${base}/v1/${docs}${request.path}`
      : `${base}/v1/${docs}/${request.path}`;
    const body = request.query
      ? { structuredQuery: { from: [{ collectionId: request.query }] } }
      : request.body?.(docs);
    const response = await fetch(url, {
      method: request.method,
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    const error = (Array.isArray(parsed) ? parsed : [parsed]).find((e) => e?.error)?.error;
    runtime[name] = {
      status: response.status,
      // Whether Security Rules allowed it: a later refusal (a failed precondition, a missing
      // document) is still an allow.
      allowed: response.status !== 403 && error?.status !== "PERMISSION_DENIED",
      ...(error
        ? { error: { status: error.status, message: String(error.message).slice(0, 160) } }
        : {}),
    };
  }
  const out = {
    recordedAgainst:
      "firebase-tools 15.28.2 (conformance devDependency), its Firestore emulator, local; not production",
    project: PROJECT,
    compile,
    runtime,
  };
  await writeFile(OUT, `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify({ compile: Object.keys(compile).length, runtime }, null, 1));
}

if (import.meta.url === `file://${process.argv[1]}` && process.argv[2] === "record") await record();
