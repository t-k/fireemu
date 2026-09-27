// This script exercises local fireemu only. Its control API is not a Firebase Rules release API.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildCorpus, validateCorpus } from "./corpus.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
const controlBase = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
if (!host || !controlBase || !controlToken) {
  throw new Error("run this script through fireemu exec with only local Storage selected");
}
if (!/^127\.0\.0\.1:\d+$/.test(host) && !/^\[::1\]:\d+$/.test(host)) {
  throw new Error("Storage host must be loopback");
}
const control = new URL("storage/rules", controlBase);
if (!["127.0.0.1", "[::1]"].includes(control.hostname)) {
  throw new Error("control URL must be loopback");
}
const binding = {
  bucket: "demo-storage-rules.appspot.com",
  prefix: "STORAGE-RULES/local-smoke/",
  uidA: "local-user-a",
  uidB: "local-user-b",
};
const corpus = buildCorpus(binding);
const closure = JSON.parse(readFileSync(new URL("../../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
validateCorpus(corpus, closure);
const [compile, switched, noRelease] = corpus.managementPrograms;
const storageBase = `http://${host}`;
const owned = new Set();
let assertions = 0;

async function send(url, init) {
  const response = await fetch(url, init);
  const bytes = Buffer.from(await response.arrayBuffer());
  return { status: response.status, bytes, headers: response.headers };
}
function status(value, expected, label) {
  assert.equal(value.status, expected, label);
  assertions++;
}
async function rules(method) {
  const result = await send(control, {
    method,
    headers: { authorization: `Bearer ${controlToken}` },
  });
  return result;
}
async function activate(source) {
  return send(new URL("/internal/setRules", storageBase), {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rules: { files: [{ name: "storage.rules", content: source }] } }),
  });
}
async function rulesSnapshot() {
  const response = await rules("GET");
  status(response, 200, "local rules readback");
  return JSON.parse(response.bytes.toString("utf8"));
}
function objectUrl(name, dialect, query = {}) {
  const path = dialect === "firebase" ? "/v0" : "/storage/v1";
  const url = new URL(`${path}/b/${binding.bucket}/o/${encodeURIComponent(name)}`, storageBase);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  return url;
}
async function adminGet(name, media = false) {
  return send(objectUrl(name, "gcs", media ? { alt: "media" } : {}), {
    headers: { authorization: "Bearer owner" },
  });
}
async function firebaseGet(name) {
  return send(objectUrl(name, "firebase", { alt: "media" }));
}
async function seed(name) {
  assert.ok(name.startsWith(binding.prefix));
  const url = new URL(`/upload/storage/v1/b/${binding.bucket}/o`, storageBase);
  url.searchParams.set("uploadType", "media");
  url.searchParams.set("name", name);
  const response = await send(url, {
    method: "POST",
    headers: { authorization: "Bearer owner", "content-type": "text/plain" },
    body: "seed",
  });
  status(response, 200, `admin seed ${name}`);
  owned.add(name);
}
async function removeOwned(name) {
  if (!owned.has(name)) return;
  const metadata = await adminGet(name);
  status(metadata, 200, `owned metadata ${name}`);
  const generation = JSON.parse(metadata.bytes.toString("utf8")).generation;
  assert.match(generation, /^\d+$/);
  const response = await send(objectUrl(name, "gcs", { ifGenerationMatch: generation }), {
    method: "DELETE",
    headers: { authorization: "Bearer owner" },
  });
  status(response, 204, `owned delete ${name}`);
  status(await adminGet(name), 404, `owned absence ${name}`);
  owned.delete(name);
}

try {
  assert.equal((await rulesSnapshot()).loaded, false, "local initial rules absent");
  await seed(noRelease.objectName);
  status(await adminGet(noRelease.objectName, true), 200, "admin read before no-release refusal");
  status(await firebaseGet(noRelease.objectName), 403, "Firebase refuses without local rules");
  status(await adminGet(noRelease.objectName, true), 200, "admin read after no-release refusal");
  assert.equal((await rulesSnapshot()).loaded, false, "no-release observation preserved absence");

  for (const candidate of compile.validSources) {
    status(await activate(candidate.content), 200, `local compile ${candidate.ref}`);
    const snapshot = await rulesSnapshot();
    assert.equal(snapshot.source, candidate.content, `local readback ${candidate.ref}`);
  }
  const priorSource = (await rulesSnapshot()).source;
  status(await activate(compile.invalidSource.content), 400, "invalid local Storage rule refused");
  assert.equal((await rulesSnapshot()).source, priorSource, "invalid local rule preserved active source");

  await seed(switched.objectA);
  await seed(switched.objectB);
  status(await activate(switched.sourceA), 200, "install local source A");
  assert.equal((await rulesSnapshot()).source, switched.sourceA, "source A readback");
  status(await firebaseGet(switched.objectA), 200, "source A allows old object");
  status(await firebaseGet(switched.objectB), 403, "source A refuses new object");
  status(await activate(switched.sourceB), 200, "install local source B");
  assert.equal((await rulesSnapshot()).source, switched.sourceB, "source B readback");
  status(await firebaseGet(switched.objectA), 403, "source B refuses old object");
  status(await firebaseGet(switched.objectB), 200, "source B allows new object");
  status(await rules("DELETE"), 200, "clear local rules");
  assert.equal((await rulesSnapshot()).loaded, false, "local rules absent after clear");
  status(await firebaseGet(switched.objectA), 403, "Firebase refuses after local clear");
  status(await adminGet(switched.objectA, true), 200, "admin bypass remains after local clear");

  console.log(`storage-rules local smoke passed: ${compile.validSources.length} valid sources, 1 invalid source, 3 management recipes, ${assertions} status checks`);
} finally {
  await rules("DELETE");
  for (const name of [...owned]) await removeOwned(name);
}
