import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { linkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindShapeEntry, readLocalInputs } from "./storage-rules-shape/shape-entry.mjs";
import { allIds, shapeCorpus, staticRequests, WRITE_IDS } from "./storage-rules-shape/plan.mjs";
import { shapeCodeDigests } from "./storage-rules-shape/pins.mjs";
import { ADC, BUCKET, OWNER_EMAIL, OWNER_SUBJECT, OWNER_TOKEN, PIN_KEYS, SOURCE_COMMIT, RULESET, cleanup, createShapeWorld, fakeRequestImpl, ownerDigest, shapeLocal, scratchCode } from "./storage-rules-shape-support.mjs";

// The stage 2f entry against a scratch main checkout and a fake production: what it reads, creates, deletes and leaves, and when it stops.
const codeRoot = scratchCode();
process.on("exit", () => cleanup(codeRoot));
const digests = await shapeCodeDigests(codeRoot);
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "shape-test-run";
const corpus = shapeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest });
const packet = { taskId: "STORAGE-RULES", packetName: "stage2f-shape-v1", packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-query"], maxRequests: 19, reserveUsd: 0.15 };
const ENVELOPE = "STORAGE-RULES-stage2f-shape-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-30 | STORAGE-RULES stage2f-shape-v1 envelope | envelopeId=${ENVELOPE}; project=fireemu-oracle-query; maxRequests=39; reserveUsd=0.25; writes=deletes only the journaled objects, accounts and rulesets; iamConfig=none; retries=none; onStop=locks-held; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-30 | STORAGE-RULES stage2f-shape-v1 | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");

async function checkout(t, { world = createShapeWorld(), gitHead = SOURCE_COMMIT, gitStatus = "", gitExtra = "", gitExtraShape = "", gitThrows = false, usage = [], mutatePacket = (value) => value, ledgerText = ledger } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-shape-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  const used = mutatePacket(structuredClone(packet));
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-shape-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: used.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(shapeLocal(adcPath)), { mode: 0o600 });
  const wire = [];
  const git = async (where, args) => { if (gitThrows) throw new Error("git failed"); if (args[0] === "rev-parse") return `${gitHead}\n`; if (args.includes("--ignored")) return args.includes("conformance/src/storage-rules-shape") ? gitExtraShape : gitExtra; return gitStatus; };
  const entry = bindShapeEntry({ root, codeRoot, requestImpl: fakeRequestImpl((spec) => world.answer(spec), wire), clock, git });
  const options = { localPath, runId, sourceCommit: SOURCE_COMMIT, packet: used, review: structuredClone(review) };
  return { root, runs, entry, options, wire, world, localPath, adcPath, ledgerPath: join(root, "docs.local", "instructions", "owner-decisions.md"), lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
const runDir = (f) => join(f.runs, `storage-rules-shape-${runId}`);
const readLines = async (f, name) => (await readFile(join(runDir(f), name), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
const factsOf = async (f) => (await readLines(f, "captures.jsonl")).flatMap((row) => { const data = row.data ?? row; return data.facts !== undefined && data.kind === "shape-answer" ? [{ operationId: data.operationId, facts: data.facts }] : []; });
const terminalOf = async (f) => (await readLines(f, "reservations.jsonl")).at(-1).data.outcome;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const urls = (f) => f.wire.map((entry) => `${entry.method} ${new URL(entry.url).host}${new URL(entry.url).pathname}${new URL(entry.url).search}`);
const lockedOnce = ["fireemu-oracle-query.lock"];
const requests = staticRequests(BUCKET);
const byId = (id) => requests.find((entry) => entry.id === id);
// A request by its ID: a static one is matched by method, URL and body; a dependent one by its ID's route.
const ROUTES = {
  "shape/ruleset/read": (spec) => spec.method === "GET" && spec.url.endsWith(`/v1/${RULESET}`),
  "shape/ruleset/delete": (spec) => spec.method === "DELETE" && spec.url.endsWith(`/v1/${RULESET}`),
  "shape/object/delete": (spec) => spec.method === "DELETE" && spec.url.includes("/storage/v1/b/"),
  "shape/document/delete": (spec) => spec.method === "DELETE" && spec.url.includes("firestore.googleapis.com"),
};
const at = (id) => (spec) => (ROUTES[id] ? ROUTES[id](spec) : spec.method === byId(id).method && spec.url === byId(id).url && (byId(id).body === null || spec.body.equals(byId(id).body)));
const nth = (id, n) => { let seen = 0; return (spec) => at(id)(spec) && ++seen === n; };

test("a clean run reads the environment first, creates and deletes one ruleset, one object and one document, records every answer, proves the deletion and releases the lock", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.changed, result.released, result.requests], ["finished", true, true, 19]);
  assert.equal(await terminalOf(f), "finished");
  assert.deepEqual(await f.lockFiles(), []);
  assert.equal(f.world.clean(), true);
  const B = `storage.googleapis.com/storage/v1/b/${BUCKET}/o`;
  const D = "firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents";
  assert.deepEqual(urls(f), [
    "POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo",
    "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100", `GET ${B}?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`, `GET ${D}/STORAGE-RULES/probe-2f-doc`,
    "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets/00000000-0000-4000-8000-0000000002f0", "POST firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets",
    `GET firebaserules.googleapis.com/v1/${RULESET}`, `DELETE firebaserules.googleapis.com/v1/${RULESET}`, `GET firebaserules.googleapis.com/v1/${RULESET}`,
    `POST storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=STORAGE-RULES%2Fprobe-2f%2Fobject.bin&ifGenerationMatch=0`, `GET ${B}?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`, `DELETE ${B}/STORAGE-RULES%2Fprobe-2f%2Fobject.bin?ifGenerationMatch=1790727977683752`,
    `POST ${D}/STORAGE-RULES?documentId=probe-2f-doc`, `GET ${D}/STORAGE-RULES/probe-2f-doc`, `DELETE ${D}/STORAGE-RULES/probe-2f-doc?currentDocument.updateTime=2026-09-30T02%3A30%3A01.654321Z`,
    "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100", `GET ${B}?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`, `GET ${D}/STORAGE-RULES/probe-2f-doc`,
  ]);
  // Six writes, each journalled under its own mutation key before it is sent; no read has one.
  const intents = (await readLines(f, "captures.jsonl")).map((row) => row.data ?? row).filter((data) => Object.hasOwn(data, "mutationKey"));
  assert.equal(intents.length, 19);
  for (const intent of intents) assert.equal(intent.mutationKey, WRITE_IDS.includes(intent.operationId) ? `shape:${intent.operationId}` : null, intent.operationId);
  assert.equal(intents.filter((intent) => intent.mutationKey !== null).length, 6);
  assert.deepEqual(f.world.sent.map((entry) => entry.method), ["POST", "POST", "DELETE", "POST", "DELETE", "POST", "DELETE"], "the token refresh and the six writes");
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
    if (new URL(entry.url).pathname === "/oauth2/v2/userinfo") assert.equal(Object.hasOwn(entry.headers, "x-goog-user-project"), false);
    else assert.equal(entry.headers["x-goog-user-project"], "fireemu-oracle-query", entry.url);
  }
  // The object is uploaded as text and the other bodies are JSON.
  assert.equal(f.wire.find((entry) => entry.url.includes("/upload/storage/")).headers["content-type"], "text/plain");
  // Each answer is a fact (status, size, digest and content type) and the raw bytes are in the private journal.
  const facts = await factsOf(f);
  assert.deepEqual(facts.map((fact) => fact.operationId), allIds.slice(2));
  const never = facts.find((fact) => fact.operationId === "shape/ruleset/never").facts;
  assert.deepEqual([never.status, never.contentType], [404, "application/json; charset=UTF-8"]);
  const del = facts.find((fact) => fact.operationId === "shape/object/delete").facts;
  assert.deepEqual(del, { status: 204, bodyBytes: 0, bodySha256: sha(Buffer.alloc(0)), contentType: null });
  const blobs = await Promise.all((await readdir(join(runDir(f), "blobs"))).map((name) => readFile(join(runDir(f), "blobs", name), "utf8").catch(() => "")));
  assert.ok(blobs.some((text) => text.includes("Requested entity was not found")), "the 404 of a ruleset that never existed is kept as bytes");
  const journals = (await Promise.all((await readdir(runDir(f))).filter((name) => name.endsWith(".jsonl")).map((name) => readFile(join(runDir(f), name), "utf8")))).join("\n");
  assert.equal(journals.includes(OWNER_TOKEN), false);
  assert.equal(journals.includes(OWNER_EMAIL), false);
});

test("a second run does the same, because the first left nothing behind", async (t) => {
  const world = createShapeWorld();
  const first = await checkout(t, { world });
  await first.entry(first.options);
  const second = await checkout(t, { world });
  const result = await second.entry(second.options);
  assert.equal(result.status, "finished");
  assert.equal(world.clean(), true);
});

test("an environment that is not the expected one stops the run before anything is created, keeps the lock and ends as preflight-failed", async (t) => {
  const spoiled = {
    "a ruleset besides the two kept": (w) => w.rulesets.set(RULESET, "2026-09-30T02:00:00Z"),
    "an object under the probe's prefix": (w) => { w.object = "1"; },
    "the probe's document exists": (w) => { w.document = "2026-09-30T02:00:00Z"; },
    "the rulesets list is paged": (w) => { w.hook.any = (spec) => (spec.url.endsWith("/rulesets?pageSize=100") ? w.json({ rulesets: [], nextPageToken: "t" }) : undefined); },
  };
  for (const [name, change] of Object.entries(spoiled)) {
    const world = createShapeWorld();
    change(world);
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.world.sent.filter((entry) => entry.method !== "POST" || !entry.key.includes("oauth2")).length, 0, name);
    assert.equal(await terminalOf(f), "preflight-failed", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("an owner who is not the expected one, or is unverified, stops the run before any read of the environment", async (t) => {
  for (const identity of [{ id: "1", email: "other@example.test", verified_email: true }, { id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: false }, { id: OWNER_SUBJECT }]) {
    const f = await checkout(t);
    f.world.hook.any = (spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? f.world.json(identity) : undefined);
    await assert.rejects(f.entry(f.options));
    assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
  }
});

// The requests that share a URL with an earlier read are matched by their place: the second read of a ruleset, the second of the prefix list, the second of the document.
const HITS = {
  "shape/ruleset/never": () => at("shape/ruleset/never"), "shape/ruleset/read": () => at("shape/ruleset/read"), "shape/ruleset/read-deleted": () => nth("shape/ruleset/read", 2),
  "shape/object/list": () => nth("preflight/objects/list", 2), "shape/document/read": () => nth("preflight/document/absent", 2),
  "verify/rulesets/list": () => nth("preflight/rulesets/list", 2), "verify/objects/list": () => nth("preflight/objects/list", 3), "verify/document/absent": () => nth("preflight/document/absent", 3),
};

test("a content type is recorded only when it is short, printable and free of markup, and is null when absent", async (t) => {
  const answers = {
    "no header": { rawHeaders: [], expected: null }, "markup": { rawHeaders: ["Content-Type", "text/<b>x</b>"], expected: null }, "control character": { rawHeaders: ["Content-Type", "text/plain\u0007"], expected: null },
    "too long": { rawHeaders: ["Content-Type", `text/${"a".repeat(101)}`], expected: null }, "empty": { rawHeaders: ["Content-Type", ""], expected: null },
    "printable": { rawHeaders: ["Content-Type", "text/plain; charset=utf-8"], expected: "text/plain; charset=utf-8" }, "upper-case name": { rawHeaders: ["CONTENT-TYPE", "text/plain"], expected: "text/plain" },
    "the first of two": { rawHeaders: ["Content-Type", "text/plain", "Content-Type", "text/html"], expected: "text/plain" }, "exactly 100": { rawHeaders: ["Content-Type", `t/${"a".repeat(98)}`], expected: `t/${"a".repeat(98)}` },
    "a lower-case angle only after": { rawHeaders: ["X-Other", "a", "Content-Type", "text/plain"], expected: "text/plain" },
  };
  for (const [name, { rawHeaders, expected }] of Object.entries(answers)) {
    const f = await checkout(t);
    f.world.hook.any = (spec) => (at("shape/ruleset/never")(spec) ? { status: 404, rawHeaders: rawHeaders.map((value) => value.replace("\\u0007", String.fromCharCode(7))), bytes: Buffer.from("{}") } : undefined);
    await f.entry(f.options);
    assert.equal((await factsOf(f)).find((fact) => fact.operationId === "shape/ruleset/never").facts.contentType, expected, name);
  }
});

test("the identity answer must be well-formed UTF-8, and the run stops before the first read of the environment", async (t) => {
  const f = await checkout(t);
  f.world.hook.any = (spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.concat([Buffer.from('{"id":"1","email":"owner@example.test","verified_email":true,"note":"'), Buffer.from([0xff]), Buffer.from('"}')]) } : undefined);
  await assert.rejects(f.entry(f.options));
  assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
});

test("a shape step that answers something unexpected is recorded and the run goes on, so everything created is still deleted", async (t) => {
  const odd = {
    "the ruleset that never existed answers 500": ["shape/ruleset/never", (w) => w.json({ error: { code: 500, message: "boom" } }, 500)],
    "the ruleset read answers HTML": ["shape/ruleset/read", () => ({ status: 200, rawHeaders: ["Content-Type", "text/html"], bytes: Buffer.from("<html>nope</html>") })],
    "the read after deletion answers 200": ["shape/ruleset/read-deleted", (w) => w.json({ name: RULESET })],
    "the object list answers an empty body": ["shape/object/list", () => ({ status: 200, rawHeaders: [], bytes: Buffer.alloc(0) })],
    "the document read answers a redirect": ["shape/document/read", () => ({ status: 302, rawHeaders: ["Location", "https://example.test/"], bytes: Buffer.alloc(0) })],
  };
  for (const [name, [id, answer]] of Object.entries(odd)) {
    const f = await checkout(t);
    const hit = HITS[id]();
    f.world.hook.any = (spec) => (hit(spec) ? answer(f.world) : undefined);
    const result = await f.entry(f.options);
    assert.equal(result.status, "finished", name);
    assert.equal(result.requests, 19, name);
    assert.equal(f.world.clean(), true, name);
    assert.equal((await factsOf(f)).length, 17, name);
  }
});

test("a delete that answers unexpectedly and did not delete goes on with the other groups, and the run ends as needs-recovery because the proving read shows what is left", async (t) => {
  const cases = {
    "the ruleset delete fails": ["shape/ruleset/delete", (f) => f.world.rulesets.has(RULESET), "verify/rulesets/list"],
    "the object delete fails": ["shape/object/delete", (f) => f.world.object !== null, "verify/objects/list"],
    "the document delete fails": ["shape/document/delete", (f) => f.world.document !== null, "verify/document/absent"],
  };
  for (const [name, [id, left]] of Object.entries(cases)) {
    const f = await checkout(t);
    f.world.hook.any = (spec) => (at(id)(spec) ? f.world.json({ error: { code: 500, message: "boom" } }, 500) : undefined);
    await assert.rejects(f.entry(f.options), /deletion not proven/, name);
    assert.equal(left(f), true, name);
    assert.equal(f.wire.length, 19, `${name}: every step was sent once`);
    assert.equal(await terminalOf(f), "needs-recovery", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("a create answer that cannot prove ownership stops the run there: nothing after it is sent, the lock stays and it ends as needs-recovery", async (t) => {
  const creates = {
    "ruleset": ["shape/ruleset/create", 7], "object": ["shape/object/create", 11], "document": ["shape/document/create", 14],
  };
  const answers = { "500": (w) => w.json({ error: { code: 500, message: "boom" } }, 500), "a foreign name": (w) => w.json({ name: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8", createTime: "2026-09-25T11:08:54.358767Z" }), "an empty object": (w) => w.json({}) };
  for (const [name, [id, sent]] of Object.entries(creates)) {
    for (const [kind, answer] of Object.entries(answers)) {
      const f = await checkout(t);
      f.world.hook.any = (spec) => (at(id)(spec) ? answer(f.world) : undefined);
      await assert.rejects(f.entry(f.options), new RegExp(`ownership not proven at ${id.replaceAll("/", "\\/")}`), `${name} ${kind}`);
      assert.equal(f.wire.length, sent, `${name} ${kind}`);
      assert.equal(await terminalOf(f), "needs-recovery", `${name} ${kind}`);
      assert.deepEqual(await f.lockFiles(), lockedOnce, `${name} ${kind}`);
    }
  }
});

test("a lost connection at any step after the reads stops the run at that request, sends nothing after it and keeps the lock", async (t) => {
  const ids = ["shape/ruleset/never", "shape/ruleset/create", "shape/ruleset/read", "shape/ruleset/delete", "shape/ruleset/read-deleted", "shape/object/create", "shape/object/list", "shape/object/delete", "shape/document/create", "shape/document/read", "shape/document/delete", "verify/rulesets/list", "verify/objects/list", "verify/document/absent"];
  for (const [index, id] of ids.entries()) {
    const f = await checkout(t);
    let lost = 0;
    const hit = HITS[id] ? HITS[id]() : at(id);
    f.world.hook.any = (spec) => { if (hit(spec)) { lost++; throw new Error("connection lost"); } return undefined; };
    await assert.rejects(f.entry(f.options), undefined, id);
    assert.equal(lost, 1, id);
    assert.equal(f.wire.length, 5 + 1 + index, id);
    assert.equal(await terminalOf(f), "needs-recovery", id);
    assert.deepEqual(await f.lockFiles(), lockedOnce, id);
  }
});

test("a proving read that shows something left ends the run as needs-recovery, after every step was sent once", async (t) => {
  const remaining = {
    "the ruleset is still listed": (f) => { const hit = HITS["verify/rulesets/list"](); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ rulesets: [...JSON.parse(f.world.answer.call(null, spec).bytes).rulesets, { name: RULESET, createTime: "2026-09-30T02:30:00Z", metadata: { services: ["firebase.storage"] } }] }) : undefined); },
    "the ruleset list has another page": (f) => { const hit = HITS["verify/rulesets/list"](); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ rulesets: [], nextPageToken: "more" }) : undefined); },
    "an object is listed under the prefix": (f) => { const hit = HITS["verify/objects/list"](); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ kind: "storage#objects", items: [{ name: "x" }] }) : undefined); },
    "the document is still there": (f) => { const hit = HITS["verify/document/absent"](); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ name: "x" }) : undefined); },
  };
  for (const [name, prepare] of Object.entries(remaining)) {
    const f = await checkout(t);
    prepare(f);
    await assert.rejects(f.entry(f.options), /deletion not proven/, name);
    assert.equal(f.wire.length, 19, name);
    assert.equal(await terminalOf(f), "needs-recovery", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("a revocation written while the probe is going stops the very next request", async (t) => {
  const f = await checkout(t);
  let revoked = false;
  f.world.hook.any = (spec) => { if (!revoked && at("shape/ruleset/delete")(spec)) { revoked = true; writeFileSync(f.ledgerPath, `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2f-shape-v1 | decision=REVOKED | Claude | private.md`); } return undefined; };
  await assert.rejects(f.entry(f.options), /admission refused/);
  assert.equal(f.world.calls[`GET firebaserules.googleapis.com/v1/${RULESET}`], 1);
  assert.equal(await terminalOf(f), "needs-recovery");
  assert.deepEqual(await f.lockFiles(), lockedOnce);
});

test("the approval binds the probe to its name, its limits and its pins", async (t) => {
  for (const [name, mutate] of Object.entries({
    "another packet name": (value) => ({ ...value, packetName: "stage2d-probe-v1" }), "more requests": (value) => ({ ...value, maxRequests: 40 }), "fewer requests": (value) => ({ ...value, maxRequests: 38 }),
    "a larger reserve": (value) => ({ ...value, reserveUsd: 0.5 }), "another project": (value) => ({ ...value, projects: ["fireemu-oracle-idp"] }), "two projects": (value) => ({ ...value, projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.wire.length, 0, name);
  }
  for (const [name, mutate] of Object.entries({
    "runner pin": (value) => ({ ...value, runnerSha256: "0".repeat(64) }), "fixture pin": (value) => ({ ...value, fixtureSchemaSha256: "0".repeat(64) }), "manifest pin": (value) => ({ ...value, manifestSha256: "0".repeat(64) }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), /pin mismatch/, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
  }
  const revoked = await checkout(t, { ledgerText: `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2f-shape-v1 | decision=REVOKED | Claude | private.md` });
  await assert.rejects(revoked.entry(revoked.options));
  assert.equal(revoked.wire.length, 0);
  const missing = await checkout(t, { ledgerText: "" });
  await assert.rejects(missing.entry(missing.options));
  assert.equal(missing.wire.length, 0);
  const used = await checkout(t, { usage: ["an-earlier-run"] });
  await assert.rejects(used.entry(used.options), /recording budget exhausted/);
  assert.equal(used.world.sent.length, 0);
});

test("pins are recomputed before anything is created, and a dirty tree, an untracked runner file or a git failure refuses the run", async (t) => {
  for (const [name, options, message] of [
    ["head is not the source commit", { gitHead: "b".repeat(40) }, /./], ["tracked change", { gitStatus: " M conformance/src/storage-rules/x.mjs\n" }, /./],
    ["untracked runner file of stage 3", { gitExtra: "?? conformance/src/storage-rules/extra.mjs\n" }, /untracked or ignored runner files/],
    ["untracked runner file of stage 2e", { gitExtraShape: "?? conformance/src/storage-rules-shape/extra.mjs\n" }, /untracked or ignored runner files/],
    ["git fails", { gitThrows: true }, /source commit unreadable$/],
  ]) {
    const f = await checkout(t, options);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
    assert.deepEqual(await f.lockFiles(), [], name);
  }
});

test("the local inputs, the owner ledger and the runs directory must be private, closed and small, and the option records are closed", async (t) => {
  const local = (f, delta) => JSON.stringify({ ...shapeLocal(f.adcPath), ...delta });
  const spoiled = {
    "local inputs readable by others": async (f) => { await chmod(f.localPath, 0o644); return /local inputs file refused/; },
    "local inputs is a symlink": async (f) => { await rm(f.localPath); await symlink(f.adcPath, f.localPath); return /local inputs file refused/; },
    "local inputs hard-linked": async (f) => { linkSync(f.localPath, join(f.root, "local-link.json")); return /local inputs file refused/; },
    "local inputs with an extra field": async (f) => { await writeFile(f.localPath, local(f, { extra: 1 }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a short digest": async (f) => { await writeFile(f.localPath, local(f, { ownerEmailSha256: "abc" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a relative ADC path": async (f) => { await writeFile(f.localPath, local(f, { adcPath: "adc.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a bad bucket": async (f) => { await writeFile(f.localPath, local(f, { bucket: "Bad Bucket" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a statePath field": async (f) => { await writeFile(f.localPath, local(f, { statePath: "/x/state.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs is not UTF-8": async (f) => { const text = local(f, {}); const at = text.indexOf(f.adcPath) + f.adcPath.length; await writeFile(f.localPath, Buffer.concat([Buffer.from(text.slice(0, at)), Buffer.from([0xff]), Buffer.from(text.slice(at))]), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs too large": async (f) => { await writeFile(f.localPath, Buffer.concat([Buffer.from(local(f, {})), Buffer.alloc(64 * 1024, 0x20)]), { mode: 0o600 }); return /local inputs file refused/; },
    "ledger writable by others": async (f) => { await chmod(f.ledgerPath, 0o666); return /owner ledger refused/; },
    "ledger is not UTF-8": async (f) => { await writeFile(f.ledgerPath, Buffer.concat([Buffer.from(`${ledger}\n`), Buffer.from([0xff])]), { mode: 0o644 }); return /owner ledger refused/; },
    "ledger too large": async (f) => { await writeFile(f.ledgerPath, Buffer.alloc(8 * 1024 * 1024 + 1, 0x20), { mode: 0o644 }); return /owner ledger refused/; },
    "the runs directory is open to others": async (f) => { await chmod(f.runs, 0o755); return /runs directory refused/; },
    "the lock directory is open to others": async (f) => { await chmod(join(f.runs, "sandbox-locks"), 0o755); return /lock directory refused/; },
    "the lock directory is missing": async (f) => { await rm(join(f.runs, "sandbox-locks"), { recursive: true }); return /lock directory missing/; },
    "the runs directory is a symlink": async (f) => { await rename(f.runs, `${f.runs}-real`); await symlink(`${f.runs}-real`, f.runs); return /runs directory refused/; },
    "the run directory exists": async (f) => { await mkdir(join(f.runs, `storage-rules-shape-${runId}`), { mode: 0o700 }); return /run directory exists/; },
    "the run directory cannot be created": async (f) => { await chmod(f.runs, 0o500); return /run directory refused/; },
  };
  for (const [name, spoil] of Object.entries(spoiled)) {
    const f = await checkout(t);
    const message = await spoil(f);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
    await chmod(f.runs, 0o700).catch(() => {});
  }
  const f = await checkout(t);
  const binding = { root: f.root, codeRoot, requestImpl: () => {}, clock, git: async () => "" };
  for (const bad of [null, undefined, [], "x", { ...binding, extra: 1 }, { ...binding, root: 5 }, { ...binding, codeRoot: 5 }, { ...binding, git: 5 }, { ...binding, requestImpl: 5 }, { ...binding, clock: { nowSeconds: () => 1 } }, { ...binding, clock: null }]) assert.throws(() => bindShapeEntry(bad), /invalid entry binding/);
  assert.throws(() => bindShapeEntry({ ...binding, root: join(f.root, "docs.local") }), /entry root is not a main checkout/);
  for (const options of [null, undefined, [], "x", { ...f.options, extra: 1 }, { ...f.options, localPath: 5 }, { ...f.options, runId: 5 }, { ...f.options, runId: "Bad Id" }, { ...f.options, sourceCommit: 5 }, { ...f.options, sourceCommit: "abc" }, { ...f.options, sourceCommit: "b".repeat(40) }, { ...f.options, sourceCommit: "abc", packet: { ...f.options.packet, sourceCommit: "abc" } }, { ...f.options, sourceCommit: "A".repeat(40), packet: { ...f.options.packet, sourceCommit: "A".repeat(40) } }, { ...f.options, packet: null }, { ...f.options, packet: [] }, { ...f.options, review: null }, { ...f.options, review: [] }, { ...f.options, review: "x" },
    ...["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].flatMap((key) => [{ ...f.options, packet: { ...f.options.packet, [key]: "abc" } }, { ...f.options, packet: { ...f.options.packet, [key]: 5 } }])]) {
    await assert.rejects(f.entry(options), /invalid shape options/, JSON.stringify(options)?.slice(0, 80));
  }
  assert.equal(f.wire.length, 0);
});

test("the local inputs reader accepts exactly the closed private file", async (t) => {
  const dir = await mkdtemp("/private/tmp/storage-rules-shape-local-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "local.json");
  await writeFile(path, JSON.stringify(shapeLocal("/x/adc.json")), { mode: 0o600 });
  const local = await readLocalInputs(path);
  assert.deepEqual({ ...local }, { adcPath: "/x/adc.json", ownerEmailSha256: ownerDigest, bucket: BUCKET });
  assert.equal(Object.isFrozen(local), true);
  await assert.rejects(readLocalInputs(join(dir, "missing.json")), /local inputs file refused/);
  await assert.rejects(readLocalInputs(5), /local inputs file refused/);
});
