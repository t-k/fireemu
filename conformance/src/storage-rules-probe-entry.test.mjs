import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { linkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindProbeEntry, readLocalInputs } from "./storage-rules-probe/probe-entry.mjs";
import { ALL_IDS, PROBE_IDS, probeCorpus } from "./storage-rules-probe/plan.mjs";
import { probeCodeDigests } from "./storage-rules-probe/pins.mjs";
import { ADC, BUCKET, OWNER_EMAIL, OWNER_SUBJECT, OWNER_TOKEN, PIN_KEYS, SOURCE_COMMIT, cleanup, createProbeWorld, fakeRequestImpl, ownerDigest, probeLocal, scratchCode } from "./storage-rules-probe-support.mjs";

// The stage 2d entry against a scratch main checkout and a fake production: what it reads, writes and leaves, and when it stops.
const codeRoot = scratchCode();
process.on("exit", () => cleanup(codeRoot));
const digests = await probeCodeDigests(codeRoot);
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "probe-test-run";
const corpus = probeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest });
const packet = { taskId: "STORAGE-RULES", packetName: "stage2d-probe-v1", packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-query"], maxRequests: 8, reserveUsd: 0.01 };
const ENVELOPE = "STORAGE-RULES-stage2d-probe-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-30 | STORAGE-RULES stage2d-probe-v1 envelope | envelopeId=${ENVELOPE}; project=fireemu-oracle-query; maxRequests=8; reserveUsd=0.01; writes=none, six reads and their answers recorded; iamConfig=none; retries=none; onStop=locks-held; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-30 | STORAGE-RULES stage2d-probe-v1 | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");

async function checkout(t, { world = createProbeWorld(), gitHead = SOURCE_COMMIT, gitStatus = "", gitExtra = "", gitExtraProbe = "", gitThrows = false, usage = [], mutatePacket = (value) => value, ledgerText = ledger } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-probe-");
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
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-probe-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: used.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(probeLocal(adcPath)), { mode: 0o600 });
  const wire = [];
  const git = async (where, args) => { if (gitThrows) throw new Error("git failed"); if (args[0] === "rev-parse") return `${gitHead}\n`; if (args.includes("--ignored")) return args.includes("conformance/src/storage-rules-probe") ? gitExtraProbe : gitExtra; return gitStatus; };
  const entry = bindProbeEntry({ root, codeRoot, requestImpl: fakeRequestImpl((spec) => world.answer(spec), wire), clock, git });
  const options = { localPath, runId, sourceCommit: SOURCE_COMMIT, packet: used, review: structuredClone(review) };
  return { root, runs, entry, options, wire, world, localPath, adcPath, ledgerPath: join(root, "docs.local", "instructions", "owner-decisions.md"), lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
const runDir = (f) => join(f.runs, `storage-rules-probe-${runId}`);
const readLines = async (f, name) => (await readFile(join(runDir(f), name), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
const factsOf = async (f) => (await readLines(f, "captures.jsonl")).flatMap((row) => { const data = row.data ?? row; return data.facts !== undefined && data.kind === "probe-answer" ? [{ operationId: data.operationId, verdict: data.verdict, facts: data.facts }] : []; });
const terminalOf = async (f) => (await readLines(f, "reservations.jsonl")).at(-1).data.outcome;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
import { createHash } from "node:crypto";
const urls = (f) => f.wire.map((entry) => `${entry.method} ${new URL(entry.url).host}${new URL(entry.url).pathname}${new URL(entry.url).search}`);
const lockedOnce = ["fireemu-oracle-query.lock"];

test("the probe sends its six reads once each after the token and identity, records every answer, writes nothing and releases the lock", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.changed, result.released, result.requests], ["finished", false, true, 8]);
  assert.equal(await terminalOf(f), "finished");
  assert.deepEqual(await f.lockFiles(), []);
  assert.deepEqual(urls(f), [
    "POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo",
    "GET firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100",
    `GET storage.googleapis.com/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`,
    `GET storage.googleapis.com/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin?alt=media`,
    "POST firebaserules.googleapis.com/v1/projects/fireemu-oracle-query:test", "POST firebaserules.googleapis.com/v1/projects/fireemu-oracle-query:test",
    "GET firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document",
  ]);
  // The only requests with a body are the token refresh and the two `:test` calls (a test stores nothing); no request writes anything.
  assert.deepEqual(f.wire.filter((entry) => entry.method !== "GET").map((entry) => new URL(entry.url).pathname), ["/token", "/v1/projects/fireemu-oracle-query:test", "/v1/projects/fireemu-oracle-query:test"]);
  // The owner's bearer travels on every request but the token refresh; the quota project on every one but userinfo.
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
    if (new URL(entry.url).pathname === "/oauth2/v2/userinfo") assert.equal(Object.hasOwn(entry.headers, "x-goog-user-project"), false);
    else assert.equal(entry.headers["x-goog-user-project"], "fireemu-oracle-query", entry.url);
  }
  // Each answer is a fact: status, size, digest and content type, in order, and the raw body is in the private journal.
  const facts = await factsOf(f);
  assert.deepEqual(facts.map((fact) => fact.operationId), PROBE_IDS);
  assert.deepEqual(facts.map((fact) => fact.facts.status), [200, 404, 404, 200, 400, 404]);
  const media = facts.find((fact) => fact.operationId === "probe/object-media-absent").facts;
  assert.deepEqual(media, { status: 404, bodyBytes: Buffer.byteLength(`No such object: ${BUCKET}/STORAGE-RULES/probe-2d/absent-object.bin`), bodySha256: sha(Buffer.from(`No such object: ${BUCKET}/STORAGE-RULES/probe-2d/absent-object.bin`)), contentType: "text/plain; charset=utf-8" });
  assert.deepEqual(facts.find((fact) => fact.operationId === "probe/rulesets-list").facts.contentType, "application/json; charset=UTF-8");
  const blobs = await Promise.all((await readdir(join(runDir(f), "blobs"))).map((name) => readFile(join(runDir(f), "blobs", name), "utf8").catch(() => "")));
  assert.ok(blobs.some((text) => text.includes("No such object:")), "the plain-text media 404 is kept as bytes");
  assert.ok(blobs.some((text) => text.includes("\"metadata\"") && text.includes("cloud.firestore")), "the ruleset list is kept as bytes");
  const journals = (await Promise.all((await readdir(runDir(f))).filter((name) => name.endsWith(".jsonl")).map((name) => readFile(join(runDir(f), name), "utf8")))).join("\n");
  assert.equal(journals.includes(OWNER_TOKEN), false);
  assert.equal(journals.includes(OWNER_EMAIL), false);
});

test("whatever the answers are, the probe records them and finishes: it judges nothing", async (t) => {
  const answers = {
    "server errors": (world) => world.json({ error: { code: 500, message: "boom", status: "INTERNAL" } }, 500),
    "an HTML page": () => ({ status: 200, rawHeaders: ["Content-Type", "text/html"], bytes: Buffer.from("<html>nope</html>") }),
    "an empty body": () => ({ status: 200, rawHeaders: [], bytes: Buffer.alloc(0) }),
    "a redirect": () => ({ status: 302, rawHeaders: ["Location", "https://example.test/"], bytes: Buffer.alloc(0) }),
    "invalid JSON": () => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("{nope") }),
  };
  for (const [name, answer] of Object.entries(answers)) {
    const f = await checkout(t);
    f.world.hook.answer = (spec, key) => (PROBE_IDS.length && ["list", "metadata", "media", "testValid", "testInvalid", "document"].includes(key) ? answer(f.world) : undefined);
    const result = await f.entry(f.options);
    assert.equal(result.status, "finished", name);
    assert.equal(result.requests, 8, name);
    const facts = await factsOf(f);
    assert.equal(facts.length, 6, name);
    assert.ok(facts.every((fact) => Number.isInteger(fact.facts.status) && fact.facts.bodySha256.length === 64), name);
  }
});

test("an owner who is not the expected one, or is unverified, stops the run before any probe read", async (t) => {
  for (const identity of [{ id: "1", email: "other@example.test", verified_email: true }, { id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: false }, { id: OWNER_SUBJECT }]) {
    const f = await checkout(t);
    f.world.hook.answer = (spec, key) => (key === "identity" ? f.world.json(identity) : undefined);
    await assert.rejects(f.entry(f.options));
    assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
  }
});

test("the identity answer must be well-formed UTF-8, and the run stops before the first probe read", async (t) => {
  const f = await checkout(t);
  f.world.hook.any = (spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.concat([Buffer.from('{"id":"1","email":"owner@example.test","verified_email":true,"note":"'), Buffer.from([0xff]), Buffer.from('"}')]) } : undefined);
  await assert.rejects(f.entry(f.options));
  assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
});

test("a content type is recorded only when it is short, printable and free of markup, and is null when absent", async (t) => {
  const answers = {
    "no header": { rawHeaders: [], expected: null }, "markup": { rawHeaders: ["Content-Type", "text/<b>x</b>"], expected: null }, "control character": { rawHeaders: ["Content-Type", "text/plain\u0007"], expected: null },
    "too long": { rawHeaders: ["Content-Type", `text/${"a".repeat(101)}`], expected: null }, "empty": { rawHeaders: ["Content-Type", ""], expected: null },
    "printable": { rawHeaders: ["Content-Type", "text/plain; charset=utf-8"], expected: "text/plain; charset=utf-8" }, "upper-case name": { rawHeaders: ["CONTENT-TYPE", "text/plain"], expected: "text/plain" },
    "the first of two": { rawHeaders: ["Content-Type", "text/plain", "Content-Type", "text/html"], expected: "text/plain" }, "exactly 100": { rawHeaders: ["Content-Type", `t/${"a".repeat(98)}`], expected: `t/${"a".repeat(98)}` },
  };
  for (const [name, { rawHeaders, expected }] of Object.entries(answers)) {
    const f = await checkout(t);
    f.world.hook.answer = (spec, key) => (key === "list" ? { status: 200, rawHeaders: rawHeaders.map((value) => value.replace("\\u0007", String.fromCharCode(7))), bytes: Buffer.from("{}") } : undefined);
    await f.entry(f.options);
    assert.equal((await factsOf(f)).find((fact) => fact.operationId === "probe/rulesets-list").facts.contentType, expected, name);
  }
});

test("a lost connection stops the run at that request, sends nothing after it, and keeps the lock", async (t) => {
  for (const key of ["list", "metadata", "media", "testValid", "testInvalid", "document"]) {
    const f = await checkout(t);
    f.world.hook.answer = (spec, which) => { if (which === key) throw new Error("connection lost"); return undefined; };
    await assert.rejects(f.entry(f.options), undefined, key);
    assert.equal(f.world.calls[key], 1, key);
    const order = ["list", "metadata", "media", "testValid", "testInvalid", "document"];
    for (const later of order.slice(order.indexOf(key) + 1)) assert.equal(f.world.calls[later] ?? 0, 0, `${key} then ${later}`);
    assert.deepEqual(await f.lockFiles(), lockedOnce, key);
  }
});

test("a revocation written while the probe is going stops the very next request", async (t) => {
  const f = await checkout(t);
  f.world.hook.answer = (spec, key) => { if (key === "metadata") writeFileSync(f.ledgerPath, `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2d-probe-v1 | decision=REVOKED | Claude | private.md`); return undefined; };
  await assert.rejects(f.entry(f.options), /admission refused/);
  assert.equal(f.world.calls.metadata, 1);
  assert.equal(f.world.calls.media ?? 0, 0);
  assert.equal(await terminalOf(f), "stopped-no-mutation");
});

test("the approval binds the probe to its name, its limits and its pins", async (t) => {
  // The name and the limits are checked by the approval when the run starts: nothing is sent.
  for (const [name, mutate] of Object.entries({
    "another packet name": (value) => ({ ...value, packetName: "stage2c-pre-v1" }), "more requests": (value) => ({ ...value, maxRequests: 9 }), "fewer requests": (value) => ({ ...value, maxRequests: 7 }),
    "a larger reserve": (value) => ({ ...value, reserveUsd: 0.5 }), "another project": (value) => ({ ...value, projects: ["fireemu-oracle-idp"] }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.wire.length, 0, name);
  }
  // The pins are recomputed before anything is created.
  for (const [name, mutate] of Object.entries({
    "runner pin": (value) => ({ ...value, runnerSha256: "0".repeat(64) }), "fixture pin": (value) => ({ ...value, fixtureSchemaSha256: "0".repeat(64) }), "manifest pin": (value) => ({ ...value, manifestSha256: "0".repeat(64) }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), /pin mismatch/, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
  }
  const revoked = await checkout(t, { ledgerText: `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2d-probe-v1 | decision=REVOKED | Claude | private.md` });
  await assert.rejects(revoked.entry(revoked.options));
  assert.equal(revoked.wire.length, 0);
  const missing = await checkout(t, { ledgerText: "" });
  await assert.rejects(missing.entry(missing.options));
  assert.equal(missing.wire.length, 0);
  const used = await checkout(t, { usage: ["an-earlier-run"] });
  await assert.rejects(used.entry(used.options), /recording budget exhausted/);
  assert.equal(used.world.calls.list ?? 0, 0);
});

test("pins are recomputed before anything is created, and a dirty tree, an untracked runner file or a git failure refuses the run", async (t) => {
  for (const [name, options, message] of [
    ["head is not the source commit", { gitHead: "b".repeat(40) }, /./], ["tracked change", { gitStatus: " M conformance/src/storage-rules/x.mjs\n" }, /./],
    ["untracked runner file of stage 3", { gitExtra: "?? conformance/src/storage-rules/extra.mjs\n" }, /untracked or ignored runner files/],
    ["untracked runner file of stage 2d", { gitExtraProbe: "?? conformance/src/storage-rules-probe/extra.mjs\n" }, /untracked or ignored runner files/],
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
  const spoiled = {
    "local inputs readable by others": async (f) => { await chmod(f.localPath, 0o644); return /local inputs file refused/; },
    "local inputs is a symlink": async (f) => { await rm(f.localPath); await symlink(f.adcPath, f.localPath); return /local inputs file refused/; },
    "local inputs hard-linked": async (f) => { linkSync(f.localPath, join(f.root, "local-link.json")); return /local inputs file refused/; },
    "local inputs with an extra field": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...probeLocal(f.adcPath), extra: 1 }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a bad bucket": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...probeLocal(f.adcPath), bucket: "Bad Bucket" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a short digest": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...probeLocal(f.adcPath), ownerEmailSha256: "abc" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a relative ADC path": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...probeLocal(f.adcPath), adcPath: "adc.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs too large": async (f) => { await writeFile(f.localPath, Buffer.concat([Buffer.from(JSON.stringify(probeLocal(f.adcPath))), Buffer.alloc(64 * 1024, 0x20)]), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs is not UTF-8": async (f) => { const text = JSON.stringify(probeLocal(f.adcPath)); const at = text.indexOf(f.adcPath) + f.adcPath.length; await writeFile(f.localPath, Buffer.concat([Buffer.from(text.slice(0, at)), Buffer.from([0xff]), Buffer.from(text.slice(at))]), { mode: 0o600 }); return /^Error: local inputs file refused$/; },
    "ledger writable by others": async (f) => { await chmod(f.ledgerPath, 0o666); return /owner ledger refused/; },
    "ledger is not UTF-8": async (f) => { await writeFile(f.ledgerPath, Buffer.concat([Buffer.from(`${ledger}\n`), Buffer.from([0xff])]), { mode: 0o644 }); return /owner ledger refused/; },
    "ledger too large": async (f) => { await writeFile(f.ledgerPath, Buffer.alloc(8 * 1024 * 1024 + 1, 0x20), { mode: 0o644 }); return /owner ledger refused/; },
    "the runs directory is open to others": async (f) => { await chmod(f.runs, 0o755); return /runs directory refused/; },
    "the lock directory is open to others": async (f) => { await chmod(join(f.runs, "sandbox-locks"), 0o755); return /lock directory refused/; },
    "the lock directory is missing": async (f) => { await rm(join(f.runs, "sandbox-locks"), { recursive: true }); return /lock directory missing/; },
    "the runs directory is a symlink": async (f) => { await rename(f.runs, `${f.runs}-real`); await symlink(`${f.runs}-real`, f.runs); return /runs directory refused/; },
    "the run directory exists": async (f) => { await mkdir(join(f.runs, `storage-rules-probe-${runId}`), { mode: 0o700 }); return /run directory exists/; },
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
  for (const bad of [null, undefined, [], "x", { ...binding, extra: 1 }, { ...binding, root: 5 }, { ...binding, codeRoot: 5 }, { ...binding, git: 5 }, { ...binding, requestImpl: 5 }, { ...binding, clock: { nowSeconds: () => 1 } }, { ...binding, clock: null }]) assert.throws(() => bindProbeEntry(bad), /invalid entry binding/);
  assert.throws(() => bindProbeEntry({ ...binding, root: join(f.root, "docs.local") }), /entry root is not a main checkout/);
  for (const options of [null, undefined, [], "x", { ...f.options, extra: 1 }, { ...f.options, localPath: 5 }, { ...f.options, runId: 5 }, { ...f.options, runId: "Bad Id" }, { ...f.options, sourceCommit: 5 }, { ...f.options, sourceCommit: "abc" }, { ...f.options, sourceCommit: "abc", packet: { ...f.options.packet, sourceCommit: "abc" } }, { ...f.options, packet: { ...f.options.packet, sourceCommit: "b".repeat(40) } }, { ...f.options, packet: [] }, { ...f.options, packet: null }, { ...f.options, review: 5 }, { ...f.options, review: [] }, { ...f.options, review: null },
    ...["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].flatMap((key) => [{ ...f.options, packet: { ...f.options.packet, [key]: "abc" } }, { ...f.options, packet: { ...f.options.packet, [key]: 5 } }])]) {
    await assert.rejects(f.entry(options), /invalid probe options/, JSON.stringify(options)?.slice(0, 80));
  }
  assert.equal(f.wire.length, 0);
});

test("the local inputs reader accepts exactly the closed private file", async (t) => {
  const dir = await mkdtemp("/private/tmp/storage-rules-probe-local-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "local.json");
  await writeFile(path, JSON.stringify(probeLocal("/x/adc.json")), { mode: 0o600 });
  const local = await readLocalInputs(path);
  assert.deepEqual({ ...local }, { adcPath: "/x/adc.json", ownerEmailSha256: ownerDigest, bucket: BUCKET });
  assert.equal(Object.isFrozen(local), true);
  await assert.rejects(readLocalInputs(join(dir, "missing.json")), /local inputs file refused/);
  await assert.rejects(readLocalInputs(5), /local inputs file refused/);
  void stat;
  void ALL_IDS;
});
