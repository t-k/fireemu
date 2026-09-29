import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const load = async () => {
  const module = await import("./storage-rules/settle.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createSettleState, "function");
  return module;
};
const publication = (overrides = {}) => ({ kind: "publication", name: "v1", maxCycles: 30, requiredConsecutive: 2, witnesses: [{ objectName: "STORAGE-RULES/r/allow.bin", expect: "allowed" }, { objectName: "STORAGE-RULES/r/deny.bin", expect: "denied" }], ...overrides });
const restoration = (overrides = {}) => ({ kind: "restoration", name: "restore", maxCycles: 15, requiredConsecutive: 2, witnesses: ["a", "b", "c", "d"].map((n) => ({ objectName: `STORAGE-RULES/r/${n}.bin`, expect: "denied" })), ...overrides });

// A reference model written independently of the reducer: read the verdicts cycle by cycle, count consecutive complete matches.
function reference(config, verdicts) {
  let consecutive = 0; let reads = 0;
  for (let cycle = 1; cycle <= config.maxCycles; cycle++) {
    let match = true;
    for (let index = 0; index < config.witnesses.length; index++) {
      const verdict = verdicts[reads++];
      if (verdict === undefined) return { status: "running", reads: reads - 1 };
      if (verdict !== config.witnesses[index].expect) match = false;
    }
    consecutive = match ? consecutive + 1 : 0;
    if (consecutive >= config.requiredConsecutive) return { status: "settled", reads, cycle };
  }
  return { status: "exhausted", reads, cycle: config.maxCycles };
}
async function run(config, verdicts) {
  const { createSettleState, nextRead, applyVerdict } = await load();
  let state = createSettleState(config);
  let reads = 0;
  for (const verdict of verdicts) {
    if (nextRead(state) === null) break;
    state = applyVerdict(state, verdict);
    reads++;
  }
  return { state, reads };
}
const prng = (seed) => () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };

test("two consecutive complete matching cycles settle a publication after four reads", async () => {
  const { state, reads } = await run(publication(), ["allowed", "denied", "allowed", "denied"]);
  assert.equal(state.status, "settled");
  assert.equal(reads, 4);
  assert.equal(state.cycle, 2);
});

test("a mismatch or an unexpected verdict resets the count", async () => {
  const good = ["allowed", "denied"];
  const cases = [["allowed", "allowed", ...good, ...good], ["denied", "denied", ...good, ...good], ["other", "denied", ...good, ...good], ["allowed", "other", ...good, ...good], [...good, "denied", "denied", ...good, ...good]];
  for (const verdicts of cases) {
    const { state, reads } = await run(publication(), verdicts);
    assert.equal(state.status, "settled", JSON.stringify(verdicts));
    assert.equal(reads, verdicts.length);
  }
  const { state } = await run(publication(), [...good, "denied", "denied", ...good]);
  assert.equal(state.status, "running");
});

test("a mid-cycle stop can never settle, whatever the reads so far were", async () => {
  const { state } = await run(publication(), ["allowed", "denied", "allowed"]);
  assert.equal(state.status, "running");
  assert.deepEqual(await (async () => { const { nextRead } = await load(); return nextRead(state); })(), { cycle: 2, index: 1, witness: { objectName: "STORAGE-RULES/r/deny.bin", expect: "denied" }, rowId: "settle/v1/2/1" });
});

test("exhausting the cycle limit ends the wait without settling", async () => {
  const bad = Array(30 * 2).fill("other");
  const { state, reads } = await run(publication(), bad);
  assert.equal(state.status, "exhausted");
  assert.equal(reads, 60);
  const almost = [];
  for (let cycle = 1; cycle <= 30; cycle++) almost.push("allowed", cycle % 2 ? "denied" : "allowed");
  assert.equal((await run(publication(), almost)).state.status, "exhausted");
});

test("a restoration counts a cycle only when all four witnesses are denied, and other answers never count as denied", async () => {
  const deniedCycle = Array(4).fill("denied");
  for (const broken of [["denied", "denied", "denied", "allowed"], ["denied", "denied", "denied", "other"], ["other", "other", "other", "other"], ["allowed", "allowed", "allowed", "allowed"]]) {
    const { state, reads } = await run(restoration(), [...deniedCycle, ...broken, ...deniedCycle]);
    assert.equal(state.status, "running", JSON.stringify(broken));
    assert.equal(reads, 12);
  }
  const { state, reads } = await run(restoration(), [...deniedCycle, ...deniedCycle]);
  assert.equal(state.status, "settled");
  assert.equal(reads, 8);
  assert.equal((await run(restoration(), Array(15 * 4).fill("other"))).state.status, "exhausted");
});

test("the reducer agrees with the reference model on random verdict sequences and never reads past its bound", async () => {
  const random = prng(20260929);
  const pick = (weights) => { const roll = random(); let sum = 0; for (const [verdict, weight] of weights) { sum += weight; if (roll < sum) return verdict; } return "other"; };
  for (const config of [publication(), publication({ maxCycles: 5 }), publication({ requiredConsecutive: 3 }), restoration(), restoration({ maxCycles: 4 })]) {
    for (let trial = 0; trial < 300; trial++) {
      const positive = random();
      const verdicts = Array.from({ length: config.maxCycles * config.witnesses.length + 3 }, (_, index) => {
        const expect = config.witnesses[index % config.witnesses.length].expect;
        return random() < positive ? expect : pick([["allowed", 0.25], ["denied", 0.25], ["other", 0.5]]);
      });
      const { state, reads } = await run(config, verdicts);
      const expected = reference(config, verdicts);
      assert.equal(state.status, expected.status, `${config.kind} trial ${trial}`);
      if (expected.status !== "running") assert.equal(reads, expected.reads, `${config.kind} trial ${trial}`);
      assert.ok(reads <= config.maxCycles * config.witnesses.length);
    }
  }
});

test("row IDs follow the manifest's naming and no read is offered after the end", async () => {
  const { createSettleState, nextRead, applyVerdict, settleRowId } = await load();
  assert.equal(settleRowId({ ...publication(), phase: "normal" }, 3, 1), "settle/v1/3/1");
  assert.equal(settleRowId({ ...restoration(), phase: "recovery" }, 2, 3), "recovery/settle/restore/2/3");
  assert.equal(settleRowId({ ...restoration(), phase: "normal" }, 2, 3), "settle/restore/2/3");
  let state = createSettleState(publication());
  for (const verdict of ["allowed", "denied", "allowed", "denied"]) state = applyVerdict(state, verdict);
  assert.equal(nextRead(state), null);
  assert.throws(() => applyVerdict(state, "allowed"), /settle is over/);
  let over = createSettleState(publication({ maxCycles: 1, requiredConsecutive: 1 }));
  over = applyVerdict(applyVerdict(over, "other"), "other");
  assert.equal(over.status, "exhausted");
  assert.throws(() => applyVerdict(over, "denied"), /settle is over/);
});

test("the configuration and every verdict are closed", async () => {
  const { createSettleState, applyVerdict } = await load();
  const bad = [
    null, {}, { ...publication(), extra: 1 }, publication({ kind: "other" }), publication({ name: "" }), publication({ maxCycles: 0 }), publication({ maxCycles: 31 }), publication({ maxCycles: 1.5 }),
    publication({ requiredConsecutive: 0 }), publication({ requiredConsecutive: 5, maxCycles: 4 }), publication({ witnesses: [] }), publication({ witnesses: [{ objectName: "x", expect: "allowed" }] }),
    publication({ witnesses: [{ objectName: "x", expect: "maybe" }, { objectName: "y", expect: "denied" }] }), publication({ witnesses: [{ objectName: "x", expect: "allowed" }, { objectName: "x", expect: "denied" }] }),
    publication({ witnesses: [{ objectName: "x", expect: "allowed" }, { objectName: "y", expect: "allowed" }] }), restoration({ witnesses: restoration().witnesses.slice(0, 3) }),
    restoration({ witnesses: restoration().witnesses.map((w, i) => (i === 0 ? { ...w, expect: "allowed" } : w)) }), restoration({ maxCycles: 16 }),
  ];
  for (const config of bad) assert.throws(() => createSettleState(config), /invalid settle configuration/, JSON.stringify(config)?.slice(0, 80));
  const state = createSettleState(publication());
  for (const verdict of ["Allowed", "ok", "", null, undefined, 403, {}]) assert.throws(() => applyVerdict(state, verdict), /invalid settle verdict/);
  const accessor = Object.defineProperty({ ...publication() }, "name", { enumerable: true, get() { return "v1"; } });
  assert.throws(() => createSettleState(accessor), /invalid settle configuration/);
});

test("states are immutable and applying a verdict does not change the old state", async () => {
  const { createSettleState, applyVerdict } = await load();
  const first = createSettleState(publication());
  const second = applyVerdict(first, "allowed");
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(second), true);
  assert.equal(first.reads, 0);
  assert.equal(second.reads, 1);
});

test("every read the reducer offers is a declared settle row for the same witness, and the manifest's numbers fit the limits", async () => {
  const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
  const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
  const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
  const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
  const byId = new Map(manifest.rows.map((r) => [r.id, r]));
  const { createSettleState, nextRead, applyVerdict } = await load();
  assert.equal(manifest.restoration.maxCycles, 15);
  assert.equal(manifest.restoration.consecutiveCompleteCycles, 2);
  const plans = [];
  for (const name of ["v1", "v2", "A", "B"]) {
    const rows = manifest.rows.filter((r) => r.family === "settle" && r.phase === "normal" && r.programId === name);
    plans.push({ kind: "publication", name, phase: "normal", maxCycles: 30, requiredConsecutive: 2, witnesses: [rows[0], rows[1]].map((r, i) => ({ objectName: r.request.objectName, expect: i === 0 ? "allowed" : "denied" })) });
  }
  for (const phase of ["normal", "recovery"]) {
    const rows = manifest.rows.filter((r) => r.family === "settle" && r.phase === phase && r.programId === "restore");
    plans.push({ kind: "restoration", name: "restore", phase, maxCycles: manifest.restoration.maxCycles, requiredConsecutive: manifest.restoration.consecutiveCompleteCycles, witnesses: rows.slice(0, 4).map((r) => ({ objectName: r.request.objectName, expect: "denied" })) });
  }
  for (const plan of plans) {
    let state = createSettleState(plan);
    const seen = new Set();
    for (let read = nextRead(state); read !== null; read = nextRead(state)) {
      const row = byId.get(read.rowId);
      assert.ok(row, read.rowId);
      assert.equal(row.request.objectName, read.witness.objectName, read.rowId);
      assert.equal(row.phase, plan.phase);
      seen.add(read.rowId);
      state = applyVerdict(state, "other");
    }
    assert.equal(state.status, "exhausted");
    assert.equal(seen.size, plan.maxCycles * plan.witnesses.length);
    assert.equal(manifest.rows.filter((r) => r.family === "settle" && r.phase === plan.phase && r.programId === plan.name).length, seen.size);
  }
});

// The closed-configuration cases above use names that already fail the name grammar; these use well-formed names so each rule is checked on its own.
test("each configuration rule holds on its own with well-formed witness names", async () => {
  const { createSettleState } = await load();
  const w = (name, expect) => ({ objectName: `STORAGE-RULES/r/${name}.bin`, expect });
  const bad = [
    publication({ witnesses: [w("same", "allowed"), w("same", "denied")] }),
    restoration({ witnesses: [w("a", "denied"), w("b", "denied"), w("c", "denied"), w("a", "denied")] }),
    publication({ witnesses: [w("allow", "allowed")] }),
    publication({ witnesses: [w("allow", "allowed"), w("deny", "denied"), w("more", "denied")] }),
    publication({ witnesses: [w("deny", "denied"), w("allow", "allowed")] }),
    publication({ witnesses: [w("a", "allowed"), w("b", "allowed")] }),
    publication({ witnesses: [w("a", "denied"), w("b", "denied")] }),
    publication({ phase: "recovery" }),
  ];
  for (const config of bad) assert.throws(() => createSettleState(config), /invalid settle configuration/, JSON.stringify(config));
  for (const config of [publication({ phase: "normal" }), restoration({ phase: "recovery" }), restoration({ phase: "normal" })]) assert.equal(createSettleState(config).status, "running");
});

test("a witness name must be a well-formed name under STORAGE-RULES/", async () => {
  const { createSettleState } = await load();
  const withName = (objectName) => publication({ witnesses: [{ objectName, expect: "allowed" }, { objectName: "STORAGE-RULES/r/deny.bin", expect: "denied" }] });
  for (const objectName of ["x", "STORAGE-RULES/", "other/r/allow.bin", "storage-rules/r/allow.bin", " STORAGE-RULES/r/allow.bin", "STORAGE-RULES/r/a b.bin", "STORAGE-RULES/r/a\n", "STORAGE-RULES/r/a?b", `STORAGE-RULES/${"a".repeat(901)}`, 7]) {
    assert.throws(() => createSettleState(withName(objectName)), /invalid settle configuration/, String(objectName).slice(0, 40));
  }
  assert.equal(createSettleState(withName(`STORAGE-RULES/${"a".repeat(900)}`)).status, "running");
  assert.equal(createSettleState(withName("STORAGE-RULES/r/a-b_c.d/e.bin")).status, "running");
});
