import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindPrepEntry, prepPaths } from "./storage-rules-prep/prep-reads.mjs";
import { loadPrivateInputs } from "./storage-rules/private-inputs.mjs";
import { ADC, API_KEYS, KEY_IDS, NUMBERS, OWNER_TOKEN, SUBJECT, privatePacket } from "./storage-rules-runner-support.mjs";
import { CODE_FILES, ENVELOPE_ID, PACKET_NAME, PIN_KEYS, SOURCE_COMMIT, cleanup, fakeRequestImpl, localInputs, prepAnswer, prepCodeDigests, prepCorpus, scratchCode } from "./storage-rules-prep-support.mjs";

// The stage 2a entry against a scratch main checkout and a fake wire: what it reads, takes and writes, and when it stops.
const closureText = readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url), "utf8");
const closure = JSON.parse(closureText);
const codeRoot = scratchCode(closureText);
process.on("exit", () => cleanup(codeRoot));
const digests = await prepCodeDigests(codeRoot);
const params = { bucket: privatePacket("/x").bucket.name, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, sourceCommit: SOURCE_COMMIT };
const corpus = prepCorpus(closure, params);
const packet = { taskId: "STORAGE-RULES", packetName: PACKET_NAME, packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-idp", "fireemu-oracle-query"], maxRequests: 13, reserveUsd: 0.01 };
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE_ID, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} envelope | envelopeId=${ENVELOPE_ID}; project=${packet.projects.join(",")}; maxRequests=13; reserveUsd=0.01; writes=none; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE_ID} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "prep-test-run";

async function checkout(t, { ledgerText = ledger, answer = prepAnswer, gitHead = SOURCE_COMMIT, gitStatus = "", usage = [], local = localInputs } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-prep-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-prep-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(local(adcPath)), { mode: 0o600 });
  const wire = [];
  const gitCalls = [];
  const git = async (where, args) => { gitCalls.push([where, ...args]); return args[0] === "rev-parse" ? `${gitHead}\n` : gitStatus; };
  const entry = bindPrepEntry({ root, codeRoot, requestImpl: fakeRequestImpl(answer, wire), clock, git });
  const options = { localPath, closure, runId, sourceCommit: SOURCE_COMMIT, packet: structuredClone(packet), review: structuredClone(review) };
  return { root, runs, entry, options, wire, gitCalls, adcPath, localPath, lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}

test("smoke: the reads run to the end, write the stage 3 inputs and release the locks", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  console.log(result.status, result.requests, f.wire.map((w) => `${w.method} ${w.url.replace(/^https:\/\//, "").slice(0, 70)}`).join("\n"));
  const inputs = JSON.parse(await readFile(result.inputsPath, "utf8"));
  assert.deepEqual(inputs, privatePacket(f.adcPath));
});
