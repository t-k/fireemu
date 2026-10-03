// Supplement comparison preserves the original full-corpus closure requirements.
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, normalizeExchange } from "./normalize.mjs";
import { differences } from "./compare.mjs";
import { parseSupplementJson } from "../storage-object/supplement-record.mjs";
import { sha256, supplementPlan } from "../storage-object/supplement.mjs";

export function decodeSupplementJournal(bytes) {
  if (bytes.length > 80 * 1024 * 1024) throw new Error("JOURNAL_CAP");
  const rows = new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .trim()
    .split("\n")
    .map(parseSupplementJson);
  const first = rows[0];
  const terminal = rows.at(-1);
  if (
    first.kind !== "STARTED" ||
    terminal.kind !== "RECORDED_UNREVIEWED" ||
    terminal.pending !== 0 ||
    terminal.parentClosed !== false ||
    terminal.requests !== 61 ||
    terminal.source?.planSha256 !== sha256(JSON.stringify(supplementPlan()))
  )
    throw new Error("INCOMPLETE_SUPPLEMENT");
  const attempts = rows.filter((row) => row.kind === "ATTEMPT");
  const responses = rows.filter((row) => row.kind === "RESPONSE");
  if (
    attempts.length !== terminal.requests ||
    responses.length !== attempts.length ||
    new Set(attempts.map((row) => row.label)).size !== attempts.length
  )
    throw new Error("PHYSICAL_ACCOUNTING");
  const exchanges = [];
  for (let index = 0; index < attempts.length; index++) {
    const intent = attempts[index];
    const response = responses[index];
    if (
      intent.sequence !== index + 1 ||
      response.sequence !== intent.sequence ||
      response.label !== intent.label ||
      response.family !== intent.family ||
      !response.complete ||
      !Number.isInteger(response.status)
    )
      throw new Error("CAPTURE_IDENTITY");
    if (intent.family !== "storage") continue;
    if (typeof response.bodyBase64 !== "string" || response.bodyBase64.length > 700000)
      throw new Error("BODY_CAPTURE");
    const raw = Buffer.from(response.bodyBase64, "base64");
    if (
      raw.toString("base64") !== response.bodyBase64 ||
      raw.length !== response.bodyBytes ||
      sha256(raw) !== response.bodySha256
    )
      throw new Error("RAW_BODY_BINDING");
    let compact = raw;
    if (/^(?:application\/json|text\/)/.test(response.headers?.["content-type"] ?? "")) {
      try {
        compact = Buffer.from(JSON.stringify(parseSupplementJson(raw)));
      } catch (error) {
        if (/DUPLICATE/.test(error.message)) throw error;
      }
    }
    exchanges.push({
      label: intent.label,
      method: intent.method,
      url: intent.url,
      status: response.status,
      headers: response.headers,
      body: compact,
      bodyBytes: response.bodyBytes,
    });
  }
  if (
    exchanges.length !== 53 ||
    terminal.families?.storage !== 53 ||
    terminal.families?.precheck !== 1 ||
    terminal.families?.oauth !== 1 ||
    terminal.families?.tokeninfo !== 1 ||
    terminal.families?.rules !== 4 ||
    terminal.families?.bucket !== 1
  )
    throw new Error("COMPLETE_PROGRAM_ACCOUNTING");
  return {
    runId: first.runId,
    project: first.project,
    bucket: "fireemu-oracle-query.firebasestorage.app",
    source: terminal.source,
    journalSha256: sha256(bytes),
    exchanges,
    outcome: terminal.kind,
  };
}

function normalized(record) {
  const context = createContext({
    runId: record.runId,
    bucket: record.bucket,
    project: record.project,
  });
  return record.exchanges.map((exchange) => ({
    label: exchange.label,
    ...normalizeExchange(exchange, context),
  }));
}
export function compareSupplementRecords({ native, local }) {
  if (
    !Array.isArray(native) ||
    native.length !== 2 ||
    native[0].runId === native[1].runId ||
    native[0].journalSha256 === native[1].journalSha256 ||
    native.some((record) => record.outcome !== "RECORDED_UNREVIEWED") ||
    !local
  )
    throw new Error("TWO_INDEPENDENT_NATIVE_RECORDS_REQUIRED");
  if (
    JSON.stringify(native[0].source) !== JSON.stringify(native[1].source) ||
    JSON.stringify(native[0].source) !== JSON.stringify(local.source)
  )
    throw new Error("SAME_SOURCE_REQUIRED");
  const records = [...native, local].map(normalized);
  const rows = [];
  for (let index = 0; index < records[0].length; index++) {
    const expected = records[0][index];
    const second = records[1][index];
    const actual = records[2][index];
    if (!second || second.label !== expected.label || !actual || actual.label !== expected.label) {
      rows.push({ label: expected.label, outcome: "NOT_RUN_OR_MISALIGNED" });
      continue;
    }
    const nativeDifferences = differences(expected, second);
    const localDifferences = differences(expected, actual);
    rows.push({
      label: expected.label,
      outcome: nativeDifferences.length
        ? "NATIVE_RECORDS_DIFFER"
        : localDifferences.length
          ? "DIVERGENCE"
          : "MATCH_UNREVIEWED",
      nativeDifferences,
      localDifferences,
    });
  }
  if (records.some((record) => record.length !== records[0].length))
    rows.push({ outcome: "EXTRA_OR_MISSING_EXCHANGES" });
  return {
    schemaVersion: 2,
    kind: "STORAGE_OBJECT_SUPPLEMENT_COMPARISON",
    decision: rows.every((row) => row.outcome === "MATCH_UNREVIEWED")
      ? "MATCH_UNREVIEWED"
      : "NEEDS_REVIEW",
    conditionIds: supplementPlan().conditionIds,
    retainedOriginalConditionCount: 28,
    nativeJournals: native.map((record) => record.journalSha256),
    localJournal: local.journalSha256,
    rows,
    parentClosed: false,
    finalArtifactGate: "OPEN",
    independentReviewGate: "OPEN",
  };
}
export function compareSupplementCommand(options) {
  const records = options.native.map((directory) =>
    decodeSupplementJournal(readFileSync(join(directory, "events.jsonl"))),
  );
  const localBytes = readFileSync(join(options.local, "events.jsonl"));
  const local = decodeSupplementJournal(localBytes);
  const receiptBytes = readFileSync(options.receipt);
  const receipt = parseSupplementJson(receiptBytes);
  if (
    receipt.kind !== "COPIED_FIREEMU_SUPPLEMENT_REPLAY" ||
    receipt.schemaVersion !== 2 ||
    receipt.profile !== "strict" ||
    receipt.journalSha256 !== sha256(localBytes) ||
    receipt.sourceClosureSha256 !== local.source.closureSha256 ||
    !/^[a-f0-9]{40}$/.test(receipt.binary?.sourceCommit ?? "") ||
    sha256(readFileSync(receipt.binary.path)) !== receipt.binary.sha256 ||
    !Number.isFinite(Date.parse(receipt.startedAt)) ||
    !(Date.parse(receipt.finishedAt) >= Date.parse(receipt.startedAt)) ||
    receipt.result?.exitCode !== 0 ||
    !Array.isArray(receipt.command) ||
    receipt.command.length === 0
  )
    throw new Error("ACTUAL_BINARY_RECEIPT_REQUIRED");
  const buildBytes = readFileSync(receipt.buildReceipt.path);
  const build = parseSupplementJson(buildBytes);
  if (
    sha256(buildBytes) !== receipt.buildReceipt.sha256 ||
    build.binarySha256 !== receipt.binary.sha256 ||
    build.sourceCommit !== receipt.binary.sourceCommit ||
    !Array.isArray(build.dirtyPaths) ||
    build.dirtyPaths.length !== 0
  )
    throw new Error("CLEAN_BUILD_RECEIPT_REQUIRED");
  return {
    ...compareSupplementRecords({ native: records, local }),
    receiptSha256: sha256(receiptBytes),
    binary: receipt.binary,
    buildReceipt: receipt.buildReceipt,
  };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = { native: [] };
  if (process.argv[2] !== "compare") throw new Error("USAGE_COMPARE");
  for (let index = 3; index < process.argv.length; index += 2) {
    const key = process.argv[index];
    const value = process.argv[index + 1];
    if (!["--native", "--local", "--receipt"].includes(key) || value === undefined)
      throw new Error("USAGE_COMPARE_INPUTS");
    if (key === "--native") options.native.push(resolve(value));
    else if (options[key.slice(2)]) throw new Error("DUPLICATE_ARGUMENT");
    else options[key.slice(2)] = resolve(value);
  }
  if (options.native.length !== 2 || !options.local || !options.receipt)
    throw new Error("TWO_NATIVE_LOCAL_RECEIPT_REQUIRED");
  console.log(JSON.stringify(compareSupplementCommand(options), null, 2));
}
