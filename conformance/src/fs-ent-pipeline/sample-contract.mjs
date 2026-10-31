import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";

const policy = JSON.parse(readFileSync(new URL("./finitepolicy.json", import.meta.url)));
const hash = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const canonical = (x) =>
  Array.isArray(x)
    ? x.map(canonical)
    : x && typeof x === "object"
      ? Object.fromEntries(
          Object.keys(x)
            .sort()
            .map((k) => [k, canonical(x[k])]),
        )
      : x;
const key = (x) => JSON.stringify(canonical(x));
export function validTimestamp(value, role, placeholder) {
  if (role === "fixture" && value === placeholder) return true;
  if (typeof value !== "string") return false;
  const m = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(
    value,
  );
  if (!m) return false;
  const [, ys, mos, ds, hs, mis, ss, , zone] = m;
  const y = Number(ys),
    mo = Number(mos),
    d = Number(ds),
    h = Number(hs),
    mi = Number(mis),
    s = Number(ss);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0),
    days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > days[mo - 1] || h > 23 || mi > 59 || s > 59)
    return false;
  if (zone !== "Z" && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59)) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && ms >= -62135596800000 && ms < 253402300800000;
}
function rows(response, role) {
  if (
    !response ||
    !isDeepStrictEqual(Object.keys(response).sort(), ["body", "status"]) ||
    response.status !== 200 ||
    !Array.isArray(response.body) ||
    response.body.length !== 1
  )
    return null;
  const unit = response.body[0];
  if (
    !unit ||
    Array.isArray(unit) ||
    typeof unit !== "object" ||
    Object.keys(unit).some((k) => !["executionTime", "results"].includes(k)) ||
    !validTimestamp(unit.executionTime, role, "<t1>")
  )
    return null;
  if (unit.results === undefined) return [];
  return Array.isArray(unit.results) ? unit.results : null;
}
function normalizeRow(row, role) {
  if (
    !row ||
    Array.isArray(row) ||
    typeof row !== "object" ||
    !isDeepStrictEqual(Object.keys(row).sort(), ["createTime", "fields", "name", "updateTime"]) ||
    !validTimestamp(row.createTime, role, "<t2>") ||
    !validTimestamp(row.updateTime, role, "<t2>") ||
    !row.fields ||
    Array.isArray(row.fields) ||
    typeof row.fields !== "object"
  )
    return null;
  const prefix =
    role === "fixture"
      ? "projects/demo-fs-query-index/databases/entpipe1/documents/"
      : "projects/fireemu-oracle-query/databases/entpipe1/documents/";
  if (typeof row.name !== "string" || !row.name.startsWith(prefix)) return null;
  return { name: row.name.slice(prefix.length), fields: row.fields };
}
export function sampleRows(selected, eligible, mode, count) {
  if (!Array.isArray(selected) || !Array.isArray(eligible)) return false;
  if (mode === "documents") {
    if (selected.length !== Math.min(count, eligible.length)) return false;
    const bag = new Map();
    for (const row of eligible) {
      const k = key(row);
      bag.set(k, (bag.get(k) ?? 0) + 1);
    }
    for (const row of selected) {
      const k = key(row),
        n = bag.get(k) ?? 0;
      if (!n) return false;
      bag.set(k, n - 1);
    }
    return true;
  }
  if (
    mode !== "percent" ||
    (count === 0 && selected.length !== 0) ||
    (count === 1 && selected.length !== eligible.length)
  )
    return false;
  let pos = 0;
  for (const row of selected) {
    while (pos < eligible.length && key(row) !== key(eligible[pos])) pos++;
    if (pos === eligible.length) return false;
    pos++;
  }
  return true;
}
export function evaluateSample({
  id,
  profile,
  request,
  seed,
  companionRequest,
  companion,
  response,
  role,
  unorderedInput = false,
}) {
  try {
    const rule = policy.recipes.find((x) => x.id === id);
    if (
      !rule ||
      profile !== "strict" ||
      !["live", "fixture"].includes(role) ||
      hash(request) !== rule.requestSha256 ||
      hash(seed) !== policy.seedSha256 ||
      hash(companionRequest) !== policy.companionRequestSha256 ||
      hash(companion) !== policy.companionFixtureSha256
    )
      return null;
    const original = rows(companion, "fixture"),
      actual = rows(response, role);
    if (!original || !actual) return null;
    const input = original.map((x) => normalizeRow(x, "fixture")),
      output = actual.map((x) => normalizeRow(x, role));
    if (input.includes(null) || output.includes(null)) return null;
    const known = seed
      .filter(([name]) => name.startsWith("su/"))
      .map(([name, fields]) => ({ name, fields }));
    if (input.length !== known.length || !sampleRows(input, known, "documents", known.length))
      return null;
    const eligible =
      rule.placement === "where"
        ? input.filter((x) => BigInt(x.fields.n.integerValue) > 1n)
        : input;
    const expected =
      rule.placement === "limit" ? Math.min(rule.size, eligible.length, 1) : rule.size;
    // For the recorded percent-50 collection query, collection input order is unspecified.
    // Every ordering of an eligible subset can be a subsequence of some legal input order.
    const unorderedPercent = unorderedInput && id.endsWith("#sample-percent-50");
    const accepted = unorderedPercent
      ? sampleRows(output, eligible, "documents", output.length)
      : sampleRows(output, eligible, rule.mode, expected);
    if (!accepted) return null;
    return {
      id,
      proofClassification: "FINITE_SAMPLE_CONTRACT",
      profile: "strict",
      requestSha256: rule.requestSha256,
      seedSha256: policy.seedSha256,
      inputCount: eligible.length,
      outputCount: output.length,
      mode: rule.mode,
      role,
    };
  } catch {
    return null;
  }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const input = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const result = evaluateSample(input);
  process.stdout.write(JSON.stringify({ binding: "UNVERIFIED", result }) + "\n");
  if (!result) process.exitCode = 1;
}
