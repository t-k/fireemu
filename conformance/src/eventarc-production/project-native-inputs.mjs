// Offline projection of the closed Eventarc journals; no response or missing proof is invented.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
const sha = (b) => createHash("sha256").update(b).digest("hex");
export const NUMERIC_ALIAS = "123456789012";
const ORIGINAL_INDEX_SHA = "c7c78acb381ddff43292160092ac6ab613ce73646dc96ccc7bc7f9559b07eaef";
const ORIGINAL_MAP_SHA = "795debdc480c709a6ddc86d78b7a7627117a86cdbbc207f046b4766c3d104eae";
const MODES = new Set([
  "default",
  "none",
  "invalid",
  "ya29-garbage",
  "jwt-garbage",
  "jwt-expired-unsigned",
  "wrong-scope",
]);
const ROW_FIELDS = [
  "n",
  "case",
  "step",
  "op",
  "at",
  "ms",
  "tokenMode",
  "transport",
  "quotaProject",
  "request",
  "requestBytes",
  "unknown",
];
const MARKER = Buffer.from([0x18, 0x01, 0x20]);
function encodeVarint(value) {
  let n = BigInt(value);
  const result = [];
  do {
    let b = Number(n & 127n);
    n >>= 7n;
    if (n) b |= 128;
    result.push(b);
  } while (n);
  return Buffer.from(result);
}
function decodeVarint(bytes, offset) {
  let n = 0n;
  for (let i = 0; i < 10 && offset + i < bytes.length; i++) {
    const b = bytes[offset + i];
    n |= BigInt(b & 127) << BigInt(i * 7);
    if (!(b & 128)) return { value: n, length: i + 1 };
  }
  return null;
}
/** Same-width protobuf substitution, also checked by the existing stage-C fixture hygiene test. */
export function sanitizePageToken(text, number) {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return text;
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) return text;
  const offset = bytes.indexOf(MARKER);
  if (offset < 0) return text;
  const decoded = decodeVarint(bytes, offset + MARKER.length);
  if (!decoded) return text;
  assert.ok(
    decoded.value === BigInt(number) || decoded.value === BigInt(NUMERIC_ALIAS),
    "foreign project number inside page token",
  );
  const replacement = encodeVarint(NUMERIC_ALIAS);
  assert.equal(replacement.length, decoded.length, "page token varint width");
  if (decoded.value === BigInt(NUMERIC_ALIAS)) return text;
  replacement.copy(bytes, offset + MARKER.length);
  const result = bytes.toString("base64url");
  assert.equal(result.length, text.length, "page token text width");
  return result;
}
function queryTokens(text, number, replacements) {
  return text.replace(/([?&]pageToken=)([^&#]*)/g, (whole, prefix, encoded) => {
    let token;
    try {
      token = decodeURIComponent(encoded.replaceAll("+", " "));
    } catch {
      return whole;
    }
    const next = sanitizePageToken(token, number);
    if (next === token) return whole;
    replacements.set(token, next);
    return prefix + encodeURIComponent(next);
  });
}
function sanitize(value, number, replacements, key = "") {
  if (typeof value === "string") {
    let next = value;
    if (key === "nextPageToken" || key === "pageToken") {
      next = sanitizePageToken(next, number);
      if (next !== value) replacements.set(value, next);
    }
    next = queryTokens(next, number, replacements);
    return next.replaceAll(number, NUMERIC_ALIAS);
  }
  if (Array.isArray(value)) return value.map((x) => sanitize(x, number, replacements));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, sanitize(v, number, replacements, k)]),
    );
  return value;
}
const CREDENTIAL =
  /\bya29\.[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[A-Za-z0-9_-]{20,}|[\w.+-]+@[\w-]+(?:\.[\w-]+)+/;
function hygienic(text, number, depth = 0) {
  assert.ok(!text.includes(number) || number === NUMERIC_ALIAS, "private project number remains");
  assert.ok(!CREDENTIAL.test(text), "credential material in projection");
  if (depth >= 2) return;
  for (const [candidate] of text.matchAll(/[A-Za-z0-9+/_-]{16,}={0,2}/g)) {
    const url = candidate.includes("-") || candidate.includes("_"),
      bytes = Buffer.from(candidate, url ? "base64url" : "base64");
    if (
      bytes.toString(url ? "base64url" : "base64").replace(/=+$/, "") !==
      candidate.replace(/=+$/, "")
    )
      continue;
    const at = bytes.indexOf(MARKER),
      value = at < 0 ? null : decodeVarint(bytes, at + 3);
    assert.ok(
      !value || value.value !== BigInt(number) || number === NUMERIC_ALIAS,
      "encoded private project number remains",
    );
    hygienic(bytes.toString("utf8"), number, depth + 1);
  }
}
function nativeBytes(response) {
  const one = Object.hasOwn(response, "bodyBase64"),
    parts = Object.hasOwn(response, "bodyBase64Parts");
  assert.ok(!(one && parts), "ambiguous native body encoding");
  if (!one && !parts) {
    assert.ok(
      !Object.hasOwn(response, "bodyBytes") && !Object.hasOwn(response, "bodySha256"),
      "partial native body envelope",
    );
    return null;
  }
  const encoded = one ? response.bodyBase64 : response.bodyBase64Parts.join("");
  assert.equal(typeof encoded, "string");
  const bytes = Buffer.from(encoded, "base64");
  assert.equal(bytes.toString("base64"), encoded, "native base64 encoding");
  assert.equal(bytes.length, response.bodyBytes, "native body length");
  assert.equal(sha(bytes), response.bodySha256, "native body digest");
  return bytes;
}
/** Keep the existing journal-row shape accepted by loadRows and loadNativeRequests. */
function projectRows({ bytes, expectedSha256, numericProjectNumber }, classifications) {
  assert.equal(sha(bytes), expectedSha256, "original journal digest");
  assert.match(numericProjectNumber, /^\d{12}$/, "project alias decimal width");
  assert.equal(
    encodeVarint(numericProjectNumber).length,
    encodeVarint(NUMERIC_ALIAS).length,
    "project alias varint width",
  );
  const originals = bytes
      .toString("utf8")
      .split("\n")
      .filter((x) => x.trim())
      .map(JSON.parse),
    lines = [],
    rows = [],
    ordinals = new Set();
  let omittedNotes = 0,
    nativeRows = 0;
  for (const recorded of originals) {
    const original =
      classifications && recorded.n !== 25
        ? {
            ...recorded,
            op: classifications[recorded.n - 1].op,
            case: classifications[recorded.n - 1].case,
          }
        : recorded;
    if (typeof original.op !== "string") {
      if (original.note === "run-start") {
        assert.equal(typeof original.runId, "string");
        lines.push({ note: "run-start", runId: original.runId });
      } else if (original.note === "service-state") {
        const note = { note: original.note };
        for (const key of ["case", "before", "state", "disabledStateRecorded"])
          if (Object.hasOwn(original, key))
            note[key] = sanitize(original[key], numericProjectNumber, new Map());
        hygienic(JSON.stringify(note), numericProjectNumber);
        lines.push(note);
      } else omittedNotes++;
      continue;
    }
    assert.ok(Number.isSafeInteger(original.n) && original.n > 0, "native ordinal");
    assert.ok(!ordinals.has(original.n), "duplicate ordinal");
    ordinals.add(original.n);
    if (Object.hasOwn(original, "tokenMode"))
      assert.ok(MODES.has(original.tokenMode), "unknown credential mode");
    if (Object.hasOwn(original, "ms"))
      assert.ok(
        typeof original.ms === "number" && Number.isFinite(original.ms) && original.ms >= 0,
        "native latency",
      );
    if (Object.hasOwn(original, "at"))
      assert.ok(
        typeof original.at === "string" && Number.isFinite(Date.parse(original.at)),
        "native response time",
      );
    assert.ok(
      original.request &&
        typeof original.request.method === "string" &&
        typeof original.request.path === "string",
      "native request",
    );
    assert.ok(
      Object.keys(original.request).every((k) => ["method", "path", "body"].includes(k)),
      "unexpected request credential/config field",
    );
    assert.ok(
      original.response &&
        Number.isInteger(original.response.status) &&
        Object.hasOwn(original.response, "body"),
      "native response",
    );
    const replacements = new Map(),
      row = {};
    for (const key of ROW_FIELDS)
      if (Object.hasOwn(original, key))
        row[key] = sanitize(original[key], numericProjectNumber, replacements);
    const response = {
      status: original.response.status,
      body: sanitize(original.response.body, numericProjectNumber, replacements),
    };
    const raw = nativeBytes(original.response);
    let encoding = null;
    if (raw) {
      nativeRows++;
      encoding = Object.hasOwn(original.response, "bodyBase64") ? "bodyBase64" : "bodyBase64Parts";
      let text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
      sanitize(JSON.parse(text), numericProjectNumber, replacements);
      for (const [before, after] of replacements)
        text = text.replaceAll(JSON.stringify(before), JSON.stringify(after));
      text = text.replaceAll(numericProjectNumber, NUMERIC_ALIAS);
      hygienic(text, numericProjectNumber);
      const projected = Buffer.from(text);
      assert.equal(projected.length, raw.length, "sanitized native byte width");
      response.bodyBase64 = projected.toString("base64");
      response.bodyBytes = projected.length;
      response.bodySha256 = sha(projected);
      response.originalBodySha256 = sha(raw);
    }
    if (Object.hasOwn(original.response, "headers"))
      response.headers = sanitize(original.response.headers, numericProjectNumber, replacements);
    if (Object.hasOwn(original.response, "unknown")) response.unknown = original.response.unknown;
    const absent = [];
    for (const key of ["at", "ms", "tokenMode"])
      if (!Object.hasOwn(original, key)) absent.push(key);
    if (!raw)
      absent.push(
        "response.bodyBase64",
        "response.bodyBytes",
        "response.bodySha256",
        "response.originalBodySha256",
      );
    if (!Object.hasOwn(original.response, "headers")) absent.push("response.headers");
    row.response = response;
    row.projectionSource = {
      journalSha256: expectedSha256,
      n: original.n,
      originalResponseBytesPresent: raw !== null,
      originalRawEncoding: encoding,
      parsedBodySource: "original-recorded-parsed-body",
      absentFields: absent,
    };
    hygienic(JSON.stringify(row), numericProjectNumber);
    rows.push(row);
    lines.push(row);
  }
  assert.ok(rows.length > 0, "empty native journal");
  return {
    rows,
    bytes: Buffer.from(lines.map((r) => JSON.stringify(r)).join("\n") + "\n"),
    summary: {
      rows: rows.length,
      nativeRows,
      parsedOnlyRows: rows.length - nativeRows,
      omittedNotes,
      ordinals: [...ordinals],
    },
  };
}
export function projectJournal(options) {
  return projectRows(options);
}
export const NATIVE_SUPPLEMENT_SHA256 =
  "54765255731c0e0622a102abac4cd8e84e484ea9002a492de7113205b8cfb153";
// Classification is derived from the closed capture, never claimed as recorded metadata.
const supplementOps = [
  "listServices",
  "getChannel",
  "getChannel",
  "getChannel",
  "listChannels",
  "listChannels",
  "listChannels",
  "createChannel",
  "getOperation",
  "getOperation",
  "getChannel",
  "listChannels",
  "createChannel",
  "getOperation",
  "getOperation",
  "getChannel",
  "listChannels",
  "createChannel",
  "getOperation",
  "getOperation",
  "getChannel",
  "listChannels",
  "publishEvents",
  "publishEvents",
  "sdk.publishEvents",
  "publishEvents",
  "publishEvents",
  "publishEvents",
  "getChannel",
  "listChannels",
  "getChannel",
  "listChannels",
  "getChannel",
  "listChannels",
  "listChannels",
  "listChannels",
  "listChannels",
  "listChannels",
  "listChannels",
  "listChannels",
  "listChannels",
  "deleteChannel",
  "getOperation",
  "getChannel",
  "deleteChannel",
  "getOperation",
  "getChannel",
  "deleteChannel",
  "getOperation",
  "getChannel",
  "listChannels",
  "listChannels",
];
export function projectNativeSupplement({ bytes, numericProjectNumber }) {
  assert.equal(sha(bytes), NATIVE_SUPPLEMENT_SHA256, "original supplement digest");
  const originals = bytes.toString("utf8").split("\n").filter(Boolean).map(JSON.parse);
  assert.equal(originals.length, 52, "closed supplement row count");
  assert.deepEqual(
    originals.map((r) => r.n),
    Array.from({ length: 52 }, (_, i) => i + 1),
    "closed supplement ordinals",
  );
  for (const r of originals) {
    if (r.n === 25)
      assert.deepEqual(
        { op: r.op, case: r.case, step: r.step },
        { op: "sdk.publishEvents", case: "native-c307", step: "s01-1" },
        "unexpected recorded classification",
      );
    else
      assert.ok(
        ["op", "case", "step"].every((k) => !Object.hasOwn(r, k)),
        "unexpected recorded classification",
      );
  }
  const classifications = supplementOps.map((op, i) => ({
    op,
    case:
      i === 24
        ? "admin-sdk-publish"
        : i >= 22 && i <= 27
          ? "publish-envelope"
          : "channel-lifecycle",
    step: `native-${i + 1}`,
  }));
  const result = projectRows(
    { bytes, expectedSha256: NATIVE_SUPPLEMENT_SHA256, numericProjectNumber },
    classifications,
  );
  for (const row of result.rows)
    Object.assign(row.projectionSource, {
      classificationSource:
        row.n === 25
          ? "original-recorded-classification"
          : "explicit-native-supplement-selectors-v1",
      derivedClassification: classifications[row.n - 1],
      originalRequestWireBytesPresent: false,
    });
  result.bytes = Buffer.from(result.rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return result;
}
function expandPublicRepeat(value) {
  if (Array.isArray(value)) return value.map(expandPublicRepeat);
  if (value && typeof value === "object") {
    if (Object.keys(value).length === 1 && Object.hasOwn(value, "$repeat")) {
      const { count, template } = value.$repeat;
      assert.ok(Number.isSafeInteger(count) && count >= 0 && count <= 10000, "public repeat count");
      assert.ok(Object.hasOwn(value.$repeat, "template"), "public repeat template");
      return Array.from({ length: count }, () => expandPublicRepeat(template));
    }
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expandPublicRepeat(v)]));
  }
  return value;
}
/** Existing public B/C fixtures are an independent binding, not an alternate expected answer. */
export function verifyExistingPublicRows(projected, existing) {
  const byN = new Map(projected.map((r) => [r.n, r]));
  for (const before of existing) {
    const row = byN.get(before.n);
    assert.ok(row, "missing existing public ordinal");
    assert.equal(row.op, before.op, "existing public operation");
    assert.ok(isDeepStrictEqual(row.request, before.request), "existing public request changed");
    assert.equal(row.response.status, before.response.status, "existing public status");
    if (Object.hasOwn(before.response, "rawBody")) {
      assert.equal(
        Buffer.from(row.response.bodyBase64, "base64").toString("utf8"),
        before.response.rawBody,
        "existing public raw bytes changed",
      );
      assert.equal(row.response.bodyBytes, before.response.bodyBytes, "existing public byte count");
      assert.equal(
        row.response.headers?.["content-type"],
        before.response.contentType,
        "existing public content type",
      );
    } else
      assert.ok(
        isDeepStrictEqual(row.response.body, before.response.body),
        "existing public parsed response changed",
      );
    for (const key of ["at", "ms", "quotaProject"])
      if (Object.hasOwn(before, key))
        assert.ok(isDeepStrictEqual(row[key], before[key]), `existing public ${key} changed`);
  }
}
/** A2's legacy compact program is retained as distinct provenance, never as exact authority. */
export function bindExistingPublicFixture({ label, projected, fixtureBytes, path }) {
  const before = JSON.parse(fixtureBytes),
    pin = { path, sha256: sha(fixtureBytes) };
  if (label === "B" || label === "C") {
    verifyExistingPublicRows(projected, before);
    return {
      existingPublicFixture: {
        ...pin,
        relationship: "exact sanitized request/status/native-byte binding",
      },
    };
  }
  assert.equal(label, "A2", "public fixture lane");
  const byN = new Map(projected.map((r) => [r.n, r]));
  const differentRequestOrdinals = before
    .filter((r) => !isDeepStrictEqual(byN.get(r.n)?.request, expandPublicRepeat(r.request)))
    .map((r) => r.n);
  return {
    legacyPublicFixture: {
      ...pin,
      relationship: "distinct compact parsed input; not equality authority",
      differentRequestOrdinals,
    },
  };
}
export function buildWitnessPlan(corpora) {
  const plan = {
    schemaVersion: 1,
    kind: "eventarc-own-witness-plan-v1",
    corpora: {
      B: {
        setupN: [16, 20],
        walks: [{ rootN: 27, inventoryN: 26, setupThroughN: 20 }],
        terminalN: [202],
      },
      C: {
        setupN: [16, 20, 41, 46, 64, 76, 80, 84, 88, 92, 96],
        walks: [
          { rootN: 27, inventoryN: 26, setupThroughN: 20 },
          { rootN: 102, inventoryN: 101, setupThroughN: 96 },
          { rootN: 110, inventoryN: 101, setupThroughN: 96 },
          { rootN: 115, inventoryN: 101, setupThroughN: 96 },
        ],
        terminalN: [398],
      },
      D: {
        setupN: [16, 19, 23, 27, 31, 35],
        walks: [
          { rootN: 41, inventoryN: 40, setupThroughN: 35 },
          { rootN: 47, inventoryN: 40, setupThroughN: 35 },
          { rootN: 50, inventoryN: 40, setupThroughN: 35 },
        ],
        terminalN: [16, 66, 186],
        independentLifecycleSlices: [
          { createN: 61, deleteN: 66, overlap: true },
          { createN: 87, deleteN: 186, overlap: false },
        ],
      },
    },
    nativeMissing: ["C102/C110 complete continuation tails"],
    disposition: "owner1145 facets only; no raw verdict, case or parent promotion",
    timing:
      "ordinary real clock; no operation duration injection; finite deadlines owned by producer",
  };
  for (const [label, spec] of Object.entries(plan.corpora)) {
    const ns = new Set(corpora[label]?.map((r) => r.n));
    const wanted = [
      ...spec.setupN,
      ...spec.terminalN,
      ...spec.walks.flatMap((w) => [w.rootN, w.inventoryN]),
      ...(spec.independentLifecycleSlices ?? []).flatMap((s) => [s.createN, s.deleteN]),
    ];
    assert.ok(
      wanted.every((n) => ns.has(n)),
      `missing witness selector in ${label}`,
    );
  }
  return plan;
}
const CAPTURES = {
  A1: "capture-d011709742b6.jsonl",
  A2: "capture-9e560c404162.jsonl",
  B: "capture-43a83839852f.jsonl",
  C: "capture-fe404dee592e.jsonl",
  D: "capture-bd0b44db5477.jsonl",
};
export function main(argv) {
  assert.equal(
    argv.length,
    4,
    "usage: --original-index <closed index> --out <projection directory>",
  );
  assert.equal(argv[0], "--original-index");
  assert.equal(argv[2], "--out");
  const indexBytes = readFileSync(argv[1]);
  assert.equal(sha(indexBytes), ORIGINAL_INDEX_SHA, "original closed index digest");
  const index = JSON.parse(indexBytes);
  assert.equal(index.length, 29);
  for (const pin of index) {
    const b = readFileSync(pin.path);
    assert.equal(b.length, pin.bytes, "closed input byte count");
    assert.equal(sha(b), pin.sha256, "closed input digest");
  }
  const native = Object.fromEntries(
    Object.entries(CAPTURES).map(([label, name]) => {
      const pins = index.filter((p) => basename(p.path) === name);
      assert.equal(pins.length, 1, "exact native journal");
      return [label, { pin: pins[0], bytes: readFileSync(pins[0].path) }];
    }),
  );
  const numberOf = (bytes) => {
    const row = bytes
      .toString()
      .split("\n")
      .map((x) => (x.trim() ? JSON.parse(x) : null))
      .find((r) => r?.n === 35);
    const number = /\/projects\/(\d{12})\//.exec(row?.request?.path)?.[1];
    assert.ok(number, "original numeric alias selector");
    return number;
  };
  const number = numberOf(native.B.bytes);
  assert.equal(numberOf(native.C.bytes), number, "native project number binding");
  const projected = Object.fromEntries(
    Object.entries(native).map(([label, input]) => [
      label,
      projectJournal({
        bytes: input.bytes,
        expectedSha256: input.pin.sha256,
        numericProjectNumber: number,
      }),
    ]),
  );
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../../.."),
    provenance = {
      schemaVersion: 1,
      kind: "eventarc-native-projection-v1",
      originalAuthority: { indexSha256: ORIGINAL_INDEX_SHA, mapSha256: ORIGINAL_MAP_SHA },
      numericAlias: NUMERIC_ALIAS,
      corpora: [],
    };
  for (const [label, result] of Object.entries(projected)) {
    const source = native[label],
      entry = {
        label,
        source: {
          recording: CAPTURES[label].slice(8, -6),
          journalSha256: source.pin.sha256,
          bytes: source.pin.bytes,
        },
        projection: { file: `${label}.jsonl`, sha256: sha(result.bytes), ...result.summary },
        transformation:
          "same-width numeric project alias including protobuf page tokens only; authority notes projected to necessary replay metadata",
      };
    if (["A2", "B", "C"].includes(label)) {
      const stage = label === "A2" ? "a" : label.toLowerCase(),
        path = `crates/fireemu-adapter-functions/tests/fixtures/eventarc-stage-${stage}/rows.json`,
        bytes = readFileSync(resolve(repo, path));
      Object.assign(
        entry,
        bindExistingPublicFixture({ label, projected: result.rows, fixtureBytes: bytes, path }),
      );
    }
    provenance.corpora.push(entry);
  }
  const plan = buildWitnessPlan(
    Object.fromEntries(Object.entries(projected).map(([label, p]) => [label, p.rows])),
  );
  for (const [label, spec] of Object.entries(plan.corpora))
    spec.projectionSha256 = sha(projected[label].bytes);
  const out = resolve(argv[3]);
  mkdirSync(out, { recursive: true });
  for (const [label, result] of Object.entries(projected))
    writeFileSync(resolve(out, `${label}.jsonl`), result.bytes);
  writeFileSync(resolve(out, "provenance.json"), JSON.stringify(provenance, null, 2) + "\n");
  writeFileSync(resolve(out, "witness-plan.json"), JSON.stringify(plan, null, 2) + "\n");
  return provenance.corpora.map(({ label, projection }) => ({
    label,
    rows: projection.rows,
    nativeRows: projection.nativeRows,
    parsedOnlyRows: projection.parsedOnlyRows,
    sha256: projection.sha256,
  }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  console.log(JSON.stringify(main(process.argv.slice(2))));
