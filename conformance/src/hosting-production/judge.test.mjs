import assert from "node:assert/strict";
import { brotliCompressSync, gzipSync } from "node:zlib";
import test from "node:test";

import {
  applyKnownDifferences,
  compareRows,
  compareRuns,
  conditionVerdicts,
  etagShape,
  lastModifiedShape,
  unclassifiedHeaderNames,
} from "./judge.mjs";
import {
  VOLATILE_HEADERS,
  assertNoSecrets,
  isComparedHeader,
  maskSecrets,
  shapeRow,
} from "./rows.mjs";

const ORIGIN = "https://site--hst-abcdef-v01-1a2b3c.web.app";
const CTX = { origin: ORIGIN, secrets: ["SECRETKEY-123456", "123456789012"], version: "v01" };
const spec = (extra = {}) => ({
  id: "v01.x",
  condition: "static-files",
  method: "GET",
  target: "/data.json",
  ...extra,
});
const answer = (extra = {}) => ({
  outcome: "answered",
  status: 200,
  headers: [
    ["Content-Type", "application/json; charset=utf-8"],
    ["Cache-Control", "public, max-age=123"],
    ["ETag", '"abc123"'],
    ["Date", "Mon, 01 Jan 2024 00:00:00 GMT"],
  ],
  body: Buffer.from('{"fixture":true}\n'),
  ...extra,
});
const row = (extraSpec, extraAnswer, ctx = CTX) =>
  shapeRow(spec(extraSpec), answer(extraAnswer), ctx);

// A small deterministic generator for the property tests.
function prng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

test("an identical row matches itself; a missing or unanswered row is UNKNOWN, never a match", () => {
  const r = row();
  assert.equal(compareRows(r, structuredClone(r)).status, "MATCH");
  assert.equal(compareRows(r, undefined).status, "UNKNOWN");
  assert.equal(compareRows(undefined, r).reason, "missing-row");
  const unknown = shapeRow(spec(), { outcome: "unknown", reason: "timeout" }, CTX);
  assert.equal(unknown.outcome, "unknown");
  assert.equal(compareRows(r, unknown).status, "UNKNOWN");
  assert.equal(compareRows(unknown, unknown).status, "UNKNOWN");
  assert.throws(() => compareRows(r, { ...r, id: "v01.y" }), /different requests/);
});

test("status, a compared header and the body each make a mismatch with the field named", () => {
  const base = row();
  const status = compareRows(base, row({}, { status: 404 }));
  assert.equal(status.status, "MISMATCH");
  assert.deepEqual(
    status.differences.map((d) => d.field),
    ["status"],
  );
  const cache = compareRows(
    base,
    row(
      {},
      {
        headers: [
          ["content-type", "application/json; charset=utf-8"],
          ["cache-control", "public, max-age=124"],
          ["etag", '"abc123"'],
        ],
      },
    ),
  );
  assert.deepEqual(
    cache.differences.map((d) => d.field),
    ["header:cache-control"],
  );
  const body = compareRows(base, row({}, { body: Buffer.from('{"fixture":trux}\n') }));
  assert.deepEqual(
    body.differences.map((d) => d.field),
    ["bodySha256"],
  );
  const longer = compareRows(base, row({}, { body: Buffer.from('{"fixture":true}\n\n') }));
  assert.deepEqual(
    longer.differences.map((d) => d.field),
    ["bodyBytes"],
  );
});

test("a header present on one side only is a mismatch; a volatile one is ignored", () => {
  const base = row();
  const withHsts = row(
    {},
    {
      headers: [...answer().headers, ["Cache-Control", "max-age=60"]],
    },
  );
  const diff = compareRows(base, withHsts);
  assert.equal(diff.status, "MISMATCH");
  assert.equal(diff.differences[0].field, "header:cache-control");
  for (const name of VOLATILE_HEADERS) {
    const noisy = row({}, { headers: [...answer().headers, [name, "different"]] });
    assert.equal(compareRows(base, noisy).status, "MATCH", name);
  }
});

test("ETag and Last-Modified compare by form; a different form is a mismatch", () => {
  const withValues = (etag, modified) =>
    row(
      {},
      {
        headers: [
          ["content-type", "application/json; charset=utf-8"],
          ["cache-control", "public, max-age=123"],
          ["etag", etag],
          ...(modified ? [["last-modified", modified]] : []),
        ],
      },
    );
  const a = withValues('"abc123"', "Mon, 01 Jan 2024 00:00:00 GMT");
  assert.equal(
    compareRows(a, withValues('"def456"', "Tue, 02 Jan 2024 00:00:00 GMT")).status,
    "MATCH_LAYOUT",
  );
  assert.equal(
    compareRows(a, withValues('"abc123"', "Mon, 01 Jan 2024 00:00:00 GMT")).status,
    "MATCH",
  );
  for (const other of ["abc123", 'W/"abc123"', '"abc12"', '"ABC+12"']) {
    const result = compareRows(a, withValues(other, "Mon, 01 Jan 2024 00:00:00 GMT"));
    assert.equal(result.status, "MISMATCH", other);
    assert.equal(result.differences[0].reason, "form");
  }
  assert.equal(compareRows(a, withValues('"abc123"', "2024-01-01T00:00:00Z")).status, "MISMATCH");
  assert.equal(compareRows(a, withValues('"abc123"', undefined)).status, "MISMATCH");
  assert.deepEqual(etagShape('W/"ab"'), { weak: true, quoted: true, length: 2, charset: "hex" });
  assert.deepEqual(etagShape("xyz!"), { weak: false, quoted: false, length: 4, charset: "other" });
  assert.equal(lastModifiedShape("Mon, 01 Jan 2024 00:00:00 GMT").imfFixdate, true);
  assert.equal(lastModifiedShape("Mon, 1 Jan 2024 00:00:00 GMT").imfFixdate, false);
});

test("an absolute Location differs from a relative one once the request origin is a token", () => {
  const redirect = (location) =>
    row(
      { target: "/old/a" },
      { status: 302, headers: [["Location", location]], body: Buffer.alloc(0) },
    );
  const absolute = redirect(`${ORIGIN}/page.html`);
  assert.deepEqual(absolute.headers.location, ["<origin>/page.html"]);
  const relative = redirect("/page.html");
  const result = compareRows(absolute, relative);
  assert.equal(result.status, "MISMATCH");
  assert.equal(result.differences[0].field, "header:location");
  assert.equal(compareRows(absolute, redirect(`${ORIGIN}/page.html`)).status, "MATCH");
  // A different origin is not the request origin and stays visible.
  assert.deepEqual(redirect("https://example.test/x").headers.location, ["https://example.test/x"]);
});

test("a content-encoded answer is compared by its decoded body, not by the wire bytes", () => {
  const plain = Buffer.from("The quick brown fox.\n".repeat(200));
  const encoded = (gz) =>
    row(
      { target: "/compress/big.txt" },
      {
        headers: [
          ["Content-Encoding", "gzip"],
          ["Content-Type", "text/plain; charset=utf-8"],
          ["Vary", "Accept-Encoding"],
        ],
        body: gz,
      },
    );
  const a = encoded(gzipSync(plain, { level: 1 }));
  const b = encoded(gzipSync(plain, { level: 9 }));
  assert.notEqual(a.bodySha256, b.bodySha256);
  assert.equal(a.decodedBytes, plain.length);
  assert.equal(compareRows(a, b).status, "MATCH");
  const other = encoded(gzipSync(Buffer.from("different"), { level: 9 }));
  assert.equal(compareRows(a, other).status, "MISMATCH");
  // Encoded on one side only: the header and the body both differ.
  const identity = row(
    { target: "/compress/big.txt" },
    {
      headers: [
        ["Content-Type", "text/plain; charset=utf-8"],
        ["Vary", "Accept-Encoding"],
      ],
      body: plain,
    },
  );
  const against = compareRows(a, identity);
  assert.equal(against.status, "MISMATCH");
  assert.ok(against.differences.some((d) => d.field === "header:content-encoding"));
});

test("the reserved init bodies keep layout, never a value, and a secret never reaches a row", () => {
  const json = JSON.stringify({
    apiKey: "SECRETKEY-123456",
    projectId: "p",
    messagingSenderId: "123456789012",
  });
  const init = row(
    { target: "/__/firebase/init.json" },
    {
      headers: [
        ["Content-Type", "application/json"],
        ["X-Echo", "SECRETKEY-123456"],
      ],
      body: Buffer.from(json),
    },
  );
  assert.equal(init.bodyKind, "init-json");
  assert.deepEqual(init.layout.keys, ["apiKey", "projectId", "messagingSenderId"]);
  assert.deepEqual(init.layout.valueBytes, { apiKey: 16, projectId: 1, messagingSenderId: 12 });
  assert.equal(init.bodySha256, undefined);
  assert.equal(init.bodyText, undefined);
  assert.deepEqual(init.headers["x-echo"], ["################"]);
  assertNoSecrets(init, CTX.secrets);
  assert.throws(() => assertNoSecrets({ leak: "123456789012" }, CTX.secrets), /private value/);
  // Same keys with different values and a different value length: the value length is a format.
  const other = row(
    { target: "/__/firebase/init.json" },
    {
      headers: [
        ["Content-Type", "application/json"],
        ["X-Echo", "SECRETKEY-123456"],
      ],
      body: Buffer.from(
        JSON.stringify({
          apiKey: "SECRETKEY-1234567",
          projectId: "q",
          messagingSenderId: "123456789012",
        }),
      ),
    },
  );
  const diff = compareRows(init, other);
  assert.equal(diff.status, "MISMATCH");
  assert.equal(diff.differences[0].field, "layout");
  const reordered = row(
    { target: "/__/firebase/init.json" },
    {
      headers: [
        ["Content-Type", "application/json"],
        ["X-Echo", "SECRETKEY-123456"],
      ],
      body: Buffer.from(
        JSON.stringify({
          projectId: "p",
          apiKey: "SECRETKEY-123456",
          messagingSenderId: "123456789012",
        }),
      ),
    },
  );
  assert.equal(compareRows(init, reordered).status, "MISMATCH");
  // init.js: layout is not compared between production and local by default, but is between runs.
  const js = (lines) =>
    row(
      { target: "/__/firebase/init.js" },
      {
        headers: [["Content-Type", "application/javascript"]],
        body: Buffer.from("x\n".repeat(lines)),
      },
    );
  assert.equal(compareRows(js(3), js(4)).status, "MATCH");
  assert.equal(compareRows(js(3), js(4), { compareInitJs: true }).status, "MISMATCH");
  // A non-200 reserved answer is an ordinary body.
  const missing = row(
    { target: "/__/firebase/init.json" },
    { status: 404, body: Buffer.from("nope") },
  );
  assert.equal(missing.bodyKind, "text");
});

test("masking replaces every occurrence with as many characters and ignores short secrets", () => {
  assert.equal(
    maskSecrets("a SECRETKEY-123456 b SECRETKEY-123456", ["SECRETKEY-123456"]),
    `a ${"#".repeat(16)} b ${"#".repeat(16)}`,
  );
  assert.equal(maskSecrets("abc", ["abc"]), "abc");
  assert.equal(maskSecrets("abc", [undefined, ""]), "abc");
});

test("header classification covers the compared set, the glob headers and the volatile set", () => {
  assert.ok(isComparedHeader("cache-control"));
  assert.ok(isComparedHeader("x-g00") && isComparedHeader("x-g15"));
  assert.ok(!isComparedHeader("x-g1") && !isComparedHeader("x-ga0"));
  assert.ok(!isComparedHeader("date"));
  const noisy = row({}, { headers: [...answer().headers, ["X-Surprise", "1"], ["Server", "gfe"]] });
  assert.deepEqual(unclassifiedHeaderNames([noisy, row()]), ["x-surprise"]);
});

test("compareRuns reports by corpus order, counts statuses and lists unclassified headers", () => {
  const a = [row(), row({ id: "v01.y" })];
  const b = [row({ id: "v01.y" }, { status: 404 })];
  const result = compareRuns(["v01.x", "v01.y", "v01.z"], a, b);
  assert.deepEqual(
    result.rows.map((r) => [r.id, r.status]),
    [
      ["v01.x", "UNKNOWN"],
      ["v01.y", "MISMATCH"],
      ["v01.z", "UNKNOWN"],
    ],
  );
  assert.deepEqual(result.summary, {
    MATCH: 0,
    MATCH_LAYOUT: 0,
    KNOWN_DIFFERENCE: 0,
    MISMATCH: 1,
    UNKNOWN: 2,
  });
});

test("a condition is closable only when every non-informational row matches", () => {
  const requests = [
    { id: "a", condition: "static-files", also: ["headers-cache"] },
    { id: "b", condition: "static-files" },
    { id: "c", condition: "path-safety", infoOnly: true },
    { id: "d", condition: "headers-cache" },
  ];
  const rows = (statuses) => ({
    rows: Object.entries(statuses).map(([id, status]) => ({ id, status })),
  });
  const ok = conditionVerdicts(
    requests,
    rows({ a: "MATCH", b: "MATCH_LAYOUT", c: "MISMATCH", d: "MATCH" }),
  );
  assert.equal(ok["static-files"].closable, true);
  assert.equal(ok["headers-cache"].rows, 2);
  assert.equal(ok["path-safety"], undefined);
  const bad = conditionVerdicts(requests, rows({ a: "MATCH", b: "MISMATCH", d: "UNKNOWN" }));
  assert.equal(bad["static-files"].closable, false);
  assert.deepEqual(bad["static-files"].mismatched, ["b"]);
  assert.equal(bad["headers-cache"].closable, false);
  assert.equal(bad["headers-cache"].counts.UNKNOWN, 1);
});

test("property: reflexive, symmetric in class, volatile-blind, and any compared change is visible", () => {
  const next = prng(20261110);
  const statuses = [200, 301, 302, 304, 404];
  const headerNames = ["content-type", "cache-control", "location", "vary", "x-fixture", "x-g03"];
  for (let i = 0; i < 300; i += 1) {
    const headers = headerNames
      .filter(() => next() < 0.6)
      .map((name) => [name, `v${Math.floor(next() * 4)}`]);
    const a = row(
      {},
      {
        status: statuses[Math.floor(next() * statuses.length)],
        headers,
        body: Buffer.from(`body${Math.floor(next() * 3)}`),
      },
    );
    const b = structuredClone(a);
    assert.equal(compareRows(a, b).status, "MATCH");
    // Volatile noise on one side changes nothing.
    b.headers.age = ["1"];
    b.headers.date = ["x"];
    assert.equal(compareRows(a, b).status, "MATCH");
    // Mutating any one compared aspect is seen, and the verdict class is symmetric.
    const mutants = [
      { ...b, status: b.status + 1 },
      { ...b, bodyBytes: b.bodyBytes + 1 },
      { ...b, bodySha256: "0".repeat(64) },
      ...Object.keys(b.headers)
        .filter(isComparedHeader)
        .map((name) => ({ ...b, headers: { ...b.headers, [name]: ["mutated"] } })),
    ];
    for (const mutant of mutants) {
      const forward = compareRows(a, mutant);
      const backward = compareRows(mutant, a);
      assert.equal(forward.status, "MISMATCH");
      assert.equal(backward.status, "MISMATCH");
      assert.deepEqual(
        forward.differences.map((d) => d.field),
        backward.differences.map((d) => d.field),
      );
    }
  }
});

test("near misses: a lone quote is not quoted, unclassified headers are not compared, several ETags are counted", () => {
  assert.equal(etagShape('"').quoted, false);
  assert.equal(etagShape('""').quoted, true);
  const base = row();
  const noisy = row({}, { headers: [...answer().headers, ["X-Surprise", "1"]] });
  assert.equal(compareRows(base, noisy).status, "MATCH");
  assert.equal(compareRows(noisy, base).status, "MATCH");
  const two = row({}, { headers: [...answer().headers, ["ETag", '"zzz999"']] });
  const result = compareRows(base, two);
  assert.equal(result.status, "MISMATCH");
  assert.equal(result.differences[0].field, "header:etag");
});

test("near misses: encoded bodies of equal length differ by digest; the body kind and the encoding side matter", () => {
  const encoded = (body) =>
    row(
      { target: "/compress/big.txt" },
      {
        headers: [
          ["Content-Encoding", "gzip"],
          ["Content-Type", "text/plain"],
        ],
        body: gzipSync(Buffer.from(body)),
      },
    );
  const a = encoded("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  const b = encoded("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  assert.equal(a.decodedBytes, b.decodedBytes);
  const diff = compareRows(a, b);
  assert.deepEqual(
    diff.differences.map((d) => d.field),
    ["decodedSha256"],
  );
  const plain = row(
    { target: "/compress/big.txt" },
    {
      headers: [["Content-Type", "text/plain"]],
      body: Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    },
  );
  const fields = compareRows(a, plain).differences.map((d) => d.field);
  assert.ok(fields.includes("decodedBytes"));
  const init = row(
    { target: "/__/firebase/init.json" },
    {
      headers: [["Content-Type", "application/json"]],
      body: Buffer.from('{"a":"b"}'),
    },
  );
  const text = row(
    { target: "/__/firebase/init.json" },
    {
      headers: [["Content-Type", "application/json"]],
      body: Buffer.from('{"a":"b"}'),
      status: 404,
    },
  );
  const kinds = compareRows(init, text).differences.map((d) => d.field);
  assert.ok(kinds.includes("status") && kinds.includes("bodyKind"));
});

test("shaping: a target with a query is still an init body; text is kept up to 8192 bytes; binary is not text; infoOnly travels", () => {
  const withQuery = row(
    { target: "/__/firebase/init.js?useEmulator=true" },
    {
      headers: [["Content-Type", "application/javascript"]],
      body: Buffer.from("a\nb\n"),
    },
  );
  assert.equal(withQuery.bodyKind, "init-js");
  const exact = row({}, { body: Buffer.alloc(8192, 0x61) });
  assert.equal(exact.bodyText.length, 8192);
  const over = row({}, { body: Buffer.alloc(8193, 0x61) });
  assert.equal(over.bodyText, undefined);
  assert.equal(over.bodyKind, "text");
  const binary = row({}, { body: Buffer.from([0xff, 0xfe, 0xfd]) });
  assert.equal(binary.bodyKind, "binary");
  assert.equal(binary.bodyText, undefined);
  assert.equal(row({ infoOnly: true }).infoOnly, true);
  assert.equal(row().infoOnly, undefined);
  assert.equal(row({}, { body: Buffer.alloc(0) }).bodyKind, "none");
});

test("an init body that arrives compressed keeps layout only: no digest of the body or of its decoding", () => {
  const json = JSON.stringify({ apiKey: "SECRETKEY-123456", projectId: "p" });
  for (const encoding of ["gzip", "br"]) {
    const compress = encoding === "gzip" ? gzipSync : brotliCompressSync;
    const init = row(
      { target: "/__/firebase/init.json" },
      {
        headers: [
          ["Content-Type", "application/json"],
          ["Content-Encoding", encoding],
        ],
        body: compress(Buffer.from(json)),
      },
    );
    assert.equal(init.bodyKind, "init-json");
    assert.deepEqual(init.layout.keys, ["apiKey", "projectId"]);
    for (const field of ["bodySha256", "decodedSha256", "decodedBytes", "bodyText"]) {
      assert.equal(init[field], undefined, `${encoding} ${field}`);
    }
    assertNoSecrets(init, CTX.secrets);
  }
  const js = row(
    { target: "/__/firebase/init.js" },
    {
      headers: [
        ["Content-Type", "application/javascript"],
        ["Content-Encoding", "gzip"],
      ],
      body: gzipSync(Buffer.from("a\nb\n")),
    },
  );
  assert.deepEqual(js.layout, { lineCount: 3 });
  assert.equal(js.decodedSha256, undefined);
  // An ordinary compressed answer keeps its decoded digest.
  const plain = row(
    {},
    { headers: [["Content-Encoding", "gzip"]], body: gzipSync(Buffer.from("x")) },
  );
  assert.ok(plain.decodedSha256);
});

// ---- known differences (rulings 15-17: differences between the recording and strict that are
// declared, not aligned) ----

const ENTRY = {
  id: "KD-X",
  rows: ["v01.x"],
  fields: ["header:cache-control"],
  appliesTo: ["production-vs-local"],
};

test("a known difference is taken out of the mismatch only for its row, field and comparison", () => {
  const diffs = [
    { field: "header:cache-control", a: ["a"], b: ["b"] },
    { field: "status", a: 200, b: 404 },
  ];
  const split = applyKnownDifferences("v01.x", diffs, [ENTRY], "production-vs-local");
  assert.deepEqual(split.known, [{ field: "header:cache-control", entry: "KD-X" }]);
  assert.deepEqual(split.remaining, [diffs[1]]);
  // another row, another comparison kind, no entries: nothing is taken out
  for (const [id, entries, kind] of [
    ["v01.y", [ENTRY], "production-vs-local"],
    ["v01.x", [ENTRY], "run-vs-run"],
    ["v01.x", [], "production-vs-local"],
  ]) {
    const none = applyKnownDifferences(id, diffs, entries, kind);
    assert.deepEqual(none.known, []);
    assert.deepEqual(none.remaining, diffs);
  }
  // "*" covers every field of its rows
  const all = applyKnownDifferences(
    "v01.x",
    diffs,
    [{ ...ENTRY, fields: "*" }],
    "production-vs-local",
  );
  assert.deepEqual(all.remaining, []);
  assert.equal(all.known.length, 2);
});

test("a row whose only differences are known is KNOWN_DIFFERENCE, not MATCH, and names them; any other difference still mismatches", () => {
  const a = row({}, { headers: [...answer().headers, ["Cache-Control", "max-age=60"]] });
  const b = row();
  const options = { known: { entries: [ENTRY], kind: "production-vs-local" } };
  const covered = compareRows(a, b, options);
  assert.equal(covered.status, "KNOWN_DIFFERENCE");
  assert.deepEqual(covered.known, [{ field: "header:cache-control", entry: "KD-X" }]);
  // the same rows without the entry
  assert.equal(compareRows(a, b).status, "MISMATCH");
  // a status difference is not covered by an entry for a header
  const other = row({}, { status: 404 });
  const mixed = compareRows(other, b, options);
  assert.equal(mixed.status, "MISMATCH");
  assert.deepEqual(
    mixed.differences.map((d) => d.field),
    ["status"],
  );
  // a condition counts the rows that carry a known difference
  const results = { rows: [{ id: "v01.x", ...covered }] };
  const verdicts = conditionVerdicts(
    [{ id: "v01.x", condition: "static-files", method: "GET", target: "/" }],
    results,
  );
  assert.equal(verdicts["static-files"].knownDifferenceRows, 1);
  assert.equal(verdicts["static-files"].closable, true);
});

test("headers set by the https edge or the preview channel are volatile, SDK-row headers are classified", () => {
  for (const name of ["strict-transport-security", "x-robots-tag"]) {
    assert.ok(VOLATILE_HEADERS.has(name), name);
    const noisy = row({}, { headers: [...answer().headers, [name, "x"]] });
    assert.equal(compareRows(row(), noisy).status, "MATCH", name);
  }
  const sdk = row(
    {},
    {
      headers: [
        ...answer().headers,
        ["Cross-Origin-Opener-Policy", "same-origin"],
        ["Pragma", "no-cache"],
        ["X-Unlisted", "1"],
      ],
    },
  );
  assert.deepEqual(unclassifiedHeaderNames([sdk]), ["x-unlisted"]);
  // pragma is compared (the association documents carry it)
  assert.equal(
    compareRows(row(), sdk).differences.some((d) => d.field === "header:pragma"),
    true,
  );
});

test("an entry's etagSuffix is removed from the tag, the rest is still compared by form", () => {
  const entry = {
    id: "KD-SUFFIX",
    rows: ["v01.x"],
    fields: [],
    etagSuffix: "-br",
    appliesTo: ["production-vs-local"],
  };
  const tagged = (value) =>
    row({}, { headers: [...answer().headers.filter(([n]) => n !== "ETag"), ["ETag", value]] });
  const hex = "a".repeat(64);
  const options = { known: { entries: [entry], kind: "production-vs-local" } };
  // the suffix of a Brotli answer: the form (quoted 64 hex) is what is compared
  const brotli = compareRows(tagged(`"${hex}-br"`), tagged(`"${hex}"`), options);
  assert.equal(brotli.status, "KNOWN_DIFFERENCE");
  assert.deepEqual(brotli.known, [{ field: "header:etag", entry: "KD-SUFFIX" }]);
  // without the entry, for another row, or for another comparison it is a mismatch
  assert.equal(compareRows(tagged(`"${hex}-br"`), tagged(`"${hex}"`)).status, "MISMATCH");
  const other = {
    known: { entries: [{ ...entry, rows: ["v01.z"] }], kind: "production-vs-local" },
  };
  assert.equal(compareRows(tagged(`"${hex}-br"`), tagged(`"${hex}"`), other).status, "MISMATCH");
  const runs = { known: { entries: [entry], kind: "run-vs-run" } };
  assert.equal(compareRows(tagged(`"${hex}-br"`), tagged(`"${hex}"`), runs).status, "MISMATCH");
  // only a tag that ends in the suffix inside the quotes is changed, and the form still counts
  assert.equal(compareRows(tagged(`"${hex}-gz"`), tagged(`"${hex}"`), options).status, "MISMATCH");
  assert.equal(
    compareRows(tagged(`"${hex}-br"`), tagged(`"${"b".repeat(64)}"`), options).status,
    "KNOWN_DIFFERENCE",
  );
  assert.equal(compareRows(tagged(`"${hex}"`), tagged(`"${hex}"`), options).status, "MATCH");
  // the suffix is removed from either side, and only at the end of the tag
  assert.equal(
    compareRows(tagged(`"${hex}"`), tagged(`"${hex}-br"`), options).status,
    "KNOWN_DIFFERENCE",
  );
  assert.equal(compareRows(tagged(`"${hex}-brx"`), tagged(`"${hex}"`), options).status, "MISMATCH");
  assert.equal(
    compareRows(tagged(`"${hex}-br-gz"`), tagged(`"${hex}"`), options).status,
    "MISMATCH",
  );
  // an entry with no etagSuffix changes no tag (a tag that happens to end in "undefined" stays)
  const plain = {
    known: { entries: [{ ...entry, etagSuffix: undefined }], kind: "production-vs-local" },
  };
  assert.equal(compareRows(tagged('"abcundefined"'), tagged('"abc"'), plain).status, "MISMATCH");
  // a short tag is a different form once the suffix is gone
  assert.equal(compareRows(tagged('"abc-br"'), tagged(`"${hex}"`), options).status, "MISMATCH");
});
