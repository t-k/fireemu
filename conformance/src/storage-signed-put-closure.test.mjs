import "./storage-signed-put/test-preload.mjs";

// Closure of the signed XML PUT observation: the normalization of the two values that differ
// between recordings of the same production answer, and the replay of the recorded answers.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

import { buildFixture, main, rawAnswers } from "./storage-signed-put/fixture.mjs";
import {
  compareRecordings,
  compareTargets,
  judgePut,
  normalizeBody,
  parseXmlError,
} from "./storage-signed-put/judge.mjs";
import { observe } from "./storage-signed-put/observe.mjs";
import { CASES } from "./storage-signed-put/plan.mjs";
import {
  IAM_CONFIG,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const load = (name) => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));

const digest = "7b9e0ce0c9b928551e3474cbab036cc2cd724aeaa8d45166ef240685e91640a7";

describe("normalizeBody masks what a production error derives from the request time", () => {
  it("masks the StringToSign digest, which hashes the canonical request including the date", () => {
    const body = `<Error><StringToSign>GOOG4-RSA-SHA256\n20261103T153459Z\n20261103/auto/storage/goog4_request\n${digest}</StringToSign></Error>`;
    const out = normalizeBody(body, []);
    assert.ok(!out.includes(digest));
    assert.match(out, /goog4_request\n<string-to-sign-digest><\/StringToSign>/);
    assert.match(out, /<date>/);
  });

  it("masks only a 64 hex digit digest at the end of StringToSign, nothing else that looks like one", () => {
    const other = `<Error><Details>${digest}</Details><StringToSign>a\nb\nc\nnot-a-digest</StringToSign><X>${digest}</X></Error>`;
    const out = normalizeBody(other, []);
    assert.equal(out.split(digest).length - 1, 2, "the digests outside StringToSign stay");
    assert.ok(out.includes("not-a-digest</StringToSign>"));
    const short = normalizeBody(`<StringToSign>x\n${digest.slice(1)}</StringToSign>`, []);
    assert.ok(short.includes(digest.slice(1)), "63 digits is not a digest");
    const upper = normalizeBody(`<StringToSign>x\n${digest.toUpperCase()}</StringToSign>`, []);
    assert.ok(upper.includes(digest.toUpperCase()), "the digest is lower case hex");
  });

  it("masks the expiry time an ExpiredToken names", () => {
    const body =
      "<Error><Code>ExpiredToken</Code><Details>The provided token has expired. Request signature expired at: 2026-11-03T15:35:12+00:00</Details></Error>";
    const out = normalizeBody(body, []);
    assert.ok(out.includes("expired at: <time></Details>"));
    assert.equal(
      normalizeBody("at 2026-11-03T15:35:12Z", []),
      "at 2026-11-03T15:35:12Z",
      "only the +00:00 form is masked",
    );
  });
});

// What production answered, as recorded on 2026-11-03 (conformance/storage-signed-put-production.json).
const RECORDED = {
  ok: [200, null],
  "ok-origin": [200, null],
  "wrong-content-type": [403, "SignatureDoesNotMatch"],
  "missing-content-type": [400, "MalformedSecurityHeader"],
  "over-range": [400, "EntityTooLarge"],
  "under-range": [400, "EntityTooSmall"],
  "range-min-ok": [200, null],
  "range-max-ok": [200, null],
  "range-header-missing": [400, "MalformedSecurityHeader"],
  "range-header-mismatch": [403, "SignatureDoesNotMatch"],
  "range-header-unsigned": [400, "MalformedSecurityHeader"],
  "no-range": [200, null],
  "tampered-signature": [403, "SignatureDoesNotMatch"],
  "signature-missing": [400, "MissingSecurityHeader"],
  expired: [400, "ExpiredToken"],
  "other-object": [403, "SignatureDoesNotMatch"],
};
// The cases fireemu answers differently, because it has no key to check a signature with.
const SIGNATURE_CASES = [
  "wrong-content-type",
  "range-header-mismatch",
  "tampered-signature",
  "other-object",
];

describe("the recorded production answers replay through the judges", () => {
  const production = load("storage-signed-put-production.json");

  it("holds both recordings of every case, with the recorded status and error code", () => {
    assert.equal(production.rows.length, 32);
    for (const row of production.rows) {
      const [status, code] = RECORDED[row.id];
      assert.deepEqual([row.status, row.code], [status, code], `${row.recording}:${row.id}`);
      assert.equal(row.shape, code ? "xml-error" : "empty");
    }
    assert.deepEqual(
      production.rows
        .map((r) => r.id)
        .filter((id, i, all) => all.indexOf(id) === i)
        .toSorted(),
      CASES.map((c) => c.id).toSorted(),
    );
  });

  it("parses each recorded body to the code the row names, and keeps its exact length", () => {
    for (const row of production.rows.filter((r) => r.shape === "xml-error")) {
      assert.equal(parseXmlError(Buffer.from(row.body))?.Code, row.code, row.id);
    }
    // A body with nothing masked in it is the exact bytes: its digest is the recorded one.
    for (const id of [
      "missing-content-type",
      "over-range",
      "under-range",
      "range-header-missing",
      "range-header-unsigned",
      "signature-missing",
    ]) {
      const row = production.rows.find((r) => r.id === id && r.recording === 1);
      assert.equal(Buffer.byteLength(row.body), row.bodyBytes, id);
      assert.equal(createHash("sha256").update(row.body).digest("hex"), row.bodySha256, id);
    }
  });

  it("judges a recorded answer the way the recorder did", () => {
    for (const row of production.rows) {
      const testCase = CASES.find((c) => c.id === row.id);
      const verdict = judgePut(testCase, { status: row.status, body: Buffer.from(row.body) });
      assert.equal(verdict.class, row.class, row.id);
      assert.equal(verdict.code, row.code, row.id);
      assert.equal(verdict.shape, row.shape, row.id);
      assert.equal(verdict.stopRun, false);
    }
  });

  it("differs between the two recordings only in the digest of five signature or time derived bodies", () => {
    const differences = compareRecordings(production.rows);
    assert.deepEqual(differences.map((d) => d.id).toSorted(), [
      "expired",
      "other-object",
      "range-header-mismatch",
      "tampered-signature",
      "wrong-content-type",
    ]);
    assert.ok(
      differences.every((d) => d.digestOnly && d.fields.join() === "bodySha256"),
      JSON.stringify(differences),
    );
  });

  it("carries no project, bucket, signer, run id or credential", () => {
    const text = readFileSync(
      new URL("../storage-signed-put-production.json", import.meta.url),
      "utf8",
    );
    for (const pattern of [
      /fireemu-oracle/,
      /iam\.gserviceaccount/,
      /@[a-z0-9-]+\./,
      /sp-[0-9a-f]{8}/,
      /\bAIza/,
      /X-Goog-Signature=[0-9a-f]/,
      /\b\d{12}\b/,
    ]) {
      assert.ok(!pattern.test(text), String(pattern));
    }
    assert.match(text, /<bucket>/);
  });
});

describe("fireemu against the recorded production answers", () => {
  const production = load("storage-signed-put-production.json");
  const fireemu = load("storage-signed-put-fireemu.json");
  const rows = compareTargets(production.rows, fireemu.rows);

  it("matches the normalized answer of every case except the four that need a signature check", () => {
    assert.equal(rows.length, 16);
    assert.deepEqual(
      rows
        .filter((r) => !r.match)
        .map((r) => r.id)
        .toSorted(),
      SIGNATURE_CASES.toSorted(),
    );
    for (const id of SIGNATURE_CASES) {
      const row = rows.find((r) => r.id === id);
      assert.deepEqual(row.fields, ["status", "code", "shape", "bodyBytes", "body"], id);
      const local = fireemu.rows.find((r) => r.recording === 1 && r.id === id);
      assert.deepEqual(
        [local.status, local.shape],
        [200, "empty"],
        `${id}: accepted, signature not verified`,
      );
    }
  });

  it("is byte for byte the production body wherever the body has nothing time derived in it", () => {
    for (const id of [
      "ok",
      "ok-origin",
      "range-min-ok",
      "range-max-ok",
      "no-range",
      "missing-content-type",
      "over-range",
      "under-range",
      "range-header-missing",
      "range-header-unsigned",
      "signature-missing",
    ]) {
      assert.equal(rows.find((r) => r.id === id).exact, true, id);
    }
    // The expiry time the body names is the time of the signing, so only the digest differs.
    const expired = rows.find((r) => r.id === "expired");
    assert.deepEqual(
      [expired.match, expired.exact, expired.exactFields],
      [true, false, ["bodySha256"]],
    );
  });

  it("answers each case the same in both of its own recordings, the expiry time of an expired URL apart", () => {
    // The body of an ExpiredToken names the end of the signed lifetime, which differs per signing.
    assert.deepEqual(compareRecordings(fireemu.rows), [
      { id: "expired", fields: ["bodySha256"], digestOnly: true },
    ]);
  });
});

describe("the fixture builder", () => {
  it("builds the rows of a run from its journal, pairing each PUT with its answer", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    const out = memoryOut();
    await observe({
      target: PRODUCTION_LIKE,
      runId: "sp-0123abcd",
      deps: world.deps,
      out,
      iam: IAM_CONFIG,
    });
    const journalText = out.entries.map((e) => JSON.stringify(e)).join("\n");
    const answers = rawAnswers(journalText);
    assert.equal(answers.size, 32);
    assert.equal(answers.get("1:ok").status, 200);
    assert.equal(answers.get("2:wrong-content-type").status, 403);
    const fixture = buildFixture({
      header: { runId: "sp-0123abcd", target: PRODUCTION_LIKE },
      journalText,
      source: { observed: "test" },
    });
    assert.equal(fixture.rows.length, 32);
    const row = fixture.rows.find((r) => r.recording === 1 && r.id === "wrong-content-type");
    assert.deepEqual(
      [row.status, row.code, row.shape],
      [403, "SignatureDoesNotMatch", "xml-error"],
    );
    assert.equal(row.bodyBytes, answers.get("1:wrong-content-type").body.length);
    assert.equal(JSON.stringify(fixture).includes("sp-0123abcd"), false);
    assert.equal(JSON.stringify(fixture).includes(PRODUCTION_LIKE.signer), false);
    assert.throws(
      () =>
        buildFixture({
          header: { runId: "x", target: PRODUCTION_LIKE },
          journalText: "",
          source: {},
        }),
      /no answer for 1:ok/,
    );
  });
});

describe("the fixture builder's command line", () => {
  const runDirectory = async (kind) => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    const out = memoryOut();
    await observe({
      target: PRODUCTION_LIKE,
      runId: "sp-0123abcd",
      deps: world.deps,
      out,
      iam: IAM_CONFIG,
    });
    const dir = mkdtempSync(join(tmpdir(), "spfixture-"));
    writeFileSync(
      join(dir, "journal.jsonl"),
      `${out.entries.map((e) => JSON.stringify(e)).join("\n")}\n`,
    );
    if (kind === "production") {
      writeFileSync(
        join(dir, "run-header.json"),
        JSON.stringify({ runId: "sp-0123abcd", target: PRODUCTION_LIKE }),
      );
    } else {
      writeFileSync(join(dir, "run-report.json"), JSON.stringify({ runId: "sp-0123abcd" }));
    }
    return dir;
  };

  it("writes a production run with its source note and refuses to overwrite a file", async () => {
    const dir = await runDirectory("production");
    try {
      const target = join(dir, "fixture.json");
      const fixture = main(["--run-dir", dir, "--out", target]);
      const written = JSON.parse(readFileSync(target, "utf8"));
      assert.deepEqual(written, fixture);
      assert.equal(readFileSync(target, "utf8"), `${JSON.stringify(fixture, null, 2)}\n`);
      assert.equal(written.rows.length, 32);
      assert.equal(written.source.observed, "2026-11-03");
      assert.deepEqual([written.source.recordings, written.source.cases], [2, 16]);
      assert.equal(
        written.source["firebase-admin"] ?? written.source.sdk["firebase-admin"],
        "14.3.0",
      );
      assert.match(written.source.target, /^production/);
      assert.throws(() => main(["--run-dir", dir, "--out", target]), /EEXIST/);
      assert.deepEqual(JSON.parse(readFileSync(target, "utf8")), written, "the file is untouched");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes a local run with the demo target masked and its own source note", async () => {
    const dir = await runDirectory("local");
    try {
      const target = join(dir, "fixture.json");
      const fixture = main(["--run-dir", dir, "--out", target, "--local"]);
      assert.equal(fixture.rows.length, 32);
      assert.match(fixture.source.target, /^fireemu/);
      assert.equal(fixture.source.sdk, undefined);
      assert.deepEqual([fixture.source.recordings, fixture.source.cases], [2, 16]);
      assert.match(fixture.source.observed, /^\d{4}-\d{2}-\d{2}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names its usage when an argument is missing, and writes nothing", () => {
    for (const argv of [
      [],
      ["--run-dir", "x"],
      ["--out", "y"],
      ["--run-dir", "x", "--out"],
      ["--run-dir", "--out", "y"],
    ]) {
      assert.throws(() => main(argv), /usage: fixture.mjs/, argv.join(" "));
    }
  });

  it("runs as a script only when it is the entry point, not when imported", async () => {
    const dir = await runDirectory("production");
    try {
      const script = new URL("./storage-signed-put/fixture.mjs", import.meta.url).pathname;
      const target = join(dir, "script.json");
      const ran = spawnSync(process.execPath, [script, "--run-dir", dir, "--out", target], {
        encoding: "utf8",
      });
      assert.equal(ran.status, 0, ran.stderr);
      assert.equal(JSON.parse(readFileSync(target, "utf8")).rows.length, 32);
      const imported = join(dir, "imported.json");
      const loaded = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `import ${JSON.stringify(script)};`,
          "--",
          "--run-dir",
          dir,
          "--out",
          imported,
        ],
        { encoding: "utf8" },
      );
      assert.equal(loaded.status, 0, loaded.stderr);
      assert.equal(existsSync(imported), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
