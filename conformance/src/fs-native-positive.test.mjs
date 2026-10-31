// Synthetic local sessions exercise the comparator; they are not production observations.
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  programs,
  producerInputs,
  compareReplays,
  exportEvidence,
  POLICY,
} from "./fs-ent-pipeline/native-positive.mjs";
import { toGrpcMessage } from "./fs-ent-pipeline/harness.mjs";
const fixture = JSON.parse(
  readFileSync(new URL("../fixtures/fs-native-positive/production.json", import.meta.url)),
);
const recorded = Object.values(fixture.programs)[0];
const sourceCommit = "a".repeat(40),
  binarySha256 = "b".repeat(64),
  namespace = "projects/demo-local/databases/entpipe1";
const canonical = "projects/demo-fs-query-index/databases/(default)";
const clone = (x) => structuredClone(x);
const map = (x, from, to) =>
  Array.isArray(x)
    ? x.map((y) => map(y, from, to))
    : x && typeof x === "object"
      ? Object.fromEntries(Object.entries(x).map(([k, v]) => [k, map(v, from, to)]))
      : typeof x === "string" && (x === from || x.startsWith(from + "/"))
        ? to + x.slice(from.length)
        : x;
function proto(value, parentKey = "") {
  if (Buffer.isBuffer(value)) return value;
  if (Array.isArray(value)) return value.map((x) => proto(x, parentKey));
  if (value && typeof value === "object") {
    const out = Object.fromEntries(Object.entries(value).map(([k, v]) => [k, proto(v, k)]));
    const key = Object.keys(out).find((k) =>
      [
        "nullValue",
        "booleanValue",
        "integerValue",
        "doubleValue",
        "stringValue",
        "bytesValue",
        "referenceValue",
        "arrayValue",
        "mapValue",
        "geoPointValue",
        "timestampValue",
        "vectorValue",
      ].includes(k),
    );
    if (key && !["fields", "aggregateFields"].includes(parentKey)) out.valueType = key;
    return out;
  }
  return value;
}
export function sessions() {
  const out = [];
  for (const profile of ["strict", "emulator"])
    for (const transport of ["grpc", "rest"])
      for (const round of [1, 2]) {
        const program = programs(transport)[0],
          raw = {};
        for (const step of program.steps) {
          const saved = clone(
            (round === 2 ? recorded.second?.[step.id] : undefined) ?? recorded.steps[step.id],
          );
          const messages = map(saved.messages, canonical, namespace);
          for (const m of messages) m.executionTime = "2030-01-02T03:04:05.123456789Z";
          if (step.id === "autogen-document-id")
            messages[0].results[0].fields.value.stringValue =
              round === 1 ? "A".repeat(20) : "B".repeat(20);
          const request = map(step.body, "{db}", namespace);
          raw[step.id] = {
            transport,
            request,
            response:
              transport === "grpc"
                ? {
                    code: 0,
                    messages: proto(toGrpcMessage(messages)),
                    details: "OK",
                    errorDetails: [],
                  }
                : { status: 200, text: JSON.stringify(messages) },
          };
        }
        out.push({
          profile,
          transport,
          round,
          namespace,
          invocation: {
            ...producerInputs(transport, profile),
            namespace,
            origin: "http://127.0.0.1:12345",
            sourceCommit,
            binarySha256,
          },
          sourceCommit,
          binarySha256,
          replay: { results: { [program.id]: { raw } }, failures: [] },
        });
      }
  return out;
}
function change(run, id, fn) {
  const r = run.replay.results[programs(run.transport)[0].id].raw[id].response;
  if (run.transport === "rest") {
    const m = JSON.parse(r.text);
    fn(m);
    r.text = JSON.stringify(m);
  } else fn(r.messages);
}
test("all 37 typed obligations are compared in both rounds of all eight sessions with metadata retained", () => {
  const runs = sessions(),
    out = compareReplays(runs, { sourceCommit, binarySha256 });
  assert.equal(out.kind, "fs-ent-pipeline-native-positive-observation-v1");
  assert.equal(out.contract, "FINITE_VALUE_AND_SHAPE_ONLY");
  assert.equal(out.proofs.length, 216);
  assert.equal(out.typedFieldComparisons, 296);
  assert.equal(out.localMetadata.length, 216);
  assert.equal(out.productionMetadata.length, 54);
  assert.equal(out.localMetadata[0].messages[0].executionTime, "2030-01-02T03:04:05.123456789Z");
  assert.equal(out.policy.absoluteTimeEquality, false);
  assert.deepEqual(out.policy, POLICY);
  const before = JSON.stringify(runs);
  compareReplays(runs, { sourceCommit, binarySha256 });
  assert.equal(JSON.stringify(runs), before);
});
test("every status, result count, full field set, value type, explicit null and metadata boundary is enforced", () => {
  for (const transport of ["grpc", "rest"])
    for (const fault of [
      "status",
      "results",
      "extra",
      "missing",
      "type",
      "null",
      "metadata",
      "metadata-extra",
      "invalid-time",
    ]) {
      const runs = sessions(),
        r = runs.find((x) => x.transport === transport);
      const id = fault === "null" ? "numeric-null-absent" : "numeric-finite-mixed";
      if (fault === "status") {
        const q = r.replay.results[programs(transport)[0].id].raw[id].response;
        if (transport === "grpc") q.code = 13;
        else q.status = 500;
      } else
        change(r, id, (m) => {
          if (fault === "results") m[0].results.push(clone(m[0].results[0]));
          else if (fault === "metadata") delete m[0].executionTime;
          else if (fault === "metadata-extra") m[0].unexpected = 1;
          else if (fault === "invalid-time") m[0].executionTime = "2030-99-99T03:04:05Z";
          else {
            const f = m[0].results[0].fields;
            if (fault === "extra") f.unexpected = { integerValue: "1" };
            if (fault === "missing") delete f.min_array_double;
            if (fault === "type") f.min_array_double = { integerValue: "2" };
            if (fault === "null") delete f.sum_empty;
          }
        });
      assert.throws(
        () => compareReplays(runs, { sourceCommit, binarySha256 }),
        undefined,
        transport + "/" + fault,
      );
    }
});
test("autogen requires twenty ASCII alphanumeric characters and different values in both rounds", () => {
  for (const value of ["x", "_".repeat(20), "Ａ".repeat(20), "A".repeat(20)]) {
    const runs = sessions(),
      r = runs.find((x) => x.profile === "strict" && x.transport === "grpc" && x.round === 2);
    change(r, "autogen-document-id", (m) => {
      m[0].results[0].fields.value.stringValue = value;
    });
    assert.throws(() => compareReplays(runs, { sourceCommit, binarySha256 }));
  }
});
test("canonical prefixes are exact and boundary checked; request shape is bound to the captured program", () => {
  for (const fault of ["prefix", "embedded", "request", "result-extra"]) {
    const runs = sessions(),
      r = runs[0];
    if (fault === "request")
      r.replay.results[programs("grpc")[0].id].raw[
        "cmp-int"
      ].request.structuredPipeline.pipeline.stages[0].name = "limit";
    else
      change(r, "replace-document-id", (m) => {
        if (fault === "result-extra") m[0].results[0].unexpected = "x";
        else {
          const x = m[0].results[0].fields.value.referenceValue;
          m[0].results[0].fields.value.referenceValue =
            fault === "prefix" ? x.replace("/entpipe1/", "/entpipe10/") : "embedded:" + x;
        }
      });
    assert.throws(() => compareReplays(runs, { sourceCommit, binarySha256 }));
  }
});
test("eight unique sessions and a single source and binary are mandatory", () => {
  for (const fault of ["missing", "duplicate", "binary", "source", "failures", "raw-extra"]) {
    const runs = sessions();
    if (fault === "missing") runs.pop();
    if (fault === "duplicate") runs[7] = clone(runs[0]);
    if (fault === "binary") runs[0].binarySha256 = "c".repeat(64);
    if (fault === "source") runs[0].sourceCommit = "d".repeat(40);
    if (fault === "failures") runs[0].replay.failures.push("failure");
    if (fault === "raw-extra") runs[0].replay.results[programs("grpc")[0].id].raw.extra = {};
    assert.throws(() => compareReplays(runs, { sourceCommit, binarySha256 }));
  }
});
test("pure export hashes the installed binary, every raw session, fixture and policy without claiming full parity", async () => {
  const d = mkdtempSync(join(tmpdir(), "native-positive-"));
  try {
    const binary = join(d, "binary");
    writeFileSync(binary, "synthetic test binary only");
    const hash = createHash("sha256").update(readFileSync(binary)).digest("hex"),
      runs = sessions();
    const manifest = {
      sourceCommit,
      binarySha256: hash,
      runs: runs.map((r, i) => {
        const path = join(d, "session-" + i + ".json");
        writeFileSync(path, JSON.stringify(r.replay));
        const invocationPath = join(d, "invocation-" + i + ".json");
        writeFileSync(invocationPath, JSON.stringify({ ...r.invocation, binarySha256: hash }));
        return {
          ...r,
          binarySha256: hash,
          invocation: { ...r.invocation, binarySha256: hash },
          replay: undefined,
          path,
          invocationPath,
          invocationSha256: createHash("sha256").update(readFileSync(invocationPath)).digest("hex"),
          sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
        };
      }),
    };
    const path = join(d, "manifest.json"),
      out = join(d, "out.json");
    writeFileSync(path, JSON.stringify(manifest));
    const evidence = await exportEvidence({ binary, manifest: path, out });
    assert.equal(evidence.binarySha256, hash);
    assert.equal(evidence.localReplaySha256.length, 8);
    assert.match(evidence.fixtureSha256, /^[a-f0-9]{64}$/);
    assert.match(evidence.policySha256, /^[a-f0-9]{64}$/);
    assert.equal(evidence.decision, "ACCEPTED_FINITE_VALUE_AND_SHAPE_CONTRACT");
    assert.equal(evidence.parentClosureClaimed, false);
    assert.deepEqual(JSON.parse(readFileSync(out)), evidence);
    manifest.runs[0].sha256 = "0".repeat(64);
    writeFileSync(path, JSON.stringify(manifest));
    await assert.rejects(exportEvidence({ binary, manifest: path, out: join(d, "bad.json") }));
    manifest.runs[0].sha256 = createHash("sha256")
      .update(readFileSync(manifest.runs[0].path))
      .digest("hex");
    manifest.runs[0].invocationSha256 = "0".repeat(64);
    writeFileSync(path, JSON.stringify(manifest));
    await assert.rejects(
      exportEvidence({ binary, manifest: path, out: join(d, "bad-producer.json") }),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
test("every PICT row drives its selected profile and transport through the real comparator", () => {
  const lines = readFileSync(
    new URL("../fixtures/fs-native-positive/native-positive.tsv", import.meta.url),
    "utf8",
  )
    .trim()
    .split(/\r?\n/)
    .slice(1);
  for (const line of lines) {
    const [transport, profile, fault] = line.split("\t"),
      runs = sessions(),
      r = runs.find((x) => x.transport === transport && x.profile === profile);
    if (fault === "none")
      assert.doesNotThrow(() => compareReplays(runs, { sourceCommit, binarySha256 }));
    else {
      if (fault === "status") {
        const q = r.replay.results[programs(transport)[0].id].raw["numeric-finite-mixed"].response;
        if (transport === "grpc") q.code = 3;
        else q.status = 400;
      } else
        change(r, fault === "autogen" ? "autogen-document-id" : "numeric-finite-mixed", (m) => {
          const f = m[0].results[0].fields;
          if (fault === "type") f.min_array_double = { integerValue: "2" };
          if (fault === "missing") delete f.min_array_double;
          if (fault === "extra") f.extra = { nullValue: null };
          if (fault === "result") m[0].results = [];
          if (fault === "reference")
            f.min_array_double = { referenceValue: namespace + "0/documents/x" };
          if (fault === "metadata") delete m[0].executionTime;
          if (fault === "autogen") f.value.stringValue = "invalid";
        });
      assert.throws(() => compareReplays(runs, { sourceCommit, binarySha256 }), undefined, line);
    }
  }
});

test("producer receipts bind the namespace, loopback target, seed, config and unchanged existing driver", () => {
  for (const fault of [
    "namespace",
    "seedSha256",
    "configSha256",
    "inputSha256",
    "harnessSha256",
    "sessionSha256",
    "origin",
  ]) {
    const runs = sessions();
    if (fault === "namespace") runs[0].namespace = "projects/demo-other/databases/wrong";
    else if (fault === "origin") runs[0].invocation.origin = "https://example.com";
    else runs[0].invocation[fault] = "0".repeat(64);
    assert.throws(() => compareReplays(runs, { sourceCommit, binarySha256 }), undefined, fault);
  }
});

// The manifest is a set of identified sessions: its enumeration order has no contract meaning.
test("generated manifest permutations preserve the complete finite verdict", () => {
  const original = sessions();
  const before = JSON.stringify(original);
  const canonicalVerdict = (value) => {
    const key = (row) => [row.profile, row.transport, row.round, row.id].join("/");
    const order = (rows) => [...rows].sort((a, b) => key(a).localeCompare(key(b)));
    return {
      ...value,
      proofs: order(value.proofs),
      localMetadata: order(value.localMetadata),
    };
  };
  const expected = canonicalVerdict(compareReplays(original, { sourceCommit, binarySha256 }));
  const seen = new Set();
  for (let seed = 1; seed <= 16; seed++) {
    let state = seed;
    const permutation = original.map((_, index) => index);
    for (let end = permutation.length - 1; end > 0; end--) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const index = state % (end + 1);
      [permutation[end], permutation[index]] = [permutation[index], permutation[end]];
    }
    seen.add(permutation.join(","));
    const shuffled = permutation.map((index) => original[index]);
    assert.doesNotThrow(
      () => {
        assert.deepEqual(
          canonicalVerdict(compareReplays(shuffled, { sourceCommit, binarySha256 })),
          expected,
        );
      },
      `manifest permutation seed=${seed} order=${permutation.join(",")}`,
    );
  }
  assert.equal(seen.size, 16, "all fixed generator seeds exercise distinct permutations");
  assert.equal(JSON.stringify(original), before, "the generator and comparison preserve inputs");
});
