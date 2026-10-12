import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MAX_DIFFERENCE_MESSAGE_BYTES,
  boundedMessage,
  classifyDifference,
  createDescriptiveDifferences,
  selectDescriptiveMode,
} from "./pubsub-observation/descriptive.mjs";
import { descriptiveModeFor, options, replayA } from "./pubsub-observation/replay.mjs";
import { fixture } from "./pubsub-production-observation-compare.test.mjs";
import { PROJECT } from "./pubsub-observation/plan.mjs";

const pin = {
  profile: "release",
  rustcWrapper: "",
  path: "/fixture/release/fireemu",
  head: "a".repeat(40),
  sha256: "b".repeat(64),
  command: ["cargo", "build", "--release"],
};
const env = {
  PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
  FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
  FIREEMU_CONTROL_TOKEN: "synthetic-control",
};
const ok = { ok: true, status: 200, code: "OK", body: {}, bodyBytes: 2 };

// Deterministic generator for the hand-rolled properties (no new dependency).
function random(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}

// The unary fixture with `count` GetTopic dispatches in R3.
function unaryFixture(count) {
  const f = fixture("GetTopic", ok);
  const [start, dispatch, response, result] = f.rows;
  const topic = `projects/${PROJECT}/topics/fe${f.summary.runId}-r3-topic`;
  dispatch.request = { name: topic };
  dispatch.routeName = topic;
  const rows = [start];
  for (let i = 0; i < count; i++)
    rows.push(
      { ...structuredClone(dispatch), requestId: i + 1 },
      { ...structuredClone(response), requestId: i + 1 },
    );
  rows.push(result);
  f.rows = rows.map((row, index) =>
    Object.assign(row, { n: index + 1, at: new Date(1000 + index * 1000).toISOString() }),
  );
  return f;
}

function failingWire(failures, calls) {
  return () => ({
    close() {},
    call: async (request) => {
      calls.push(request.method);
      const failure = failures.get(calls.length);
      if (failure) throw failure;
      return { ...ok, body: {} };
    },
  });
}

test("descriptive mode is refused outside the emulator profile and for any other mode", () => {
  for (const profile of ["strict", undefined, "", "Emulator", "emulator "])
    assert.throws(
      () => createDescriptiveDifferences({ profile, mode: "descriptive" }),
      /requires the emulator profile/,
    );
  for (const mode of [undefined, "", "strict", "Descriptive", "descriptive "])
    assert.throws(
      () => createDescriptiveDifferences({ profile: "emulator", mode }),
      /descriptive replay mode required/,
    );
  assert.equal(
    createDescriptiveDifferences({ profile: "emulator", mode: "descriptive" }).mode,
    "descriptive",
  );
});

test("classification separates production-binding assertions, crashes and local runtime failures", () => {
  for (const message of [
    "native terminal witness mismatch",
    "native receive semantic mismatch",
    "native receive cardinality mismatch",
    "unproven live ACK correlation",
    "missing or conflicting ack binding",
    "missing or conflicting message binding",
    "own issued continuation unavailable",
    "missing supplemental dispatch",
    "native expected receive missing",
  ])
    assert.equal(classifyDifference(new Error(message)), "production-binding-assertion", message);
  // near misses of the listed assertions stay unclassified
  for (const message of [
    "native terminal witness mismatch!",
    "xnative receive semantic mismatch",
    "missing or conflicting Ack binding",
    "replay REST route refused",
    "foreign replay resource refused",
  ])
    assert.equal(classifyDifference(new Error(message)), "unclassified-harness-assertion", message);
  assert.equal(
    classifyDifference(new TypeError("native terminal witness mismatch")),
    "harness-crash",
  );
  assert.equal(classifyDifference(new RangeError("x")), "harness-crash");
  assert.equal(classifyDifference(new Error("fetch failed")), "local-runtime-failure");
  assert.equal(
    classifyDifference(new Error("local clock advance refused")),
    "local-runtime-failure",
  );
  assert.equal(
    classifyDifference("native terminal witness mismatch"),
    "production-binding-assertion",
  );
});

test("property: recorded messages are bounded, printable and keep short messages unchanged", () => {
  const next = random(7);
  const alphabet = ["a", "\u0000", "\n", "\u007f", "é", "\u{1f600}", "\ud800", " "];
  for (let i = 0; i < 400; i++) {
    const length = Math.floor(next() * 3000);
    let text = "";
    for (let j = 0; j < length; j++) text += alphabet[Math.floor(next() * alphabet.length)];
    const bounded = boundedMessage(text);
    assert.ok(Buffer.byteLength(bounded) <= MAX_DIFFERENCE_MESSAGE_BYTES);
    assert.equal(/[\u0000-\u001f\u007f]/.test(bounded), false);
    assert.equal(bounded.isWellFormed(), true);
    if (/^[a ]*$/.test(text) && text.length <= MAX_DIFFERENCE_MESSAGE_BYTES)
      assert.equal(bounded, text);
  }
});

test("attempt records a failure with its context and returns null on success", async () => {
  const d = createDescriptiveDifferences({ profile: "emulator", mode: "descriptive" });
  assert.equal(await d.attempt({ sourceN: 1, cellId: "R3" }, async () => {}), null);
  const first = await d.attempt(
    { sourceN: 2, cellId: "R3", sourceEvent: "request-dispatch", method: "Pull" },
    async () => {
      throw new Error("unproven live ACK correlation");
    },
    () => ({ local: { status: 200 } }),
  );
  assert.deepEqual(first, {
    ordinal: 1,
    sourceN: 2,
    sourceEvent: "request-dispatch",
    cellId: "R3",
    method: "Pull",
    errorName: "Error",
    message: "unproven live ACK correlation",
    classification: "production-binding-assertion",
    followsEarlierDifferenceInCell: false,
    evidence: { local: { status: 200 } },
  });
  const second = await d.attempt(
    { sourceN: 3, cellId: "R3" },
    () => {
      throw new TypeError("x is undefined");
    },
    () => {
      throw new Error("no local exchange");
    },
  );
  assert.equal(second.followsEarlierDifferenceInCell, true);
  assert.equal(second.evidenceUnavailable, "no local exchange");
  const other = await d.attempt({ sourceN: 4, cellId: "R4" }, () => {
    throw new Error("native terminal witness mismatch");
  });
  assert.equal(other.followsEarlierDifferenceInCell, false);
  const summary = d.summary();
  assert.equal(summary.gate, false);
  assert.equal(summary.differences, 3);
  assert.equal(summary.primaryDifferences, 2);
  assert.deepEqual(summary.byClassification, {
    "production-binding-assertion": 2,
    "harness-crash": 1,
  });
  assert.throws(() => d.record({ cellId: {} }, new Error("x")), /string, number or null/);
});

test("strict replay still stops at the first failing row with the unchanged message", async () => {
  for (const message of ["native terminal witness mismatch", "unproven live ACK correlation"]) {
    const calls = [];
    await assert.rejects(
      replayA(unaryFixture(3), env, pin, {
        advance: async () => {},
        wireFactory: failingWire(new Map([[2, new Error(message)]]), calls),
      }),
      (error) => error instanceof Error && error.message === message,
    );
    assert.deepEqual(calls, ["GetTopic", "GetTopic"]);
  }
});

test("descriptive replay records the failing row and replays every later row", async () => {
  const calls = [];
  const descriptive = createDescriptiveDifferences({ profile: "emulator", mode: "descriptive" });
  const report = await replayA(unaryFixture(3), env, pin, {
    advance: async () => {},
    wireFactory: failingWire(new Map([[2, new Error("native terminal witness mismatch")]]), calls),
    descriptive,
  });
  assert.deepEqual(calls, ["GetTopic", "GetTopic", "GetTopic"]);
  assert.equal(report.evidenceKind, "production-vs-emulator-descriptive-local");
  assert.equal(report.descriptive.gate, false);
  assert.equal(report.descriptive.differences, 1);
  const [entry] = report.descriptive.entries;
  assert.equal(entry.sourceN, 4);
  assert.equal(entry.cellId, "R3");
  assert.equal(entry.method, "GetTopic");
  assert.equal(entry.message, "native terminal witness mismatch");
  assert.equal(entry.classification, "production-binding-assertion");
  assert.deepEqual(entry.evidence.recorded, { ok: true, status: 200, code: "OK" });
  assert.equal(entry.evidence.local, null);
  const journaled = report.localRows.filter((row) => row.event === "descriptive-difference");
  assert.equal(journaled.length, 1);
  assert.equal(journaled[0].message, "native terminal witness mismatch");
});

test("property: strict and descriptive replays agree on everything but the recorded differences", async () => {
  const next = random(11);
  for (let i = 0; i < 40; i++) {
    const count = 1 + Math.floor(next() * 5);
    const failures = new Map();
    for (let call = 1; call <= count; call++)
      if (next() < 0.35)
        failures.set(
          call,
          new Error(
            next() < 0.5
              ? "native receive semantic mismatch"
              : "missing or conflicting ack binding",
          ),
        );
    const strictCalls = [];
    const strict = replayA(unaryFixture(count), env, pin, {
      advance: async () => {},
      wireFactory: failingWire(failures, strictCalls),
    });
    const descriptiveCalls = [];
    const descriptive = await replayA(unaryFixture(count), env, pin, {
      advance: async () => {},
      wireFactory: failingWire(failures, descriptiveCalls),
      descriptive: createDescriptiveDifferences({ profile: "emulator", mode: "descriptive" }),
    });
    assert.equal(descriptiveCalls.length, count);
    assert.deepEqual(
      descriptive.descriptive.entries.map((e) => [e.sourceN, e.message]),
      [...failures].map(([call, error]) => [2 * call, error.message]),
    );
    if (failures.size) {
      const first = Math.min(...failures.keys());
      await assert.rejects(strict, (error) => error.message === failures.get(first).message);
      assert.equal(strictCalls.length, first);
    } else {
      const report = await strict;
      assert.equal(Object.hasOwn(report, "descriptive"), false);
      assert.equal(report.evidenceKind, "fixture");
      const { descriptive: summary, evidenceKind, localRows, ...rest } = descriptive;
      const { evidenceKind: strictKind, localRows: strictRows, ...strictRest } = report;
      assert.equal(summary.differences, 0);
      const stable = (rows) => rows.map(({ at: _at, ...row }) => row);
      assert.deepEqual(stable(localRows), stable(strictRows));
      assert.deepEqual(JSON.parse(JSON.stringify(rest)), JSON.parse(JSON.stringify(strictRest)));
    }
  }
});

test("descriptive mode is selected only by an explicit flag and an emulator-profile launch config", () => {
  const directory = mkdtempSync(join(tmpdir(), "fireemu-descriptive-"));
  try {
    const write = (name, value) => {
      const path = join(directory, name);
      const bytes = Buffer.from(JSON.stringify(value));
      writeFileSync(path, bytes, { mode: 0o600 });
      return { config: path, configSha256: createHash("sha256").update(bytes).digest("hex") };
    };
    const emulator = write("emulator.json", { schemaVersion: 1, profile: "emulator" });
    const strict = write("strict.json", { schemaVersion: 1, profile: "strict" });
    assert.equal(descriptiveModeFor(undefined, strict), null);
    assert.equal(descriptiveModeFor(undefined, emulator), null);
    assert.equal(descriptiveModeFor("descriptive", emulator).mode, "descriptive");
    assert.throws(() => descriptiveModeFor("descriptive", strict), /requires the emulator profile/);
    assert.throws(() => descriptiveModeFor("strict", emulator), /replay mode refused/);
    assert.throws(() => descriptiveModeFor("", emulator), /replay mode refused/);
    assert.throws(
      () => descriptiveModeFor("descriptive", { ...emulator, configSha256: "0".repeat(64) }),
      /digest mismatch/,
    );
    assert.throws(() => descriptiveModeFor("descriptive", null), /launch config required/);
    const link = join(directory, "link.json");
    symlinkSync(emulator.config, link);
    assert.throws(
      () => descriptiveModeFor("descriptive", { ...emulator, config: link }),
      /pin required/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("replay options keep every pin required and accept only an optional mode", () => {
  const base = [
    "--input",
    "i",
    "--input-sha256",
    "s",
    "--build-pin",
    "b",
    "--build-pin-sha256",
    "p",
    "--out",
    "o",
  ];
  assert.deepEqual(options(base), {
    input: "i",
    "input-sha256": "s",
    "build-pin": "b",
    "build-pin-sha256": "p",
    out: "o",
  });
  assert.equal(options([...base, "--mode", "descriptive"]).mode, "descriptive");
  for (let i = 0; i < base.length; i += 2)
    assert.throws(
      () => options([...base.slice(0, i), ...base.slice(i + 2), "--mode", "descriptive"]),
      /replay input\/build pins and out required/,
    );
  assert.throws(() => options([...base, "--mode", "a", "--mode", "b"]), /unique/);
  assert.throws(() => options([...base, "--profile", "emulator"]), /unique/);
  assert.throws(() => options([...base, "--mode"]), /unique/);
});

test("mode selection reads the launch config only through the caller's pinned reader", () => {
  const reads = [];
  const reader = (body) => (path, digest) => {
    reads.push([path, digest]);
    return Buffer.from(body);
  };
  const launch = { config: "/c.json", configSha256: "d".repeat(64) };
  assert.equal(selectDescriptiveMode(undefined, launch, reader("{}")), null);
  assert.deepEqual(reads, []);
  assert.equal(
    selectDescriptiveMode("descriptive", launch, reader('{"profile":"emulator"}')).profile,
    "emulator",
  );
  assert.deepEqual(reads, [["/c.json", "d".repeat(64)]]);
  for (const body of ['{"profile":"strict"}', "{}", "null", '{"profile":["emulator"]}'])
    assert.throws(
      () => selectDescriptiveMode("descriptive", launch, reader(body)),
      /requires the emulator profile/,
    );
  for (const bad of [
    { config: "/c.json" },
    { configSha256: "d" },
    { config: 1, configSha256: "d" },
  ])
    assert.throws(
      () => selectDescriptiveMode("descriptive", bad, reader('{"profile":"emulator"}')),
      /launch config required/,
    );
});
