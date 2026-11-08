import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { digest, families, validate } from "./functions-python/compare.mjs";
const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const record = () => JSON.parse(read("spec/compatibility/closure/FUNCTIONS-PYTHON.json"));
const corpus = () => JSON.parse(read("conformance/functions-python/corpus.json"));
const bytes = () => read(corpus().fixturePath);
const secondBytes = () => read("conformance/functions-python/fixtures/observations-pass2.json");

test("Python parent inventories all eight recorded and unobserved families", () => {
  assert.equal(record().conditions.length, 8, "eight Python family obligations");
  validate(record(), corpus(), bytes(), secondBytes());
});
for (const [index, family] of families.entries()) {
  test(`${family}: its fixture is read and meaningful alterations fail`, () => {
    const fixture = JSON.parse(bytes());
    if (index < 6) fixture.observations[index].frames[0].kind = "corrupted-frame";
    else if (index === 6) fixture.observations[index].clientStatus = 200;
    else fixture.observations[index].localComparison = true;
    assert.throws(
      () => validate(record(), corpus(), JSON.stringify(fixture), secondBytes()),
      /fixture digest/,
    );
    const missing = record();
    missing.conditions.splice(index, 1);
    assert.throws(
      () => validate(missing, corpus(), bytes(), secondBytes()),
      /exact condition inventory/,
    );
  });
}
test("record refuses promotion, a fabricated pass, accepted differences and missing owner questions", () => {
  for (const mutate of [
    (r) => {
      r.parentStatus = "COMPAT_VERIFIED";
    },
    (r) => {
      r.conditions[0].status = "VERIFIED";
    },
    (r) => {
      r.recordingPolicy.observedPasses = 3;
    },
    (r) => {
      r.recordingPolicy.waiver = "assumed";
    },
    (r) => {
      r.scopeDecisions.pop();
    },
    (r) => {
      r.scopeDecisions[0].authority = "";
    },
    (r) => {
      r.declaredDifferences[0].status = "APPROVED";
    },
    (r) => {
      r.declaredDifferences[0].fields = ["*"];
    },
    (r) => {
      r.conditions[0].fixtureSha256 = "0".repeat(64);
    },
    (r) => {
      r.conditions[0].profiles.strict = "UNRESTRICTED";
    },
    (r) => {
      r.conditions[0].profiles.emulator = "PRODUCTION_CLAIM";
    },
  ]) {
    const r = record();
    mutate(r);
    assert.throws(() => validate(r, corpus(), bytes(), secondBytes()));
  }
});
test("correcting hashes cannot manufacture SDK success, extra frames or local deployment parity", () => {
  for (const mutate of [
    (f) => {
      f.observations[3].wholeSecondSdkFrames = 1;
    },
    (f) => {
      f.observations[6].sdkEventObserved = true;
    },
    (f) => {
      f.observations[6].clientStatus = 200;
    },
    (f) => {
      f.observations[7].localComparison = true;
    },
    (f) => {
      f.observations[0].frames.push(f.observations[0].frames[0]);
    },
    (f) => {
      f.observations[0].sdkCases = [];
    },
    (f) => {
      f.observations[0].frames[1].request.headers.authorization = "forbidden";
    },
  ]) {
    const f = JSON.parse(bytes());
    mutate(f);
    const text = JSON.stringify(f),
      r = record(),
      c = corpus();
    c.fixtureSha256 = digest(text);
    c.recordings[0].fixtureSha256 = digest(text);
    r.recordings[0].fixtureSha256 = digest(text);
    for (const condition of r.conditions) condition.fixtureSha256 = digest(text);
    assert.throws(() => validate(r, c, text, secondBytes()));
  }
});

// An owner can replace one decision entry without promoting any evidence or the parent.
test("a recorded owner answer changes one decision entry and cannot waive the pass policy", () => {
  for (let i = 0; i < 3; i += 1) {
    const r = record();
    r.scopeDecisions[i] = {
      ...r.scopeDecisions[i],
      status: "ANSWERED",
      answer: "fixture answer",
      authority: "synthetic test authority",
    };
    validate(r, corpus(), bytes(), secondBytes());
    assert.equal(r.parentStatus, "IMPLEMENTING");
    assert.equal(r.recordingPolicy.waiver, null);
  }
});

test("deleting or widening a declared replay difference is rejected", () => {
  for (const mutate of [
    (r) => {
      r.declaredDifferences = r.declaredDifferences.filter(
        (d) => d.id !== "emulator-scheduler-offset",
      );
    },
    (r) => {
      r.declaredDifferences[0].fields.push("request.method");
    },
  ]) {
    const r = record();
    mutate(r);
    assert.throws(() => validate(r, corpus(), bytes(), secondBytes()), /difference inventory/);
  }
});

test("the three owner answers retain recorded strict scope, unresolved differences and blocking OPEN", () => {
  const r = record();
  assert.deepEqual(
    r.scopeDecisions.map((d) => d.status),
    ["ANSWERED", "ANSWERED", "ANSWERED"],
  );
  assert.deepEqual(
    r.scopeDecisions.map((d) => d.answer),
    ["recorded-strict-only", "declare-compared-differences-keep-unverified", "keep-blocking-open"],
  );
  assert.equal(r.parentStatus, "IMPLEMENTING");
  assert.deepEqual(r.recordingPolicy, { observedPasses: 2, requiredPasses: 2, waiver: null });
  assert.equal(r.conditions.find((c) => c.conditionId.endsWith("/auth-blocking")).status, "OPEN");
});

test("two independent recordings retain partial Tasks coverage and corrected accounting", () => {
  const r = record(),
    c = corpus();
  assert.equal(r.recordingPolicy.observedPasses, 2);
  const secondBytes = read("conformance/functions-python/fixtures/observations-pass2.json");
  validate(r, c, bytes(), secondBytes);
  assert.deepEqual(
    c.recordings.map((p) => p.alias),
    ["pass-1", "pass-2"],
  );
  assert.deepEqual(JSON.parse(bytes()).recording.accounting, {
    recorderRequests: 160,
    cliWriteRows: 28,
    cliWriteAttempts: 44,
    accountedRequests: 204,
  });
  assert.deepEqual(JSON.parse(secondBytes).recording.accounting, {
    recorderRequests: 172,
    cliWriteRows: 26,
    cliWriteAttempts: 42,
    accountedRequests: 214,
  });
  assert.deepEqual(
    r.conditions.slice(0, 6).map((x) => x.observedPasses),
    [2, 2, 2, 2, 2, 1],
  );
  const tasks = JSON.parse(secondBytes).observations.find((x) => x.condition === "tasks-events");
  assert.equal(tasks.coverage, "UNOBSERVED");
  assert.deepEqual(tasks.sdkCases, []);
});

test("second recording counters, inventory and family claims cannot be fabricated by rehashing", () => {
  for (const alter of [
    (f) => {
      f.recording.accounting.cliWriteAttempts = 26;
    },
    (f) => {
      f.recording.alias = "pass-1";
    },
    (f) => {
      f.recording.eventFrames = 16;
    },
    (f) => {
      f.observations[5].coverage = "RECORDED";
    },
    (f) => {
      f.observations[5].sdkCases = [f.observations[0].sdkCases[0]];
    },
    (f) => {
      f.observations[0].frames.pop();
    },
    (f) => {
      f.observations[0].sdkCases = [];
    },
    (f) => {
      f.observations[3].wholeSecondSdkFrames = 1;
    },
    (f) => {
      f.observations[0].frames.find((x) => x.request).request.headers.authorization = "forbidden";
    },
  ]) {
    const f = JSON.parse(secondBytes()),
      c = corpus();
    alter(f);
    const text = JSON.stringify(f);
    c.recordings[1].fixtureSha256 = digest(text);
    const r = record();
    r.recordings[1].fixtureSha256 = digest(text);
    assert.throws(() => validate(r, c, bytes(), text));
  }
  for (const alter of [
    (r, c) => {
      c.recordings[1].alias = "pass-1";
    },
    (r, c) => {
      c.recordings[1].fixturePath = c.recordings[0].fixturePath;
    },
    (r) => {
      r.conditions[5].observedPasses = 2;
    },
    (r) => {
      r.conditions[0].recordingAliases = ["pass-1", "pass-1"];
    },
  ]) {
    const r = record(),
      c = corpus();
    alter(r, c);
    assert.throws(() => validate(r, c, bytes(), secondBytes()));
  }
  assert.throws(() => validate(record(), corpus(), bytes()), /fixture required/);
});

test("a one-recording inventory remains valid without inventing its second pass", () => {
  const r = record(),
    c = corpus();
  r.recordingPolicy.observedPasses = 1;
  c.recordings.pop();
  r.recordings.pop();
  for (const row of r.conditions.slice(0, 6)) {
    row.observedPasses = 1;
    row.recordingAliases = ["pass-1"];
  }
  validate(r, c, bytes());
});
