import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const script = readFileSync(new URL("./run-w1.sh", import.meta.url), "utf8");
const source = script.split("// W1 verdict\n")[1].split("// W1 orchestration\n")[0];
const { calendarVerdict } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

test("calendar comparison matches an observed refusal only when the artifact refuses", () => {
  assert.deepEqual(calendarVerdict("cr08", "refused", [{ accepted: false, reason: "schedule: bounds" }]), {
    status: "MATCH", reason: "Both production and local refuse the declaration: schedule: bounds",
  });
  assert.equal(calendarVerdict("cr08", "refused", [{ accepted: true }]).status, "DIVERGES");
});

test("calendar comparison reports a local refusal of a production accepted declaration", () => {
  assert.deepEqual(calendarVerdict("gr08", "accepted", [{ accepted: false, reason: "schedule: unsupported" }]), {
    status: "DIVERGES", reason: "Production accepts; local refuses: schedule: unsupported",
  });
});

test("calendar comparison preserves the callback judge reason when both anchors diverge", () => {
  const local = [{ accepted: true, callback: { matched: false, reason: "callback ran before advertised boundary" } }];
  assert.deepEqual(calendarVerdict("gr12", "accepted", local), {
    status: "DIVERGES", reason: "callback ran before advertised boundary",
  });
});

test("calendar comparison accepts a matching creation anchor without erasing other evidence", () => {
  const local = [
    { accepted: true, callback: { matched: false, reason: "callback count or supplied time differs" } },
    { accepted: true, callback: { matched: true, reason: null } },
  ];
  assert.equal(calendarVerdict("nx02", "accepted", local).status, "MATCH");
});

test("calendar comparison leaves a crossed creation boundary and unknown production answer incomparable", () => {
  assert.equal(calendarVerdict("nx02", "accepted", [
    { accepted: true, callback: { matched: false, reason: "creation bracket crosses advertised boundary" } },
  ]).status, "NOT_COMPARABLE");
  assert.equal(calendarVerdict("cr01", "unknown", [{ accepted: true }]).status, "NOT_COMPARABLE");
});

test("calendar comparison limits attempt deadline and DST claims to recorded evidence", () => {
  assert.deepEqual(calendarVerdict("rt08", "accepted", [{ accepted: true }]), {
    status: "NOT_COMPARABLE", reason: "S4: Cloud Scheduler attemptDeadline readback has no local counterpart",
  });
  const fold = calendarVerdict("ds02", "accepted", [{ accepted: true, callback: { matched: true } }]);
  assert.equal(fold.status, "MATCH");
  assert.match(fold.reason, /repeated-hour production delivery is not proven/);
});
