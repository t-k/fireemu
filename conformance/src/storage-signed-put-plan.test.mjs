import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ASSIGNED_RANGE,
  CASES,
  MAIN_CAP,
  NARROW_RANGE,
  PNG_MAGIC,
  RANGE_HEADER,
  TOTAL_CAP,
  caseObjects,
  expectedRequests,
  newRunId,
  plannedNames,
  recordingPrefix,
  staticBounds,
} from "./storage-signed-put/plan.mjs";

const byId = (id) => CASES.find((c) => c.id === id);

describe("signed PUT plan", () => {
  it("has unique ids and the assigned refusal shapes", () => {
    assert.equal(new Set(CASES.map((c) => c.id)).size, CASES.length);
    for (const id of [
      "wrong-content-type",
      "over-range",
      "under-range",
      "range-header-missing",
      "tampered-signature",
      "expired",
      "other-object",
    ]) {
      assert.ok(byId(id), id);
    }
  });

  it("signs the assigned flow exactly: image/png with the 0,10485760 range", () => {
    const control = byId("ok");
    assert.equal(control.control, true);
    assert.deepEqual(control.signed, { contentType: "image/png", range: ASSIGNED_RANGE });
    assert.deepEqual(control.sent, { contentType: "image/png", range: ASSIGNED_RANGE });
    assert.equal(ASSIGNED_RANGE, "0,10485760");
    assert.equal(RANGE_HEADER, "x-goog-content-length-range");
    assert.deepEqual([...control.body], [...PNG_MAGIC]);
  });

  it("puts the size cases on both sides of the narrow range and on its edges", () => {
    const [min, max] = NARROW_RANGE.split(",").map(Number);
    assert.equal(byId("over-range").body.length, max + 1);
    assert.equal(byId("under-range").body.length, min - 1);
    assert.equal(byId("range-min-ok").body.length, min);
    assert.equal(byId("range-max-ok").body.length, max);
    for (const id of ["over-range", "under-range", "range-min-ok", "range-max-ok"]) {
      assert.equal(byId(id).signed.range, NARROW_RANGE);
      assert.equal(byId(id).sent.range, NARROW_RANGE);
    }
  });

  it("makes each refusal case differ from the control in exactly the intended way", () => {
    const control = byId("ok");
    assert.notEqual(byId("wrong-content-type").sent.contentType, control.sent.contentType);
    assert.equal(byId("missing-content-type").sent.contentType, null);
    assert.equal(byId("range-header-missing").sent.range, null);
    assert.equal(byId("range-header-missing").signed.range, ASSIGNED_RANGE);
    assert.notEqual(
      byId("range-header-mismatch").sent.range,
      byId("range-header-mismatch").signed.range,
    );
    assert.equal(byId("range-header-unsigned").signed.range, null);
    assert.notEqual(byId("range-header-unsigned").sent.range, null);
    assert.equal(byId("expired").short, true);
    assert.equal(byId("tampered-signature").mutate, "tamper");
    assert.equal(byId("signature-missing").mutate, "drop-signature");
    assert.notEqual(
      caseObjects(byId("other-object")).sent,
      caseObjects(byId("other-object")).signed,
    );
  });

  it("keeps the static bounds inside the caps and the expected count below them", () => {
    const bounds = staticBounds();
    assert.ok(bounds.main <= MAIN_CAP, `main ${bounds.main}`);
    assert.ok(bounds.total <= TOTAL_CAP, `total ${bounds.total}`);
    assert.ok(expectedRequests() <= bounds.total);
    assert.ok(expectedRequests(CASES, 2, "local") < expectedRequests());
    assert.equal(TOTAL_CAP, 200);
  });

  it("lists every name a recording can create under the recording prefix", () => {
    const names = plannedNames("sp-0123abcd");
    assert.equal(names.length, 2 * new Set(CASES.map((c) => caseObjects(c).sent)).size);
    for (const name of names)
      assert.match(name, /^storage-signed-put\/sp-0123abcd\/rec[12]\/[a-z-]+\.png$/);
    assert.ok(names.includes(`${recordingPrefix("sp-0123abcd", 2)}other-sent.png`));
  });

  it("builds run ids from the random source", () => {
    assert.match(newRunId(), /^sp-[0-9a-f]{8}$/);
    assert.equal(
      newRunId(() => 0),
      "sp-00000000",
    );
  });
});
