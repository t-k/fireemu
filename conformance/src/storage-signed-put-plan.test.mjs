import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ASSIGNED_RANGE,
  CASES,
  DEFAULT_WINDOW_MINUTES,
  MAX_REMOVE_ATTEMPTS,
  MAX_ROLE_READS,
  MAX_SIGN_PROBES,
  MAX_WINDOW_MINUTES,
  ROLE_ID,
  SIGNER_PERMISSION,
  SIGN_PROBE_WAIT_MS,
  STORAGE_PERMISSIONS,
  ESTIMATED_USD,
  EXPIRY_MARGIN_MS,
  MAIN_CAP,
  MAX_CLOCK_SKEW_MS,
  READBACK_CAP,
  RECORDINGS,
  REQUEST_TIMEOUT_MS,
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
    assert.equal(bounds.main, MAIN_CAP);
    assert.equal(bounds.total, TOTAL_CAP);
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

  it("pins the constants the packet states", () => {
    assert.deepEqual([...PNG_MAGIC], [137, 80, 78, 71]);
    assert.deepEqual(
      [
        MAIN_CAP,
        TOTAL_CAP,
        READBACK_CAP,
        REQUEST_TIMEOUT_MS,
        EXPIRY_MARGIN_MS,
        MAX_CLOCK_SKEW_MS,
        ESTIMATED_USD,
        RECORDINGS,
      ],
      [130, 205, 45, 30_000, 2500, 5000, 0.05, 2],
    );
    assert.equal(CASES.length, 16);
    assert.deepEqual(staticBounds(), {
      setup: 15,
      iamGrant: 15,
      perRecording: 50,
      main: 130,
      iamRemove: 9,
      cleanup: 75,
      total: 205,
    });
    assert.equal(expectedRequests(), 9 + 9 + 2 * 50 + 2 + 2 * 5 * 2);
    assert.equal(expectedRequests(CASES, 2, "local"), 1 + 2 * 34 + 2 + 2 * 5 * 2);
    assert.equal(byId("ok-origin").preflight, true);
    assert.equal(CASES.filter((c) => c.preflight).length, 1);
    assert.equal(CASES.filter((c) => c.expect === "create").length, 5);
    assert.ok(
      byId("range-header-mismatch").body.length <= 3,
      "inside the range the mismatched header names",
    );
  });

  it("builds hexadecimal run ids from the whole random range", () => {
    assert.equal(
      newRunId(() => 0.9999999),
      "sp-ffffffff",
    );
    assert.match(
      newRunId(() => 0.5),
      /^sp-8{8}$/,
    );
    let n = 0;
    assert.match(
      newRunId(() => (n++ % 16) / 16),
      /^sp-0123456[0-9a-f]$/,
    );
  });

  it("names the sent object after the case unless the case names another", () => {
    assert.deepEqual(caseObjects(byId("ok")), { signed: "ok.png", sent: "ok.png" });
    assert.deepEqual(caseObjects(byId("other-object")), {
      signed: "other-object.png",
      sent: "other-sent.png",
    });
  });

  it("pins the signer role constants the packet states", () => {
    assert.deepEqual(
      [
        ROLE_ID,
        SIGNER_PERMISSION,
        MAX_ROLE_READS,
        MAX_SIGN_PROBES,
        SIGN_PROBE_WAIT_MS,
        DEFAULT_WINDOW_MINUTES,
        MAX_WINDOW_MINUTES,
        MAX_REMOVE_ATTEMPTS,
      ],
      ["fireemuAdminSdkSigner", "iam.serviceAccounts.signBlob", 8, 12, 20_000, 60, 180, 3],
    );
    assert.deepEqual(STORAGE_PERMISSIONS, [
      "storage.objects.create",
      "storage.objects.get",
      "storage.objects.delete",
    ]);
  });
});
