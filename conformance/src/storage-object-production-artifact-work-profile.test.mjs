import assert from "node:assert/strict";
import test from "node:test";
import * as work from "./storage-object/production-artifact-work-profile.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const limits = { maxValues: 1000, maxUtf8Bytes: 1048576, maxIndexNodes: 1048576 };
function profile() {
  assert.equal(typeof work.createProductionArtifactWorkProfile, "function");
  return work.createProductionArtifactWorkProfile({ plan, limits });
}
function binding(cap) {
  return work.originalProductionArtifactWorkProfile(cap, { plan });
}
function account(cap, kind = "inventory") {
  return work.createProductionArtifactWorkAccount({ profile: cap, kind });
}

test("a structural profile binds canonical plan and exact registry limits without granting admission", () => {
  const cap = profile(),
    bound = binding(cap);
  assert.ok(bound);
  assert.equal(bound.scope, "STRUCTURAL_NOT_ADMISSION");
  assert.equal(bound.sendAuthorized, false);
  assert.deepEqual(bound.limits, limits);
  assert.equal(binding({ ...cap }), null);
  assert.equal(
    work.originalProductionArtifactWorkProfile(cap, {
      plan: { ...plan, bucket: "foreign.appspot.com" },
    }),
    null,
  );
  assert.throws(() =>
    work.createProductionArtifactWorkProfile({ plan: { ...plan, maxRequests: 6001 }, limits }),
  );
});
test("all aggregate arithmetic remains exact beyond Number safe integers", () => {
  const b = binding(profile()),
    l = 2097152n,
    f = 121024n,
    bytes = 2752512n,
    e = 1001n,
    g = 420n * l,
    h = (831n + 410n * 22n) * l + 2n,
    report = 2n * 420n * 32768n,
    expected = e * (f * (bytes + g) + 4n * (2097152n + h)) + report;
  assert.equal(typeof b.maxTaskScanCodeUnits, "bigint");
  assert.ok(b.maxTaskScanCodeUnits > BigInt(Number.MAX_SAFE_INTEGER));
  assert.equal(b.maxTaskScanCodeUnits, expected);
  assert.equal(b.maxSingleScanCodeUnits, Number(h));
  assert.equal(b.maxSharedInspectionCodeUnits, Number(4n * (2097152n + h)));
  assert.equal(b.maxSharedTaskCodeUnits, e * 4n * (2097152n + h));
  assert.equal(b.maxReportTaskCodeUnits, report);
});
test("local allowance clamps BigInt before converting to Number and never resets on query", () => {
  const cap = profile(),
    b = binding(cap),
    a = account(cap);
  assert.equal(a.consumed(), 0n);
  assert.equal(a.allowance("owned-scan"), b.maxSingleScanCodeUnits);
  a.consume(b.maxTaskScanCodeUnits - 3n);
  assert.equal(a.allowance("owned-scan"), 3);
  assert.equal(a.allowance("shared-reader"), 3);
  assert.equal(a.allowance("shared-report"), 3);
  assert.equal(a.consumed(), b.maxTaskScanCodeUnits - 3n);
  a.consume(3);
  assert.equal(a.allowance("owned-scan"), 0);
  assert.throws(() => a.consume(1));
  assert.throws(() => a.allowance("owned-scan"));
  assert.equal(a.consumed(), b.maxTaskScanCodeUnits);
});
test("account kind has its own exact limit and cannot borrow another kind's budget", () => {
  const cap = profile(),
    b = binding(cap);
  for (const [kind, max, operation] of [
    ["shared-reader", b.maxSharedTaskCodeUnits, "shared-reader"],
    ["shared-report", b.maxReportTaskCodeUnits, "shared-report"],
  ]) {
    const a = account(cap, kind);
    a.consume(max);
    assert.equal(a.consumed(), max);
    assert.equal(a.allowance(operation), 0);
    assert.throws(() => a.consume(1));
  }
  assert.throws(() => account(cap, "foreign"));
  assert.throws(() => account({ ...cap }));
});
test("invalid amounts latch failure and no caller supplied snapshot can restore a budget", () => {
  for (const value of [-1, -1n, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1", {}, 1.5]) {
    const a = account(profile());
    assert.throws(() => a.consume(value));
    assert.throws(() => a.consume(0));
    assert.equal(a.consumed(), 0n);
  }
  const a = account(profile());
  assert.throws(() => a.allowance("foreign"));
  assert.throws(() => a.consume(0));
});
test("profile and account inputs reject getters and proxies without invoking hooks", () => {
  let hooks = 0;
  const getter = Object.defineProperty({}, "plan", {
    enumerable: true,
    get() {
      hooks++;
      return plan;
    },
  });
  assert.throws(() => work.createProductionArtifactWorkProfile(getter));
  const proxy = new Proxy(
    { plan, limits },
    {
      get() {
        hooks++;
        throw new Error();
      },
      ownKeys() {
        hooks++;
        throw new Error();
      },
    },
  );
  assert.throws(() => work.createProductionArtifactWorkProfile(proxy));
  assert.throws(() =>
    work.createProductionArtifactWorkAccount(
      new Proxy(
        { profile: profile(), kind: "inventory" },
        {
          get() {
            hooks++;
            throw new Error();
          },
          ownKeys() {
            hooks++;
            throw new Error();
          },
        },
      ),
    ),
  );
  assert.equal(hooks, 0);
  for (const changed of [
    { ...limits, maxValues: 1536082 },
    { ...limits, maxUtf8Bytes: 268435457 },
    { ...limits, maxIndexNodes: 1048577 },
    { ...limits, maxValues: 0 },
    { ...limits, foreign: 1 },
  ])
    assert.throws(() => work.createProductionArtifactWorkProfile({ plan, limits: changed }));
});
test("legacy prototype accounting remains a finite Number budget with exact next-unit rejection", () => {
  const a = work.createProductionArtifactWorkAccount({
    profile: null,
    kind: "inventory",
    prototypeLimit: 100,
  });
  assert.equal(a.consumed(), 0);
  assert.equal(a.allowance("shared-reader"), 100);
  a.consume(99);
  assert.equal(a.allowance("owned-scan"), 1);
  a.consume(1);
  assert.equal(a.consumed(), 100);
  assert.equal(a.allowance("owned-scan"), 0);
  assert.throws(() => a.consume(1));
  assert.throws(() => a.consume(0));
  assert.throws(() =>
    work.createProductionArtifactWorkAccount({
      profile: null,
      kind: "inventory",
      prototypeLimit: 268435457,
    }),
  );
});

test("original account identity rejects complete diagnostic DTOs and halt never resets consumed work", () => {
  const cap = profile(),
    a = account(cap),
    b = binding(cap);
  a.consume(17);
  const snapshot = work.originalProductionArtifactWorkAccount(a, cap);
  assert.deepEqual(snapshot, {
    kind: "inventory",
    work: 17n,
    limit: b.maxTaskScanCodeUnits,
    failed: false,
  });
  assert.equal(work.originalProductionArtifactWorkAccount({ ...a }, cap), null);
  assert.equal(work.originalProductionArtifactWorkAccount(snapshot, cap), null);
  assert.equal(work.originalProductionArtifactWorkAccount(a, profile()), null);
  assert.equal(work.originalProductionArtifactWorkProfile(b), null);
  assert.throws(() => account(b));
  a.halt();
  assert.throws(() => a.consume(0));
  assert.throws(() => a.allowance());
  assert.equal(a.consumed(), 17n);
  assert.equal(work.originalProductionArtifactWorkAccount(a, cap).failed, true);
});
test("structural input copies are deeply frozen and never follow later plan or limit mutation", () => {
  const copiedPlan = JSON.parse(JSON.stringify(plan)),
    copiedLimits = { ...limits };
  const cap = work.createProductionArtifactWorkProfile({ plan: copiedPlan, limits: copiedLimits });
  const bound = binding(cap);
  copiedPlan.recordings[0].prefix = "foreign/";
  copiedLimits.maxValues = 1;
  assert.equal(bound.plan.recordings[0].prefix, plan.recordings[0].prefix);
  assert.equal(bound.limits.maxValues, limits.maxValues);
  assert.ok(Object.isFrozen(bound.plan.recordings[0]));
  assert.throws(() => {
    bound.plan.recordings[0].prefix = "foreign/";
  });
  assert.throws(() => {
    bound.limits.maxValues = 1;
  });
});
test("nested plan and registry limits reject hooks before producing a work cap", () => {
  let hooks = 0;
  const getterLimits = { ...limits };
  Object.defineProperty(getterLimits, "maxValues", {
    enumerable: true,
    get() {
      hooks++;
      return 1000;
    },
  });
  const nestedPlan = {
    ...plan,
    recordings: new Proxy(plan.recordings, {
      ownKeys() {
        hooks++;
        return [];
      },
    }),
  };
  for (const input of [
    { plan, limits: getterLimits },
    { plan: nestedPlan, limits },
  ])
    assert.throws(() => work.createProductionArtifactWorkProfile(input));
  assert.equal(hooks, 0);
  const legacy = work.createProductionArtifactWorkAccount({
    profile: null,
    kind: "inventory",
    prototypeLimit: 100,
  });
  assert.throws(() => legacy.consume(1n));
  assert.equal(legacy.consumed(), 0);
});
