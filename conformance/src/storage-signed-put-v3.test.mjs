// Packet v3 fixes (presend reviews of v2): IAM removal that survives reporting failures, the
// reviewed whole-run maximum enforced, exact-digest comparisons, cleanup that continues past a
// failed list, and an expired case that cannot cross the SDK's past-expiry check.

import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { compareRecordings, compareTargets, putRow } from "./storage-signed-put/judge.mjs";
import { observe } from "./storage-signed-put/observe.mjs";
import {
  CASES,
  MAIN_CAP,
  MAX_REMOVE_ATTEMPTS,
  TOTAL_CAP,
  expectedRequests,
  staticBounds,
} from "./storage-signed-put/plan.mjs";
import {
  IAM_CONFIG,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const RUN = "sp-0123abcd";
const urlOf = (entry) => new URL(entry.url).pathname;
const respond = (status, body = "{}") => ({ status, body: Buffer.from(body) });
const enospc = () =>
  Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });

async function go({
  clock = createVirtualClock(),
  intercept,
  iam,
  faults,
  out = memoryOut(),
  world: options = {},
} = {}) {
  const world = createFakeWorld({
    target: PRODUCTION_LIKE,
    clock,
    iam,
    faults,
    ...options,
    intercept: intercept ? (request, log) => intercept(request, log, world) : undefined,
  });
  const result = await observe({
    target: PRODUCTION_LIKE,
    runId: RUN,
    deps: world.deps,
    out,
    iam: IAM_CONFIG,
  });
  return { ...result, world, out, clock };
}

const removedAll = (world) => {
  assert.equal(world.signerEnabled(), false);
  assert.equal(
    world.iam.roles.get(`projects/${PRODUCTION_LIKE.project}/roles/fireemuAdminSdkSigner`).deleted,
    true,
  );
  assert.deepEqual(world.iam.policy.bindings ?? [], []);
  assert.equal(world.objects.size, 0);
};

describe("reporting failures never skip the IAM removal (Codex 2)", () => {
  const failing = (names) => {
    const out = memoryOut();
    const save = out.save;
    out.save = (name, data) => {
      if (names === "all" || names.includes(name)) throw enospc();
      save(name, data);
    };
    return out;
  };

  it("when the failure, results and cleanup files cannot be written", async () => {
    const out = failing([
      "failure.json",
      "results.json",
      "cleanup-failure.json",
      "iam-failure.json",
    ]);
    const { report, world } = await go({
      out,
      faults: { "ok.png": respond(403, "<Error><Code>AccessDenied</Code></Error>") },
    });
    removedAll(world);
    assert.equal(report.closureReady, false);
    assert.ok(report.reportingErrors.length > 0);
    assert.ok(report.reportingErrors.every((e) => /ENOSPC/.test(e)));
  });

  it("when nothing at all can be written or journaled", async () => {
    const out = {
      journal: () => {
        throw enospc();
      },
      save: () => {
        throw enospc();
      },
    };
    const { report, world } = await go({
      out,
      faults: { "ok.png": respond(403, "<Error><Code>AccessDenied</Code></Error>") },
    });
    removedAll(world);
    assert.equal(report.closureReady, false);
    assert.equal(report.cleanupVerified, false, "an unrecorded run is not verified");
    assert.ok(report.reportingErrors.length > 0);
  });

  it("when the disk fills part-way through the run", async () => {
    const out = memoryOut();
    let written = 0;
    const journal = out.journal;
    out.journal = (entry) => {
      written += 1;
      if (written > 40) throw enospc();
      journal(entry);
    };
    const { world, report } = await go({ out });
    removedAll(world);
    assert.equal(report.closureReady, false);
  });
});

describe("the reviewed whole-run maximum is enforced (Codex 4, Opus S3)", () => {
  it("counts the removal retries: 2 * MAX_REMOVE_ATTEMPTS + 3 requests, 205 in all", () => {
    const bounds = staticBounds();
    assert.equal(bounds.iamRemove, 2 * MAX_REMOVE_ATTEMPTS + 3);
    assert.equal(bounds.iamRemove, 9);
    assert.deepEqual(
      [bounds.setup, bounds.iamGrant, bounds.main, bounds.cleanup, bounds.total],
      [15, 15, 130, 75, 205],
    );
  });

  it("makes the caps the reviewed maxima themselves", () => {
    assert.equal(MAIN_CAP, staticBounds().main);
    assert.equal(TOTAL_CAP, staticBounds().total);
    assert.deepEqual([MAIN_CAP, TOTAL_CAP], [130, 205]);
  });

  it("expects 141 requests for the real signer's three roles and one probe", () => {
    assert.equal(expectedRequests(CASES, 2, "production", { roleReads: 3, probes: 1 }), 141);
  });

  it("reaches exactly 205 requests in the worst case and stays inside the caps", async () => {
    const roles = Array.from({ length: 8 }, (_, i) => `roles/r${i}`);
    const { report, world } = await go({
      world: { lenient: true },
      iam: {
        propagationMs: 11 * 20_000,
        projectBindings: roles.map((role) => ({
          role,
          members: [`serviceAccount:${PRODUCTION_LIKE.signer}`],
        })),
        predefinedRoles: Object.fromEntries(
          roles.map((r, i) => [
            r.slice(6),
            i === 0
              ? ["storage.objects.create", "storage.objects.get", "storage.objects.delete"]
              : [],
          ]),
        ),
      },
      intercept: (request, log, w) => {
        if (urlOf(request).endsWith(":setIamPolicy")) {
          const n = log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length;
          if (n === 2 || n === 3) w.iam.policy.etag = `bumped-${n}`;
        }
        return undefined;
      },
    });
    assert.equal(report.iam.roleReads, 8);
    assert.equal(report.iam.signProbes, 12);
    assert.equal(report.requests, 205, JSON.stringify(report.unresolved));
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
    assert.equal(world.objects.size, 0);
  });

  it("stops at the reviewed total, not at a larger cap", async () => {
    const { report } = await go({ world: { lenient: true } });
    assert.ok(report.requests <= 205);
  });
});

describe("exact digests where identity is required (Codex 5)", () => {
  const row = (extra = {}) => ({
    recording: 1,
    id: "a",
    status: 403,
    class: "refused",
    code: "X",
    shape: "xml-error",
    bodyBytes: 3,
    bodySha256: "11".repeat(32),
    body: "aaa",
    headers: {},
    ...extra,
  });

  it("recordings differ when only the digest differs, and say so", () => {
    const a = row();
    const b = row({ recording: 2, bodySha256: "22".repeat(32) });
    assert.deepEqual(compareRecordings([a, b]), [
      { id: "a", fields: ["bodySha256"], digestOnly: true },
    ]);
    assert.deepEqual(
      compareRecordings([a, row({ recording: 2, bodySha256: "22".repeat(32), body: "bbb" })]),
      [{ id: "a", fields: ["body", "bodySha256"], digestOnly: false }],
    );
    assert.deepEqual(compareRecordings([a, row({ recording: 2 })]), []);
  });

  it("two invalid UTF-8 bodies that decode alike are different recordings", () => {
    const left = Buffer.from([0x3c, 0xff, 0x3e]);
    const right = Buffer.from([0x3c, 0xfe, 0x3e]);
    assert.equal(left.toString("utf8"), right.toString("utf8"));
    const make = (recording, bytes) =>
      putRow({
        recording,
        testCase: { id: "a" },
        answer: { status: 403, body: bytes, headers: {} },
        verdict: { class: "refused", code: null, shape: "other" },
        masks: [],
      });
    const differences = compareRecordings([make(1, left), make(2, right)]);
    assert.deepEqual(differences, [{ id: "a", fields: ["bodySha256"], digestOnly: true }]);
  });

  it("targets match only on the normalized comparison and say whether the bytes are identical", () => {
    const same = compareTargets([row()], [row()]);
    assert.deepEqual(
      [same[0].match, same[0].exact, same[0].fields, same[0].exactFields],
      [true, true, [], []],
    );
    const digestOnly = compareTargets([row()], [row({ bodySha256: "22".repeat(32) })]);
    assert.deepEqual([digestOnly[0].match, digestOnly[0].exact], [true, false]);
    assert.deepEqual(digestOnly[0].exactFields, ["bodySha256"]);
    const equalLength = compareTargets(
      [row()],
      [row({ body: "bbb", bodySha256: "22".repeat(32) })],
    );
    assert.equal(
      equalLength[0].match,
      false,
      "equal length bodies with different text do not match",
    );
    assert.ok(equalLength[0].fields.includes("body"));
    assert.equal(equalLength[0].exact, false);
    const status = compareTargets(
      [row()],
      [
        row({
          status: 200,
          bodyBytes: 0,
          body: "",
          code: null,
          shape: "empty",
          bodySha256: "33".repeat(32),
        }),
      ],
    );
    assert.equal(status[0].match, false);
    assert.deepEqual(status[0].fields, ["status", "code", "shape", "bodyBytes", "body"]);
  });

  it("masks the recording number in bodies so a path alone is a digest-only difference", async () => {
    const answer = (recording) => ({
      status: 403,
      body: Buffer.from(
        `<Error><Code>X</Code><Details>/b/storage-signed-put/sp-0123abcd/rec${recording}/ok.png</Details></Error>`,
      ),
      headers: {},
    });
    const make = (recording) =>
      putRow({
        recording,
        testCase: { id: "a" },
        answer: answer(recording),
        verdict: { class: "refused", code: "X", shape: "xml-error" },
        masks: [[RUN, "<run>"]],
      });
    assert.deepEqual(compareRecordings([make(1), make(2)]), [
      { id: "a", fields: ["bodySha256"], digestOnly: true },
    ]);
  });
});

describe("cleanup continues past a failed list (Codex should)", () => {
  for (const [label, answer] of [
    ["503", respond(503)],
    ["403", respond(403)],
    ["transport", "transport"],
  ]) {
    it(`deletes the confirmed objects when the first cleanup list answers ${label}`, async () => {
      let lists = 0;
      const { report, world } = await go({
        intercept: (request) =>
          request.url.includes("/o?prefix=") && (lists += 1) === 2 ? answer : undefined,
      });
      assert.equal(world.objects.size, 0, "all ten confirmed objects were deleted");
      assert.ok(report.cleanupError);
      assert.equal(report.closureReady, false);
      assert.equal(world.signerEnabled(), false);
    });
  }

  it("deletes the objects when the final list fails too, and reports both", async () => {
    let lists = 0;
    const { report, world } = await go({
      intercept: (request) =>
        request.url.includes("/o?prefix=") && (lists += 1) >= 2 ? respond(503) : undefined,
    });
    assert.equal(world.objects.size, 0);
    assert.ok(report.cleanupError);
    assert.equal(report.cleanupVerified, false);
  });
});

describe("the expired case cannot cross the SDK's past-expiry check (Opus S2)", () => {
  it("waits for the next second when the clock is near the end of this one", async () => {
    const clock = createVirtualClock(Date.UTC(2026, 10, 3, 12, 0, 0, 999));
    const specs = [];
    // Only the shortest-lifetime signing is slow, so the clock is still at .999 when it starts.
    const world = createFakeWorld({
      target: PRODUCTION_LIKE,
      clock,
      signDelayMs: (spec) => (spec.accessibleAt === undefined ? 0 : 2),
    });
    const deps = {
      ...world.deps,
      sign: async (spec, meter) => {
        if (spec.accessibleAt !== undefined) specs.push({ spec, at: clock.now() });
        return world.deps.sign(spec, meter);
      },
    };
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps,
      out: memoryOut(),
      iam: IAM_CONFIG,
    });
    assert.equal(report.finished, true, report.stopped);
    assert.equal(specs.length, 2);
    for (const { spec, at } of specs) {
      assert.equal(spec.accessibleAt % 1000, 0);
      assert.ok(at - spec.accessibleAt <= 800 + 1, `${at - spec.accessibleAt} ms into the second`);
      assert.equal(spec.expires - spec.accessibleAt, 1000);
    }
  });

  it("does not wait when the clock is early in the second", async () => {
    const clock = createVirtualClock(Date.UTC(2026, 10, 3, 12, 0, 0, 100));
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
    const sleeps = [];
    const sleep = world.deps.sleep;
    const deps = {
      ...world.deps,
      sleep: async (ms) => {
        sleeps.push(ms);
        return sleep(ms);
      },
    };
    await observe({ target: PRODUCTION_LIKE, runId: RUN, deps, out: memoryOut(), iam: IAM_CONFIG });
    assert.ok(sleeps.every((ms) => ms === 250 || ms === 20_000 || ms < 1000));
    const second = Date.UTC(2026, 10, 3, 12, 0, 0, 800);
    const late = createVirtualClock(second);
    const lateWorld = createFakeWorld({ target: PRODUCTION_LIKE, clock: late });
    const lateSleeps = [];
    const lateDeps = {
      ...lateWorld.deps,
      sleep: async (ms) => {
        lateSleeps.push(ms);
        return lateWorld.deps.sleep(ms);
      },
    };
    await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: lateDeps,
      out: memoryOut(),
      iam: IAM_CONFIG,
    });
    assert.ok(lateSleeps.length > 0);
  });
});
