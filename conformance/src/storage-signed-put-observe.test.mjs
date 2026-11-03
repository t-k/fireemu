import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { classifyRequest } from "./storage-signed-put/guard.mjs";
import { observe, readbackAbsent } from "./storage-signed-put/observe.mjs";
import {
  CASES,
  READBACK_CAP,
  TOTAL_CAP,
  caseObjects,
  expectedRequests,
  plannedNames,
  runPrefix,
  staticBounds,
} from "./storage-signed-put/plan.mjs";
import {
  LOCAL_LIKE,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const RUN = "sp-0123abcd";

async function run({
  target = PRODUCTION_LIKE,
  faults = {},
  caps,
  cases,
  mutateDeps,
  intercept,
} = {}) {
  const clock = createVirtualClock();
  const world = createFakeWorld({ target, clock, faults, intercept });
  const out = memoryOut();
  const deps = mutateDeps ? mutateDeps(world.deps) : world.deps;
  const result = await observe({ target, runId: RUN, deps, out, caps, cases });
  return { ...result, world, out };
}

const row = (rows, recording, id) => rows.find((r) => r.recording === recording && r.id === id);

describe("signed PUT observer on the fake world", () => {
  it("records every case twice, cleans up and counts exactly the planned requests (production shape)", async () => {
    const { report, rows, reads, world } = await run();
    assert.equal(report.finished, true, report.stopped);
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
    assert.equal(report.requests, expectedRequests(CASES, 2, "production"));
    assert.equal(rows.length, 2 * CASES.length);
    assert.equal(world.objects.size, 0);
    assert.deepEqual(report.recordingDifferences, []);
    assert.deepEqual(report.unknownRequests, []);
    for (const recording of [1, 2]) {
      assert.deepEqual(
        [row(rows, recording, "ok").status, row(rows, recording, "ok").shape],
        [200, "empty"],
      );
      for (const id of ["ok-origin", "range-min-ok", "range-max-ok", "no-range"])
        assert.equal(row(rows, recording, id).status, 200, id);
      assert.deepEqual(
        [
          "wrong-content-type",
          "missing-content-type",
          "range-header-missing",
          "range-header-mismatch",
          "range-header-unsigned",
          "tampered-signature",
          "other-object",
        ].map((id) => [id, row(rows, recording, id).status, row(rows, recording, id).code]),
        [
          ["wrong-content-type", 403, "SignatureDoesNotMatch"],
          ["missing-content-type", 403, "SignatureDoesNotMatch"],
          ["range-header-missing", 403, "SignatureDoesNotMatch"],
          ["range-header-mismatch", 403, "SignatureDoesNotMatch"],
          ["range-header-unsigned", 403, "SignatureDoesNotMatch"],
          ["tampered-signature", 403, "SignatureDoesNotMatch"],
          ["other-object", 403, "SignatureDoesNotMatch"],
        ],
      );
      assert.equal(row(rows, recording, "over-range").code, "EntityTooLarge");
      assert.equal(row(rows, recording, "under-range").code, "EntityTooSmall");
      assert.equal(row(rows, recording, "expired").code, "ExpiredToken");
      assert.equal(row(rows, recording, "signature-missing").status, 403);
    }
    const full = reads.filter((r) => r.id === "ok");
    assert.deepEqual(
      full.map((r) => r.step),
      ["metadata", "exists", "media", "metadata", "exists", "media"],
    );
    assert.ok(full.filter((r) => r.step === "exists").every((r) => r.value === true));
    assert.ok(full.filter((r) => r.step === "media").every((r) => r.equalsBody));
  });

  it("counts the local dry run's requests too, and sends nothing to the signer or IAM", async () => {
    const { report, world } = await run({ target: LOCAL_LIKE });
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
    assert.equal(report.requests, expectedRequests(CASES, 2, "local"));
    assert.ok(world.log.every((r) => r.url.startsWith(LOCAL_LIKE.origin)));
  });

  it("waits out the shortest SDK lifetime before the expired PUT, and signs it with a one second lifetime", async () => {
    const clock = createVirtualClock();
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
    const seen = [];
    const deps = { ...world.deps };
    const sign = deps.sign;
    deps.sign = async (spec, meter) => {
      const url = await sign(spec, meter);
      if (spec.accessibleAt !== undefined) seen.push({ spec, url, at: clock.now() });
      return url;
    };
    const putTimes = [];
    const net = deps.net;
    deps.net = async (request) => {
      if (request.method === "PUT" && request.url.includes("expired.png"))
        putTimes.push(clock.now());
      return net(request);
    };
    await observe({ target: PRODUCTION_LIKE, runId: RUN, deps, out: memoryOut() });
    assert.equal(seen.length, 2);
    for (const { spec, url } of seen) {
      assert.equal(spec.expires - spec.accessibleAt, 1000);
      assert.equal(spec.accessibleAt % 1000, 0);
      assert.match(url, /X-Goog-Expires=1&/);
    }
    assert.equal(putTimes.length, 2);
    putTimes.forEach((time, i) =>
      assert.ok(time >= seen[i].spec.expires + 2500, `${time} vs ${seen[i].spec.expires}`),
    );
  });

  it("every request leaves through the guard and stays under the run prefix", async () => {
    const { world } = await run();
    for (const entry of world.log) {
      classifyRequest(PRODUCTION_LIKE, { method: entry.method, url: entry.url }, runPrefix(RUN));
    }
    assert.ok(world.log.some((e) => e.method === "PUT"));
  });

  it("stops before any PUT when the run prefix is not empty", async () => {
    const clock = createVirtualClock();
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
    world.objects.set(`${runPrefix(RUN)}rec1/leftover.png`, {
      name: `${runPrefix(RUN)}rec1/leftover.png`,
      generation: "7",
      body: Buffer.alloc(0),
      contentType: "x",
    });
    const out = memoryOut();
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out,
    });
    assert.equal(report.finished, false);
    assert.match(report.stopped, /prefix is not empty/);
    assert.ok(!world.log.some((e) => e.method === "PUT"));
    // The leftover is not a planned name: it is reported, never deleted.
    assert.equal(report.closureReady, false);
    assert.ok(report.unresolved.some((u) => u.reason === "foreign object under the run prefix"));
    assert.equal(world.objects.size, 1);
  });

  it("stops on a local clock that differs from the server's", async () => {
    const { report, world } = await run({
      mutateDeps: (deps) => ({ ...deps, now: () => deps.now() + 60_000 }),
    });
    assert.match(report.stopped, /clock/);
    assert.ok(!world.log.some((e) => e.method === "PUT"));
  });

  it("stops when the positive control is refused, records no refusals, and still cleans up", async () => {
    const { report, rows, world } = await run({
      faults: {
        "ok.png": {
          status: 403,
          headers: {},
          body: Buffer.from("<Error><Code>AccessDenied</Code></Error>"),
        },
      },
    });
    assert.match(report.stopped, /positive control ok was not accepted \(status 403\)/);
    assert.equal(rows.length, 1);
    assert.equal(report.finished, false);
    assert.equal(report.closureReady, false);
    assert.equal(world.objects.size, 0);
  });

  it("treats a 5xx, a 3xx, a sub-200 status and a transport error on a PUT as unknown and stops", async () => {
    for (const fault of [{ status: 503 }, { status: 302 }, { status: 102 }, "transport"]) {
      const { report, rows, world } = await run({
        faults: { [`PUT /${PRODUCTION_LIKE.bucket}/${runPrefix(RUN)}rec1/ok-origin.png`]: fault },
      });
      assert.equal(report.finished, false, JSON.stringify(fault));
      assert.equal(report.closureReady, false);
      assert.deepEqual(report.unknownRequests, ["1-ok-origin-put"]);
      assert.equal(rows.length, 1, "nothing after the unknown answer");
      assert.ok(
        report.unresolved.some((u) => u.reason === "unknown create, no positive read"),
        JSON.stringify(report.unresolved),
      );
      assert.equal(world.objects.size, 0, "the earlier object is still deleted");
    }
  });

  it("does not settle an unknown create that landed by reading 404; it settles through a positive list", async () => {
    // A 503 whose PUT in fact created the object: the cleanup list shows it, so it is deleted and read back.
    const clock = createVirtualClock();
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
    const net = world.deps.net;
    let faulted = false;
    const deps = {
      ...world.deps,
      net: async (request) => {
        const res = await net(request);
        if (!faulted && request.method === "PUT" && request.url.includes("ok-origin.png")) {
          faulted = true;
          return { status: 503, headers: {}, body: Buffer.alloc(0) };
        }
        return res;
      },
    };
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps,
      out: memoryOut(),
    });
    assert.deepEqual(report.unknownRequests, ["1-ok-origin-put"]);
    assert.equal(report.closureReady, false, "an unknown request keeps the closure open");
    assert.equal(world.objects.size, 0);
    assert.deepEqual(
      report.unresolved,
      [],
      "the object itself settled through the list and its own delete",
    );
  });

  it("keeps a refusal case that was accepted open when its object then reads 404", async () => {
    const { report } = await run({
      faults: { "wrong-content-type.png": { status: 200, headers: {}, body: Buffer.alloc(0) } },
    });
    assert.equal(report.finished, true);
    assert.equal(report.closureReady, false);
    assert.ok(report.unresolved.some((u) => /created, not deleted/.test(u.reason)));
  });

  it("never re-sends an unknown DELETE and keeps the closure open", async () => {
    const { report, world } = await run({
      faults: { "DELETE /storage/v1/b/demo-bucket.firebasestorage.app/o/": { status: 503 } },
    });
    const deletes = world.log.filter((e) => e.method === "DELETE");
    assert.equal(report.closureReady, false);
    assert.ok(report.unresolved.some((u) => u.reason === "unknown delete"));
    assert.equal(new Set(deletes.map((d) => d.url)).size, deletes.length, "no DELETE is repeated");
    assert.equal(report.unknownRequests.length, 1);
  });

  it("refuses to send a request the guard does not allow (a signer returning another bucket)", async () => {
    const { report, world } = await run({
      mutateDeps: (deps) => ({
        ...deps,
        sign: async (spec, meter) =>
          (await deps.sign(spec, meter)).replace(PRODUCTION_LIKE.bucket, "someone-elses-bucket"),
      }),
    });
    assert.equal(report.finished, false);
    assert.match(report.stopped, /request refused/);
    assert.ok(!world.log.some((e) => e.method === "PUT"));
  });

  it("stops at the request cap and keeps the cleanup inside the total cap", async () => {
    const { report, world } = await run({ caps: { main: 30, total: TOTAL_CAP } });
    assert.equal(report.finished, false);
    assert.match(report.stopped, /budget/);
    assert.ok(report.requests <= TOTAL_CAP);
    assert.equal(world.objects.size, 0);
  });

  it("property: under random faults the run never exceeds the cap, never leaves a leftover silently, and never repeats a DELETE", async () => {
    let a = 0x5eed1234;
    const next = () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
    };
    const needles = [
      "GET /storage/v1/b/demo-bucket.firebasestorage.app/o/",
      "DELETE /storage",
      "PUT /demo-bucket",
      "ok.png",
      "range-max-ok.png",
      "/o?prefix",
    ];
    const faults = [
      { status: 503 },
      { status: 302 },
      { status: 404, body: Buffer.from("{}") },
      { status: 200, body: Buffer.alloc(0) },
      "transport",
    ];
    for (let i = 0; i < 120; i += 1) {
      const chosen = {};
      for (let k = 0; k < 1 + Math.floor(next() * 3); k += 1) {
        chosen[needles[Math.floor(next() * needles.length)]] =
          faults[Math.floor(next() * faults.length)];
      }
      const { report, world } = await run({ faults: chosen });
      const label = JSON.stringify(Object.keys(chosen));
      assert.ok(report.requests <= TOTAL_CAP, label);
      const deletes = world.log.filter((e) => e.method === "DELETE").map((e) => e.url);
      assert.equal(new Set(deletes).size, deletes.length, label);
      if (report.closureReady) {
        assert.equal(world.objects.size, 0, label);
        assert.equal(report.finished, true, label);
        assert.deepEqual(report.unknownRequests, [], label);
      }
      if (world.objects.size > 0) assert.equal(report.closureReady, false, label);
    }
  });

  it("A2 read-back: every planned name reads 404 and the prefix lists empty after a clean run", async () => {
    const { world } = await run();
    const out = memoryOut();
    const report = await readbackAbsent({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out,
    });
    assert.equal(report.allAbsent, true);
    assert.equal(report.listEmpty, true);
    assert.equal(report.requests, 1 + plannedNames(RUN).length);
    assert.ok(report.requests <= READBACK_CAP);
    assert.deepEqual(report.statuses, []);
  });

  it("A2 read-back: a leftover object, a 5xx and a transport failure each keep allAbsent false", async () => {
    const leftover = `${runPrefix(RUN)}rec1/ok.png`;
    for (const mode of ["leftover", "5xx", "transport", "list-5xx"]) {
      const clock = createVirtualClock();
      const faults = {};
      if (mode === "5xx") faults[`/o/${encodeURIComponent(leftover)}`] = { status: 503 };
      if (mode === "transport") faults[`/o/${encodeURIComponent(leftover)}`] = "transport";
      if (mode === "list-5xx") faults["/o?prefix"] = { status: 500 };
      const world = createFakeWorld({ target: PRODUCTION_LIKE, clock, faults });
      if (mode === "leftover")
        world.objects.set(leftover, {
          name: leftover,
          generation: "1",
          body: Buffer.alloc(0),
          contentType: "x",
        });
      const report = await readbackAbsent({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: world.deps,
        out: memoryOut(),
      });
      assert.equal(report.allAbsent, false, mode);
    }
  });

  it("fails the cleanup, and the closure, when a cleanup list is not a 200", async () => {
    for (const needle of ["GET /storage/v1/b/demo-bucket.firebasestorage.app/o"]) {
      // The first list is the preflight; fault the second and third separately.
      for (const skip of [1, 2]) {
        let seen = 0;
        const { report } = await run({
          mutateDeps: (deps) => ({
            ...deps,
            net: async (request) => {
              if (request.method === "GET" && request.url.includes("/o?prefix=")) {
                seen += 1;
                if (seen === skip + 1) {
                  return { status: 403, headers: {}, body: Buffer.from('{"error":{"code":403}}') };
                }
              }
              return deps.net(request);
            },
          }),
        });
        assert.ok(report.cleanupError, needle + skip);
        assert.equal(report.closureReady, false);
        assert.equal(report.cleanupVerified, false);
      }
    }
  });

  it("reports cleanupVerified for a stopped run whose cleanup is complete, but not closureReady", async () => {
    const { report } = await run({
      faults: {
        "ok.png": {
          status: 403,
          headers: {},
          body: Buffer.from("<Error><Code>AccessDenied</Code></Error>"),
        },
      },
    });
    assert.equal(report.cleanupVerified, true);
    assert.equal(report.closureReady, false);
    const clean = await run();
    assert.equal(clean.report.cleanupVerified, true);
    assert.equal(clean.report.closureReady, true);
  });

  it("with every PUT accepted the request count equals the static bound exactly", async () => {
    const clock = createVirtualClock();
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock, lenient: true });
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
    });
    const bounds = staticBounds();
    assert.equal(report.requests, bounds.total);
    assert.equal(report.rows, 2 * CASES.length);
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
    assert.equal(world.objects.size, 0);
    assert.deepEqual(bounds, { setup: 3, perRecording: 50, main: 103, cleanup: 66, total: 169 });
  });

  it("sends the headers each case names and nothing else on the PUT; credentials only on admin requests", async () => {
    const { world } = await run();
    const puts = world.log.filter((e) => e.method === "PUT");
    assert.equal(puts.length, 2 * CASES.length);
    for (const entry of puts) {
      const id = CASES.find(
        (c) =>
          entry.url.includes(`/rec1/${caseObjects(c).sent}?`) ||
          entry.url.includes(`/rec2/${caseObjects(c).sent}?`),
      ).id;
      const testCase = CASES.find((c) => c.id === id);
      const sent = Object.fromEntries(Object.entries(entry.headers));
      const expected = {};
      if (testCase.sent.contentType) expected["content-type"] = testCase.sent.contentType;
      if (testCase.sent.range) expected["x-goog-content-length-range"] = testCase.sent.range;
      if (testCase.sent.origin) expected.origin = testCase.sent.origin;
      assert.deepEqual(sent, expected, testCase.id);
    }
    for (const entry of world.log.filter((e) => e.method !== "PUT" && e.method !== "OPTIONS")) {
      assert.equal(entry.headers.authorization, "Bearer fake", entry.url);
    }
    const options = world.log.filter((e) => e.method === "OPTIONS");
    assert.equal(options.length, 2);
    assert.ok(
      options.every(
        (e) =>
          e.headers.authorization === undefined && e.headers.origin === "http://localhost:3000",
      ),
    );
  });

  it("journals a before and an after for every request, never a credential or a signature", async () => {
    const { out, report } = await run();
    const before = out.entries.filter((e) => e.phase === "before");
    const after = out.entries.filter((e) => e.phase === "after");
    assert.equal(before.length, after.length);
    assert.deepEqual(
      before.map((e) => e.n),
      after.map((e) => e.n),
    );
    assert.equal(
      before.length + out.entries.filter((e) => e.phase === "sdk-before").length,
      report.requests,
    );
    const sdk = out.entries.filter((e) => e.phase.startsWith("sdk-"));
    assert.equal(sdk.filter((e) => e.phase === "sdk-after").length, 2 * CASES.length);
    const text = JSON.stringify(out.entries);
    assert.ok(!/Bearer/i.test(text));
    assert.ok(!/X-Goog-Signature=[0-9a-f]{16}/.test(text));
    assert.ok(!/X-Goog-Credential=[^<]/.test(text));
    const put = before.find((e) => e.kind === "xml-put");
    assert.ok(put.url.includes("X-Goog-Signature=<redacted>") && put.case && put.recording);
    assert.ok(
      after.every((e) => typeof e.bodyBase64 === "string" && Number.isInteger(e.bodyBytes)),
    );
    assert.deepEqual(
      [...out.saved.keys()].filter((k) => k.startsWith("signed-url-")).length,
      2 * CASES.length,
    );
    assert.equal(out.saved.get("results.json").rows.length, 2 * CASES.length);
    assert.equal(out.saved.get("report.json").requests, report.requests);
  });

  it("journals a transport failure as unknown and saves the failure files", async () => {
    const { out } = await run({
      faults: {
        [`PUT /${PRODUCTION_LIKE.bucket}/${runPrefix(RUN)}rec1/ok-origin.png`]: "transport",
      },
    });
    assert.ok(out.entries.some((e) => e.phase === "unknown" && e.label === "1-ok-origin-put"));
    assert.match(out.saved.get("failure.json").message, /unknown answer/);
    assert.ok(out.saved.has("report.json"));
  });

  it("records the content of the positive control's reads and the preflight OPTIONS answer", async () => {
    const { reads } = await run();
    const meta = reads.find((r) => r.id === "ok" && r.step === "metadata" && r.recording === 1);
    assert.deepEqual(
      [meta.status, meta.metadata.size, meta.metadata.contentType, meta.metadata.bucket],
      [200, "4", "image/png", "<bucket>"],
    );
    assert.equal(meta.metadata.name, "storage-signed-put/<run>/rec1/ok.png");
    assert.ok(!("generation" in meta.metadata));
    const options = reads.filter((r) => r.step === "options");
    assert.equal(options.length, 2);
    assert.deepEqual(
      [options[0].status, options[0].code, options[0].id],
      [403, "AccessDenied", "ok-origin"],
    );
    assert.ok(options[0].bodyBytes > 0);
    for (const testCase of CASES.filter((c) => c.expect === "refuse")) {
      const steps = reads
        .filter((r) => r.id === testCase.id && r.recording === 1)
        .map((r) => r.step);
      assert.deepEqual(steps, ["absence"], testCase.id);
    }
    assert.deepEqual(
      reads
        .filter((r) => r.step === "absence")
        .map((r) => r.status)
        .filter((s) => s !== 404),
      [],
    );
  });

  it("marks the media read as different when the bytes differ", async () => {
    const { reads } = await run({
      mutateDeps: (deps) => ({
        ...deps,
        net: async (request) => {
          const res = await deps.net(request);
          if (request.url.includes("alt=media")) return { ...res, body: Buffer.from("other") };
          return res;
        },
      }),
    });
    assert.deepEqual(
      reads.filter((r) => r.step === "media").map((r) => r.equalsBody),
      [false, false],
    );
    const ok = await run();
    assert.deepEqual(
      ok.reads.filter((r) => r.step === "media").map((r) => r.equalsBody),
      [true, true],
    );
  });

  it("stops when the bucket or the signer is not the one expected, even on a 200", async () => {
    for (const [needle, body, pattern] of [
      [
        `/storage/v1/b/${PRODUCTION_LIKE.bucket}`,
        '{"name":"someone-elses"}',
        /bucket is not the expected one/,
      ],
      [
        "iam.googleapis.com",
        '{"email":"other@x.iam.gserviceaccount.com"}',
        /signer service account not readable/,
      ],
    ]) {
      const { report, world } = await run({
        mutateDeps: (deps) => ({
          ...deps,
          net: async (request) => {
            const res = await deps.net(request);
            const hit =
              needle === "iam.googleapis.com"
                ? request.url.includes(needle)
                : request.url.endsWith(needle);
            return hit ? { ...res, status: 200, body: Buffer.from(body) } : res;
          },
        }),
      });
      assert.match(report.stopped, pattern);
      assert.ok(!world.log.some((e) => e.method === "PUT"));
    }
    for (const status of [403, 404]) {
      const { report } = await run({
        mutateDeps: (deps) => ({
          ...deps,
          net: async (request) => {
            const res = await deps.net(request);
            return request.url.endsWith(`/storage/v1/b/${PRODUCTION_LIKE.bucket}`)
              ? { ...res, status }
              : res;
          },
        }),
      });
      assert.match(report.stopped, /bucket is not the expected one/);
    }
  });

  it("signs the shortest lifetime on a whole second at or before now, and the others for five minutes", async () => {
    const clock = createVirtualClock();
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
    const specs = [];
    const deps = {
      ...world.deps,
      sign: async (spec, meter) => {
        specs.push({ spec, at: clock.now() });
        return world.deps.sign(spec, meter);
      },
    };
    const putAt = [];
    const net = deps.net;
    deps.net = async (request) => {
      if (request.method === "PUT" && request.url.includes("/expired.png")) putAt.push(clock.now());
      return net(request);
    };
    await observe({ target: PRODUCTION_LIKE, runId: RUN, deps, out: memoryOut() });
    for (const { spec, at } of specs) {
      if (spec.accessibleAt === undefined) {
        assert.equal(spec.expires - at, 300_000);
      } else {
        assert.ok(
          spec.accessibleAt <= at && at - spec.accessibleAt < 1000,
          `${at} ${spec.accessibleAt}`,
        );
        assert.ok(spec.expires > at);
      }
    }
    specs
      .filter((s) => s.spec.accessibleAt !== undefined)
      .forEach(({ spec }, i) => {
        assert.ok(putAt[i] - (spec.expires + 2500) < 250 && putAt[i] >= spec.expires + 2500);
      });
  });

  it("stops without sending when the signer's URL does not carry the name it signed", async () => {
    const { report, world } = await run({
      mutateDeps: (deps) => ({
        ...deps,
        sign: async (spec, meter) =>
          (await deps.sign(spec, meter)).replace("other-object.png", "elsewhere.png"),
      }),
    });
    assert.match(report.stopped, /signed name not found/);
    assert.ok(!world.log.some((e) => e.method === "PUT" && e.url.includes("other-sent")));
    assert.deepEqual(report.unresolved, [], "a refused request is not an unknown create");
  });

  it("deletes by name an object the list does not show, when its create or read was confirmed", async () => {
    const hidden = `${runPrefix(RUN)}rec1/ok.png`;
    const clock = createVirtualClock();
    const world = createFakeWorld({
      target: PRODUCTION_LIKE,
      clock,
      hideFromList: new Set([hidden]),
    });
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
    });
    assert.equal(world.objects.size, 0);
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
  });

  it("deletes an object a refused PUT left behind once an own read shows it", async () => {
    const stray = `${runPrefix(RUN)}rec1/wrong-content-type.png`;
    const clock = createVirtualClock();
    const world = createFakeWorld({
      target: PRODUCTION_LIKE,
      clock,
      hideFromList: new Set([stray]),
    });
    const net = world.deps.net;
    const deps = {
      ...world.deps,
      net: async (request) => {
        const res = await net(request);
        if (
          request.method === "PUT" &&
          request.url.includes("/rec1/wrong-content-type.png") &&
          res.status === 403
        ) {
          world.objects.set(stray, {
            name: stray,
            generation: "9",
            body: Buffer.alloc(0),
            contentType: "x",
          });
        }
        return res;
      },
    };
    const { report, reads } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps,
      out: memoryOut(),
    });
    assert.ok(
      reads.some(
        (r) =>
          r.step === "unexpected-object" &&
          r.name === "storage-signed-put/<run>/rec1/wrong-content-type.png",
      ),
    );
    assert.equal(world.objects.size, 0, "the read confirmed it, so cleanup deleted it by name");
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
  });

  it("treats an unknown signBlob answer as unknown and a refused one as a stop", async () => {
    const unknown = await run({ faults: { signBlob: 503 } });
    assert.deepEqual(unknown.report.unknownRequests, ["signBlob"]);
    assert.equal(unknown.report.closureReady, false);
    assert.equal(unknown.report.cleanupVerified, false);
    const refused = await run({ faults: { signBlob: 403 } });
    assert.deepEqual(refused.report.unknownRequests, []);
    assert.match(refused.report.stopped, /signBlob refused with 403/);
    assert.equal(refused.report.cleanupVerified, true);
    assert.equal(refused.rows.length, 0);
  });

  it("surfaces a non-unknown error during cleanup as a cleanup error", async () => {
    const { report } = await run({ caps: { main: 130, total: 104 } });
    assert.ok(report.cleanupError);
    assert.match(report.cleanupError, /budget/);
    assert.equal(report.closureReady, false);
  });

  it("keeps going after an unknown read-back and reports it", async () => {
    let afterDelete = false;
    const { report, world } = await run({
      mutateDeps: (deps) => ({
        ...deps,
        net: async (request) => {
          if (request.method === "DELETE") afterDelete = true;
          else if (afterDelete && request.method === "GET" && request.url.includes("/o/")) {
            afterDelete = false;
            return { status: 503, headers: {}, body: Buffer.alloc(0) };
          }
          return deps.net(request);
        },
      }),
    });
    assert.equal(report.cleanupError, null);
    assert.equal(report.closureReady, false);
    assert.ok(report.unknownRequests.includes("cleanup-readback"));
    assert.equal(world.objects.size, 0);
    assert.equal(report.cleanupVerified, false);
  });

  it("saves a cleanup failure file when the cleanup list is unreadable", async () => {
    let lists = 0;
    const { out, report } = await run({
      mutateDeps: (deps) => ({
        ...deps,
        net: async (request) => {
          if (request.method === "GET" && request.url.includes("/o?prefix=")) {
            lists += 1;
            if (lists === 2) return { status: 403, headers: {}, body: Buffer.from("{}") };
          }
          return deps.net(request);
        },
      }),
    });
    assert.match(out.saved.get("cleanup-failure.json").message, /cleanup list answered 403/);
    assert.match(report.cleanupError, /cleanup list answered 403/);
  });
});
