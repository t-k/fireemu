import assert from "node:assert/strict";
import test from "node:test";
import { compareCloudEventKeys } from "./compare.mjs";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { createRequire } from "node:module";
import { hManifest, hPublishes } from "./h-script.mjs";
import { hCapture, judgeH } from "./h-capture.mjs";
import { hManifestProblems, hReady, runHCli } from "./h-deploy.mjs";
import { hProductionAnswer, hProductionEvidence } from "./h-production.mjs";
import { recordH, hA2 } from "./h-record.mjs";

const recorded = JSON.parse(
  readFileSync(new URL("./fixtures/h-fe/h-readiness.json", import.meta.url)),
);
const object = recorded.find((r) => r.run === "H1-v5" && r.case === "object");
const a = hManifest({ project: "demo-eventarc-h", runId: "faceabcdefab", recording: "h2-a" });

test("H2 freezes independent executions, segments, meters and a thirteen dollar reserve", () => {
  const b = hManifest({ project: a.project, runId: "deafabcdefab", recording: "h2-b" });
  assert.equal(a.recording, "h2-a");
  assert.equal(b.recording, "h2-b");
  assert.equal(a.functions.length, 7);
  assert.equal(b.functions.length, 6);
  assert.equal(a.reserveUsd, 7);
  assert.equal(b.reserveUsd, 6);
  assert.deepEqual(a.limits, {
    preflight: 69,
    readiness: 7210,
    publish: 97,
    capture: 500,
    cleanup: 672,
    a2: 105,
  });
  assert.deepEqual(b.limits, { ...a.limits, readiness: 6165, cleanup: 591 });
  assert.deepEqual(a.functions.find((f) => f.segment === "source").filters, {
    source: a.source,
    tenant: a.tenant,
  });
  assert.equal(a.functions.find((f) => f.segment === "source").type, a.type);
  assert.ok(!b.functions.some((f) => f.segment === "source"));
  assert.throws(() => hManifest({ project: a.project, recording: "h2-c" }));
  assert.equal(a.wallMs, 9 * 60 * 60_000);
});

test("H2 retains all original subjects and freezes ninety-seven publications and paired isolation controls", () => {
  const plan = hPublishes(a);
  assert.equal(plan.length, 97);
  assert.equal(plan.filter((p) => p.segment === "core").length, 67);
  assert.equal(plan.filter((p) => p.segment === "extension").length, 12);
  assert.equal(plan.filter((p) => p.segment === "multi").length, 18);
  const original = hPublishes(hManifest({ project: a.project, runId: a.runId }));
  assert.deepEqual(
    plan.filter((p) => original.some((q) => q.case === p.case)).map((p) => p.case),
    original.map((p) => p.case),
  );
  for (const name of [
    "scalar",
    "null",
    "binary",
    "text",
    "isolation-default",
    "isolation-named",
    "extension-match",
    "extension-wrong-type",
    "extension-wrong-tenant",
    "extension-missing-tenant",
    "multi-match",
    "multi-wrong-type",
    "multi-wrong-tenant",
    "multi-missing-tenant",
    "multi-wrong-subject",
    "multi-missing-subject",
  ]) {
    const p = plan.find((p) => p.case === name);
    assert.equal(p.windowMs, 120_000, name);
    assert.equal(p.bracket, name);
    assert.equal(
      plan.filter((q) => q.bracket === name && q.control && q.position === "before").length,
      name.startsWith("isolation") ? 2 : 1,
    );
    assert.equal(
      plan.filter((q) => q.bracket === name && q.control && q.position === "after").length,
      name.startsWith("isolation") ? 2 : 1,
    );
  }
  const ids = plan.flatMap((p) => (p.body?.events ?? p.events).map((e) => e.id).filter(Boolean));
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(
    plan.reduce(
      (sum, p) => sum + (p.control ? p.controlWaitMs : (p.windowMs ?? 0)),
      a.propagationMs + 120_000,
    ),
    185 * 60_000,
  );
});

test("H2 judges every new case with recorded H1 object frames and declared synthetic variants", () => {
  const plan = hPublishes(a);
  let clock = 0;
  const observations = plan
    .filter((p) => p.bracket)
    .map((p) => {
      const sentAt = clock;
      clock += (p.control ? p.controlWaitMs : p.windowMs) + 1;
      return {
        ...p,
        known: true,
        status: p.refused ? 400 : 200,
        sentAt,
        endedAt: clock - 1,
        before: true,
        after: true,
      };
    });
  const frames = observations.flatMap((p) =>
    p.expectedRecipients.map((r, i) => {
      const e = p.body.events.find((e) => e.id === r.id);
      const event = {
        ...object.handlerFrames[0].frame.event,
        id: e.id,
        source: e.source,
        type: e.type,
        time: e.attributes.time.ceTimestamp,
        subject: e.attributes.subject?.ceString,
        tenant: e.attributes.tenant?.ceString,
        data:
          p.case === "binary"
            ? { type: "Buffer", data: [...Buffer.from(e.binaryData, "base64")] }
            : p.case === "text"
              ? e.textData
              : JSON.parse(e.textData),
      };
      if (!e.attributes.subject) delete event.subject;
      if (!e.attributes.tenant) delete event.tenant;
      return {
        insertId: `${p.case}-${i}`,
        logTimestamp: new Date(1000).toISOString(),
        readAt: new Date(2000).toISOString(),
        frame: {
          ...object.handlerFrames[0].frame,
          handler: r.handler,
          run: a.runId,
          recording: a.recording,
          case: p.case,
          correlation: { id: e.id, source: e.source },
          event,
          eventKeys: Object.keys(event),
        },
      };
    }),
  );
  const capture = {
    complete: true,
    finalRead: true,
    frames,
    origins: a.functions
      .filter((f) => f.segment !== "source")
      .map((f) => ({ handler: f.name, service: f.name.toLowerCase(), location: a.location })),
  };
  assert.equal(judgeH({ manifest: a, observations, capture }).complete, true);
  for (const p of observations.filter((p) => !p.control)) {
    const result = judgeH({ manifest: a, observations, capture }).observations.find(
      (o) => o.case === p.case,
    );
    assert.equal(result.complete, true, p.case);
    if (p.expectedRecipients.length && !p.shape) {
      const missing = {
        ...capture,
        frames: frames.filter((f) => f.frame.event.id !== p.body.events[0].id),
      };
      assert.equal(
        judgeH({ manifest: a, observations, capture: missing }).observations.find(
          (o) => o.case === p.case,
        ).complete,
        false,
        p.case,
      );
    }
    const foreign = structuredClone(
      frames.find((f) => f.frame.case === `${p.bracket}-before`) ?? frames[0],
    );
    foreign.frame.event.id = p.body.events[0].id;
    foreign.frame.event.source = p.body.events[0].source;
    foreign.frame.handler =
      p.case === "isolation-default"
        ? a.named
        : p.case === "isolation-named"
          ? a.observe
          : a.filtered;
    assert.equal(
      judgeH({
        manifest: a,
        observations,
        capture: { ...capture, frames: [...frames, foreign] },
      }).observations.find((o) => o.case === p.case).complete,
      false,
      p.case,
    );
  }
  for (const name of ["scalar", "null", "binary", "text"]) {
    const p = observations.find((p) => p.case === name);
    const absent = {
      ...capture,
      frames: frames.filter((f) => f.frame.event.id !== p.body.events[0].id),
    };
    const result = judgeH({ manifest: a, observations, capture: absent }).observations.find(
      (o) => o.case === name,
    );
    assert.equal(result.outcome, "bounded-non-delivery", name);
    assert.equal(result.complete, true);
    const changed = observations.map((o) =>
      o.case === name ? { ...o, endedAt: o.sentAt + 119_999 } : o,
    );
    assert.equal(
      judgeH({ manifest: a, observations: changed, capture: absent }).observations.find(
        (o) => o.case === name,
      ).complete,
      false,
    );
    const later = structuredClone(frames.filter((f) => f.frame.event.id === p.body.events[0].id));
    for (const frame of later) frame.readAt = new Date(p.endedAt + 60_000).toISOString();
    assert.equal(
      judgeH({
        manifest: a,
        observations,
        capture: { ...absent, frames: [...absent.frames, ...later] },
      }).observations.find((o) => o.case === name).outcome,
      "delivered-shape",
    );
  }
  for (const missing of [[], capture.origins.filter((o) => o.handler !== a.named)]) {
    assert.equal(
      judgeH({ manifest: a, observations, capture: { ...capture, origins: missing } }).complete,
      false,
    );
  }
  const shortControl = observations.map((o) =>
    o.case === "scalar-before" ? { ...o, endedAt: o.sentAt + 119_999 } : o,
  );
  assert.equal(
    judgeH({ manifest: a, observations: shortControl, capture }).observations.find(
      (o) => o.case === "scalar",
    ).complete,
    false,
  );
  const missingControl = frames.filter((f) => f.frame.case !== "scalar-before");
  assert.equal(
    judgeH({
      manifest: a,
      observations,
      capture: { ...capture, frames: missingControl },
    }).observations.find((o) => o.case === "scalar").complete,
    false,
  );
  const wrongBytes = structuredClone(frames);
  wrongBytes.find((f) => f.frame.case === "binary").frame.event.data = {
    type: "Buffer",
    data: [0, 1, 2, 254],
  };
  assert.equal(
    judgeH({ manifest: a, observations, capture: { ...capture, frames: wrongBytes } }).complete,
    false,
  );
  const missingTrace = structuredClone(frames);
  delete missingTrace.find((f) => f.frame.case === "scalar").frame.event.traceparent;
  assert.equal(
    judgeH({ manifest: a, observations, capture: { ...capture, frames: missingTrace } }).complete,
    false,
  );
  const changedData = structuredClone(frames);
  changedData.find((f) => f.frame.case === "scalar").frame.event.data = "1";
  assert.equal(
    judgeH({ manifest: a, observations, capture: { ...capture, frames: changedData } }).complete,
    false,
  );
  assert.equal(
    judgeH({ manifest: a, observations, capture: { ...capture, finalRead: false } }).complete,
    false,
  );
});

test("H2 records canonical native refusals and does not relabel accepted non-delivery", () => {
  for (const r of recorded.filter((r) => r.run === "H1-v5" || r.run === "H1-v4")) {
    const url = new URL(r.url);
    const spec = {
      host:
        r.run === "H1-v4" || r.case === "function-create"
          ? "functions"
          : r.case === "empty-logging"
            ? "logging"
            : "publishing",
      method: r.method,
      path: url.pathname + url.search,
    };
    assert.equal(hProductionAnswer(r, spec), true, r.case);
    if (spec.host === "publishing")
      assert.equal(hProductionEvidence.publish(r, spec), true, r.case);
    assert.equal(hProductionAnswer({ ...r, bodyBytes: r.bodyBytes + 1 }, spec), false);
  }
  const plan = hPublishes(a);
  const p = plan.find((p) => p.case === "binary");
  const observations = plan
    .filter((p) => p.bracket === "binary")
    .map((p, i) => ({
      ...p,
      known: true,
      status: p.control ? 200 : 400,
      sentAt: i * 120_000,
      endedAt: (i + 1) * 120_000,
      before: true,
      after: true,
    }));
  const frames = observations
    .filter((p) => p.control)
    .flatMap((p) =>
      p.expectedRecipients.map((r) => ({
        frame: {
          handler: r.handler,
          event: {
            ...object.handlerFrames[0].frame.event,
            ...r,
            type: p.body.events.find((e) => e.id === r.id).type,
            source: r.source,
            tenant: a.tenant,
            subject: p.case,
            data: { probe: true },
          },
        },
      })),
    );
  assert.equal(
    judgeH({
      manifest: a,
      observations,
      capture: {
        complete: true,
        finalRead: true,
        frames,
        origins: a.functions
          .filter((f) => f.segment !== "source")
          .map((f) => ({ handler: f.name, service: f.name.toLowerCase(), location: a.location })),
      },
    }).observations.find((o) => o.case === p.case).outcome,
    "refused-shape",
  );
  assert.equal(
    judgeH({
      manifest: a,
      observations: observations.map((o) => (o.control ? o : { ...o, known: false })),
      capture: {
        complete: true,
        finalRead: true,
        frames,
        origins: a.functions
          .filter((f) => f.segment !== "source")
          .map((f) => ({ handler: f.name, service: f.name.toLowerCase(), location: a.location })),
      },
    }).complete,
    false,
  );
});

test("H2 native capability answers bind the complete request, layout and own operation target", () => {
  const refusal = recorded.find((r) => r.case === "source-refusal");
  const accepted = recorded.find((r) => r.case === "function-create");
  for (const segment of ["core", "extension", "multi", "source"]) {
    const f = a.functions.find((f) => f.segment === segment);
    const full = `projects/${a.project}/locations/${a.location}/functions/${f.name}`;
    const address = `https://cloudfunctions.googleapis.com/v2/projects/${a.project}/locations/${a.location}/functions`;
    const request = {
      buildConfig: { runtime: "nodejs22" },
      serviceConfig: { minInstanceCount: 0, maxInstanceCount: 2 },
      name: full,
      eventTrigger: {
        eventType: f.type,
        retryPolicy: f.retry ? "RETRY_POLICY_RETRY" : "RETRY_POLICY_DO_NOT_RETRY",
        channel: f.channel,
        eventFilters: Object.entries(f.filters).map(([attribute, value]) => ({ attribute, value })),
      },
    };
    for (const status of segment === "core" ? [200] : [200, 400]) {
      const body = structuredClone((status === 400 ? refusal : accepted).body);
      if (status === 400)
        body.error.message = body.error.message
          .replace(/projects\/[^/]+/, `projects/${a.project}`)
          .replace(/'source'/g, `'${Object.keys(f.filters)[0]}'`);
      else {
        body.metadata.target = full;
        body.name = body.name.replace(/projects\/[^/]+/, `projects/${a.project}`);
      }
      const native = [
        {
          kind: "cli-native-issued",
          value: {
            id: "native-create",
            host: "cloudfunctions.googleapis.com",
            method: "POST",
            path: new URL(address).pathname,
          },
        },
        {
          kind: "cli-native-body",
          value: {
            id: "native-create",
            bodyBase64: Buffer.from(JSON.stringify(request)).toString("base64"),
          },
        },
        {
          kind: "cli-native-answer",
          value: {
            id: "native-create",
            status,
            bodyBase64: Buffer.from(`${JSON.stringify(body, null, 2)}\n`).toString("base64"),
          },
        },
      ];
      const deployed = {
        stdout: `[apiv2][query] POST ${address} functionId=${f.name}\n>>> [apiv2][body] POST ${address} ${JSON.stringify(request)}\n`,
        native,
      };
      const judged = hProductionEvidence.cliWrites(deployed, a, f.name);
      assert.equal(judged.complete, true, `${segment}:${status}`);
      assert.equal(judged.refusal, status === 400);
      assert.deepEqual(judged.native.request, request);
      assert.equal(
        judged.native.bodyBytes,
        Buffer.from(native[2].value.bodyBase64, "base64").length,
      );
      assert.equal(judged.function.state, status === 400 ? "unknown" : "pending");
      for (const change of [
        (d) => d.native.pop(),
        (d) => (d.native[1].value.bodyBase64 = Buffer.from("{}").toString("base64")),
        (d) =>
          (d.native[2].value.bodyBase64 = Buffer.from(JSON.stringify(body)).toString("base64")),
        (d) => (d.native[2].value.status = 503),
      ]) {
        const bad = structuredClone(deployed);
        change(bad);
        assert.equal(hProductionEvidence.cliWrites(bad, a, f.name).complete, false);
      }
      const wrong = structuredClone(request);
      wrong.eventTrigger.eventFilters.push({ attribute: "unowned", value: "wrong" });
      assert.equal(
        hProductionEvidence.cliWrites(
          {
            ...deployed,
            stdout: deployed.stdout.replace(JSON.stringify(request), JSON.stringify(wrong)),
          },
          a,
          f.name,
        ).complete,
        false,
      );
      const wrongNative = structuredClone(native);
      wrongNative[1].value.bodyBase64 = Buffer.from(JSON.stringify(wrong)).toString("base64");
      assert.equal(
        hProductionEvidence.cliWrites(
          {
            ...deployed,
            stdout: deployed.stdout.replace(JSON.stringify(request), JSON.stringify(wrong)),
            native: wrongNative,
          },
          a,
          f.name,
        ).complete,
        false,
      );
      if (status === 200) {
        const wrongTarget = structuredClone(native);
        wrongTarget[2].value.bodyBase64 = Buffer.from(
          `${JSON.stringify({ ...body, metadata: { ...body.metadata, target: `${full}-foreign` } }, null, 2)}\n`,
        ).toString("base64");
        assert.equal(
          hProductionEvidence.cliWrites({ ...deployed, native: wrongTarget }, a, f.name).complete,
          false,
        );
      }
    }
  }
});

test("H2 owned CLI captures the emitted CREATE bytes before native send", async () => {
  const dir = mkdtempSync(join(tmpdir(), "h2-native-body-"));
  try {
    const journal = join(dir, "issued.jsonl");
    writeFileSync(journal, "");
    const bootstrap = join(dir, "bootstrap.cjs");
    writeFileSync(
      bootstrap,
      `const { EventEmitter } = require('node:events');
const fs = require('node:fs');
require('node:https').request = () => {
  const req = new EventEmitter();
  Object.assign(req, { host: 'cloudfunctions.googleapis.com', method: 'POST', path: '/v2/projects/demo-eventarc-h/locations/us-central1/functions' });
  req.write = () => true;
  req.end = () => {
    const rows = fs.readFileSync(process.env.EVENTARC_H_ISSUED_JOURNAL, 'utf8').trim().split('\\n').map(JSON.parse);
    if (rows.at(-1).kind !== 'cli-native-body') throw Error('body was not durable before send');
    if (Buffer.from(rows.at(-1).value.bodyBase64, 'base64').toString() !== '{"name":"owned"}') throw Error('body bytes differ');
    queueMicrotask(() => { const res = new EventEmitter(); res.statusCode = 400; req.emit('response', res); res.emit('data', Buffer.from('{"error":{"code":400}}')); res.emit('end'); });
  };
  return req;
};`,
    );
    const result = await runHCli({
      node: process.execPath,
      firebaseJs: "--input-type=commonjs",
      issuedPath: journal,
      plan: {
        cwd: dir,
        env: {
          PATH: process.env.PATH,
          EVENTARC_H_RECORDING: "h2-a",
          NODE_OPTIONS: `--require=${bootstrap}`,
        },
        args: [
          "-e",
          `const req=require('node:https').request();req.write('{"name":');req.end('"owned"}');console.log('1 Functions Errored');`,
        ],
      },
      save: () => {},
    });
    assert.equal(result.exitCode, 0);
    const rows = readFileSync(journal, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(
      rows.map((r) => r.kind),
      ["cli-native-issued", "cli-native-body", "cli-native-answer"],
    );
    assert.equal(new Set(rows.map((r) => r.value.id)).size, 1);
    assert.equal(rows[2].value.status, 400);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H2 capture caps all overlapping pages and final reads at five hundred", async () => {
  let clock = 0;
  const empty = recorded.find(
    (r) => r.status === 200 && r.url?.includes("logging.googleapis.com") && !r.body.entries,
  );
  const capture = hCapture({
    manifest: a,
    origins: [],
    startedAt: 0,
    now: () => clock,
    saveFrame: () => {},
    transport: {
      request: async () => {
        clock += object.latencyMs;
        return empty;
      },
    },
  });
  for (let i = 0; i < 500; i++) await capture.poll();
  assert.equal(capture.result().complete, false);
  for (let i = 0; i < 10; i++) await capture.poll();
  await capture.finish();
  assert.equal(capture.result().requests, 500);
  assert.equal(capture.result().complete, false);
  assert.equal(capture.result().finalRead, false);
});

test("H2 selected fixture segments preserve discovery filters and non-retrying fan-out", () => {
  const source = readFileSync(
    new URL("../../eventarc-functions/index.js", import.meta.url),
    "utf8",
  );
  for (const segment of ["core", "extension", "multi", "source"]) {
    const exports = {};
    vm.runInNewContext(source, {
      exports,
      process: {
        env: {
          EVENTARC_H_RUN_ID: a.runId,
          EVENTARC_H_RECORDING: a.recording,
          EVENTARC_H_SEGMENT: segment,
          GCLOUD_PROJECT: a.project,
        },
      },
      require: (id) =>
        id === "firebase-functions/v2/eventarc"
          ? { onCustomEventPublished: (options, handler) => ({ options, handler }) }
          : id === "firebase-admin/app"
            ? {}
            : id === "firebase-admin/firestore"
              ? {}
              : createRequire(import.meta.url)(id),
    });
    const expected = a.functions.filter((f) => f.segment === segment);
    assert.deepEqual(Object.keys(exports).sort(), expected.map((f) => f.name).sort());
    const endpoints = Object.fromEntries(
      expected.map((f) => [
        f.name,
        {
          platform: "gcfv2",
          region: [a.location],
          minInstances: 0,
          maxInstances: 2,
          eventTrigger: {
            eventType: exports[f.name].options.eventType,
            eventFilters: exports[f.name].options.filters ?? {},
            retry: exports[f.name].options.retry,
            channel: exports[f.name].options.channel ?? "locations/us-central1/channels/firebase",
          },
        },
      ]),
    );
    assert.deepEqual(hManifestProblems(endpoints, { ...a, segment }), []);
    if (segment === "source")
      assert.deepEqual(JSON.parse(JSON.stringify(exports[expected[0].name].options.filters)), {
        source: a.source,
        tenant: a.tenant,
      });
  }
});

test("H2 observes recorded retry latencies without rewriting the original H1 judge", () => {
  const attempts = object.handlerFrames.filter((f) => f.frame.case === "retry");
  const h1 = hManifest({ project: a.project, runId: "2ad53563e61c" });
  const sentAt = Date.parse(attempts[0].logTimestamp) - 1000;
  const old = {
    case: "retry",
    known: true,
    status: 200,
    sentAt,
    endedAt: sentAt + 600_000,
    before: true,
    after: true,
    retryHandler: h1.observe,
    candidates: [attempts[0].frame.event],
  };
  assert.equal(
    judgeH({
      manifest: h1,
      observations: [old],
      capture: { complete: true, finalRead: true, frames: attempts },
    }).complete,
    false,
  );
  const m = hManifest({ project: a.project, runId: h1.runId, recording: "h2-b" });
  const p = hPublishes(m).find((p) => p.retry);
  const event = JSON.parse(p.body.events[0].textData);
  const frames = attempts.map((f) => ({
    ...f,
    frame: {
      ...f.frame,
      recording: m.recording,
      event: { ...f.frame.event, id: p.body.events[0].id, data: event },
    },
  }));
  frames.push({
    ...frames[1],
    frame: { ...frames[1].frame, handler: m.fanout, invocationId: "fanout-success" },
  });
  const observation = {
    ...p,
    known: true,
    status: 200,
    sentAt,
    endedAt: sentAt + 600_000,
    retryHandler: m.observe,
  };
  const capture = {
    complete: true,
    finalRead: true,
    frames,
    origins: m.functions
      .filter((f) => f.segment !== "source")
      .map((f) => ({ handler: f.name, service: f.name.toLowerCase(), location: m.location })),
  };
  assert.equal(judgeH({ manifest: m, observations: [observation], capture }).complete, true);
  for (const mutate of [
    (f) => (f[1].frame.invocationId = f[0].frame.invocationId),
    (f) => (f[1].frame.event.data.case = "changed"),
    (f) => (f[1].logTimestamp = new Date(sentAt + 600_001).toISOString()),
    (f) => (f[1].readAt = new Date(sentAt + 600_001).toISOString()),
  ]) {
    const bad = structuredClone(frames);
    mutate(bad);
    assert.equal(
      judgeH({ manifest: m, observations: [observation], capture: { ...capture, frames: bad } })
        .complete,
      false,
    );
  }
});

test("H2 serial orchestration holds windows, caps and cleanup ownership with recorded latencies", async (t) => {
  for (const scenario of [
    "accepted-b",
    "pending-delete",
    "extension-refusal",
    "refused-no-settlement",
    "preexisting-named",
    "source-refusal",
    "source-accepted",
    "refused-deploy",
    "unknown-create",
    "unknown-delete",
    "partial-cleanup",
    "wrong-marker",
    "unadmitted-segment",
    "slow-requests",
    "preflight-wall",
    "named-unknown-create",
  ])
    await t.test(scenario, async () => {
      const m = hManifest({
        project: a.project,
        runId: a.runId,
        recording: scenario.startsWith("source-") ? "h2-a" : "h2-b",
      });
      let clock = Date.parse("2026-10-07T00:00:00Z");
      const start = clock;
      let marker;
      let sequence = 0;
      let readinessRounds = 0;
      let closedSdk = false;
      const functions = new Map();
      const channels = new Map();
      const operations = new Map();
      const entries = [];
      const calls = [];
      const cliCalls = [];
      const notes = [];
      const admissions = [];
      if (scenario === "preexisting-named")
        channels.set(m.namedChannel, {
          name: m.namedChannel,
          state: "ACTIVE",
          pubsubTopic: `projects/${m.project}/topics/preexisting-named`,
        });
      const options = {
        manifest: m,
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
        },
        note: (kind, value) => notes.push({ kind, value: structuredClone(value) }),
        saveFrame: () => {},
        transports: Object.fromEntries(
          [
            "usage",
            "artifact",
            "firestore",
            "functions",
            "run",
            "eventarc",
            "pubsub",
            "publishing",
            "logging",
          ].map((host) => [
            host,
            {
              request: async (spec) => {
                calls.push({ host, ...spec, at: clock });
                clock += scenario === "slow-requests" ? 30_000 : object.latencyMs;
                if (scenario === "preflight-wall" && calls.length === 1)
                  clock = start + m.wallMs - m.cleanupReserveMs - 29_999;
                if (
                  scenario === "slow-requests" &&
                  spec.label?.case === "h-readiness" &&
                  spec.path.endsWith("/functions") &&
                  ++readinessRounds % 40 !== 39
                )
                  return { status: 200, body: {} };
                if (host === "usage")
                  return {
                    status: 200,
                    body: {
                      services: [
                        "artifactregistry",
                        "cloudbuild",
                        "cloudfunctions",
                        "cloudresourcemanager",
                        "eventarc",
                        "eventarcpublishing",
                        "firestore",
                        "logging",
                        "pubsub",
                        "run",
                        "storage",
                      ].map((api) => ({
                        name: `projects/${"123456".repeat(2)}/services/${api}.googleapis.com`,
                        state: "ENABLED",
                        config: { name: `${api}.googleapis.com` },
                      })),
                    },
                  };
                if (host === "artifact")
                  return {
                    status: 200,
                    body: spec.path.includes("/packages")
                      ? {}
                      : { cleanupPolicies: { existing: {} } },
                  };
                if (host === "logging") return { status: 200, body: { entries } };
                if (host === "firestore") {
                  if (spec.path.endsWith("databases/(default)"))
                    return {
                      status: 200,
                      body: { type: "FIRESTORE_NATIVE", locationId: m.location },
                    };
                  if (spec.method === "DELETE") {
                    marker = undefined;
                    return { status: 200, body: {} };
                  }
                  return marker
                    ? {
                        status: 200,
                        body: {
                          name: spec.path.slice(4),
                          fields: {
                            run: { stringValue: m.runId },
                            source: {
                              stringValue:
                                scenario === "wrong-marker" ? `${m.source}/foreign` : m.source,
                            },
                            eventId: { stringValue: marker },
                          },
                        },
                      }
                    : { status: 404, body: { error: { status: "NOT_FOUND" } } };
                }
                if (operations.has(spec.path.slice(4))) {
                  const operation = operations.get(spec.path.slice(4));
                  return {
                    status: 200,
                    body: {
                      name: spec.path.slice(4),
                      metadata: { target: operation.target },
                      done: clock - operation.at >= 120_000,
                    },
                  };
                }
                if (spec.path.endsWith("/functions"))
                  return {
                    status: 200,
                    body: { functions: [...functions.values()].map((f) => f.function) },
                  };
                if (spec.path.endsWith("/services"))
                  return {
                    status: 200,
                    body: { services: [...functions.values()].map((f) => f.service) },
                  };
                if (spec.path.endsWith("/triggers"))
                  return {
                    status: 200,
                    body: { triggers: [...functions.values()].map((f) => f.trigger) },
                  };
                if (spec.path.includes("/topics?"))
                  return {
                    status: 200,
                    body: {
                      topics: [...functions.values()]
                        .map((f) => ({ name: f.trigger.transport.pubsub.topic }))
                        .concat([...channels.values()].map((c) => ({ name: c.pubsubTopic }))),
                    },
                  };
                if (spec.path.includes("/subscriptions?")) {
                  if (scenario === "partial-cleanup" && spec.label?.case === "h-cleanup")
                    return { status: 503, body: {} };
                  return {
                    status: 200,
                    body: {
                      subscriptions: [...functions.values()].map((f) => ({
                        name: f.trigger.transport.pubsub.subscription,
                      })),
                    },
                  };
                }
                if (host === "eventarc" && spec.method === "POST") {
                  if (scenario === "named-unknown-create") return { status: 503, body: {} };
                  const c = {
                    name: spec.body.name,
                    state: "ACTIVE",
                    pubsubTopic: `projects/${m.project}/topics/named-channel-topic`,
                  };
                  channels.set(c.name, c);
                  return {
                    status: 200,
                    body: {
                      name: `projects/${m.project}/locations/${m.location}/operations/channel-create`,
                      metadata: { target: c.name },
                      done: true,
                    },
                  };
                }
                if (spec.method === "DELETE") {
                  const full = spec.path.slice(4);
                  if (host === "functions") {
                    if (scenario === "unknown-delete" && full.endsWith(m.multi))
                      return { status: 503, unknown: true, body: {} };
                    functions.delete(full.split("/").at(-1));
                  } else channels.delete(full);
                  const operation = `projects/${m.project}/locations/${m.location}/operations/delete-${++sequence}`;
                  if (scenario === "pending-delete" && full.endsWith(m.multi))
                    operations.set(operation, { at: clock, target: full });
                  return {
                    status: 200,
                    body: {
                      name: operation,
                      metadata: { target: full },
                      done: !operations.has(operation),
                    },
                  };
                }
                if (host === "eventarc" && spec.path.includes("/channels/"))
                  return channels.has(spec.path.slice(4))
                    ? { status: 200, body: channels.get(spec.path.slice(4)) }
                    : { status: 404, body: { error: { status: "NOT_FOUND" } } };
                if (host === "publishing") {
                  const events = spec.body.events;
                  const first = events[0];
                  const caseId = first.attributes.subject?.ceString;

                  if (caseId === "binary" || caseId === "text")
                    return recorded.find(
                      (r) => r.case === (caseId === "binary" ? "binary" : "text-refusal"),
                    );
                  if (events.length > 100 || events.some((e) => !e.type))
                    return { status: 400, body: { error: { status: "INVALID_ARGUMENT" } } };
                  for (const e of events) {
                    if (
                      !e.attributes.time ||
                      e.attributes.convbytes ||
                      ["scalar", "null"].includes(e.attributes.subject?.ceString)
                    )
                      continue;
                    for (const f of m.functions.filter(
                      (f) =>
                        functions.has(f.name) &&
                        f.channel === spec.path.slice(4).replace(":publishEvents", "") &&
                        f.type === e.type &&
                        Object.entries(f.filters).every(
                          ([key, value]) =>
                            (key === "source" ? e.source : e.attributes[key]?.ceString) === value,
                        ),
                    )) {
                      const event = {
                        id: e.id,
                        specversion: "1.0",
                        ...Object.fromEntries(
                          Object.entries(e.attributes)
                            .filter(([key]) => key !== "datacontenttype")
                            .map(([key, value]) => [key, value.ceString ?? value.ceTimestamp]),
                        ),
                        type: e.type,
                        source: e.source,
                        data: JSON.parse(e.textData),
                        traceparent: object.handlerFrames[0].frame.event.traceparent,
                      };
                      const retry = /^fe[a-f0-9]+-h-retry-/.test(e.id) && f.name === m.observe;
                      if (retry) marker = e.id;
                      for (const attempt of retry ? ["failed", "succeeded"] : ["succeeded"]) {
                        const frame = {
                          handler: f.name,
                          generation: 2,
                          run: m.runId,
                          recording: m.recording,
                          case: /^fe[a-f0-9]+-h-(.+)-\d+$/.exec(e.id)[1],
                          correlation: { id: e.id, source: e.source },
                          invocationId: `invocation-${++sequence}`,
                          attempt,
                          eventKeys: Object.keys(event),
                          event,
                        };
                        entries.push({
                          insertId: String(sequence),
                          timestamp: new Date(clock).toISOString(),
                          logName: `projects/${m.project}/logs/run.googleapis.com%2Fstdout`,
                          resource: {
                            type: "cloud_run_revision",
                            labels: {
                              project_id: m.project,
                              service_name: f.name.toLowerCase(),
                              location: m.location,
                            },
                          },
                          textPayload: `FE_EVENTS_FRAME ${JSON.stringify(frame)}`,
                        });
                      }
                    }
                  }
                  return { status: 200, body: {} };
                }
                return { status: 404, body: { error: { status: "NOT_FOUND" } } };
              },
            },
          ]),
        ),
        cli: async (name) => {
          cliCalls.push(name);
          clock += object.latencyMs;
          const f = m.functions.find((f) => f.name === name);
          if (
            (scenario === "unknown-create" || scenario === "refused-deploy") &&
            f.segment === "extension"
          )
            return {
              exitCode: scenario === "refused-deploy" ? 0 : 1,
              stdout: "1 Functions Errored\n",
              name,
            };
          if (
            (scenario === "source-refusal" && f.segment === "source") ||
            (["extension-refusal", "refused-no-settlement"].includes(scenario) &&
              f.segment === "extension")
          )
            return { exitCode: 1, name, stdout: "1 Functions Errored\n" };
          channels.set(m.channel, {
            name: m.channel,
            state: "ACTIVE",
            pubsubTopic: `projects/${m.project}/topics/default-channel-topic`,
          });
          const full = `projects/${m.project}/locations/${m.location}/functions/${name}`;
          const service = {
            name: `projects/${m.project}/locations/${m.location}/services/${name.toLowerCase()}`,
          };
          const trigger = {
            name: `projects/${m.project}/locations/${m.location}/triggers/${name.toLowerCase()}`,
            channel: f.channel,
            destination: { cloudFunction: full },
            eventFilters: [
              { attribute: "type", value: f.type },
              ...Object.entries(f.filters).map(([attribute, value]) => ({ attribute, value })),
            ],
            transport: {
              pubsub: {
                topic: `projects/${m.project}/topics/${name}`,
                subscription: `projects/${m.project}/subscriptions/${name}`,
              },
            },
          };
          functions.set(name, {
            service,
            trigger,
            function: {
              name: full,
              environment: "GEN_2",
              state: "ACTIVE",
              serviceConfig: { service: service.name, minInstanceCount: 0, maxInstanceCount: 2 },
              eventTrigger: {
                eventFilters: Object.entries(f.filters).map(([attribute, value]) => ({
                  attribute,
                  value,
                })),
                eventType: f.type,
                channel: f.channel,
                trigger: trigger.name,
                triggerRegion: m.location,
                retryPolicy: f.retry ? "RETRY_POLICY_RETRY" : "RETRY_POLICY_DO_NOT_RETRY",
              },
              buildConfig: {
                runtime: "nodejs22",
                build: `projects/${m.project}/locations/${m.location}/builds/${name}`,
                dockerRepository: `projects/${m.project}/locations/${m.location}/repositories/gcf-artifacts`,
                source: {
                  storageSource: { bucket: `gcf-v2-sources-${"123456".repeat(2)}-us-central1` },
                },
              },
            },
          });
          return { exitCode: 0, stdout: "0 Functions Errored\n", name };
        },
        evidence: {
          preflight: () => true,
          readiness: () => true,
          operation: () => true,
          logging: () => true,
          publish: () => true,
          notFound: (r) => r.status === 404,
          a2ListRuling: true,
          a2ChannelRuling: true,
          admitSegment: async ({ segment, settlement }) => {
            admissions.push({ segment, settlement });
            return (
              scenario !== "unadmitted-segment" &&
              !(scenario === "refused-no-settlement" && settlement)
            );
          },
          cliWrites: (deployed) => ({
            complete: true,
            function: { state: "unknown" },
            refusal:
              (scenario === "source-refusal" && deployed.name === m.sourceProbe) ||
              (["extension-refusal", "refused-no-settlement"].includes(scenario) &&
                deployed.name === m.extension),
            native:
              scenario === "source-refusal" && deployed.name === m.sourceProbe
                ? recorded.find((r) => r.case === "source-refusal")
                : { status: 200 },
            resources:
              deployed.name === m.observe
                ? [
                    {
                      name: m.channel,
                      action: "create",
                      host: "eventarc",
                      kind: "channel",
                      state: "unknown",
                    },
                  ]
                : [],
          }),
          retention: async () => ({ complete: true, atBaseline: true, resources: [] }),
        },
        makeSdk: async ({ transport }) => ({
          close: async () => {
            closedSdk = true;
          },
          publish: async (p) => {
            const e = p.events[0];
            await transport.request({
              method: "POST",
              path: `/v1/${m.channel}:publishEvents`,
              body: {
                events: [
                  {
                    id: e.id ?? `fe${m.runId}-h-sdk-generated-${++sequence}`,
                    source: e.source ?? "//generated/sdk",
                    type: e.type,
                    specVersion: "1.0",
                    attributes: {
                      time: { ceTimestamp: e.time ?? new Date(clock).toISOString() },
                      tenant: { ceString: e.tenant },
                      subject: { ceString: p.case },
                    },
                    textData: JSON.stringify(e.data),
                  },
                ],
              },
            });
            return {};
          },
        }),
      };
      const result = await recordH(options);
      for (const [phase, count] of Object.entries(result.counts))
        assert.ok(count <= m.limits[phase], phase);
      assert.ok(clock - start <= m.wallMs);
      assert.equal(new Set(cliCalls).size, cliCalls.length);
      const deletes = calls.filter((c) => c.method === "DELETE");
      assert.equal(new Set(deletes.map((c) => c.path)).size, deletes.length);
      assert.ok(deletes.every((c) => ["functions", "eventarc", "firestore"].includes(c.host)));
      if (["accepted-b", "pending-delete"].includes(scenario)) {
        assert.equal(result.stopped, null);
        assert.equal(result.publishes.length, 97);
        assert.equal(result.evidence.complete, true);
        assert.equal(result.cleanupReady, true);
        assert.equal(result.closureReady, true);
        assert.equal(cliCalls.length, 6);
        assert.equal(closedSdk, true);
        for (const p of result.publishes)
          assert.ok(p.endedAt - p.sentAt >= (p.control ? p.controlWaitMs : (p.windowMs ?? 0)));
        const ready = notes.filter((n) => n.kind === "h-readiness-lists").at(-1).value;
        const names = m.functions.map((f) => f.name);
        assert.equal(hReady({ manifest: m, ...ready, names }).ready, true);
        for (const mutate of [
          (r) => (r.triggers[0].channel = m.namedChannel),
          (r) => (r.triggers[0].eventFilters[0].value += ".wrong"),
          (r) => (r.functions[0].serviceConfig.maxInstanceCount = 3),
          (r) => (r.functions[0].buildConfig.runtime = "nodejs20"),
        ]) {
          const bad = structuredClone(ready);
          mutate(bad);
          assert.equal(hReady({ manifest: m, ...bad, names }).ready, false);
        }
        const channelsDeleted = deletes.filter((c) => c.host === "eventarc");
        assert.deepEqual(
          channelsDeleted.map((c) => c.path.slice(4)).sort(),
          [m.channel, m.namedChannel].sort(),
        );
        if (scenario === "pending-delete") {
          const reads = calls.filter((c) => c.path.includes("/operations/delete-"));
          assert.equal(reads.length, 25);
          assert.equal(reads.at(-1).at - reads[0].at, 120_000);
          assert.equal(new Set(reads.map((r) => r.path)).size, 1);
        }
        assert.equal(functions.size, 0);
        assert.equal(channels.size, 0);
      } else {
        assert.equal(result.closureReady, false);
        assert.ok(
          result.stopped || result.cleanup.unsettled.length || result.cleanup.unconfirmed.length,
        );
        if (scenario === "preexisting-named") {
          assert.equal(cliCalls.length, 0);
          assert.equal(deletes.length, 0);
          assert.equal(channels.size, 1);
        }
        if (scenario === "refused-no-settlement") {
          assert.equal(cliCalls.length, 5);
          assert.match(result.stopped, /multi needs coordinator admission/);
        }
        if (scenario === "extension-refusal") {
          assert.equal(admissions.find((gate) => gate.segment === "multi").settlement, "extension");
          assert.equal(cliCalls.length, 6);
          assert.equal(result.segments.find((s) => s.segment === "multi").status, "observed");
          assert.equal(result.publishes.filter((p) => p.segment === "extension").length, 0);
        }
        if (scenario === "source-refusal") {
          assert.equal(result.segments.at(-1).status, "native-refusal");
          assert.equal(
            result.writes.find((w) => w.name.endsWith(m.sourceProbe) && w.action === "create")
              .state,
            "unknown",
          );
        }
        if (scenario === "source-accepted") assert.match(result.stopped, /unexpectedly accepted/);
        if (scenario === "unadmitted-segment") assert.equal(cliCalls.length, 4);
        if (scenario === "refused-deploy") {
          assert.equal(cliCalls.length, 5);
          assert.match(result.stopped, /deploy failed/);
        }
        if (scenario === "named-unknown-create") assert.equal(cliCalls.length, 0);
        if (["unknown-delete", "partial-cleanup"].includes(scenario))
          assert.equal(deletes.filter((c) => c.host === "eventarc").length, 0);
        if (scenario === "wrong-marker")
          assert.equal(deletes.filter((c) => c.host === "firestore").length, 0);
        if (scenario === "preflight-wall") {
          assert.equal(result.counts.preflight, 1);
          assert.equal(calls.length, 1);
          assert.equal(cliCalls.length, 0);
          assert.match(result.stopped, /wall cap/);
        }
        if (scenario === "slow-requests") assert.match(result.stopped, /wall cap/);
      }
    });
});

test("H2 A2 separately settles both exact channel topics and keeps unknown creates and deletes open", async () => {
  for (const failure of [
    null,
    "already-clean",
    "prior-unknown-delete",
    "unknown-create",
    "unknown-delete",
    "foreign-topic",
    "late-a2",
    "missing-ruling",
    "wrong-marker",
  ]) {
    const m = hManifest({ project: a.project, runId: a.runId, recording: "h2-b" });
    let clock = 600_000;
    const calls = [];
    const topics = new Map([
      [m.channel, `projects/${m.project}/topics/exact-default`],
      [m.namedChannel, `projects/${m.project}/topics/exact-named`],
    ]);
    const channels = new Set(topics.keys());
    const recording = {
      manifest: m,
      startedAt: failure === "late-a2" ? -m.wallMs : 0,
      lastRequestAt: 0,
      stopped: "needs-review",
      evidence: { complete: false },
      identities: [],
      baselineLists: { functions: [], services: [], triggers: [], topics: [], subscriptions: [] },
      baseline: { status: 404 },
      namedBaseline: { status: 404 },
      channelTopics: Object.fromEntries(topics),
      cleanup: { unconfirmed: [], unsettled: [], retained: [] },
      writes: [...topics.keys()].map((name) => ({
        name,
        host: "eventarc",
        action: "create",
        state: failure === "unknown-create" && name === m.namedChannel ? "unknown" : "confirmed",
      })),
    };
    if (failure === "already-clean" || failure === "prior-unknown-delete") {
      channels.clear();
      for (const name of topics.keys())
        recording.writes.push({
          name,
          host: "eventarc",
          action: "delete",
          state:
            failure === "prior-unknown-delete" && name === m.namedChannel ? "unknown" : "confirmed",
        });
    }
    if (failure === "wrong-marker") {
      recording.marker = `projects/${m.project}/databases/(default)/documents/markers/retry`;
      recording.publishes = [{ retry: true, body: { events: [{ id: "owned-retry" }] } }];
      recording.writes.push({
        name: recording.marker,
        host: "firestore",
        action: "create",
        state: "confirmed",
      });
    }
    const result = await hA2({
      recording,
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      },
      note: () => {},
      evidence: {
        a2ListRuling: true,
        a2ChannelRuling: failure !== "missing-ruling",
        readiness: () => true,
        notFound: (r) => r.status === 404,
        operation: () => true,
        retention: async () => ({ complete: true, atBaseline: true }),
      },
      transports: Object.fromEntries(
        ["functions", "run", "eventarc", "pubsub", "firestore"].map((host) => [
          host,
          {
            request: async (spec) => {
              calls.push({ host, ...spec });
              clock += object.latencyMs;
              if (host === "firestore")
                return {
                  status: 200,
                  body: {
                    name: recording.marker,
                    fields: {
                      run: { stringValue: m.runId },
                      source: { stringValue: `${m.source}/foreign` },
                      eventId: { stringValue: "owned-retry" },
                    },
                  },
                };
              if (spec.path.includes("/topics?"))
                return {
                  status: 200,
                  body: {
                    topics: [...channels]
                      .map((name) => ({ name: topics.get(name) }))
                      .concat(
                        failure === "foreign-topic"
                          ? [{ name: `projects/${m.project}/topics/foreign` }]
                          : [],
                      ),
                  },
                };
              if (/(functions|services|triggers|subscriptions)(\?|$)/.test(spec.path))
                return { status: 200, body: {} };
              const name = spec.path.slice(4);
              if (spec.method === "DELETE") {
                if (failure === "unknown-delete" && name === m.namedChannel)
                  return { status: 503, body: {} };
                channels.delete(name);
                return {
                  status: 200,
                  body: {
                    name: `projects/${m.project}/locations/${m.location}/operations/delete-${name.split("/").at(-1)}`,
                    metadata: { target: name },
                    done: true,
                  },
                };
              }
              return channels.has(name) &&
                !(failure === "unknown-create" && name === m.namedChannel)
                ? { status: 200, body: { name, state: "ACTIVE", pubsubTopic: topics.get(name) } }
                : { status: 404, body: { error: { status: "NOT_FOUND" } } };
            },
          },
        ]),
      ),
    });
    assert.ok(result.requests <= 105);
    assert.equal(result.closureReady, false);
    assert.equal(result.cleanupReady, failure === null || failure === "already-clean", failure);
    if (failure === "prior-unknown-delete")
      assert.equal(result.facts.find((f) => f.name === m.namedChannel).closed, false);
    if (failure === "wrong-marker")
      assert.equal(result.facts.find((f) => f.name === recording.marker).read, "unknown");
    const deletions = calls.filter((c) => c.method === "DELETE");
    assert.equal(new Set(deletions.map((c) => c.path)).size, deletions.length);
    assert.ok(deletions.every((c) => c.host === "eventarc"));
    if (failure === null) {
      assert.equal(deletions.length, 2);
      assert.equal(channels.size, 0);
    }
    if (["late-a2", "missing-ruling"].includes(failure)) assert.equal(calls.length, 0);
  }
});

test("CloudEvent keys compare as a set while their wire order remains unmodelled", () => {
  assert.deepEqual(
    compareCloudEventKeys(["id", "data", "traceparent"], ["data", "id", "traceparent"]),
    {
      verdict: "MATCH",
      order: "UNMODELLED",
      missing: [],
      extra: [],
    },
  );
  assert.deepEqual(compareCloudEventKeys(["id", "traceparent"], ["id"]), {
    verdict: "DIVERGES",
    order: "UNMODELLED",
    missing: ["traceparent"],
    extra: [],
  });
});
