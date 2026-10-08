import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";
import { hManifest, hPublishes } from "./eventarc-production/h-script.mjs";
import { parseHEntries, hLogRequest, judgeH } from "./eventarc-production/h-capture.mjs";
import { hDisposition, hUnknown } from "./eventarc-production/h-deploy.mjs";

const manifest = hManifest({ project: "demo-eventarc-h", runId: "012345abcdef" });
const event = {
  id: "fe012345abcdef-h-object-1",
  source: manifest.source,
  type: manifest.type,
  specversion: "1.0",
  data: null,
  tenant: manifest.tenant,
};
const frame = {
  handler: manifest.observe,
  generation: 2,
  run: manifest.runId,
  recording: "h1",
  case: "object",
  correlation: { id: event.id, source: event.source },
  invocationId: "attempt-1",
  attempt: "succeeded",
  eventKeys: Object.keys(event),
  event,
};
const entry = {
  insertId: "entry-1",
  timestamp: "2026-10-06T00:00:01.000000Z",
  logName: `projects/${manifest.project}/logs/run.googleapis.com%2Fstdout`,
  resource: {
    type: "cloud_run_revision",
    labels: {
      project_id: manifest.project,
      service_name: "actual-run-service",
      location: "us-central1",
    },
  },
  textPayload: `FE_EVENTS_FRAME ${JSON.stringify(frame)}`,
};
const origins = [
  { handler: manifest.observe, service: "actual-run-service", location: "us-central1" },
];

test("H freezes two run-owned functions and 48 unique publish attempts", () => {
  assert.equal(
    manifest.channel,
    "projects/demo-eventarc-h/locations/us-central1/channels/firebase",
  );
  assert.equal(manifest.observe, "fe012345abcdefHObserve");
  assert.equal(manifest.filtered, "fe012345abcdefHFiltered");
  const plan = hPublishes(manifest);
  assert.equal(plan.length, 48);
  assert.equal(plan.filter((p) => p.sdk).length, 5);
  const ids = plan.flatMap(
    (p) => p.body?.events.map((e) => e.id) ?? p.events.map((e) => e.id).filter(Boolean),
  );
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(plan.find((p) => p.case === "refused-101").body.events.length, 101);
  for (const name of ["refused-middle", "refused-first", "refused-last"]) {
    const events = plan.find((p) => p.case === name).body.events;
    assert.equal(events.filter((e) => !Object.hasOwn(e, "type")).length, 1);
  }
  for (const name of [
    "no-time",
    "ce-bytes",
    "wrong-type",
    "wrong-source",
    "wrong-tenant",
    "missing-tenant",
    "refused-101",
    "refused-middle",
    "refused-first",
    "refused-last",
  ]) {
    const index = plan.findIndex((p) => p.case === name);
    assert.equal(plan[index - 1].control, true);
    assert.equal(plan[index + 1].control, true);
    assert.equal(plan[index].windowMs, 120_000);
  }
  for (const caseId of ["no-time", "ce-bytes"])
    assert.deepEqual(plan.find((p) => p.case === caseId).negativeHandlers, [
      manifest.observe,
      manifest.filtered,
    ]);
  assert.equal(plan.find((p) => p.case === "retry").windowMs, 600_000);
  assert.throws(() => hManifest({ project: "demo-eventarc-h", runId: "bad" }));
});

test("H frame capture preserves absence, key order, full extensions and retries", () => {
  const seen = new Set();
  const options = { manifest, origins, readAt: "2026-10-06T00:00:02Z", seen };
  const first = parseHEntries({ entries: [entry] }, options);
  assert.equal(first.incomplete, false);
  assert.deepEqual(first.frames[0].frame.event, event);
  assert.equal(Object.hasOwn(first.frames[0].frame.event, "subject"), false);
  assert.equal(first.frames[0].text, entry.textPayload);
  assert.equal(parseHEntries({ entries: [entry] }, options).frames.length, 0);
  const retry = {
    ...entry,
    insertId: "entry-2",
    textPayload: entry.textPayload.replace("attempt-1", "attempt-2"),
  };
  assert.equal(parseHEntries({ entries: [retry] }, options).frames.length, 1);
  for (const bad of [
    { ...entry, insertId: undefined },
    {
      ...entry,
      resource: {
        type: "cloud_run_revision",
        labels: { ...entry.resource.labels, service_name: "foreign" },
      },
    },
    { ...entry, textPayload: "FE_EVENTS_FRAME broken" },
    { ...entry, textPayload: entry.textPayload.replace(manifest.runId, "ffffffffffff") },
  ]) {
    assert.equal(
      parseHEntries({ entries: [bad] }, { ...options, seen: new Set() }).incomplete,
      true,
    );
  }
  assert.equal(parseHEntries({ entries: "bad" }, options).incomplete, true);
  assert.equal(parseHEntries({}, options).incomplete, false);
  const request = hLogRequest({
    manifest,
    origins,
    start: "2026-10-06T00:00:00Z",
    end: "2026-10-06T00:00:02Z",
  });
  assert.match(request.body.filter, /actual-run-service/);
  assert.equal(request.body.pageSize, 200);
});

test("H applies checklist section 3 to every write class and never clears an unconfirmed create with 404", () => {
  for (const kind of ["function", "service", "trigger", "channel", "marker"]) {
    for (const mode of ["run", "a2"]) {
      assert.equal(
        hDisposition({ kind, create: "unknown", read: "absent", mode, ageMs: 600_000 }).closed,
        false,
      );
      assert.equal(
        hDisposition({ kind, create: "pending", read: "absent", mode, ageMs: 600_000 }).closed,
        false,
      );
    }
    assert.equal(
      hDisposition({ kind, create: "unknown", read: "present", mode: "run" }).confirmed,
      true,
    );
    assert.equal(
      hDisposition({ kind, create: "confirmed", read: "absent", mode: "run" }).closed,
      false,
    );
    assert.equal(
      hDisposition({ kind, create: "confirmed", read: "absent", mode: "a2", ageMs: 600_000 })
        .closed,
      true,
    );
    assert.equal(
      hDisposition({ kind, create: "confirmed", read: "absent", mode: "a2", ageMs: 599_999 })
        .closed,
      false,
    );
    for (const deletion of ["unknown", "pending"]) {
      assert.equal(
        hDisposition({ kind, create: "confirmed", deletion, read: "absent", mode: "run" }).closed,
        false,
      );
      assert.equal(
        hDisposition({ kind, create: "confirmed", deletion, read: "present", mode: "run" })
          .canDelete,
        false,
      );
      assert.equal(
        hDisposition({
          kind,
          create: "confirmed",
          deletion,
          read: "absent",
          mode: "a2",
          ageMs: 600_000,
        }).closed,
        true,
      );
    }
    assert.equal(
      hDisposition({
        kind,
        create: "confirmed",
        deletion: "confirmed",
        read: "absent",
        mode: "run",
      }).closed,
      true,
    );
    assert.equal(
      hDisposition({
        kind,
        create: "unknown",
        laterConflict: true,
        read: "absent",
        mode: "a2",
        ageMs: 600_000,
      }).closed,
      false,
    );
  }
  for (const status of [0, 199, 301, 500, 501, 503])
    assert.equal(hUnknown({ status, body: {} }), true);
  assert.equal(hUnknown({ status: 200, body: { raw: "unreadable" } }), true);
  assert.equal(hUnknown({ status: 200, body: {} }), false);
});

test("H handler retains native event members and writes a fail-once marker only for retry", async () => {
  const source = readFileSync(new URL("../eventarc-functions/index.js", import.meta.url), "utf8");
  const endpoints = {};
  const printed = [];
  const markers = new Map();
  let creates = 0;
  let transactions = 0;
  const db = {
    doc: (path) => ({ path }),
    runTransaction: async (fn, options) => {
      transactions++;
      assert.equal(options.maxAttempts, 3);
      return fn({
        get: async (ref) => ({ exists: markers.has(ref.path) }),
        create: (ref, data) => {
          creates++;
          markers.set(ref.path, data);
        },
      });
    },
  };
  const exports = {};
  const require = createRequire(import.meta.url);
  vm.runInNewContext(source, {
    exports,
    process: { env: { EVENTARC_H_RUN_ID: manifest.runId } },
    console: { log: (text) => printed.push(text) },
    Buffer,
    require: (name) => {
      if (name === "firebase-functions/v2/eventarc")
        return {
          onCustomEventPublished: (opts, fn) => {
            endpoints[Object.keys(endpoints).length] = opts;
            return fn;
          },
        };
      if (name === "firebase-admin/app") return { getApps: () => [], initializeApp: () => ({}) };
      if (name === "firebase-admin/firestore") return { getFirestore: () => db };
      return require(name);
    },
  });
  assert.deepEqual(
    Object.keys(exports).toSorted(),
    [manifest.filtered, manifest.observe].toSorted(),
  );
  assert.equal(endpoints[0].region, "us-central1");
  assert.equal(endpoints[0].retry, true);
  assert.equal(Object.hasOwn(endpoints[0], "channel"), false);
  assert.equal(Object.hasOwn(endpoints[0], "filters"), false);
  assert.equal(endpoints[0].minInstances, 0);
  assert.equal(endpoints[0].maxInstances, 2);
  assert.equal(endpoints[1].eventType, manifest.filteredType);
  assert.equal(Object.hasOwn(endpoints[1], "filters"), false);
  assert.equal(endpoints[1].retry, false);
  await exports[manifest.observe](event);
  assert.equal(transactions, 0);
  const ordinary = JSON.parse(printed[0].slice("FE_EVENTS_FRAME ".length));
  assert.deepEqual(ordinary.event, event);
  assert.deepEqual(ordinary.eventKeys, Object.keys(event));
  const retry = {
    ...event,
    id: "fe012345abcdef-h-retry-1",
    time: "2026-10-06T00:00:00.123456789Z",
    data: { fixtureKind: "retry", run: manifest.runId, recording: "h1", case: "retry" },
  };
  await assert.rejects(exports[manifest.observe](retry), /intentional/);
  await exports[manifest.observe](retry);
  await exports[manifest.filtered](retry);
  assert.equal(creates, 1);
  assert.equal(transactions, 2);
  assert.match([...markers.keys()][0], /^fe_h_012345abcdef\/[a-f0-9]{64}$/);
  const frames = printed.slice(1).map((text) => JSON.parse(text.slice("FE_EVENTS_FRAME ".length)));
  assert.deepEqual(
    frames.map((f) => f.attempt),
    ["failed", "succeeded", "succeeded"],
  );
  assert.deepEqual(frames[0].event, frames[1].event);
  assert.notEqual(frames[0].invocationId, frames[1].invocationId);
  await exports[manifest.observe]({ ...retry, source: `${manifest.source}/other` });
  assert.equal(creates, 1);
  assert.equal(transactions, 2);
});

test("H bounded negative evidence requires controls, a complete window and known publish answers", () => {
  const subject = {
    case: "wrong-tenant",
    candidates: [{ id: event.id, source: event.source }],
    negativeHandlers: [manifest.filtered],
    sentAt: 1000,
    endedAt: 121000,
    status: 200,
    before: true,
    after: true,
    known: true,
  };
  const capture = { complete: true, frames: [], finalRead: true };
  assert.equal(
    judgeH({ manifest, observations: [subject], capture }).observations[0].outcome,
    "bounded-non-delivery",
  );
  for (const change of [
    { before: false },
    { after: false },
    { endedAt: 120999 },
    { known: false },
  ]) {
    assert.equal(
      judgeH({ manifest, observations: [{ ...subject, ...change }], capture }).complete,
      false,
    );
  }
  assert.equal(
    judgeH({ manifest, observations: [subject], capture: { ...capture, complete: false } })
      .complete,
    false,
  );
  const late = { frame: { ...frame, handler: manifest.filtered }, readAt: "2099-01-01T00:00:00Z" };
  assert.equal(
    judgeH({ manifest, observations: [subject], capture: { ...capture, frames: [late] } })
      .observations[0].outcome,
    "delivered",
  );
});

test("H never treats refused or undelivered envelope cases as complete handler evidence", () => {
  const capture = { complete: true, frames: [], finalRead: true };
  for (const caseId of [
    "object",
    "scalar",
    "null",
    "array",
    "binary",
    "multi",
    "sdk-default",
    "sdk-full",
    "sdk-relative",
    "sdk-generated",
    "sdk-metadata",
  ]) {
    for (const status of [200, 400]) {
      const o = {
        case: caseId,
        candidates: [{ id: event.id, source: event.source, type: manifest.type }],
        status,
        known: true,
      };
      assert.equal(
        judgeH({ manifest, observations: [o], capture }).complete,
        false,
        `${caseId}/${status}`,
      );
    }
  }
});

test("H retry cannot close on attempts outside its 600-second window", () => {
  const o = {
    case: "retry",
    candidates: [{ id: event.id, source: event.source, type: manifest.type }],
    status: 200,
    known: true,
    retryHandler: manifest.observe,
    sentAt: 0,
    endedAt: 600000,
    windowMs: 600000,
    before: true,
    after: true,
  };
  const failed = {
    frame: { ...frame, attempt: "failed" },
    logTimestamp: new Date(900000).toISOString(),
    readAt: new Date(900001).toISOString(),
  };
  const success = {
    frame: { ...frame, invocationId: "attempt-2" },
    logTimestamp: new Date(900002).toISOString(),
    readAt: new Date(900003).toISOString(),
  };
  assert.equal(
    judgeH({
      manifest,
      observations: [o],
      capture: { complete: true, finalRead: true, frames: [failed, success] },
    }).complete,
    false,
  );
});

test("H fixture pins the FE runtime and dependencies without expanding infrastructure", () => {
  const pkg = JSON.parse(
    readFileSync(new URL("../eventarc-functions/package.json", import.meta.url), "utf8"),
  );
  const config = JSON.parse(
    readFileSync(new URL("../eventarc-functions/firebase.json", import.meta.url), "utf8"),
  );
  assert.equal(pkg.engines.node, "22");
  assert.deepEqual(pkg.dependencies, {
    "firebase-admin": "14.3.0",
    "firebase-functions": "7.3.2",
    "@google-cloud/functions-framework": "5.0.5",
  });
  assert.deepEqual(Object.keys(config), ["functions"]);
  assert.equal(config.functions.runtime, "nodejs22");
  assert.equal(config.functions.codebase, "eventarc-h");
});

test("H settlement satisfies its independent specification for all bounded state combinations", () => {
  for (const create of ["unknown", "pending", "confirmed", "failed"])
    for (const deletion of [undefined, "unknown", "pending", "confirmed", "failed"])
      for (const read of ["present", "absent", "unknown"])
        for (const mode of ["run", "a2"])
          for (const ageMs of [0, 599999, 600000, 600001]) {
            const f = hDisposition({ create, deletion, read, mode, ageMs });
            const confirmed =
              create === "confirmed" ||
              (["pending", "unknown"].includes(create) && read === "present");
            const closed =
              (create === "failed" && read === "absent") ||
              (confirmed &&
                read === "absent" &&
                (deletion === "confirmed" || (mode === "a2" && ageMs >= 600000)));
            assert.equal(f.closed, closed);
            if (deletion === "unknown" || deletion === "pending") assert.equal(f.canDelete, false);
            if (create === "unknown" && read === "absent") assert.equal(f.closed, false);
          }
});

test("H rejects an isolated run mismatch and retry timestamps beyond the window independently", () => {
  const wrongRun = {
    ...entry,
    textPayload: `FE_EVENTS_FRAME ${JSON.stringify({ ...frame, run: "ffffffffffff" })}`,
  };
  assert.equal(
    parseHEntries({ entries: [wrongRun] }, { manifest, origins, readAt: "2026-10-06T00:00:02Z" })
      .incomplete,
    true,
  );
  const subject = {
    case: "retry",
    candidates: [{ id: event.id, source: event.source, type: manifest.type }],
    status: 200,
    known: true,
    retryHandler: manifest.observe,
    sentAt: 0,
    endedAt: 600000,
    windowMs: 600000,
    before: true,
    after: true,
  };
  const failed = {
    frame: { ...frame, attempt: "failed" },
    logTimestamp: new Date(10).toISOString(),
    readAt: new Date(20).toISOString(),
  };
  const success = {
    frame: { ...frame, invocationId: "attempt-2" },
    logTimestamp: new Date(600001).toISOString(),
    readAt: new Date(600000).toISOString(),
  };
  assert.equal(
    judgeH({
      manifest,
      observations: [subject],
      capture: { complete: true, finalRead: true, frames: [failed, success] },
    }).complete,
    false,
  );
});

test("H generates a fresh run ID and pins caller-supplied recording identities", () => {
  const ids = new Set();
  for (let i = 0; i < 128; i++) {
    const current = hManifest({ project: "fireemu-oracle-events" });
    assert.match(current.runId, /^[a-f0-9]{12}$/);
    assert.equal(ids.has(current.runId), false);
    ids.add(current.runId);
    assert.equal(current.observe, `fe${current.runId}HObserve`);
    assert.equal(current.markerCollection, `fe_h_${current.runId}`);
    assert.equal(
      hManifest({ project: current.project, runId: current.runId }).runId,
      current.runId,
    );
  }
});

test("H pagination preserves recorded query fields, order and the phase meter", async () => {
  const { hReadList } = await import("./eventarc-production/h-deploy.mjs");
  for (let pages = 1; pages <= 5; pages++) {
    let count = 0;
    let meter = 0;
    const result = await hReadList(
      {
        request: async (spec) => {
          const url = new URL(spec.path, "https://offline.invalid");
          assert.equal(url.searchParams.get("filter"), "state:ENABLED");
          assert.equal(url.searchParams.get("pageSize"), "200");
          assert.equal(url.searchParams.get("pageToken"), count ? `page ${count}` : null);
          count++;
          return {
            status: 200,
            body: {
              services: [{ name: `item-${count}` }],
              ...(count < pages ? { nextPageToken: `page ${count}` } : {}),
            },
          };
        },
      },
      {
        path: "/v1/projects/demo/services?filter=state:ENABLED&pageSize=200",
        key: "services",
        phase: "preflight",
      },
      () => meter++,
    );
    assert.equal(meter, pages);
    assert.deepEqual(
      result.map((item) => item.name),
      Array.from({ length: pages }, (_, i) => `item-${i + 1}`),
    );
  }
});

test("H rejects recorded frame key order that differs from the native event", () => {
  const bad = {
    ...entry,
    textPayload: `FE_EVENTS_FRAME ${JSON.stringify({ ...frame, eventKeys: Object.keys(event).toReversed() })}`,
  };
  assert.equal(
    parseHEntries({ entries: [bad] }, { manifest, origins, readAt: "2026-10-06T00:00:02Z" })
      .incomplete,
    true,
  );
});

test("H each observation stays incomplete when the capture is incomplete", () => {
  const observation = {
    case: "wrong-tenant",
    candidates: [],
    negativeHandlers: [manifest.filtered],
    known: true,
    status: 200,
    before: true,
    after: true,
    sentAt: 0,
    endedAt: 120000,
  };
  assert.equal(
    judgeH({
      manifest,
      observations: [observation],
      capture: { complete: false, finalRead: true, frames: [] },
    }).observations[0].complete,
    false,
  );
});

test("H retry received after the window remains incomplete even with timely log timestamps", () => {
  const subject = {
    case: "retry",
    candidates: [{ id: event.id, source: event.source }],
    retryHandler: manifest.observe,
    known: true,
    status: 200,
    before: true,
    after: true,
    sentAt: 0,
    endedAt: 600000,
    windowMs: 600000,
  };
  const frames = [
    {
      frame: { ...frame, attempt: "failed" },
      logTimestamp: new Date(1).toISOString(),
      readAt: new Date(2).toISOString(),
    },
    {
      frame: { ...frame, invocationId: "attempt-2", attempt: "succeeded" },
      logTimestamp: new Date(3).toISOString(),
      readAt: new Date(600001).toISOString(),
    },
  ];
  assert.equal(
    judgeH({
      manifest,
      observations: [subject],
      capture: { complete: true, finalRead: true, frames },
    }).complete,
    false,
  );
});

test("H controls publish both exclusive types and keep source and tenant outside trigger filters", () => {
  assert.equal(manifest.filteredType, `${manifest.type}.filtered`);
  const plan = hPublishes(manifest);
  for (const control of plan.filter((p) => p.control))
    assert.deepEqual(
      control.body.events.map((e) => e.type),
      [manifest.type, manifest.filteredType],
    );
  const mixed = plan.find((p) => p.case === "multi").body.events;
  assert.equal(mixed[0].type, manifest.filteredType);
  assert.equal(mixed[1].type, manifest.type);
  assert.equal(mixed[2].type, manifest.type);
  for (const caseId of ["wrong-source", "wrong-tenant", "missing-tenant"])
    assert.equal(plan.find((p) => p.case === caseId).body.events[0].type, manifest.type);
});

test("H refuses cross-type handler receipts even when matching receipts also exist", () => {
  const candidate = { id: event.id, source: event.source, type: manifest.type };
  const observation = { case: "object", candidates: [candidate], known: true, status: 200 };
  const correct = { frame };
  const unexpected = { frame: { ...frame, handler: manifest.filtered } };
  const capture = { complete: true, finalRead: true, frames: [correct, unexpected] };
  assert.equal(judgeH({ manifest, observations: [observation], capture }).complete, false);
  const filteredEvent = { ...event, type: manifest.filteredType };
  const filteredObservation = {
    ...observation,
    candidates: [{ ...candidate, type: manifest.filteredType }],
    expectedRecipients: [{ ...candidate, handler: manifest.filtered }],
  };
  capture.frames = [{ frame: { ...frame, handler: manifest.filtered, event: filteredEvent } }];
  assert.equal(judgeH({ manifest, observations: [filteredObservation], capture }).complete, true);
  capture.frames.push({ frame: { ...frame, event: filteredEvent } });
  assert.equal(judgeH({ manifest, observations: [filteredObservation], capture }).complete, false);
});

for (const recording of ["h2-a", "h2-b"]) {
  for (const caseId of ["no-time", "ce-bytes"]) {
    test(`H2 ${recording}/${caseId} completes admitted deliveries and rejects missing or foreign receipts`, () => {
      const m = hManifest({ project: "demo-eventarc-h", runId: "012345abcdef", recording });
      const plan = hPublishes(m);
      const index = plan.findIndex((p) => p.case === caseId);
      const start = Date.parse("2026-10-06T00:00:00Z");
      const observations = plan.slice(index - 1, index + 2).map((p, i) => ({
        ...p,
        known: true,
        status: 200,
        before: true,
        after: true,
        sentAt: start + i * 120_000,
        endedAt: start + (i + 1) * 120_000,
      }));
      const subject = observations[1];
      const e = subject.body.events[0];
      assert.deepEqual(
        subject.expectedRecipients,
        [m.observe, m.fanout].map((handler) => ({ handler, id: e.id, source: e.source })),
      );
      assert.equal(subject.negativeHandlers, undefined);
      const ownedOrigins = m.functions
        .filter((f) => f.segment === "core")
        .map((f) => ({ handler: f.name, service: `owned-${f.name}`, location: m.location }));
      const entries = observations.flatMap((o) => {
        const recipients =
          o === subject
            ? [m.observe, m.fanout].map((handler) => ({ handler, id: e.id }))
            : o.expectedRecipients;
        return recipients.map((r, i) => {
          const proto = o.body.events.find((p) => p.id === r.id);
          const visible = {
            id: proto.id,
            source: proto.source,
            type: proto.type,
            specversion: proto.specVersion,
            ...Object.fromEntries(
              Object.entries(proto.attributes)
                .filter(([key]) => !["datacontenttype", "convbytes"].includes(key))
                .map(([key, value]) => [key, value.ceString ?? value.ceTimestamp]),
            ),
            data: JSON.parse(proto.textData),
            traceparent: `00-${"1".repeat(32)}-${"2".repeat(16)}-01`,
          };
          const receipt = {
            ...frame,
            handler: r.handler,
            recording,
            case: o.case,
            invocationId: `${o.case}-${i}`,
            correlation: { id: proto.id, source: proto.source },
            event: visible,
            eventKeys: Object.keys(visible),
          };
          return {
            ...entry,
            insertId: `${o.case}-${i}`,
            timestamp: new Date(o.sentAt + 1).toISOString(),
            resource: {
              type: "cloud_run_revision",
              labels: {
                project_id: m.project,
                service_name: `owned-${r.handler}`,
                location: m.location,
              },
            },
            textPayload: `FE_EVENTS_FRAME ${JSON.stringify(receipt)}`,
          };
        });
      });
      const judge = (raw) => {
        const parsed = parseHEntries(
          { entries: raw },
          {
            manifest: m,
            origins: ownedOrigins,
            readAt: new Date(observations.at(-1).endedAt).toISOString(),
          },
        );
        return judgeH({
          manifest: m,
          observations,
          capture: {
            ...parsed,
            origins: ownedOrigins,
            complete: !parsed.incomplete,
            finalRead: true,
          },
        });
      };
      assert.equal(judge(entries).complete, true);
      for (const handler of [m.observe, m.fanout]) {
        assert.equal(
          judge(
            entries.filter((r) => {
              const f = JSON.parse(r.textPayload.slice("FE_EVENTS_FRAME ".length));
              return f.case !== caseId || f.handler !== handler;
            }),
          ).complete,
          false,
          `missing ${handler}`,
        );
      }
      assert.equal(
        judge(entries.filter((r) => !r.insertId.startsWith(`${caseId}-`))).complete,
        false,
        "missing both recipients",
      );
      const wrongHandler = structuredClone(entries);
      const target = wrongHandler.find((r) => r.insertId === `${caseId}-0`);
      const foreign = JSON.parse(target.textPayload.slice("FE_EVENTS_FRAME ".length));
      foreign.handler = m.filtered;
      target.resource.labels.service_name = `owned-${m.filtered}`;
      target.textPayload = `FE_EVENTS_FRAME ${JSON.stringify(foreign)}`;
      assert.equal(judge(wrongHandler).complete, false, "wrong handler");
      const wrongOrigin = structuredClone(entries);
      wrongOrigin.find((r) => r.insertId === `${caseId}-0`).resource.labels.service_name =
        "foreign-service";
      assert.equal(judge(wrongOrigin).complete, false, "wrong origin");
    });
  }
}

test("H2 subject recipients follow admitted names, channels, types and filters", () => {
  for (const recording of ["h2-a", "h2-b"]) {
    for (const variant of ["rename", "channel", "type", "filter"]) {
      const m = hManifest({ project: "demo-eventarc-h", runId: "012345abcdef", recording });
      const observe = m.functions.find((f) => f.name === m.observe);
      if (variant === "rename") observe.name += "Renamed";
      if (variant === "channel") observe.channel = m.namedChannel;
      if (variant === "type") observe.type = m.filteredType;
      if (variant === "filter") observe.filters.tenant = `${m.tenant}-miss`;
      for (const caseId of ["no-time", "ce-bytes"]) {
        const p = hPublishes(m).find((p) => p.case === caseId);
        assert.deepEqual(
          p.expectedRecipients.map((r) => r.handler),
          variant === "rename" ? [observe.name, m.fanout] : [m.fanout],
          `${recording}/${variant}/${caseId}`,
        );
      }
    }
  }
});
