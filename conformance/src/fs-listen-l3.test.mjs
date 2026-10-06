import assert from "node:assert/strict";
import { test } from "node:test";
import {
  captureFrames,
  maskWire,
  outgoingTargets,
  WIRE_FRAMES,
} from "./fs-listen/browser-driver.mjs";
import { L3_IDS, l3Problems } from "./fs-listen/browser-modes.mjs";
import { browserRows, browserWritesKnown } from "./fs-listen/browser-record.mjs";
import { sdkCases } from "./fs-listen/sdk-cases.mjs";
import { classifyRow, canonicalRow } from "./fs-listen/compare.mjs";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { runInNewContext } from "node:vm";
import { L3_PHASES, MODE_SETTINGS } from "./fs-listen/browser-modes.mjs";

const server = { docs: ["alpha", "beta"], fromCache: false, hasPendingWrites: false, changes: [] };
const evidenceFor = (id) => ({
  phases: L3_PHASES[id].map((phase) => ({
    phase,
    snapshots: [{ ...server, fromCache: phase.endsWith("offline") }],
    failures: [],
    errors: [],
    cacheRead: {
      outcome: "success",
      docs: ["alpha", "beta"],
      fromCache: true,
      hasPendingWrites: false,
    },
    networkDisabled: phase.endsWith("offline"),
    playwrightOffline: phase.endsWith("offline"),
    enableCalls: phase.endsWith("online") ? 1 : 0,
  })),
  markers:
    id === "201"
      ? ["checkpoint", "reload", "server"]
      : ["checkpoint", "close", "new-tab", "server"],
  oldSession: 1,
  newSession: 2,
  closeOutcome: "closed",
  terminate: [{ event: 1, dispatched: true, outcome: "completed", status: 200 }],
  uninterrupted: true,
  cacheMode: id === "203" ? "persistent" : "memory",
  sameProfile: true,
  processExited: true,
  wire: L3_PHASES[id]
    .filter((p) => !p.endsWith("offline"))
    .map((phase, index) => ({
      event: index + 1,
      phase,
      targets: [{ targetId: 2, resumeToken: null, readTime: null }],
      boundaries: [
        { sequence: 1, targetIds: [2], readTime: "2026-10-06T01:02:03.123456Z", resumeToken: null },
      ],
      bodyBytes: 180,
      boundaryComplete: true,
      status: 200,
    })),
});

test("L3 comparison CLI reports matches, divergences and incomparable browser rows with reasons", () => {
  mkdirSync(new URL("../../target", import.meta.url), { recursive: true });
  const dir = mkdtempSync(new URL("../../target/l3-cli-", import.meta.url));
  try {
    const row = { l3: true, observed: [{ phases: [], cacheMode: "persistent" }], failures: [] };
    const production = {
      version: 1,
      kind: "browser",
      run: "production",
      cleanup: { complete: true },
      rows: { match: row, differs: row, unfinished: row, missing: row },
    };
    const local = {
      ...production,
      run: "local",
      rows: {
        match: row,
        differs: { ...row, observed: [{ phases: [], cacheMode: "memory" }] },
        unfinished: { ...row, timedOut: true },
        extra: row,
      },
    };
    for (const [name, recording] of Object.entries({ production, local }))
      writeFileSync(`${dir}/${name}.json`, JSON.stringify(recording));
    const args = ["--production", `${dir}/production.json`, "--local", `${dir}/local.json`];
    const cli = new URL("./fs-listen/compare.mjs", import.meta.url);
    const result = spawnSync(
      process.execPath,
      [cli.pathname, ...args, "--out", `${dir}/report.json`, "--md", `${dir}/summary.md`],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(readFileSync(`${dir}/report.json`, "utf8"));
    assert.deepEqual(report.summary, { MATCH: 1, DIVERGES: 1, NOT_COMPARABLE: 3 });
    assert.deepEqual(
      Object.fromEntries(Object.entries(report.rows).map(([id, r]) => [id, r.status])),
      {
        differs: "DIVERGES",
        extra: "NOT_COMPARABLE",
        match: "MATCH",
        missing: "NOT_COMPARABLE",
        unfinished: "NOT_COMPARABLE",
      },
    );
    assert.equal(report.rows.differs.comparatorResult, "DIFFER");
    assert.equal(report.rows.unfinished.comparatorResult, "INDETERMINATE");
    const md = readFileSync(`${dir}/summary.md`, "utf8");
    assert.match(report.normalization, /Request byte counts are RECORDED_NOT_JUDGED.*13:26Z M4/);
    assert.ok(md.includes(report.normalization));
    assert.deepEqual(report.rows.match.bodyBytes, { production: [], local: [] });
    for (const [id, { status, reason }] of Object.entries(report.rows)) {
      assert.ok(reason.length > 0);
      assert.ok(md.includes(`| ${id} | ${status} | ${reason} |`));
    }
    const noOutput = spawnSync(process.execPath, [cli.pathname, ...args], { encoding: "utf8" });
    assert.equal(noOutput.status, 2);
    local.rows = production.rows;
    writeFileSync(`${dir}/local.json`, JSON.stringify(local));
    const matching = spawnSync(
      process.execPath,
      [cli.pathname, ...args, "--out", `${dir}/report.json`],
      { encoding: "utf8" },
    );
    assert.equal(matching.status, 0, matching.stderr);
    assert.deepEqual(JSON.parse(readFileSync(`${dir}/report.json`, "utf8")).summary, {
      MATCH: 4,
      DIVERGES: 0,
      NOT_COMPARABLE: 0,
    });
    const frame = JSON.stringify([
      [0, ["c", "x".repeat(22), "", 8, 15, 30000]],
      [1, [{ targetChange: { targetChangeType: "CURRENT", readTime: "2026-10-06T00:00:00Z" } }]],
    ]);
    const wire = {
      phase: "restarted-online",
      targets: [{ targetId: 1002 }],
      boundaryComplete: true,
      body: `${frame.length}\n${frame}`,
      boundaryBodyBytes: frame.length + String(frame.length).length + 1,
    };
    production.rows = { 203: { l3: true, observed: [{ wire: [wire] }] } };
    local.rows = structuredClone(production.rows);
    const altered = local.rows["203"].observed[0].wire[0];
    const entries = JSON.parse(frame);
    entries.push(
      [2, [{ filter: { targetId: 1002, count: 2 } }]],
      [3, [{ targetChange: { targetChangeType: "RESET", targetIds: [1002] } }]],
    );
    const changedBody = JSON.stringify(entries);
    altered.body = `${changedBody.length}\n${changedBody}`;
    altered.boundaryBodyBytes = Buffer.byteLength(altered.body);
    writeFileSync(`${dir}/production.json`, JSON.stringify(production));
    writeFileSync(`${dir}/local.json`, JSON.stringify(local));
    const structural = spawnSync(
      process.execPath,
      [cli.pathname, ...args, "--out", `${dir}/report.json`],
      { encoding: "utf8" },
    );
    assert.equal(structural.status, 1, structural.stderr);
    const divergence = JSON.parse(readFileSync(`${dir}/report.json`, "utf8")).rows["203"];
    assert.equal(divergence.status, "DIVERGES");
    assert.match(divergence.reason, /D4: existence-filter presence differs at restart/);
    assert.match(divergence.reason, /D5: RESET\/replay message count or placement differs/);
    production.rows = local.rows = { match: row, differs: row, unfinished: row, missing: row };
    writeFileSync(`${dir}/production.json`, JSON.stringify(production));
    local.cleanup.complete = false;
    writeFileSync(`${dir}/local.json`, JSON.stringify(local));
    const unclean = spawnSync(
      process.execPath,
      [cli.pathname, ...args, "--out", `${dir}/report.json`],
      { encoding: "utf8" },
    );
    assert.equal(unclean.status, 1, unclean.stderr);
    assert.deepEqual(JSON.parse(readFileSync(`${dir}/report.json`, "utf8")).summary, {
      MATCH: 0,
      DIVERGES: 0,
      NOT_COMPARABLE: 4,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("L3 records request byte counts without judging them and compares decoded boundary contents", () => {
  for (const [request, response, localRequest, localResponse] of [
    [1200, 2962, 1161, 1108],
    [1273, 1720, 1234, 556],
    [1200, 1469, 1161, 1108],
    [1200, 1469, 1161, 1108],
    [1275, 539, 1234, 556],
    [1200, 2962, 1161, 1108],
  ]) {
    const rows = [
      ["fireemu-oracle-query", request, response],
      ["demo-fs-listen", localRequest, localResponse],
    ].map(([project, requestBodyBytes, boundaryBodyBytes]) => {
      const database = `projects/${project}/databases/(default)`;
      const addTargetBodies = [
        JSON.stringify({ database, addTarget: { query: { parent: `${database}/documents` } } }),
      ];
      const message = [
        {
          targetChange: {
            targetChangeType: "CURRENT",
            targetIds: [2],
            resumeToken:
              project === "fireemu-oracle-query" ? "AAAAAAAAAAAAAAAA" : "BBBBBBBBBBBBBBBB",
          },
        },
        {
          documentChange: {
            document: {
              name: `${database}/documents/alpha`,
              fields: { value: { stringValue: "a0" } },
            },
            targetIds: [2],
          },
        },
      ];
      let body = JSON.stringify([[1, message]]);
      const length = boundaryBodyBytes - String(boundaryBodyBytes).length - 1;
      body = `${length}\n${body.padEnd(length)}`;
      return {
        l3: true,
        observed: [
          {
            wire: [
              {
                phase: "warm",
                targets: [{ targetId: 2 }],
                addTargetBodies,
                requestBodyBytes,
                boundaryBodyBytes,
                boundaryComplete: true,
                body,
              },
            ],
          },
        ],
      };
    });
    const [production, local] = rows.map((r) => canonicalRow(r).observed[0].resume[0]);
    assert.equal(production.requestBodyBytes, undefined);
    assert.equal(local.requestBodyBytes, undefined);
    assert.deepEqual(production.boundaryContents, local.boundaryContents);
    // Request counts include auth form fields that the recorder does not retain.
    assert.equal(classifyRow(...rows), "MATCH");
    rows[0].observed[0].wire[0].requestBodyBytes -= request - localRequest - 12;
    assert.equal(classifyRow(...rows), "MATCH");
    const changed = structuredClone(rows[1]);
    changed.observed[0].wire[0].requestBodyBytes += 1;
    assert.equal(classifyRow(rows[0], changed), "MATCH");
    for (const replacement of [
      (messages) => {
        messages[0].targetChange.targetChangeType = "RESET";
      },
      (messages) => {
        messages[0].targetChange.resumeToken = "";
      },
      (messages) => {
        delete messages[0].targetChange.resumeToken;
      },
      (messages) => {
        messages[1].documentChange.document.fields.value.stringValue = "b0";
      },
    ]) {
      const different = structuredClone(rows[1]);
      const wire = different.observed[0].wire[0];
      const messages = captureFrames(wire.body).frames.map((f) => f.message);
      replacement(messages);
      const json = JSON.stringify([[1, messages]]);
      wire.body = `${Buffer.byteLength(json)}\n${json}`;
      wire.boundaryBodyBytes = Buffer.byteLength(wire.body);
      assert.equal(classifyRow(rows[0], different), "DIFFER");
    }
  }
});

test("L3 framed streaming capture keeps complete boundaries and refuses truncated or oversized frames", () => {
  const frame = JSON.stringify([
    [
      7,
      [
        {
          targetChange: {
            targetIds: [2],
            resumeToken: "YWJj=",
            readTime: "2026-10-06T01:02:03.123456Z",
          },
        },
      ],
    ],
  ]);
  const wire = `${Buffer.byteLength(frame)}\n${frame}`;
  const parsed = captureFrames(wire);
  assert.equal(parsed.complete, true);
  assert.equal(parsed.frames[0].sequence, 7);
  assert.equal(parsed.frames[0].message.targetChange.readTime, "2026-10-06T01:02:03.123456Z");
  assert.equal(captureFrames(wire.slice(0, -1)).complete, false);
  assert.equal(captureFrames("2\n{}").complete, false);
  assert.equal(captureFrames(wire, 4).complete, false);
  const replay = captureFrames(maskWire(wire));
  assert.equal(replay.complete, true);
  assert.equal(replay.frames[0].endByte, Buffer.byteLength(wire));
  assert.equal(replay.frames[0].message.targetChange.resumeToken, "XXXx=");
  for (let cut = 1; cut < Buffer.byteLength(wire); cut += 1)
    assert.equal(
      captureFrames(Buffer.from(wire).subarray(0, cut).toString()).complete,
      false,
      `prefix ${cut}`,
    );
});

test("L3 masks values without changing byte length, precision or member order", () => {
  const body =
    '{"resumeToken":"Ab1+/=","readTime":"2026-10-06T01:02:03.123456Z","SID":"abc-12","key":"secret"}';
  const masked = maskWire(body);
  assert.equal(Buffer.byteLength(masked), Buffer.byteLength(body));
  assert.equal(
    masked,
    '{"resumeToken":"Xx0+/=","readTime":"2026-10-06T01:02:03.123456Z","SID":"xxx-00","key":"xxxxxx"}',
  );
  assert.equal(maskWire('{"resumeToken":"Secret123'), '{"resumeToken":"Xxxxxx000');
  assert.equal(maskWire('[[0,["c","Session12"'), '[[0,["c","Xxxxxxx00"');
  const request = new URLSearchParams({
    req0___data__: JSON.stringify({ addTarget: { targetId: 2, resumeToken: "Ab1+/=" } }),
  }).toString();
  assert.deepEqual(outgoingTargets(request), [
    { targetId: 2, resumeToken: "Ab1+/=", readTime: null },
  ]);
  assert.throws(() => outgoingTargets("req0___data__=broken"));
});

test("L3 UTF-16 lengths with non-ASCII JSON fail closed in byte-counted capture", () => {
  for (const value of ["é", "日本語", "😀"]) {
    const body = JSON.stringify([[1, [{ documentChange: { value } }]]]);
    assert.ok(Buffer.byteLength(body) > body.length);
    const parsed = captureFrames(`${body.length}\n${body}`);
    assert.equal(parsed.complete, false, value);
    assert.equal(parsed.decodeError, true, value);
    assert.deepEqual(parsed.frames, [], value);
  }
});

test("L3 frozen production bodies replay by run, mode and event through capture and wire judges", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fs-listen/data/l3-production-frames.json", import.meta.url), "utf8"),
  );
  assert.equal(fixture.run, "nmuw7z5c9");
  assert.equal(fixture.frames.length, 12);
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  // Exercise the driver's boundary extraction itself, including its sticky error checks.
  const updateSource = source.slice(
    source.indexOf("    const update = (held) => {"),
    source.indexOf("    const append = (held, data) => {"),
  );
  const update = runInNewContext(updateSource + "update;", {
    Buffer,
    captureFrames,
    maskWire,
    label: () => 1,
    sessions: new Map(),
    valueMask: (value) => "x".repeat(value.length),
    token: (value) => (value ? { length: value.length } : null),
    totalFrames: 0,
    WIRE_FRAMES,
  });
  for (const mode of ["long-polling", "streaming"]) {
    const frames = fixture.frames.filter((f) => f.mode === mode);
    assert.equal(frames.length, 6, mode);
    assert.deepEqual(
      [...new Set(frames.map((f) => f.phase))],
      ["warm", "restarted-online", "cold-online"],
    );
    assert.deepEqual(
      fixture.rows.filter((r) => r.mode === mode).map((r) => r.id),
      ["203", "203C"],
    );
    const wire = frames.map((frame) => {
      const citation = `${fixture.run}/${mode}/event ${frame.event}`;
      assert.equal(Buffer.byteLength(frame.body), frame.bodyBytes, citation);
      assert.equal(captureFrames(frame.body).complete, frame.frameComplete, citation);
      const event = {
        event: frame.event,
        phase: frame.phase,
        status: frame.status,
        contentLength: frame.contentLength,
        targets: frame.targets,
      };
      update({ event, raw: [Buffer.from(frame.body)], frames: 0 });
      for (const key of ["bodyBytes", "frameComplete", "boundaryComplete", "boundaries"])
        assert.deepEqual(JSON.parse(JSON.stringify(event[key])), frame[key], `${citation}: ${key}`);
      assert.equal(event.boundaryBodyBytes ?? null, frame.boundaryBodyBytes, citation);
      // The recorded Content-Length is independent of the decoded response body size.
      if (frame.contentLength !== null)
        assert.notEqual(Number(frame.contentLength), frame.bodyBytes, citation);
      return event;
    });
    for (const row of fixture.rows.filter((r) => r.mode === mode)) {
      const evidence = { ...row.evidence, wire: wire.filter((w) => row.events.includes(w.event)) };
      const citation = `${fixture.run}/${mode}/${row.id}/events ${row.events.join(",")}`;
      assert.deepEqual(l3Problems(row.id, evidence), [], citation);
      for (const event of evidence.wire.filter((w) => w.boundaryComplete)) {
        const broken = structuredClone(evidence);
        const replacement = broken.wire.find((w) => w.event === event.event);
        update({ event: replacement, raw: [Buffer.from("invalid\n")], frames: 0 });
        assert.ok(
          l3Problems(row.id, broken).includes(`missing wire boundary: ${event.phase}`),
          `${citation}: corrupt event ${event.event}`,
        );
      }
    }
  }
});

test("L3 receipts fail closed on missing, duplicate, malformed and lost phase checkpoints", () => {
  assert.deepEqual(L3_IDS, ["201C", "201", "202", "203", "203C"]);
  const receipt = {
    thrown: null,
    cases: sdkCases().map((c) => ({ caseId: c.caseId, failures: [] })),
    teardown: [],
    l3: {
      seeds: [{ acknowledged: true }, { acknowledged: true }],
      phases: [],
      cleanup: { complete: true },
    },
  };
  assert.equal(browserWritesKnown(receipt), false);
  const rows = browserRows({ streaming: { receipt } });
  assert.equal(rows["browser-streaming/sdk/203"].timedOut, true);
  assert.deepEqual(rows["browser-streaming/sdk/203"].conditions, [
    "FS-LISTEN-SDK/backend-cache-transitions",
  ]);
  assert.equal(
    classifyRow(rows["browser-streaming/sdk/203"], rows["browser-streaming/sdk/203"]),
    "INDETERMINATE",
  );
  assert.ok(l3Problems("201", {}).includes("missing lifecycle checkpoints"));
  assert.ok(l3Problems("203", { phases: [] }).includes("missing cache checkpoints"));
});

test("L3 reload needs distinct sessions and server checkpoints without requiring terminate", () => {
  for (const terminate of [
    undefined,
    [],
    [{ dispatched: true, outcome: "unknown", status: null }],
  ]) {
    const evidence = { ...evidenceFor("201"), terminate };
    assert.deepEqual(l3Problems("201", evidence), []);
    evidence.newSession = evidence.oldSession;
    assert.ok(l3Problems("201", evidence).includes("missing distinct channel sessions"));
    evidence.newSession = 2;
    evidence.phases[1].snapshots[0].fromCache = true;
    assert.ok(l3Problems("201", evidence).includes("missing server-backed set"));
  }
});

test("L3 judges require intact controls, persistent offline state and decoded server boundaries", () => {
  for (const id of L3_IDS) assert.deepEqual(l3Problems(id, evidenceFor(id)), [], id);
  for (const terminate of [undefined, {}])
    assert.ok(
      l3Problems("202", { ...evidenceFor("202"), terminate }).includes(
        "missing terminate observation",
      ),
    );
  for (const outcome of ["cancelled", "unknown", "dispatched"])
    assert.deepEqual(
      l3Problems("202", {
        ...evidenceFor("202"),
        terminate: [{ dispatched: true, outcome, status: null }],
      }),
      [],
    );
  for (const status of [0, 199, 302, 500])
    assert.deepEqual(
      l3Problems("202", {
        ...evidenceFor("202"),
        terminate: [{ dispatched: true, outcome: "completed", status }],
      }),
      [],
    );

  for (const change of [
    (e) => {
      e.processExited = false;
    },
    (e) => {
      e.sameProfile = false;
    },
    (e) => {
      e.cacheMode = "memory";
    },
    (e) => {
      e.phases[1].cacheRead.docs = [];
    },
    (e) => {
      e.phases[1].snapshots[0].docs = [];
    },
    (e) => {
      e.phases[1].snapshots[0].hasPendingWrites = true;
    },
    (e) => {
      e.phases[2].enableCalls = 2;
    },
    (e) => {
      e.wire[0].overflow = true;
    },
    (e) => {
      e.wire[0].decodeError = true;
    },
    (e) => {
      e.wire[0].boundaryComplete = false;
    },
    (e) => {
      e.wire[0].targets = [];
    },
    (e) => {
      e.wire[0].boundaries[0].readTime = null;
    },
    (e) => {
      e.phases[0].failures = ["persistence-failed"];
    },
  ]) {
    const e = evidenceFor("203");
    change(e);
    assert.ok(l3Problems("203", e).length);
  }
  const cold = evidenceFor("203C");
  cold.phases[0].cacheRead = { outcome: "error", code: "unavailable" };
  cold.phases[0].snapshots[0].docs = [];
  assert.deepEqual(l3Problems("203C", cold), []);
  assert.ok(l3Problems("201C", { ...evidenceFor("201C"), uninterrupted: false }).length);
  assert.ok(l3Problems("201", { phases: [null], markers: "bad", terminate: "bad" }).length);
});

test("L3 receipts reject duplicate IDs, lost checkpoints, partial seeds, malformed failures and page death", () => {
  const phases = [
    "control-start",
    "before-reload",
    "after-reload",
    "before-close",
    "replacement",
    "control-end",
    "warm",
    "restarted-offline",
    "restarted-online",
    "cold-offline",
    "cold-online",
  ];
  const receipt = {
    thrown: null,
    cases: [
      ...sdkCases().map((c) => ({ caseId: c.caseId, failures: [] })),
      ...L3_IDS.map((id) => ({
        caseId: `FS-LISTEN-SDK-${id}`,
        failures: [],
        observed: [evidenceFor(id)],
        complete: true,
      })),
    ],
    teardown: [{ closed: true }],
    l3: {
      seeds: [
        { name: "alpha", acknowledged: true },
        { name: "beta", acknowledged: true },
      ],
      phases: phases.map((phase) => ({ phase, failures: [], snapshots: [server], errors: [] })),
      cleanup: { complete: true },
    },
  };
  assert.equal(browserWritesKnown(receipt), true);
  for (const change of [
    (r) => {
      r.cases[1] = r.cases[0];
    },
    (r) => {
      r.l3.phases.pop();
    },
    (r) => {
      r.cases.at(-1).observed = [{}];
    },
    (r) => {
      r.l3.phases[0].snapshots = [];
    },
    (r) => {
      r.l3.seeds.pop();
    },
    (r) => {
      r.l3.seeds[0].acknowledged = false;
    },
    (r) => {
      r.cases[0].failures = [{}];
    },
    (r) => {
      r.cases.at(-1).failures = ["step-threw:page-death"];
    },
    (r) => {
      r.l3.thrown = "page-death";
    },
    (r) => {
      r.teardown[0].closed = false;
    },
  ]) {
    const copy = structuredClone(receipt);
    change(copy);
    assert.equal(browserWritesKnown(copy), false);
  }
});

test("L3 page initializes persistence before operations, never falls back, and clears only after termination", async () => {
  const calls = [];
  const firestore = new Proxy(
    {},
    {
      get:
        (_, method) =>
        (...args) => {
          calls.push([method, ...args]);
          if (method === "initializeFirestore") return {};
          if (method === "query") return "query";
          if (method === "enableIndexedDbPersistence" && failPersistence)
            throw new Error("persistence-failed");
          if (method === "onSnapshot") return () => calls.push(["unsubscribe"]);
        },
    },
  );
  let failPersistence = false;
  const window = {};
  const source = readFileSync(new URL("./fs-listen/browser-page.mjs", import.meta.url), "utf8");
  runInNewContext(source.slice(source.indexOf("// L3 state")), {
    window,
    firestore,
    initializeApp: (_, name) => ({ name }),
    deleteApp: () => calls.push(["deleteApp"]),
    MODE_SETTINGS,
    performance: { now: () => 0 },
  });
  const config = {
    mode: "streaming",
    run: "run-s",
    base: 100,
    web: {},
    persistent: true,
    offline: true,
  };
  await window.listenL3Init(config);
  assert.deepEqual(
    calls.slice(0, 3).map((c) => c[0]),
    ["initializeFirestore", "enableIndexedDbPersistence", "disableNetwork"],
  );
  await window.listenL3Seed("alpha");
  assert.deepEqual(JSON.parse(JSON.stringify(calls.find((c) => c[0] === "setDoc").at(-1))), {
    rank: 101,
    owner: "run-s",
    value: "a0",
  });
  window.listenL3Subscribe();
  await window.listenL3Online();
  assert.equal(window.listenL3Checkpoint().enableCalls, 1);
  await window.listenL3Stop(true);
  assert.deepEqual(
    calls.slice(-4).map((c) => c[0]),
    ["unsubscribe", "terminate", "clearIndexedDbPersistence", "deleteApp"],
  );
  calls.length = 0;
  failPersistence = true;
  await assert.rejects(window.listenL3Init(config), /persistence-failed/);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ["initializeFirestore", "enableIndexedDbPersistence"],
  );
});

test("L3 token relationships compare without token literals or exact elapsed times", () => {
  const e = evidenceFor("203");
  e.wire[0].boundaries[0].resumeToken = { relation: 3, masked: "xxx", length: 3 };
  e.wire[1].targets[0].resumeToken = { relation: 3, masked: "xxx", length: 3 };
  const row = { l3: true, observed: [e], failures: [], end: null };
  const later = structuredClone(row);
  later.observed[0].phases[0].snapshots[0].elapsedMs = 12345;
  later.observed[0].wire[0].boundaries[0].resumeToken = { relation: 7, masked: "XXX", length: 3 };
  later.observed[0].wire[1].targets[0].resumeToken = { relation: 7, masked: "XXX", length: 3 };
  assert.equal(classifyRow(row, later), "MATCH");
  later.observed[0].wire[1].targets[0].resumeToken.relation = 8;
  assert.equal(classifyRow(row, later), "DIFFER");
});

test("L3 forward targets retain empty fields and framing rejects each malformed entry and handshake overflow", () => {
  assert.deepEqual(
    outgoingTargets(
      new URLSearchParams({
        req0___data__: JSON.stringify({
          addTarget: { targetId: 2, resumeToken: "", readTime: "" },
        }),
      }).toString(),
    ),
    [{ targetId: 2, resumeToken: "", readTime: "" }],
  );
  for (const entry of [null, [1.5, []], [1, {}]]) {
    const body = JSON.stringify([entry]);
    assert.equal(captureFrames(`${Buffer.byteLength(body)}\n${body}`).decodeError, true);
  }
  for (const count of [WIRE_FRAMES, WIRE_FRAMES + 1]) {
    const body = JSON.stringify(Array.from({ length: count }, (_, i) => [i, ["c", "session"]]));
    const result = captureFrames(`${Buffer.byteLength(body)}\n${body}`);
    assert.equal(result.frames.length, WIRE_FRAMES);
    assert.equal(result.complete, count === WIRE_FRAMES);
    assert.equal(result.overflow, count === WIRE_FRAMES ? undefined : true);
  }
});

test("L3 judges reject individual checkpoint, session, offline and wire near misses", () => {
  const malformed = evidenceFor("201");
  malformed.phases[0].snapshots = {};
  malformed.markers = [];
  assert.deepEqual(l3Problems("201", malformed), ["malformed checkpoint"]);
  for (const [id, changes] of [
    [
      "201",
      [
        (e) => {
          e.phases[0].phase = 1;
        },
        (e) => {
          e.phases[0].snapshots = {};
        },
        (e) => {
          e.phases[0].errors = {};
        },
        (e) => {
          e.phases[0].failures = {};
        },
        (e) => {
          e.phases[0].errors = ["unavailable"];
        },
        (e) => {
          e.phases[0].snapshots[0].docs = {};
        },
        (e) => {
          e.markers = {};
        },
        (e) => {
          e.markers.reverse();
        },
        (e) => {
          e.oldSession = null;
        },
        (e) => {
          e.newSession = null;
        },
        (e) => {
          e.newSession = e.oldSession;
        },
      ],
    ],
    [
      "203",
      [
        (e) => {
          e.phases[1].networkDisabled = false;
        },
        (e) => {
          e.phases[1].playwrightOffline = false;
        },
        (e) => {
          e.phases[1].enableCalls = 1;
        },
        (e) => {
          e.phases[1].snapshots = [];
        },
        (e) => {
          e.phases[1].snapshots[0].fromCache = false;
        },
        (e) => {
          e.phases[1].cacheRead.docs = {};
        },
        (e) => {
          e.phases[1].snapshots[0].docs = {};
        },
        (e) => {
          e.wire = {};
        },
        (e) => {
          e.wire[0].phase = "other";
        },
        (e) => {
          e.wire[0].boundaries = {};
        },
        (e) => {
          e.wire[0].boundaries[0].readTime = 1;
        },
        (e) => {
          e.wire[0].status = 199;
        },
        (e) => {
          e.wire[0].status = 300;
        },
      ],
    ],
    [
      "203C",
      [
        (e) => {
          e.cacheMode = "persistent";
        },
        (e) => {
          e.phases[0].cacheRead = null;
        },
      ],
    ],
  ])
    for (const change of changes) {
      const evidence = evidenceFor(id);
      change(evidence);
      assert.notDeepEqual(l3Problems(id, evidence), [], `${id}: ${change}`);
    }
});

test("L3 rows isolate complete records and distinguish cache and lifecycle conditions", () => {
  const receipt = {
    cases: L3_IDS.map((id) => ({
      caseId: `FS-LISTEN-SDK-${id}`,
      observed: [evidenceFor(id)],
      failures: [],
      complete: true,
    })),
  };
  const rows = browserRows({ streaming: { receipt } });
  for (const id of L3_IDS) {
    const row = rows[`browser-streaming/sdk/${id}`];
    assert.equal(row.timedOut, false, id);
    assert.deepEqual(row.observed, [evidenceFor(id)]);
    assert.deepEqual(row.conditions, [
      `FS-LISTEN-SDK/${id.startsWith("203") ? "backend-cache-transitions" : "browser-tab-lifecycle"}`,
    ]);
  }
  for (const change of [
    (r) => {
      r.cases.push(r.cases[1]);
    },
    (r) => {
      r.cases[1].complete = false;
    },
    (r) => {
      r.cases[1].failures = {};
    },
  ]) {
    const copy = structuredClone(receipt);
    change(copy);
    assert.equal(
      browserRows({ streaming: { receipt: copy } })["browser-streaming/sdk/201"].timedOut,
      true,
    );
  }
  const malformed = structuredClone(receipt);
  malformed.cases[1].observed = [false];
  assert.equal(
    browserRows({ streaming: { receipt: malformed } })["browser-streaming/sdk/201"].observed[0],
    false,
  );
  assert.deepEqual(
    browserRows({ streaming: { receipt: { cases: {} } } })["browser-streaming/sdk/201"].observed,
    [{}],
  );
});

test("L3 writes require each receipt field independently", () => {
  const receipt = {
    cases: [
      ...sdkCases().map((c) => ({ caseId: c.caseId, failures: [] })),
      ...L3_IDS.map((id) => ({
        caseId: `FS-LISTEN-SDK-${id}`,
        failures: [],
        observed: [evidenceFor(id)],
      })),
    ],
    teardown: [{ closed: true }],
    l3: {
      seeds: [
        { name: "alpha", acknowledged: true },
        { name: "beta", acknowledged: true },
      ],
      phases: [
        "control-start",
        "before-reload",
        "after-reload",
        "before-close",
        "replacement",
        "control-end",
        "warm",
        "restarted-offline",
        "restarted-online",
        "cold-offline",
        "cold-online",
      ].map((phase) => ({ phase, failures: [], errors: [], snapshots: [server] })),
      cleanup: { complete: true },
    },
  };
  assert.equal(browserWritesKnown(receipt), true);
  for (const change of [
    (r) => {
      r.cases[0].caseId = 1;
    },
    (r) => {
      r.cases[0].failures = {};
    },
    (r) => {
      r.cases.at(-1).observed = {};
    },
    (r) => {
      r.cases.at(-1).observed.push(evidenceFor("203C"));
    },
    (r) => {
      r.cases.at(-1).observed[0].phases = {};
    },
    (r) => {
      r.cases.at(-1).observed[0].phases[0].failures = {};
    },
    (r) => {
      r.cases.at(-1).observed[0].phases[0].errors = {};
    },
    (r) => {
      r.cases.at(-1).observed[0].phases[0].snapshots = {};
    },
    (r) => {
      r.cases.at(-1).observed[0].phases[0].snapshots = [];
    },
    (r) => {
      r.l3 = null;
    },
    (r) => {
      r.l3.seeds = {};
    },
    (r) => {
      r.l3.seeds = { length: 2 };
    },
    (r) => {
      r.l3.phases[0].failures = {};
    },
    (r) => {
      r.l3.phases[0].snapshots = {};
    },
    (r) => {
      r.l3.phases[0].errors = {};
    },
  ]) {
    const copy = structuredClone(receipt);
    change(copy);
    assert.equal(browserWritesKnown(copy), false, String(change));
  }
});

test("L3 canonical rows retain empty fields, collapse only adjacent snapshots and select matching wire phases", () => {
  assert.deepEqual(canonicalRow({ l3: true }), {
    l3: true,
    observed: [],
    failures: undefined,
    end: null,
  });
  for (const row of [
    { l3: true, observed: false },
    { l3: true, observed: [{ phases: false }] },
    { l3: true, observed: [{ phases: [{ snapshots: false }] }] },
  ])
    assert.throws(() => canonicalRow(row), TypeError);
  const matching = evidenceFor("203");
  matching.wire[0].boundaries[0].resumeToken = { relation: 4, length: 3 };
  matching.wire[1].targets[0].resumeToken = { relation: 4, length: 3 };
  assert.equal(
    canonicalRow({ l3: true, observed: [matching] }).observed[0].resume[1].targets[0].reused,
    true,
  );
  const evidence = evidenceFor("203");
  evidence.phases[0].snapshots = [server, server, { ...server, docs: [] }, server];
  evidence.wire.unshift({
    phase: "noise",
    event: 0,
    targets: [],
    boundaries: [],
    boundaryComplete: true,
  });
  evidence.wire[1].targets[0] = { resumeToken: { relation: 4, length: 0 }, readTime: "" };
  evidence.wire[1].boundaries.unshift({ readTime: null, resumeToken: { length: 99 } });
  evidence.wire[1].boundaries[1].resumeToken = { relation: 4, length: 0 };
  evidence.wire[2].targets[0] = { resumeToken: { relation: 4, length: 0 }, readTime: "" };
  const row = canonicalRow({ l3: true, observed: [evidence] }).observed[0];
  assert.equal(row.phases[0].snapshots.length, 3);
  assert.equal(row.resume.length, 2);
  assert.equal(row.resume[0].phase, "warm");
  assert.equal(row.resume[0].targets[0].readTimeFormat, "");
  assert.equal(row.resume[0].targets[0].reused, false);
  assert.equal(row.resume[1].targets[0].reused, true);
  assert.equal(row.resume[0].boundaryFields.length, 1);
  assert.equal(row.resume[0].boundaryFields[0].readTimeFormat, "0000-00-00T00:00:00.000000Z");
  assert.equal(row.resume[0].boundaryFields[0].tokenLength, 0);
  const missing = canonicalRow({ l3: true, observed: [{ phases: [{ phase: "x" }], wire: [] }] });
  assert.equal(missing.observed[0].phases[0].cacheRead, null);
  assert.deepEqual(missing.observed[0].phases[0].snapshots, []);
});

test("L3 page preserves local configuration, snapshot identities, error codes and optional cache clearing", async () => {
  const calls = [];
  let snapshotCallback, errorCallback, cache;
  const firestore = new Proxy(
    {},
    {
      get:
        (_, method) =>
        (...args) => {
          calls.push([method, ...args]);
          if (method === "onSnapshot") {
            [, , snapshotCallback, errorCallback] = args;
            return () => calls.push(["unsubscribe"]);
          }
          if (method === "getDocsFromCache") {
            if (cache instanceof Error) throw cache;
            return cache;
          }
          return {};
        },
    },
  );
  const window = {};
  const source = readFileSync(new URL("./fs-listen/browser-page.mjs", import.meta.url), "utf8");
  runInNewContext(source.slice(source.indexOf("// L3 state")), {
    window,
    firestore,
    initializeApp: () => ({}),
    deleteApp: () => calls.push(["deleteApp"]),
    MODE_SETTINGS,
    performance: { now: () => 1.9 },
  });
  await window.listenL3Init({
    mode: "streaming",
    run: "r",
    base: 100,
    web: {},
    local: true,
    firestoreEmulator: { host: "127.0.0.1", port: 8080 },
  });
  assert.deepEqual(
    calls
      .filter(([method]) =>
        ["connectFirestoreEmulator", "enableIndexedDbPersistence", "disableNetwork"].includes(
          method,
        ),
      )
      .map(([method]) => method),
    ["connectFirestoreEmulator"],
  );
  assert.equal(window.listenL3Checkpoint().networkDisabled, false);
  assert.equal(window.listenL3Checkpoint().cacheRead, null);
  await window.listenL3Seed("beta");
  assert.deepEqual(
    JSON.parse(JSON.stringify(calls.find(([method]) => method === "setDoc").at(-1))),
    { rank: 102, owner: "r", value: "b0" },
  );
  cache = {
    docs: [{ id: "r-alpha" }, { id: "r-beta" }, { id: "other" }],
    metadata: { fromCache: true, hasPendingWrites: false },
    docChanges: () =>
      ["r-alpha", "r-beta", "other"].map((id) => ({
        type: "added",
        doc: { id },
        oldIndex: -1,
        newIndex: 0,
      })),
  };
  window.listenL3Subscribe();
  snapshotCallback(cache);
  const checkpoint = JSON.parse(JSON.stringify(window.listenL3Checkpoint()));
  assert.deepEqual(checkpoint.snapshots[0].docs, ["alpha", "beta", "other"]);
  assert.deepEqual(
    checkpoint.snapshots[0].changes.map((c) => c.doc),
    ["alpha", "beta", "other"],
  );
  assert.equal(checkpoint.snapshots[0].elapsedMs, 1);
  errorCallback({ code: "" });
  errorCallback({});
  assert.deepEqual(Array.from(window.listenL3Checkpoint().errors), ["", "unknown"]);
  await window.listenL3Read();
  assert.equal(window.listenL3Checkpoint().cacheRead.outcome, "success");
  cache = Object.assign(new Error("cache"), { code: "" });
  await window.listenL3Read();
  assert.equal(window.listenL3Checkpoint().cacheRead.code, "");
  await window.listenL3Stop();
  assert.equal(
    calls.some(([method]) => method === "clearIndexedDbPersistence"),
    false,
  );
});

test("L3 driver routing, session labels and observation caps preserve their boundaries", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  let now = 0,
    refused = false,
    routeHandler,
    ledgerOptions;
  const admitted = [],
    closed = [],
    routed = [];
  const context = {
    on: () => {},
    close: async () => {
      closed.push("context");
    },
    route: async (_, handler) => {
      routeHandler = handler;
    },
  };
  const scope = {
    config: { mode: "local", originPort: 1, web: {}, authEmulator: "local", firestoreEmulator: {} },
    browser: {},
    run: "r",
    mode: "streaming",
    accounts: {},
    cases: [],
    originOf: () => "http://localhost:1",
    modeRun: () => "rs",
    bandOf: () => 0,
    Date: { now: () => now },
    createWireLedger: (options) => {
      ledgerOptions = options;
      return { closed: () => refused, admit: (...args) => admitted.push(args) };
    },
    allowedHosts: () => [],
    emit: () => {},
    DEADLINE_MS: 100,
    GSTATIC: "https://www.gstatic.com/",
    BUNDLES: ["firebase-app.js"],
    FILES: { "/": { type: "text/html", body: "page" } },
    FIREBASE: "/unused",
    join: (...args) => args.join("/"),
    readFileSync: () => "bundle",
    URL,
    webChannelBearer: () => undefined,
    listenChannelCi: () => null,
  };
  const driver = await runInNewContext(
    source
      .slice(source.indexOf("const valueMask"), source.indexOf("/** The official SDK"))
      .replace("export function", "function") +
      source.slice(
        source.indexOf("async function runMode"),
        source.indexOf("  const observation = observe();"),
      ) +
      "return { input, check, label, token, hookContext, closeContext, contexts, cleanup, stop: () => { stopped = true; } }; }\nrunMode({browser,config,run,mode,accounts,cases});",
    scope,
  );
  assert.equal(driver.input.local, true);
  const labels = new Map();
  assert.equal(driver.label(labels, null), null);
  assert.equal(driver.label(labels, "s"), 1);
  assert.equal(driver.label(labels, "s"), 1);
  assert.equal(driver.label(labels, "t"), 2);
  assert.equal(driver.token(null), null);
  assert.deepEqual(JSON.parse(JSON.stringify(driver.token("Ab1"))), {
    relation: 1,
    masked: "Xx0",
    length: 3,
  });
  driver.check();
  now = 100;
  assert.throws(driver.check, /stopped/);
  now = 0;
  refused = true;
  assert.throws(driver.check, /stopped/);
  refused = false;
  await driver.hookContext(context);
  for (const url of [
    "http://localhost:1/",
    "https://www.gstatic.com/firebase-app.js",
    "https://www.gstatic.com/unlisted.js",
    "http://local/listen",
  ]) {
    await routeHandler({
      request: () => ({
        url: () => url,
        headers: () => ({}),
        postData: () => "",
        method: () => "GET",
      }),
      fulfill: (value) => routed.push(value.body),
      continue: () => routed.push("continued"),
      abort: (reason) => routed.push(reason),
    });
  }
  assert.deepEqual(routed, ["page", "bundle", "continued", "continued"]);
  assert.deepEqual(
    admitted.map(([host]) => host),
    ["www.gstatic.com", "local"],
  );
  await driver.closeContext(context, "ok");
  assert.equal(driver.contexts.size, 0);
  await driver.closeContext(
    {
      close: async () => {
        throw new Error("closed");
      },
    },
    "failed",
  );
  assert.equal(driver.cleanup.complete, false);
  assert.equal(driver.cleanup.outcomes.at(-1).closed, false);
  await driver.hookContext(context);
  ledgerOptions.onRefuse({ host: "refused", path: "/", reason: "cap" });
  assert.equal(closed.length, 2);
  assert.throws(driver.check, /stopped/);
  await assert.rejects(driver.hookContext(context), /already stopped/);
  assert.equal(closed.length, 3);
});

test("L3 close captures terminate outcomes at context scope after the page is gone", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const handlers = new Map();
  const context = { on: (name, handler) => handlers.set(name, handler), route: async () => {} };
  const driver = runInNewContext(
    source.slice(source.indexOf("  const ci = {};"), source.indexOf("  const attach = async")) +
      "({ hookContext, wire, pages, l3, sessions, capture: (value = true) => { capturing = value; } });",
    {
      config: {},
      mode: "streaming",
      origin: "http://localhost:1",
      Date: { now: () => 0 },
      DEADLINE_MS: 100,
      Buffer,
      URL,
      createWireLedger: () => ({}),
      allowedHosts: () => [],
      emit: () => {},
      valueMask: (value) => value.replace(/[A-Za-z0-9]/g, "x"),
      WIRE_BYTES: 1024,
      listenChannelCi: (url) => (new URL(url).pathname === "/listen" ? "0" : null),
    },
  );
  await driver.hookContext(context);
  assert.equal(handlers.size, 4);
  const page = {};
  driver.pages.set(page, { name: "A", phase: "before-close" });
  const request = (url, detached = false, error = "net::ERR_ABORTED") => ({
    url: () => url,
    method: () => "POST",
    postData: () => "",
    frame: () => {
      if (detached) throw new Error("page gone");
      return { page: () => page };
    },
    failure: () => ({ errorText: error }),
  });
  const ignored = request("http://local/listen?TYPE=terminate&SID=old");
  handlers.get("request")(ignored);
  assert.equal(driver.wire.length, 0);
  driver.capture();
  handlers.get("request")(ignored);
  assert.equal(driver.wire.length, 0);
  driver.sessions.set("old", 1);
  driver.sessions.set("other", 2);
  driver.l3.closeSession = 1;
  driver.capture(false);
  handlers.get("request")(ignored);
  assert.equal(driver.wire.length, 0);
  driver.capture();
  for (const url of [
    "http://local/other?TYPE=terminate&SID=old",
    "http://local/listen?SID=old",
    "http://local/listen?TYPE=terminate&SID=other",
    "http://local/listen?TYPE=terminate",
  ])
    handlers.get("request")(request(url));
  assert.equal(driver.wire.length, 0);
  handlers.get("requestfinished")(ignored);
  handlers.get("requestfailed")(ignored);
  handlers.get("response")({ request: () => ignored, status: () => 200 });
  for (const scenario of [
    "completed",
    "cancelled",
    "unknown",
    "dispatched",
    "no-response",
    "http-error",
    "detached",
  ]) {
    const req = request(
      "http://local/listen?TYPE=terminate&SID=old",
      scenario === "detached",
      scenario === "unknown" ? "net::ERR_FAILED" : "net::ERR_ABORTED",
    );
    handlers.get("request")(req);
    const event = driver.wire.at(-1);
    assert.equal(event.terminate, true);
    assert.equal(event.dispatched, true);
    assert.equal(event.session, 1);
    assert.equal(event.sessionMask, "xxx");
    assert.equal(event.outcome, "unknown");
    assert.equal(event.status, null);
    if (scenario !== "detached") {
      assert.equal(event.phase, "before-close");
      assert.equal(event.page, "A");
    }
    driver.pages.delete(page);
    if (scenario !== "no-response")
      handlers.get("response")({
        request: () => req,
        status: () => (scenario === "http-error" ? 500 : 200),
      });
    if (["completed", "no-response", "http-error", "detached"].includes(scenario))
      handlers.get("requestfinished")(req);
    if (["cancelled", "unknown"].includes(scenario)) handlers.get("requestfailed")(req);
    assert.equal(
      event.outcome,
      ["completed", "no-response", "http-error", "detached"].includes(scenario)
        ? "completed"
        : scenario === "cancelled"
          ? "cancelled"
          : "unknown",
    );
    const evidence = { ...evidenceFor("202"), terminate: [event] };
    assert.deepEqual(l3Problems("202", evidence), []);
    driver.pages.set(page, { name: "A", phase: "before-close" });
  }
  assert.equal(driver.wire.length, 7);
  const oversized = {
    ...request("http://local/listen?TYPE=terminate&SID=old"),
    postData: () => "x".repeat(1025),
  };
  handlers.get("request")(oversized);
  assert.equal(driver.wire.at(-1).overflow, true);
  assert.equal(driver.wire.at(-1).requestBodyBytes, 1025);
  assert.equal(driver.wire[0].overflow, false);
  assert.equal(driver.wire.at(-1).session, 1);
  assert.equal(driver.wire.at(-1).sessionMask, "xxx");
  assert.deepEqual(l3Problems("202", { ...evidenceFor("202"), terminate: [] }), []);
  const start = source.indexOf("    const terminateUntil =");
  const end = source.indexOf("    l3.controlCompleted =", start);
  for (const scenario of [
    "completed",
    "pending",
    "expired",
    "other-session",
    "not-terminate",
    "absent",
  ]) {
    let now = 0,
      checks = 0;
    const event = {
      terminate: scenario !== "not-terminate",
      session: scenario === "other-session" ? 2 : 1,
      outcome: scenario === "completed" ? "completed" : "unknown",
    };
    await runInNewContext("(async () => {" + source.slice(start, end) + "})()", {
      Date: { now: () => now },
      STEP_TIMEOUT_MS: 200,
      wire: scenario === "absent" ? [] : [event],
      l3: { closeSession: 1 },
      check: () => {
        checks += 1;
      },
      setTimeout: (fn, delay) => {
        assert.equal(delay, 100);
        now += delay;
        if (scenario === "pending") event.outcome = "completed";
        fn();
      },
    });
    assert.equal(checks, scenario === "expired" ? 2 : scenario === "pending" ? 1 : 0);
  }
});

test("L3 CDP capture distinguishes ignored requests, streaming frames, sticky errors and byte caps", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const handlers = new Map(),
    connections = [],
    pageEvents = [];
  let streamResult = {},
    bodyResult = { body: "", base64Encoded: false },
    streamReject = false;
  const cdp = {
    on: (name, handler) => handlers.set(name, handler),
    send: async (name) => {
      if (name === "Network.streamResourceContent") {
        if (streamReject) throw new Error("unavailable");
        return streamResult;
      }
      if (name === "Network.getResponseBody") return bodyResult;
    },
  };
  const context = { newCDPSession: async () => cdp },
    page = { on: (...args) => pageEvents.push(args) };
  const driver = runInNewContext(
    source
      .slice(source.indexOf("const valueMask"), source.indexOf("/** The official SDK"))
      .replace("export function", "function") +
      source.slice(source.indexOf("  const ci = {};"), source.indexOf("  const load = async")) +
      "({attach, wire, contextIds, cleanup, setCapture: (v) => { capturing = v; }, setCloseSession: (v) => { l3.closeSession = v; }, setBytes: (v) => { totalBytes = v; }, setFrames: (v) => { totalFrames = v; }, totals: () => ({totalBytes,totalFrames,queuedBytes})});",
    {
      Buffer,
      URL,
      URLSearchParams,
      Date: { now: () => 0 },
      started: 0,
      origin: "http://localhost:1",
      config: {},
      mode: "streaming",
      allowedHosts: () => [],
      createWireLedger: () => ({ connection: (host) => connections.push(host) }),
      emit: () => {},
      GSTATIC: "https://www.gstatic.com/",
      WIRE_BYTES: 1024,
      WIRE_FRAMES: 10,
      captureFrames,
      outgoingTargets,
      listenChannelCi: (url) => (new URL(url).pathname === "/listen" ? "0" : null),
    },
  );
  driver.contextIds.set(context, 1);
  const state = await driver.attach(context, page, "warm");
  state.name = "warm";
  handlers.get("Network.requestWillBeSent")({
    requestId: "ignored",
    request: { url: "http://local/listen" },
  });
  driver.setCapture(true);
  handlers.get("Network.requestWillBeSent")({
    requestId: "ignored",
    request: { url: "http://local/other" },
  });
  assert.equal(driver.wire.length, 0);
  for (const [id, url, postData] of [
    ["one", "http://local/listen?SID=Ab1", undefined],
    [
      "two",
      "http://local/listen?TYPE=terminate",
      new URLSearchParams({
        req0___data__: JSON.stringify({ addTarget: { targetId: 2, resumeToken: "Ab1" } }),
        req1___data__: JSON.stringify({ removeTarget: 2 }),
        auth: "ignored",
      }).toString(),
    ],
  ])
    handlers.get("Network.requestWillBeSent")({
      requestId: id,
      request: { url, method: "POST", postData },
    });
  assert.equal(driver.wire[0].session, 1);
  assert.equal(driver.wire[0].terminate, false);
  assert.equal(driver.wire[1].session, null);
  assert.equal(driver.wire[1].terminate, true);
  assert.equal(driver.wire[1].targets[0].resumeToken.masked, "Xx0");
  assert.equal(driver.wire[1].addTargetBodies.length, 1);
  driver.setCloseSession(1);
  handlers.get("Network.requestWillBeSent")({
    requestId: "context-owned-terminate",
    request: { url: "http://local/listen?TYPE=terminate&SID=Ab1", method: "POST" },
  });
  assert.equal(driver.wire.length, 2);
  const handshake = JSON.stringify([
    [0, ["noop", "ignored"]],
    [1, ["c", "Other1"]],
  ]);
  const boundary = JSON.stringify([
    [
      1,
      [
        { targetChange: { readTime: "time" } },
        { targetChange: { resumeToken: "Ab1", targetIds: [2], targetChangeType: "CURRENT" } },
        { targetChange: { resumeToken: "Ab1", targetIds: 0, targetChangeType: "", readTime: "" } },
        {},
        { targetChange: {} },
      ],
    ],
  ]);
  streamResult = {
    bufferedData: Buffer.from(`${Buffer.byteLength(handshake)}\n${handshake}`).toString("base64"),
  };
  await handlers.get("Network.responseReceived")({
    requestId: "one",
    response: {
      url: "http://local/listen",
      connectionId: 1,
      status: 200,
      headers: { "Content-Length": "100", other: "1" },
    },
  });
  const before = driver.totals().totalFrames;
  handlers.get("Network.dataReceived")({
    requestId: "one",
    data: Buffer.from(`${Buffer.byteLength(boundary)}\n${boundary}`).toString("base64"),
  });
  const first = driver.wire[0];
  assert.equal(first.session, 2);
  assert.equal(first.sessionMask, "Xxxxx0");
  assert.equal(first.boundaries.length, 3);
  assert.equal(first.boundaries[0].type, "NO_CHANGE");
  assert.equal(first.boundaries[1].type, "CURRENT");
  assert.equal(first.boundaries[1].resumeToken.relation, 1);
  assert.equal(first.boundaryComplete, true);
  assert.equal(first.contentLength, "100");
  assert.equal(first.boundaries[2].targetIds, 0);
  assert.equal(first.boundaries[2].type, "");
  assert.equal(first.boundaries[2].readTime, "");
  assert.equal(
    first.boundaryBodyBytes,
    Buffer.byteLength(
      `${Buffer.byteLength(handshake)}\n${handshake}${Buffer.byteLength(boundary)}\n${boundary}`,
    ),
  );
  const boundaryBytes = first.boundaryBodyBytes;
  assert.equal(driver.totals().totalFrames > before, true);
  handlers.get("Network.dataReceived")({
    requestId: "one",
    data: Buffer.from("bad\n{}").toString("base64"),
  });
  assert.equal(first.decodeError, true);
  assert.equal(first.boundaryComplete, false);
  await handlers.get("Network.loadingFinished")({ requestId: "one" });
  assert.equal(first.outcome, "completed");
  assert.equal(first.boundaryBodyBytes, boundaryBytes);
  for (const [url, connectionId] of [
    ["http://localhost:1/", 10],
    ["https://www.gstatic.com/bundle", 11],
    ["http://local/listen", 1],
  ])
    await handlers.get("Network.responseReceived")({
      requestId: "missing",
      response: { url, connectionId, status: 200, headers: {} },
    });
  assert.deepEqual(connections, ["local"]);
  await handlers.get("Network.responseReceived")({
    requestId: "missing",
    response: { url: "http://local/listen", connectionId: 0, status: 200, headers: {} },
  });
  assert.deepEqual(connections, ["local"]);
  await handlers.get("Network.loadingFinished")({ requestId: "missing" });
  handlers.get("Network.dataReceived")({ requestId: "missing", data: "AA==" });
  handlers.get("Network.loadingFailed")({ requestId: "missing", canceled: true });
  handlers.get("Network.loadingFailed")({ requestId: "two", canceled: true });
  assert.equal(driver.wire[1].outcome, "cancelled");
  handlers.get("Network.loadingFailed")({ requestId: "two", canceled: false });
  assert.equal(driver.wire[1].outcome, "unknown");
  streamReject = true;
  await handlers.get("Network.responseReceived")({
    requestId: "two",
    response: { url: "http://local/listen", connectionId: 2, status: 204, headers: {} },
  });
  assert.equal(driver.wire[1].captureUnavailable, true);
  assert.equal(driver.wire[1].contentLength, null);
  bodyResult = { body: "0\n[]", base64Encoded: false };
  await handlers.get("Network.loadingFinished")({ requestId: "two" });
  assert.equal(driver.wire[1].decodeError, true);
  driver.setBytes(1024);
  handlers.get("Network.requestWillBeSent")({
    requestId: "cap",
    request: { url: "http://local/listen", postData: "x" },
  });
  assert.equal(driver.wire.at(-1).overflow, true);
  handlers.get("Network.dataReceived")({ requestId: "cap", data: "AA==" });
  assert.equal(driver.totals().totalBytes, 1025);
  assert.equal(driver.wire.at(-1).bodyBytes, 0);
  driver.setBytes(0);
  driver.setFrames(10);
  handlers.get("Network.requestWillBeSent")({
    requestId: "frames",
    request: { url: "http://local/listen" },
  });
  handlers.get("Network.dataReceived")({
    requestId: "frames",
    data: Buffer.from(`${Buffer.byteLength(handshake)}\n${handshake}`).toString("base64"),
  });
  assert.equal(driver.wire.at(-1).overflow, true);
  assert.equal(driver.wire.at(-1).boundaryComplete, false);
  driver.setFrames(0);
  driver.setBytes(0);
  streamReject = false;
  handlers.get("Network.requestWillBeSent")({
    requestId: "queue",
    request: { url: "http://local/listen", postData: "req0___data__=broken" },
  });
  let release;
  streamResult = new Promise((resolve) => {
    release = resolve;
  });
  const streaming = handlers.get("Network.responseReceived")({
    requestId: "queue",
    response: {
      url: "http://local/listen",
      connectionId: 3,
      status: 200,
      headers: { "content-length": "" },
    },
  });
  const queued = Buffer.from(`${Buffer.byteLength(handshake)}\n${handshake}`).toString("base64");
  handlers.get("Network.dataReceived")({ requestId: "queue", data: queued });
  assert.equal(driver.totals().queuedBytes, Buffer.from(queued, "base64").length);
  release({ bufferedData: "" });
  await streaming;
  assert.equal(driver.totals().queuedBytes, 0);
  assert.equal(driver.wire.at(-1).decodeError, true);
  assert.equal(driver.wire.at(-1).contentLength, "");
  handlers.get("Network.requestWillBeSent")({
    requestId: "queue-cap",
    request: { url: "http://local/listen" },
  });
  streamResult = new Promise((resolve) => {
    release = resolve;
  });
  const capped = handlers.get("Network.responseReceived")({
    requestId: "queue-cap",
    response: { url: "http://local/listen", connectionId: 4, status: 200, headers: {} },
  });
  driver.setBytes(1024);
  handlers.get("Network.dataReceived")({ requestId: "queue-cap", data: "AA==" });
  assert.equal(driver.wire.at(-1).overflow, true);
  assert.equal(driver.totals().queuedBytes, 0);
  release({});
  await capped;
  assert.equal(driver.wire.at(-1).captureUnavailable, undefined);
  await handlers.get("Network.loadingFinished")({ requestId: "queue-cap" });
  assert.equal(driver.wire.at(-1).overflow, true);
  driver.setBytes(0);
  streamReject = true;
  for (const base64Encoded of [false, true]) {
    const id = `fallback-${base64Encoded}`;
    handlers.get("Network.requestWillBeSent")({
      requestId: id,
      request: { url: "http://local/listen" },
    });
    await handlers.get("Network.responseReceived")({
      requestId: id,
      response: { url: "http://local/listen", connectionId: 5, status: 200, headers: {} },
    });
    bodyResult = {
      body: base64Encoded ? queued : Buffer.from(queued, "base64").toString(),
      base64Encoded,
    };
    await handlers.get("Network.loadingFinished")({ requestId: id });
    assert.equal(driver.wire.at(-1).frameComplete, true);
    assert.equal(driver.wire.at(-1).bodyBytes, Buffer.from(queued, "base64").length);
  }
});

test("L3 driver waits require the final snapshot and the requested page boundary", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  let checkpoint = { errors: [], snapshots: [server] },
    now = 0,
    checks = 0;
  const window = { listenL3Checkpoint: () => checkpoint },
    cleanup = { complete: true, outcomes: [] },
    pages = new Map(),
    l3 = { phases: [] },
    wire = [];
  const driver = runInNewContext(
    source.slice(source.indexOf("  const waitSnapshot ="), source.indexOf("  const observe =")) +
      "({waitSnapshot, checkpoint, stopPage, waitWire});",
    {
      window,
      cleanup,
      pages,
      l3,
      wire,
      Date: { now: () => now },
      started: 0,
      sequence: 7,
      mode: "streaming",
      emit: () => {},
      STEP_TIMEOUT_MS: 2,
      check: () => {
        checks += 1;
      },
      setTimeout: (fn) => {
        now += 1;
        fn();
      },
    },
  );
  let ready;
  const page = {
    waitForFunction: async (predicate, offline, options) => {
      assert.equal(options.timeout, 2);
      ready = predicate(offline);
    },
    evaluate: async () => checkpoint,
  };
  for (const [snapshots, offline, expected] of [
    [[], false, undefined],
    [[server], false, true],
    [[{ ...server, fromCache: true }], false, false],
    [[{ ...server, hasPendingWrites: true }], false, false],
    [[{ ...server, docs: [] }], false, false],
    [[{ ...server, docs: [], fromCache: true }], true, true],
  ]) {
    checkpoint = { errors: [], snapshots };
    await driver.waitSnapshot(page, offline);
    assert.equal(ready, expected);
  }
  checkpoint.errors = ["unavailable"];
  await assert.rejects(driver.waitSnapshot(page), /listener failed/);
  const value = await driver.checkpoint(page, "offline", true);
  assert.equal(value.playwrightOffline, true);
  assert.equal(value.wireThroughEvent, 7);
  assert.equal(l3.phases.length, 1);
  pages.set(page, {});
  page.evaluate = async () => ({ closed: true });
  await driver.stopPage(page, "ok");
  assert.equal(pages.get(page).stopAttempted, true);
  assert.equal(cleanup.outcomes[0].closed, true);
  page.evaluate = async () => {
    throw new Error("page died");
  };
  await driver.stopPage(page, "failed");
  assert.equal(cleanup.complete, false);
  assert.equal(cleanup.outcomes[1].closed, false);
  wire.push(
    { phase: "wrong", page: "A", boundaryComplete: true },
    { phase: "warm", page: "B", boundaryComplete: true },
    { phase: "warm", page: "A", boundaryComplete: false },
  );
  await assert.rejects(driver.waitWire("warm", "A"), /missing wire boundary/);
  assert.equal(checks, 2);
  wire.push({ phase: "warm", page: "A", boundaryComplete: true });
  await driver.waitWire("warm", "A");
  assert.equal(checks, 3);
});

test("L3 driver receipts keep lifecycle sessions, phase controls and incomplete cleanup", () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  for (const id of L3_IDS)");
  const end = source.indexOf("\n}\n\nasync function main", start);
  const phases = [...new Set(L3_IDS.flatMap((id) => L3_PHASES[id]))].map((phase) => ({
    phase,
    snapshots: [{ ...server, fromCache: phase.endsWith("offline") }],
    errors: [],
    failures: [],
    enableCalls: phase.endsWith("online") ? 1 : 0,
    cacheRead: { outcome: "success", docs: ["alpha", "beta"] },
    networkDisabled: phase.endsWith("offline"),
    playwrightOffline: phase.endsWith("offline"),
  }));
  for (const incomplete of [false, true]) {
    const l3 = {
      phases: incomplete ? phases.slice(1) : phases,
      controlCompleted: true,
      reloadSession: 1,
      closeSession: 3,
      closeOutcome: "closed",
      profile: { sameProfile: true, processExited: true },
      ...(incomplete ? { thrown: "timeout" } : {}),
    };
    const wire = [
      { page: "A", phase: "after-reload", session: 2 },
      { page: "A2", phase: "replacement", session: 4 },
      { page: "noise", phase: "replacement", session: 9 },
      { page: "A", phase: "noise", session: 8 },
      { terminate: true, session: 1, dispatched: true, outcome: "completed", status: 200 },
      { terminate: true, session: 3, dispatched: true, outcome: "completed", status: 204 },
      { terminate: false, session: 1 },
      ...evidenceFor("203").wire,
      ...evidenceFor("203C").wire,
    ];
    const receipt = { cases: [], teardown: [], cleanup: { complete: false } },
      cleanup = { complete: true, outcomes: [{ name: "context", closed: true }] };
    const result = runInNewContext("(() => {" + source.slice(start, end) + "})()", {
      L3_IDS,
      L3_PHASES,
      l3Problems,
      l3,
      wire,
      receipt,
      cleanup,
      mode: "streaming",
      modeRunId: "rs",
      ledger: { records: [1], connections: () => 2, closed: () => false },
      listenChannel: 3,
      ci: { 0: 3 },
      totalBytes: 100,
      totalFrames: 2,
    });
    const cases = result.receipt.cases;
    assert.equal(cases.length, 5);
    assert.equal(cases[0].observed[0].uninterrupted, !incomplete);
    assert.equal(cases[1].observed[0].oldSession, 1);
    assert.equal(cases[1].observed[0].newSession, 2);
    assert.equal(cases[2].observed[0].oldSession, 3);
    assert.equal(cases[2].observed[0].newSession, 4);
    assert.deepEqual(Array.from(cases[1].observed[0].markers), ["checkpoint", "reload", "server"]);
    assert.deepEqual(Array.from(cases[2].observed[0].markers), [
      "checkpoint",
      "close",
      "new-tab",
      "server",
    ]);
    assert.equal(cases[1].observed[0].terminate.length, 1);
    assert.equal(cases[1].observed[0].terminate[0].session, 1);
    assert.equal(cases[2].observed[0].terminate[0].session, 3);
    assert.equal(cases[3].observed[0].cacheMode, "persistent");
    assert.equal(cases[4].observed[0].cacheMode, "memory");
    assert.equal(cases[3].observed[0].wire.length, 2);
    assert.equal(cases[4].observed[0].wire.length, 1);
    assert.equal(cases[0].complete, !incomplete);
    assert.equal(
      cases[0].failures.some((f) => f.startsWith("step-threw:")),
      incomplete,
    );
    assert.equal(
      cases[1].failures.some((f) => f.startsWith("step-threw:")),
      false,
    );
    assert.equal(result.receipt.cleanup.complete, false);
  }
});

for (const scenario of [
  "empty terminate",
  "recorded terminate",
  "missing server snapshot",
  "missing close outcome",
]) {
  test(`L3 row 202 records ${scenario} and derives completeness in the driver`, async () => {
    const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
    const start = source.indexOf("  for (const id of L3_IDS)");
    const end = source.indexOf("\n}\n\nasync function main", start);
    const evidence = evidenceFor("202");
    if (scenario === "missing server snapshot") evidence.phases[1].snapshots[0].fromCache = true;
    const terminate =
      scenario === "recorded terminate"
        ? [{ terminate: true, session: 1, dispatched: true, outcome: "cancelled", status: null }]
        : [];
    const l3 = { phases: evidence.phases, closeSession: 1 };
    if (scenario !== "missing close outcome") {
      const closeStart = source.indexOf("    const closed = a.waitForEvent");
      const closeEnd = source.indexOf("    const a2 =", closeStart);
      const closeSource = source.slice(closeStart, closeEnd);
      await runInNewContext("(async () => {" + closeSource + "})()", {
        l3,
        STEP_TIMEOUT_MS: 100,
        a: {
          waitForEvent: (event) => {
            assert.equal(event, "close");
            return Promise.resolve();
          },
          close: async (options) => {
            assert.equal(options.runBeforeUnload, true);
          },
        },
      });
    }
    const result = runInNewContext("(() => {" + source.slice(start, end) + "})()", {
      L3_IDS,
      L3_PHASES,
      l3Problems,
      l3,
      wire: [{ page: "A2", phase: "replacement", session: 2 }, ...terminate],
      receipt: { cases: [], teardown: [], cleanup: { complete: true } },
      cleanup: { complete: true, outcomes: [] },
      mode: "streaming",
      modeRunId: "rs",
      ledger: { records: [], connections: () => 0, closed: () => false },
      listenChannel: 0,
      ci: {},
      totalBytes: 0,
      totalFrames: 0,
    });
    const record = result.receipt.cases.find((c) => c.caseId === "FS-LISTEN-SDK-202");
    const row = browserRows({ streaming: result })["browser-streaming/sdk/202"];
    assert.deepEqual(Array.from(row.observed[0].terminate), terminate);
    assert.equal(row.observed[0].closeOutcome, l3.closeOutcome);
    const complete = !scenario.startsWith("missing");
    assert.equal(record.complete, complete);
    assert.equal(row.timedOut, !complete);
    assert.equal(row.failures.includes("terminate not confirmed"), false);
    assert.equal(row.failures.includes("missing or duplicate complete record"), !complete);
    assert.equal(classifyRow(row, row), complete ? "MATCH" : "INDETERMINATE");
    if (!complete)
      assert.ok(
        row.failures.includes(
          scenario === "missing server snapshot"
            ? "missing server-backed set"
            : "close not confirmed",
        ),
      );
    else assert.deepEqual(row.failures, []);
  });
}

test("L3 persistent cleanup signals only owned Chromium and deletes storage only after exit", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("      // Stop all clients before removing the profile");
  const end = source.indexOf("\n    }\n    const cold", start);
  for (const scenario of ["clean", "forced", "alive", "context", "delete-failed"]) {
    const stopped = [],
      killed = [],
      removed = [],
      cleanup = { complete: true, outcomes: [] },
      l3 = { profile: { deleted: false } };
    const pages = new Map([
      [{ isClosed: () => false }, { l3Owned: true, name: "open" }],
      [{ isClosed: () => false }, { l3Owned: false, name: "catalog" }],
      [{ isClosed: () => false }, { l3Owned: true, stopAttempted: true, name: "stopped" }],
      [{ isClosed: () => true }, { l3Owned: true, name: "closed" }],
    ]);
    const contexts = new Set(scenario === "context" ? ["failed"] : []);
    let reads = 0;
    const processList =
      "11 Chromium --user-data-dir=/owned\n12 Chromium --user-data-dir=/other\n13 node --user-data-dir=/owned";
    await runInNewContext("(async () => {" + source.slice(start, end) + "})()", {
      pages,
      contexts,
      cleanup,
      l3,
      profile: "/owned",
      stopPage: async (_, name) => stopped.push(name),
      closeContext: async () => {},
      execFileSync: () => {
        reads += 1;
        return scenario === "alive" || (scenario === "forced" && reads < 3)
          ? processList
          : "12 Chromium --user-data-dir=/other\n13 node --user-data-dir=/owned";
      },
      process: { kill: (pid, signal) => killed.push([pid, signal]) },
      setTimeout: (fn) => fn(),
      rmSync: (path) => {
        if (scenario === "delete-failed") throw new Error("denied");
        removed.push(path);
      },
    });
    assert.deepEqual(stopped, ["open"]);
    assert.deepEqual(
      killed,
      ["forced", "alive"].includes(scenario)
        ? [
            [11, "SIGTERM"],
            [11, "SIGKILL"],
          ]
        : [],
    );
    assert.equal(cleanup.complete, scenario === "clean");
    assert.equal(l3.profile.deleted, ["clean", "forced"].includes(scenario));
    assert.deepEqual(removed, ["clean", "forced"].includes(scenario) ? ["/owned"] : []);
    assert.equal(cleanup.outcomes.at(-1).closed, scenario !== "alive");
    assert.equal(cleanup.outcomes.at(-1).forced, ["forced", "alive"].includes(scenario));
  }
});

test("L3 shared browser cleanup keeps failed receipt cleanup and verifies process identity", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("    let closed = true;");
  const end = source.indexOf('\n  }\n  emit({\n    event: "receipt"', start);
  for (const scenario of ["clean", "forced", "alive", "missing-profile", "close-failed"]) {
    const killed = [],
      events = [];
    let reads = 0;
    const receipt = {
      teardown: [],
      cleanup: { complete: false },
      l3: { cleanup: { complete: false } },
    };
    const results = { streaming: { receipt }, failed: {} };
    await runInNewContext("(async () => {" + source.slice(start, end) + "})()", {
      browser: {
        close: async () => {
          if (scenario === "close-failed") throw new Error("close");
        },
      },
      profile: scenario === "missing-profile" ? undefined : "/owned",
      results,
      execFileSync: () => {
        reads += 1;
        return scenario === "alive" || (scenario === "forced" && reads < 3)
          ? "11 Chromium --user-data-dir=/owned\n12 Chromium --user-data-dir=/other\n13 node --user-data-dir=/owned"
          : "12 Chromium --user-data-dir=/other\n13 node --user-data-dir=/owned";
      },
      process: { kill: (pid, signal) => killed.push([pid, signal]) },
      setTimeout: (fn) => fn(),
      emit: (event) => events.push(event),
    });
    assert.equal(receipt.teardown[0].closed, scenario === "clean");
    assert.equal(receipt.cleanup.complete, false);
    assert.equal(receipt.l3.cleanup.complete, false);
    assert.deepEqual(
      killed,
      ["forced", "alive"].includes(scenario)
        ? [
            [11, "SIGTERM"],
            [11, "SIGKILL"],
          ]
        : [],
    );
    assert.equal(events.length, ["forced", "alive"].includes(scenario) ? 1 : 0);
    if (events.length) assert.equal(events[0].processExited, scenario !== "alive");
  }
});

test("L3 observation records separate reload and close sessions and verifies warm process exit", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  const observe = async () =>");
  const end = source.indexOf("  const observation = observe();", start);
  for (const alive of [false, true]) {
    const contexts = new Set(),
      pages = new Map(),
      l3 = { seeds: [], phases: [] },
      wire = [
        { page: "noise", session: 99 },
        { page: "A", session: 1 },
        { page: "B", session: 9 },
      ];
    const context = { setOffline: async () => {} },
      calls = [];
    let persistent = 0;
    const scope = {
      browser: { newContext: async () => context },
      context,
      contexts,
      pages,
      l3,
      wire,
      config: {},
      mode: "streaming",
      input: {},
      receipt: undefined,
      hookContext: async (value) => {
        contexts.add(value);
        return value;
      },
      attach: async () => {},
      load: async () => {},
      newPage: async (owner, name, phase) => {
        const page = {
          isClosed: () => false,
          evaluate: async (fn, value) => {
            calls.push([name, String(fn)]);
            return { name: value, acknowledged: true };
          },
          reload: async () => {
            wire.push({ page: "A", session: 2 }, { page: "B", session: 10 });
          },
          waitForSelector: async () => {},
          waitForEvent: async () => {},
          close: async () => {},
        };
        pages.set(page, { name, phase, l3Owned: true });
        return page;
      },
      waitSnapshot: async () => {},
      checkpoint: async (_, phase) => l3.phases.push({ phase }),
      stopPage: async (page) => {
        pages.get(page).stopAttempted = true;
      },
      closeContext: async (owner) => contexts.delete(owner),
      waitWire: async () => {},
      check: () => {},
      mkdtempSync: () => "/owned",
      HERE: "/unused",
      join: (...parts) => parts.join("/"),
      chromium: {
        launchPersistentContext: async () => {
          persistent += 1;
          return { setOffline: async () => {} };
        },
      },
      browserArgs: () => [],
      execFileSync: () =>
        alive
          ? "11 Chromium --user-data-dir=/owned"
          : "12 Chromium --user-data-dir=/other\n13 node --user-data-dir=/owned",
      cleanup: { complete: true, outcomes: [] },
      process: { kill: () => {} },
      setTimeout: (fn) => fn(),
      rmSync: () => {},
      STEP_TIMEOUT_MS: 1,
      emit: () => {},
    };
    context.newPage = async () => ({
      evaluate: async () => ({ cases: [], teardown: [], cleanup: { complete: true } }),
      close: async () => {},
    });
    const observation = runInNewContext(source.slice(start, end) + "observe();", scope);
    if (alive) {
      await assert.rejects(observation, /warm Chromium did not exit/);
      assert.equal(persistent, 1);
    } else {
      await observation;
      assert.equal(persistent, 2);
      assert.deepEqual(
        l3.phases.map((p) => p.phase),
        [
          "control-start",
          "before-reload",
          "after-reload",
          "before-close",
          "replacement",
          "control-end",
          "warm",
          "restarted-offline",
          "restarted-online",
          "cold-offline",
          "cold-online",
        ],
      );
      assert.equal(l3.profile.processExited, true);
      assert.equal(l3.profile.deleted, true);
    }
    assert.equal(l3.reloadSession, 1);
    assert.equal(l3.closeSession, 2);
    assert.equal(l3.controlCompleted, true);
    assert.deepEqual(
      l3.seeds.map((seed) => seed.name),
      ["alpha", "beta"],
    );
  }
});

test("L3 observation failure and deadline cleanup preserve unknown writes", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  const observation = observe();");
  const end = source.indexOf("  for (const id of L3_IDS)", start);
  for (const scenario of ["no-receipt", "receipt", "deadline", "remaining"]) {
    const cleanup = { complete: true },
      l3 = {},
      stops = [],
      closes = [],
      pages = new Map();
    for (const [name, owned, attempted, closed] of [
      ["open", true, false, false],
      ["catalog", false, false, false],
      ["stopped", true, true, false],
      ["closed", true, false, true],
    ])
      pages.set({ isClosed: () => closed }, { name, l3Owned: owned, stopAttempted: attempted });
    const contexts = new Set(["context"]),
      timers = [];
    const scope = {
      observe: async () => {
        if (scenario === "deadline") return new Promise(() => {});
        if (scenario !== "remaining") throw Object.assign(new Error("failure"), { code: "" });
      },
      receipt: scenario === "no-receipt" ? undefined : {},
      l3,
      cleanup,
      pages,
      contexts,
      stopPage: async (_, name) => stops.push(name),
      closeContext: async (context) => {
        closes.push(context);
        if (scenario !== "remaining") contexts.delete(context);
      },
      ledger: { closed: () => false },
      stopped: false,
      timer: undefined,
      DEADLINE_MS: 100,
      CLEANUP_MS: 10,
      setTimeout: (fn, delay) => {
        timers.push([fn, delay]);
        return {
          unref: () => {
            fn();
          },
        };
      },
      clearTimeout: () => {},
    };
    const pending = runInNewContext("(async () => {" + source.slice(start, end) + "})()", scope);
    if (scenario === "deadline") timers[0][0]();
    if (scenario === "no-receipt")
      await assert.rejects(pending, (error) => error.message === "" && error.refused === false);
    else await pending;
    if (["no-receipt", "receipt"].includes(scenario)) assert.equal(l3.thrown, "");
    if (scenario === "deadline") assert.equal(l3.thrown, "Error");
    assert.deepEqual(stops, ["open"]);
    assert.deepEqual(closes, ["context"]);
    assert.equal(scope.stopped, true);
    assert.equal(cleanup.complete, false);
  }
});

test("L3 mode loop stops on refusal and preserves empty error names", async () => {
  const source = readFileSync(new URL("./fs-listen/browser-driver.mjs", import.meta.url), "utf8");
  const start = source.indexOf("    for (const mode of modes)");
  const end = source.indexOf("\n  } finally", start);
  for (const scenario of [
    "receipt-refused",
    "transport-refused",
    "error-refused",
    "error-normal",
    "normal",
  ]) {
    const results = {},
      calls = [];
    await runInNewContext("(async () => {" + source.slice(start, end) + "})()", {
      modes: ["long-polling", "streaming"],
      results,
      browser: {},
      config: {},
      run: "r",
      accounts: {},
      cases: [],
      modeRun: (_, mode) => `r-${mode}`,
      runMode: async ({ mode }) => {
        calls.push(mode);
        if (scenario.startsWith("error")) throw { name: "", refused: scenario === "error-refused" };
        return scenario === "receipt-refused"
          ? { refused: true }
          : { transport: { refused: scenario === "transport-refused" } };
      },
    });
    assert.equal(calls.length, scenario.endsWith("refused") ? 1 : 2);
    if (scenario.startsWith("error")) {
      assert.equal(results["long-polling"].error, "");
      assert.equal(results["long-polling"].refused, scenario === "error-refused");
    }
  }
});

test("L3 typed response comparison covers both modes, every complete batch and direct token relations", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fs-listen/data/l3-production-frames.json", import.meta.url), "utf8"),
  );
  for (const mode of ["long-polling", "streaming"]) {
    const rows = ["production", "local"].map((run, side) => {
      const database = `projects/${side ? "demo-fs-listen" : "fireemu-oracle-query"}/databases/(default)`;
      const wire = fixture.frames
        .filter((f) => f.mode === mode)
        .map((f) => {
          let docs = 0;
          const entries = captureFrames(f.body).frames.map(({ sequence, message }) => {
            const document = message.documentChange?.document;
            if (document) {
              const identity = docs++ % 2 === 0 ? "alpha" : "beta";
              document.name = `${database}/documents/conf_listen/${run}-${identity}`;
              document.fields.owner.stringValue = `${run}-${mode}`;
              document.fields.rank.integerValue = String((identity === "alpha" ? 100 : 200) + side);
              document.fields.value.stringValue = identity === "alpha" ? "a0" : "b0";
            }
            if (Array.isArray(message)) message[1] = (side ? "B" : "a").repeat(22);
            const masked = JSON.parse(
              JSON.stringify(message, (key, value) => {
                if (key === "resumeToken") return (side ? "B" : "a").repeat(value.length);
                if (
                  ["createTime", "updateTime", "readTime"].includes(key) &&
                  typeof value === "string"
                )
                  return value.replace("2026-10-06", side ? "2026-10-07" : "2026-10-06");
                return value;
              }),
            );
            return [sequence, Array.isArray(masked) ? masked : [masked]];
          });
          const json = JSON.stringify(entries),
            body = `${Buffer.byteLength(json)}\n${json}`;
          return {
            ...f,
            body,
            requestBodyBytes: side ? 11 : 9999,
            contentLength: side ? "10" : "10000",
            addTargetBodies: [JSON.stringify({ database })],
            boundaryBodyBytes: f.boundaryComplete ? Buffer.byteLength(body) : null,
            boundaries: f.boundaries.map((b) => ({
              ...b,
              resumeToken: { ...b.resumeToken, relation: `${run}:${b.readTime ?? "reset"}` },
            })),
          };
        });
      return { l3: true, observed: [{ wire }] };
    });
    assert.equal(classifyRow(...rows), "MATCH", mode);
    const canonical = canonicalRow(rows[0]).observed[0].resume;
    for (const phase of canonical) {
      assert.equal(phase.boundaryContents[0].sequence, 0);
      const expected = fixture.frames
        .filter((f) => f.mode === mode && f.phase === phase.phase)
        .flatMap((f) => captureFrames(f.body).frames);
      assert.equal(phase.boundaryContents.length, expected.length);
    }
    for (const mutation of [
      "scalar",
      "width",
      "removed",
      "default-type",
      "default-ids",
      "rank-type",
      "owner-type",
      "value",
      "timestamp-equality",
      "token-length",
      "token-relation",
      "request-token-relation",
      "after-boundary-reset",
      "filter",
    ]) {
      const changed = structuredClone(rows[1]);
      const wire = changed.observed[0].wire;
      const event = wire.find((w) => w.boundaryComplete);
      const frames = captureFrames(event.body).frames;
      const doc = frames.find((f) => f.message.documentChange)?.message.documentChange;
      const current = frames.find((f) => f.message.targetChange?.targetChangeType === "CURRENT");
      const noChange = frames.find(
        (f) => f.message.targetChange && !f.message.targetChange.targetChangeType,
      );
      if (mutation === "scalar" || mutation === "width") {
        const hello = captureFrames(wire[0].body).frames[0].message;
        if (mutation === "scalar") hello[4] = 12;
        else hello[1] += "B";
        const json = JSON.stringify([[0, hello]]);
        wire[0].body = `${Buffer.byteLength(json)}\n${json}`;
      } else if (mutation === "removed") doc.removedTargetIds = [];
      else if (mutation === "default-type")
        noChange.message.targetChange.targetChangeType = "NO_CHANGE";
      else if (mutation === "default-ids") noChange.message.targetChange.targetIds = [];
      else if (mutation === "rank-type") doc.document.fields.rank.integerValue = 101;
      else if (mutation === "owner-type") doc.document.fields.owner.stringValue = 101;
      else if (mutation === "value") doc.document.fields.value.stringValue = "b0";
      else if (mutation === "timestamp-equality") doc.document.updateTime = "2026-10-08T00:00:00Z";
      else if (mutation === "token-length") current.message.targetChange.resumeToken += "B";
      else if (mutation === "token-relation")
        event.boundaries.find((b) => b.sequence === noChange.sequence).resumeToken.relation =
          "other";
      else if (mutation === "request-token-relation") {
        const request = wire.find((w) => w.phase === "restarted-online" && w.targets.length);
        request.targets[0].resumeToken = { length: 16, relation: "wrong" };
      } else if (mutation === "after-boundary-reset")
        frames.push({
          sequence: 99,
          message: { targetChange: { targetChangeType: "RESET", targetIds: [1002] } },
        });
      else if (mutation === "filter")
        frames.push({ sequence: 99, message: { filter: { targetId: 1002, count: 2 } } });
      const json = JSON.stringify(frames.map(({ sequence, message }) => [sequence, [message]]));
      event.body = `${Buffer.byteLength(json)}\n${json}`;
      event.boundaryBodyBytes = Buffer.byteLength(event.body);
      assert.equal(classifyRow(rows[0], changed), "DIFFER", `${mode}: ${mutation}`);
    }
    // Boundary offsets select the complete batch; later response events are excluded.
    const later = structuredClone(rows[1]);
    later.observed[0].wire.push({ phase: "cold-online", body: "10\n[[99,[]]]" });
    assert.equal(classifyRow(rows[0], later), "MATCH");
  }
});

test("L3 token metadata follows message occurrences within one sequence and malformed boundaries are incomparable", () => {
  const messages = [
    {
      targetChange: {
        targetChangeType: "CURRENT",
        resumeToken: "xxx",
        readTime: "2026-10-06T00:00:00Z",
      },
    },
    { targetChange: { resumeToken: "xxx", readTime: "2026-10-06T00:00:00Z" } },
    { targetChange: { targetChangeType: "RESET", resumeToken: "xxx" } },
  ];
  const json = JSON.stringify([[1, messages]]),
    body = `${json.length}\n${json}`;
  const row = {
    l3: true,
    observed: [
      {
        wire: [
          {
            phase: "warm",
            targets: [{ targetId: 1002 }],
            body,
            boundaryComplete: true,
            boundaryBodyBytes: body.length,
            boundaries: [
              { sequence: 1, resumeToken: { relation: 1, length: 3 } },
              { sequence: 1, resumeToken: { relation: 1, length: 3 } },
              { sequence: 1, resumeToken: { relation: 2, length: 3 } },
            ],
          },
        ],
      },
    ],
  };
  const changed = structuredClone(row);
  changed.observed[0].wire[0].boundaries[1].resumeToken.relation = 2;
  changed.observed[0].wire[0].boundaries[2].resumeToken.relation = 1;
  assert.equal(classifyRow(row, changed), "DIFFER");
  for (const suffix of ["2\n{}", "10\n[", "x\n[]"]) {
    const invalid = structuredClone(row);
    invalid.observed[0].wire[0].body += suffix;
    invalid.observed[0].wire[0].boundaryBodyBytes += suffix.length;
    assert.equal(classifyRow(row, invalid), "INDETERMINATE");
    assert.equal(classifyRow(invalid, invalid), "INDETERMINATE");
  }
});
