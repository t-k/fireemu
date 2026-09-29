import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import {
  createStage3RequestCounter,
  originalProductionStage3CounterSnapshot,
} from "./storage-object/request-counter.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const resources = {
  projectNumber: "123456789012",
  apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
  rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
};
const pins = {
  sourceCommit: "a".repeat(40),
  packetSha256: "b".repeat(64),
  planSha256: "c".repeat(64),
  rulesSourceSha256: plan.rulesSourceSha256,
  corpusSha256: "d".repeat(64),
};
const limits = {
  maxValues: 81,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
async function fixture(action) {
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-schema-")));
  fs.chmodSync(directory, 0o700);
  const registry = createProductionSecretRegistry(limits),
    profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    boundary = createProductionStandaloneFailStop({ directory, profile });
  const counter = createStage3RequestCounter(plan, {
    onStart: () => {},
    onReserve: () => {},
    artifactProfile: profile,
  });
  try {
    const api = await import("./storage-object/production-shared-records.mjs");
    const projection = api.createProductionSharedRecordProjection({
      plan,
      pins,
      profile,
      boundary,
      counter,
    });
    return await action({ api, projection, registry, profile, boundary, counter, directory });
  } finally {
    registry.close();
    fs.rmSync(directory, { recursive: true });
  }
}
test("shared rows obtain fixed IDs, pinned inputs, source time and counts from the original counter", async () =>
  fixture(async ({ api, projection, counter }) => {
    await counter.start();
    await counter.send("r1/control/" + "a".repeat(64), () => undefined);
    const receipt = api.buildProductionSharedRecord(projection, {
      recording: 1,
      kind: "terminal",
      outcome: "NEEDS_RECOVERY",
    });
    const bytes = api.copyProductionSharedRecordBytes(receipt, projection),
      row = JSON.parse(bytes.toString());
    assert.deepEqual(
      Object.keys(row).toSorted(),
      [
        "corpusSha256",
        "kind",
        "lane",
        "outcome",
        "packetSha256",
        "planSha256",
        "projectId",
        "recording",
        "requests",
        "rulesSourceSha256",
        "runId",
        "sourceCommit",
        "subject",
        "cleanup",
        "timestamp",
        "type",
      ].toSorted(),
    );
    assert.equal(row.type, "production-shared-record");
    assert.equal(row.lane, "codex-lane2");
    assert.equal(row.requests, 1);
    assert.equal(row.subject, 1);
    assert.equal(row.cleanup, 0);
    assert.equal(row.runId, "recordone");
    assert.equal(row.sourceCommit, pins.sourceCommit);
    assert.equal(bytes.at(-1), 10);
    assert.ok(Number.isFinite(Date.parse(row.timestamp)));
    assert.equal(api.copyProductionSharedRecordBytes({ ...receipt }, projection), null);
    bytes.fill(0);
    assert.notEqual(api.copyProductionSharedRecordBytes(receipt, projection).at(0), 0);
  }));
test("replacing the public snapshot method cannot replace the private original count", async () =>
  fixture(async ({ api, projection, counter }) => {
    await counter.start();
    await counter.send("r1/control/" + "a".repeat(64), () => undefined);
    counter.snapshot = () => ({
      total: 9999,
      recording: 1,
      recordings: [{ subject: 9999, cleanup: 0 }],
      mode: "closed",
    });
    const receipt = api.buildProductionSharedRecord(projection, {
      recording: 1,
      kind: "terminal",
      outcome: "BLOCKED",
    });
    assert.equal(JSON.parse(api.copyProductionSharedRecordBytes(receipt, projection)).requests, 1);
  }));
test("shared factories reject copied counters, foreign plan, modified source pins and caller clocks without hooks", async () =>
  fixture(({ api, profile, boundary, counter, registry, directory }) => {
    const foreignProfile = createProductionArtifactProfile({
        plan,
        resources,
        secretRegistry: registry,
      }),
      foreignBoundary = createProductionStandaloneFailStop({ directory, profile: foreignProfile });
    const other = structuredClone(plan);
    other.bucket = "foreign.appspot.com";
    for (const input of [
      { plan, pins, profile, boundary, counter: { ...counter } },
      { plan, pins, profile: foreignProfile, boundary: foreignBoundary, counter },
      { plan: other, pins, profile, boundary, counter },
      { plan, pins: { ...pins, rulesSourceSha256: "f".repeat(64) }, profile, boundary, counter },
      { plan, pins: { ...pins, sourceCommit: "not-a-source-pin" }, profile, boundary, counter },
      { plan, pins, profile, boundary, counter, clock: () => 0 },
    ])
      assert.throws(
        () => api.createProductionSharedRecordProjection(input),
        /invalid production shared record projection/,
      );
    let hooks = 0;
    const input = { plan, pins, profile, boundary, counter };
    Object.defineProperty(input, "clock", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => api.createProductionSharedRecordProjection(input),
      /invalid production shared record projection/,
    );
    assert.equal(hooks, 0);
  }));
const failures = [
  "url",
  "name",
  "metadata",
  "runtime-hash",
  "count",
  "timestamp",
  "reason",
  "unknown-key",
  "getter",
  "proxy",
  "wrong-recording",
  "wrong-code",
  "known-secret",
  "registry-closed",
  "registry-failed",
  "unknown-kind",
  "started-with-terminal-code",
  "terminal-with-started-code",
  "configuration-with-blocked-code",
  "incomplete-local-complete",
  "started-before-admission",
  "configuration-recording-one",
];
for (const recording of [1, 2])
  for (const mode of failures.filter(
    (candidateMode) =>
      recording === 1 ||
      !["started-before-admission", "configuration-recording-one"].includes(candidateMode),
  ))
    test(`recording ${recording} refuses the ${mode} shared-row input and stops synchronously`, () => {
      const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-stop-")));
      fs.chmodSync(root, 0o700);
      const source = join(root, "child.mjs"),
        url = (name) => new URL("./storage-object/" + name, import.meta.url).href;
      const script = `
import fs from "node:fs";
import {createProductionSharedRecordProjection,buildProductionSharedRecord} from ${JSON.stringify(url("production-shared-records.mjs"))};
import {createStage3RequestCounter} from ${JSON.stringify(url("request-counter.mjs"))};
import {createProductionSecretRegistry} from ${JSON.stringify(url("production-secret-registry.mjs"))};
import {createProductionArtifactProfile} from ${JSON.stringify(url("production-artifact-policy.mjs"))};
import {createProductionStandaloneFailStop} from ${JSON.stringify(url("production-standalone-fail-stop.mjs"))};
const directory=${JSON.stringify(root)},plan=${JSON.stringify(plan)},pins=${JSON.stringify(pins)},resources=${JSON.stringify(resources)},recording=${recording},mode=${JSON.stringify(mode)};
const registry=createProductionSecretRegistry(${JSON.stringify(limits)}),profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile}),counter=createStage3RequestCounter(plan,{onStart:()=>{},onReserve:()=>{},artifactProfile:profile});
if(mode!=="started-before-admission")await counter.start();if(recording===2){counter.beginCleanup();await counter.startNextProductionRecording();}
const projection=createProductionSharedRecordProjection({plan,pins,profile,boundary,counter});
fs.writeFileSync(directory+"/started-held","held",{mode:0o600});queueMicrotask(()=>fs.writeFileSync(directory+"/after-microtask","bad"));
let row={recording,kind:"terminal",outcome:"NEEDS_RECOVERY"};
const fields={url:["url","https://storage.googleapis.com/secret"],name:["name","runtime-object"],metadata:["metadata",{key:"runtime-value"}],"runtime-hash":["bodySha256","f".repeat(64)],count:["requests",200],timestamp:["timestamp","2000-01-01T00:00:00.000Z"],reason:["reason","runtime-failure"],"unknown-key":["other","runtime-value"]};
if(fields[mode])row[fields[mode][0]]=fields[mode][1];
if(mode==="wrong-recording")row.recording=3-recording;
if(mode==="wrong-code")row.outcome="runtime-failure";
if(mode==="unknown-kind")row.kind="runtime-kind";
if(mode==="started-with-terminal-code")row.kind="started";
if(mode==="terminal-with-started-code")row.outcome="STARTED";
if(mode==="configuration-with-blocked-code"){row.kind="configuration-change";row.outcome="BLOCKED";}
if(mode==="incomplete-local-complete")row.outcome="LOCAL_COMPLETE";
if(mode==="started-before-admission"){row.kind="started";row.outcome="STARTED";}
if(mode==="configuration-recording-one"){row.kind="configuration-change";row.outcome="CONFIGURATION_CHANGED";}
if(mode==="known-secret")registry.register("timestamp");
if(mode==="registry-closed")registry.close();
if(mode==="registry-failed"){try{registry.register("");}catch{}}
if(mode==="getter")Object.defineProperty(row,"reason",{enumerable:true,get(){fs.writeFileSync(directory+"/hook-ran","bad");throw new Error("hook");}});
if(mode==="proxy")row=new Proxy(row,{getPrototypeOf(){fs.writeFileSync(directory+"/hook-ran","bad");throw new Error("hook");}});
buildProductionSharedRecord(projection,row);fs.writeFileSync(directory+"/normal-return","bad");
`;
      try {
        fs.writeFileSync(source, script, { mode: 0o600 });
        const child = spawnSync(process.execPath, [source], {
          encoding: "utf8",
          timeout: 10000,
          env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
        });
        assert.equal(child.error, undefined);
        assert.equal(child.status, 2, child.stderr);
        assert.equal(child.stdout, "");
        assert.equal(child.stderr, "");
        assert.equal(fs.existsSync(root + "/started-held"), true);
        for (const name of [
          "hook-ran",
          "after-microtask",
          "normal-return",
          "appended-row",
          "end-row",
          "unlock",
        ])
          assert.equal(fs.existsSync(root + "/" + name), false, name);
        const audit = JSON.parse(fs.readFileSync(root + "/privacy-r" + recording + ".json"));
        assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
        assert.equal(
          audit.reason,
          mode === "known-secret" ? "shared-record-withheld-privacy" : "shared-record-uncheckable",
        );
      } finally {
        fs.rmSync(root, { recursive: true });
      }
    });

test("private diagnostics identify the target recording before either started callback and after failed admission", async () =>
  fixture(async ({ profile }) => {
    const frames = [];
    const counter = createStage3RequestCounter(plan, {
      artifactProfile: profile,
      onReserve: () => {},
      onStart: (event) => {
        frames.push({ event, snapshot: originalProductionStage3CounterSnapshot(counter, profile) });
        if (event.recording === 2) throw new Error("synthetic second admission failure");
      },
    });
    assert.equal(originalProductionStage3CounterSnapshot(counter, profile).startAttempted, false);
    await counter.start();
    counter.beginCleanup();
    await assert.rejects(
      counter.startNextProductionRecording(),
      /synthetic second admission failure/,
    );
    assert.deepEqual(
      frames.map(({ event, snapshot }) => ({
        event: event.recording,
        recording: snapshot.recording,
        started: snapshot.startAttempted,
        busy: snapshot.busy,
      })),
      [
        { event: 1, recording: 1, started: true, busy: true },
        { event: 2, recording: 2, started: true, busy: true },
      ],
    );
    const stopped = originalProductionStage3CounterSnapshot(counter, profile);
    assert.equal(stopped.recording, 2);
    assert.equal(stopped.startAttempted, true);
    assert.equal(stopped.admissionFailed, true);
    assert.equal(stopped.busy, false);
    const unbound = createStage3RequestCounter(plan, { onStart: () => {}, onReserve: () => {} });
    assert.equal(originalProductionStage3CounterSnapshot(unbound, undefined), null);
  }));

test("both started candidates use the target run and configuration changes remain recording-two candidates", async () =>
  fixture(async ({ api, profile, boundary }) => {
    const rows = [];
    let projection;
    const counter = createStage3RequestCounter(plan, {
      artifactProfile: profile,
      onReserve: () => {},
      onStart: (event) => {
        const receipt = api.buildProductionSharedRecord(projection, {
          recording: event.recording,
          kind: "started",
          outcome: "STARTED",
        });
        rows.push(JSON.parse(api.copyProductionSharedRecordBytes(receipt, projection)));
      },
    });
    projection = api.createProductionSharedRecordProjection({
      plan,
      pins,
      profile,
      boundary,
      counter,
    });
    await counter.start();
    await counter.send("r1/control/" + "a".repeat(64), () => undefined);
    counter.beginCleanup();
    await counter.startNextProductionRecording();
    await counter.send("r2/control/" + "b".repeat(64), () => undefined);
    for (const [kind, outcome] of [
      ["configuration-change", "CONFIGURATION_CHANGED"],
      ["terminal", "BLOCKED"],
    ]) {
      const receipt = api.buildProductionSharedRecord(projection, { recording: 2, kind, outcome });
      rows.push(JSON.parse(api.copyProductionSharedRecordBytes(receipt, projection)));
    }
    assert.deepEqual(
      rows.map((row) => ({
        recording: row.recording,
        runId: row.runId,
        kind: row.kind,
        outcome: row.outcome,
        requests: row.requests,
        subject: row.subject,
        cleanup: row.cleanup,
      })),
      [
        {
          recording: 1,
          runId: "recordone",
          kind: "started",
          outcome: "STARTED",
          requests: 0,
          subject: 0,
          cleanup: 0,
        },
        {
          recording: 2,
          runId: "recordtwo",
          kind: "started",
          outcome: "STARTED",
          requests: 1,
          subject: 0,
          cleanup: 0,
        },
        {
          recording: 2,
          runId: "recordtwo",
          kind: "configuration-change",
          outcome: "CONFIGURATION_CHANGED",
          requests: 2,
          subject: 1,
          cleanup: 0,
        },
        {
          recording: 2,
          runId: "recordtwo",
          kind: "terminal",
          outcome: "BLOCKED",
          requests: 2,
          subject: 1,
          cleanup: 0,
        },
      ],
    );
  }));
