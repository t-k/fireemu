import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import net from "node:net";
import dns from "node:dns";
import {
  loadNativeRequests,
  createCollector,
  issueOperation,
  collectOperationTerminal,
} from "./lifecycle-evidence.mjs";
import { sessionEndpoint } from "./run.mjs";
import { createSdk } from "./sdk.mjs";
import { createOwnership } from "./names.mjs";
import { createRawRest } from "./rest.mjs";
const sha = (b) => createHash("sha256").update(b).digest("hex");
export function selectSpecs(target, runId) {
  const project = target.split("/")[1];
  const source = `//fireemu/recorder/${runId}`,
    object = (extra = {}) => ({ type: "fireemu.recorder.v1.sdk", data: { probe: true }, ...extra });
  return [
    ["full-channel", { channel: target, events: object({ source }) }],
    [
      "relative-channel",
      { channel: target.replace(`projects/${project}/`, ""), events: object({ source }) },
    ],
    [
      "multiple-events",
      { channel: target, events: [object({ source }), object({ source, data: "text" })] },
    ],
    ["generated-metadata", { channel: target, events: object(), source }],
    [
      "caller-metadata",
      {
        channel: target,
        events: object({
          source,
          id: `fe${runId}-sdk-id`,
          time: "2026-10-05T01:02:03.000Z",
          subject: "sdk-subject",
          datacontenttype: "application/json",
          custom: "extension",
        }),
      },
    ],
    ["default-channel", { events: object({ source }) }],
    [
      "allowed-event-types",
      {
        channel: target,
        channelOptions: { allowedEventTypes: ["fireemu.recorder.v1.other"] },
        events: object({ source }),
      },
    ],
    ["missing-source", { channel: target, events: object() }],
    ["missing-data", { channel: target, events: { type: "t", source } }],
    ["bad-time", { channel: target, events: object({ source, time: "yesterday" }) }],
    ["non-string-extension", { channel: target, events: object({ source, custom: 5 }) }],
    ["number-data", { channel: target, events: object({ source, data: 5 }) }],
    ["bad-channel-name", { channel: "not/a/channel", events: object({ source }) }],
  ];
}
/** Original SDK outcome notes must be supplied from a digest-bound native input, never inferred from REST. */
export function loadSdkInput({ path, sha256, sdkDir, outcomesPath, outcomesSha256 }) {
  const bytes = readFileSync(path);
  assert.equal(sha(bytes), sha256, "original SDK journal digest");
  const rows = bytes.toString().split("\n").filter(Boolean).map(JSON.parse);
  const expected = rows.filter(
    (r) => r.case === "admin-sdk-publish" && r.op === "sdk.publishEvents",
  );
  assert.deepEqual(
    expected.map((r) => r.n),
    [156, 157, 158, 159, 160, 162],
  );
  const target = expected[0].request.path.slice(4).replace(/:publishEvents$/, "");
  const runId = expected[0].request.body.events[0].source.split("/").at(-1);
  const originalOutcomes = outcomesPath
    ? (() => {
        const noteBytes = readFileSync(outcomesPath);
        assert.equal(sha(noteBytes), outcomesSha256, "original SDK notes digest");
        return JSON.parse(noteBytes);
      })()
    : rows.filter((r) => r.case === "admin-sdk-publish" && r.note === "sdk-outcome");
  const specs = selectSpecs(target, runId);
  assert.deepEqual(
    originalOutcomes.map((r) => r.name),
    specs.map(([name]) => name),
    "original SDK outcome notes required",
  );
  const native = loadNativeRequests({ path, sha256, ordinals: [151, 188] });
  assert.equal(native.get(151).request.body.name, target);
  assert.equal(native.get(188).request.path, "/v1/" + target);
  return {
    packet: { project: target.split("/")[1], channels: [target], runId, sdkDir },
    expected,
    create: native.get(151),
    deleted: native.get(188),
    specs,
    originalOutcomes,
    nativeSha256: sha256,
  };
}
export function checkWire(body, expected, { caller = false } = {}) {
  assert.equal(body.events.length, expected.events.length);
  const generated = [];
  for (let i = 0; i < body.events.length; i++) {
    const actual = structuredClone(body.events[i]),
      original = structuredClone(expected.events[i]);
    if (!caller) {
      assert.match(
        actual.id,
        /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
      );
      const time = actual.attributes.time.ceTimestamp;
      assert.equal(new Date(time).toISOString(), time);
      generated.push({ id: actual.id, time });
      delete actual.id;
      delete original.id;
      delete actual.attributes.time;
      delete original.attributes.time;
    }
    assert.deepEqual(actual, original, "SDK stable envelope fields");
  }
  return generated;
}
function bounded(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error(label + " timeout: UNKNOWN")), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}
export async function runProbe(input, { base }, testDependencies = {}) {
  const origin = new URL(sessionEndpoint(base)).origin,
    target = input.packet.channels[0],
    path = `/v1/${target}:publishEvents`;
  const fixtureOnly = testDependencies.fixtureOnly === true;
  assert.ok(fixtureOnly || Object.keys(testDependencies).length === 0, "test dependencies only");
  if (!fixtureOnly) {
    assert.ok(
      String(net.Socket.prototype.connect).includes("offline: remote socket refused"),
      "offline socket guard required",
    );
    assert.ok(
      String(dns.lookup).includes("offline: remote DNS refused"),
      "offline DNS guard required",
    );
    assert.ok(
      String(globalThis.fetch).includes("offline: remote fetch refused"),
      "offline fetch guard required",
    );
  }
  const limits = fixtureOnly
    ? testDependencies.limits
    : { publishMs: 8000, settleMs: 8000, closeMs: 5000 };
  const result = {
    fixtureOnly,
    complete: false,
    base: origin,
    target,
    native: {
      create: 151,
      publishes: [156, 157, 158, 159, 160, 162],
      deleted: 188,
      sha256: input.nativeSha256,
    },
    proofs: [],
    sdkEvents: [],
    calls: [],
    sdkWire: [],
    sdkWork: [],
    sdkUnsettled: false,
    cleanupComplete: false,
  };
  const collector = (testDependencies.createCollector ?? createCollector)({
    base: origin,
    maxElapsedMs: 150000,
    maxRequests: 600,
    timeoutMs: 8000,
  });
  const issue = testDependencies.issueOperation ?? issueOperation,
    terminal = testDependencies.collectOperationTerminal ?? collectOperationTerminal;
  let sdk,
    createAttempted = false,
    deleteAttempted = false,
    forwarded = 0,
    activeCall = null;
  const work = [];
  const track = (kind, promise) => {
    const state = { kind, status: "pending" };
    result.sdkWork.push(state);
    const tracked = Promise.resolve(promise).then(
      (value) => {
        state.status = "fulfilled";
        return value;
      },
      (error) => {
        state.status = "rejected";
        throw error;
      },
    );
    tracked.catch(() => {});
    work.push(tracked);
    return tracked;
  };
  const defaultTarget = `projects/${input.packet.project}/locations/us-central1/channels/firebase`;
  const defaultForward = createRawRest({
    base: origin,
    defaultTimeoutMs: 8000,
    getToken: async () => "ya29.replay-token",
    quotaProject: null,
    budget: { consume() {} },
    capture: {
      record: (entry) => {
        if (entry.op === "sdk.publishEvents") result.sdkWire.push(entry);
        else result.defaultReadWire = entry;
      },
    },
    fetchImpl: (url, options) => {
      const u = new URL(url);
      assert.equal(u.origin, origin);
      assert.ok(
        [path, "/v1/" + defaultTarget + ":publishEvents", "/v1/" + defaultTarget].includes(
          u.pathname,
        ),
      );
      assert.ok(["POST", "GET"].includes(options.method));
      return fetch(url, { ...options, redirect: "error" });
    },
  });
  try {
    createAttempted = true;
    const issued = await issue({ collector, input: input.create });
    const ready = await terminal({ collector, issued });
    assert.equal(ready.complete, true);
    result.proofs.push(ready);
    const ownership = createOwnership({ project: input.packet.project, runId: input.packet.runId });
    ownership.allowPublish(target);
    const absent = await (testDependencies.defaultRead ?? defaultForward.request)({
      label: { case: "admin-sdk-publish", step: "default-read" },
      op: "getChannel",
      method: "GET",
      path: "/v1/" + defaultTarget,
    });
    result.defaultRead = absent;
    assert.equal(absent.status, 404);
    assert.equal(absent.body?.error?.status, "NOT_FOUND");
    ownership.allowPublish(defaultTarget);
    const requireSdk = createRequire(join(input.packet.sdkDir, "firebase-admin/package.json"));
    result.sdkResolved = fixtureOnly
      ? { fixtureOnly: true }
      : Object.fromEntries(
          ["firebase-admin/app", "firebase-admin/eventarc"].map((name) => [
            name,
            requireSdk.resolve(name),
          ]),
        );
    sdk = await bounded(
      track(
        "construction",
        (testDependencies.makeSdk ?? createSdk)({
          project: input.packet.project,
          runId: input.packet.runId,
          caseId: "admin-sdk-publish",
          getToken: async () => "ya29.replay-token",
          ownership,
          publishPrefix: "/v1",
          note: (kind, state) => result.sdkEvents.push({ kind, state }),
          importer: (name) => import(pathToFileURL(requireSdk.resolve(name)).href),
          transport: {
            request: (spec) => {
              assert.ok(activeCall);
              assert.equal(++activeCall.forwarded, 1, "one forward per SDK call");
              ++forwarded;
              assert.equal(spec.method, "POST");
              assert.equal(spec.op, "sdk.publishEvents");
              const expected = input.expected[activeCall.index];
              assert.ok(expected);
              assert.equal(spec.path, expected.request.path);
              activeCall.generatedFormat = checkWire(spec.body, expected.request.body, {
                caller: activeCall.name === "caller-metadata",
              });
              return track(
                "forward:" + activeCall.name,
                (testDependencies.forward ?? defaultForward.request)(spec),
              );
            },
          },
        }),
      ),
      limits.publishMs,
      "construction",
    );
    for (let index = 0; index < input.specs.length; index++) {
      const [name, spec] = input.specs[index];
      activeCall = {
        index,
        name,
        input: spec,
        inputSha256: sha(JSON.stringify(spec)),
        forwarded: 0,
        started: true,
      };
      result.calls.push(activeCall);
      const outcome = await bounded(
        track("publish:" + name, sdk.publish(spec)),
        limits.publishMs,
        "publish:" + name,
      );
      activeCall.outcome = outcome;
      activeCall.originalBOutcome = input.originalOutcomes.find((x) => x.name === name);
      assert.ok(activeCall.originalBOutcome, "missing original SDK outcome");
      const original = activeCall.originalBOutcome;
      assert.deepEqual(
        outcome,
        {
          threw: original.threw,
          ...(original.error ? { error: original.error } : {}),
          requests: original.requests,
          suppressed: original.suppressed,
        },
        "original SDK outcome",
      );
      activeCall.settled = true;
      const wires = index < 6 ? 1 : 0;
      assert.equal(outcome.requests, wires);
      assert.equal(outcome.suppressed, 0);
      assert.equal(activeCall.forwarded, wires);
      if (index === 6) assert.equal(outcome.threw, false);
      if (index > 6) {
        assert.equal(outcome.threw, true);
        assert.equal(outcome.error?.code, "eventarc/invalid-argument");
      }
      activeCall = null;
    }
    assert.equal(result.calls.length, 13);
    assert.equal(forwarded, 6);
  } catch (error) {
    result.failure = { name: error.name, message: error.message };
  } finally {
    if (sdk) {
      try {
        await bounded(track("close", sdk.close()), limits.closeMs, "close");
      } catch (error) {
        result.closeFailure = { name: error.name, message: error.message };
      }
    }
    try {
      await bounded(Promise.allSettled(work), limits.settleMs, "SDK settlement");
    } catch (error) {
      result.settlementFailure = { name: error.name, message: error.message };
    }
    result.sdkUnsettled =
      result.sdkWork.some((x) => x.status === "pending") ||
      !!result.closeFailure ||
      (result.sdkWork.some((x) => x.kind === "construction") && !sdk);
    if (createAttempted && !result.sdkUnsettled) {
      try {
        deleteAttempted = true;
        const issued = await issue({ collector, input: input.deleted });
        const absent = await terminal({ collector, issued });
        assert.equal(absent.complete, true);
        result.proofs.push(absent);
        result.cleanupComplete = true;
      } catch (error) {
        result.cleanupFailure = { name: error.name, message: error.message };
      }
    }
  }
  result.deleteAttempted = deleteAttempted;
  result.exchanges = collector.exchanges;
  result.complete =
    !result.failure &&
    !result.closeFailure &&
    !result.settlementFailure &&
    result.cleanupComplete &&
    !result.sdkUnsettled;
  return result;
}

/** Recompute original SDK outcomes and stable envelopes from the retained genuine invocation. */
export function validateSdkReport(report, input) {
  assert.equal(report.complete, true, "incomplete SDK report");
  if (report.supervision) {
    assert.equal(report.supervision.complete, true, "SDK outer ownership completion failed");
    assert.equal(report.supervision.ownedAbsence, true);
    assert.equal(report.supervision.ownershipUnresolved, false);
    assert.ok(!report.supervision.failure);
  }
  assert.equal(report.fixtureOnly, false, "HTTP-only or substituted SDK invocation");
  assert.equal(report.sdkUnsettled, false);
  assert.equal(report.cleanupComplete, true);
  assert.deepEqual(
    report.proofs.map((proof) => proof.verb),
    ["create", "delete"],
    "missing SDK lifecycle case",
  );
  assert.ok(
    report.sdkWork.some((x) => x.kind === "close" && x.status === "fulfilled"),
    "missing SDK close",
  );
  assert.equal(report.calls?.length, input.specs.length, "missing SDK calls");
  assert.equal(input.originalOutcomes.length, input.specs.length, "missing native SDK outcomes");
  for (const [name, suffix] of [
    ["firebase-admin/app", "/firebase-admin/lib/app/index.js"],
    ["firebase-admin/eventarc", "/firebase-admin/lib/eventarc/index.js"],
  ])
    assert.ok(
      report.sdkResolved?.[name]?.replaceAll("\\", "/").endsWith(suffix),
      "actual SDK resolution required",
    );
  assert.ok(
    report.sdkWork.some((x) => x.kind === "construction" && x.status === "fulfilled"),
    "missing SDK construction",
  );
  assert.ok(
    report.sdkWork.every((x) => x.status === "fulfilled"),
    "unsettled SDK work",
  );
  assert.equal(report.sdkWire.length, input.expected.length, "missing SDK forward");
  for (let i = 0; i < input.specs.length; i++) {
    const [name, spec] = input.specs[i],
      call = report.calls[i],
      original = input.originalOutcomes[i];
    assert.equal(call.name, name);
    assert.equal(call.index, i);
    assert.equal(call.settled, true);
    assert.deepEqual(call.input, spec, "original SDK caller input");
    assert.equal(call.inputSha256, sha(JSON.stringify(spec)));
    const wanted = {
      threw: original.threw,
      ...(original.error ? { error: original.error } : {}),
      requests: original.requests,
      suppressed: original.suppressed,
    };
    assert.deepEqual(call.outcome, wanted, "original SDK outcome");
    assert.equal(call.forwarded, original.requests);
    assert.ok(report.sdkWork.some((x) => x.kind === "publish:" + name && x.status === "fulfilled"));
    if (i >= input.expected.length) continue;
    const wire = report.sdkWire[i],
      native = input.expected[i];
    assert.equal(wire.request.method, "POST");
    assert.equal(wire.request.path, native.request.path);
    checkWire(wire.request.body, native.request.body, { caller: name === "caller-metadata" });
    const encoded = wire.response.bodyBase64 ?? wire.response.bodyBase64Parts?.join("");
    const bytes = Buffer.from(encoded, "base64");
    assert.equal(bytes.toString("base64"), encoded);
    assert.equal(bytes.length, wire.response.bodyBytes);
    assert.equal(sha(bytes), wire.response.bodySha256);
    assert.equal(wire.response.headers["content-length"], String(bytes.length));
    assert.deepEqual(JSON.parse(bytes.toString()), wire.response.body);
    assert.equal(wire.response.status, native.response.status, "original SDK forward status");
    assert.deepEqual(wire.response.body, native.response.body, "original SDK forward body");
  }
  return true;
}
