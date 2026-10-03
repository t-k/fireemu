import assert from "node:assert/strict";
import test from "node:test";
import { buildNativeManifest } from "./storage-rules/management-native-manifest.mjs";

export function nativeParams(branch = "absent") {
  return {
    runId: "native-mock-a",
    sourceCommit: "7b4861263943cd17f455051c1c4878ff27f5e982",
    sourceTree: "54ea32bcd98ecc7f733555146244ed62a66246dc",
    bucket: "fireemu-oracle-query.firebasestorage.app",
    baseline:
      branch === "absent"
        ? { kind: "absent", observedAt: 1000, bucketAbsent: true, bucketlessAbsent: true }
        : {
            kind: "present",
            observedAt: 1000,
            release: {
              name: "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app",
              rulesetName: "projects/fireemu-oracle-query/rulesets/baseline",
              updateTime: "2026-10-03T00:00:00Z",
            },
            source:
              "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow get: if true; } } }",
            bucketlessAbsent: true,
          },
    limits: {
      settleCycles: 4,
      intervalMs: 1,
      listPages: 2,
      credentialAttempts: 2,
      deadlineSeconds: 120,
    },
    priorCompileProofs: ["c", "d"].map((tag) => ({
      runId: `stage3-20260930${tag}`,
      journalSha256: tag.repeat(64),
      validSourceCount: 338,
    })),
  };
}

test("the dedicated inventory counts each typed route once and keeps the full valid-source obligation", () => {
  for (const branch of ["absent", "present"]) {
    const m = buildNativeManifest(nativeParams(branch));
    assert.equal(m.sendAuthorized, false);
    assert.equal(m.closureReady, false);
    assert.equal(new Set(m.rows.map((r) => r.id)).size, m.rows.length);
    assert.equal(
      Object.values(m.counts.partitions).reduce((a, b) => a + b, 0),
      m.counts.total,
    );
    assert.equal(m.counts.total, m.rows.length);
    assert.equal(m.rows.filter((r) => r.kind === "invalid-test").length, 1);
    assert(m.rows.every((r) => !r.request.origin.includes("identitytoolkit")));
    assert.equal(m.priorCompileProofs[0].validSourceCount, 338);
    assert.equal(m.accountProof.status, "NO_CREATION");
  }
});

const { buildNativeSchedule } = await import("./storage-rules/management-native-schedule.mjs");
test("installed-before and after proofs enclose the single invalid attempt and precede restore", () => {
  const m = buildNativeManifest(nativeParams()),
    s = buildNativeSchedule(m);
  const ids = s.normal.flatMap((step) => step.ids);
  assert(ids.indexOf("before/deny/decision") < ids.indexOf("invalid/test"));
  assert(ids.indexOf("invalid/test") < ids.indexOf("after/release"));
  assert(ids.indexOf("after/deny/decision") < ids.indexOf("restore/guard"));
  assert.equal(s.allIds.length, m.rows.length);
  assert.equal(new Set(s.allIds).size, s.allIds.length);
  assert.equal(s.maximumRecoveryRuns, 1);
  assert.equal(s.settleConsecutive, 2);
  const altered = structuredClone(m);
  altered.rows.find((r) => r.id === "invalid/test").phase = "recovery";
  assert.throws(() => buildNativeSchedule(altered), /manifest/);
});

const {
  createNativeGate,
  createOwnerOnlyProvider,
  validateNativeApproval,
  runNativeRecordCommand,
} = await import("./storage-rules/management-native-record.mjs");
const bytes = (body, status = 200) => ({
  status,
  rawHeaders: [
    "content-type",
    "application/json; charset=utf-8",
    "content-length",
    String(Buffer.byteLength(JSON.stringify(body))),
  ],
  bytes: Buffer.from(JSON.stringify(body)),
});
function mockProvider() {
  return createOwnerOnlyProvider({
    refreshBody: Buffer.from(
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: "synthetic-client",
        client_secret: "synthetic-secret",
        refresh_token: "synthetic-refresh",
      }).toString(),
    ),
    nowSeconds: () => 1001,
    digestSalt: "a".repeat(64),
  });
}
function gateHarness(manifest, fault = {}) {
  const events = [],
    sent = [],
    provider = mockProvider();
  let checks = 0;
  const admission = {
    begin: async () => ({ admitted: true }),
    check: async () => {
      checks++;
      return { admitted: !fault.revoked };
    },
  };
  const reservations = {
    onStarted: async (r) => events.push(["started", r]),
    onReserve: async (r) => events.push(["reserved", r]),
    onTerminal: async (r) => events.push(["terminal", r]),
  };
  const capture = {
    writeIntent: async (r) => events.push(["intent", r]),
    writeDelegatedTarget: async (r) => events.push(["delegated", r]),
    writeResponse: async (r) => {
      if (fault.capture) throw Error("capture failed");
      events.push(["response", r]);
    },
    writeNote: async (r) => events.push(["note", r]),
    writeCredentialProof: async (r) => events.push(["credential", r]),
    snapshot: () => ({ uncertain: false }),
  };
  const targets = { verify: (p) => p === prepared || p === bucket };
  const prepared = {
    rowId: "preflight/owner-userinfo",
    credential: "admin",
    project: "fireemu-oracle-query",
    redacted: "GET owner-userinfo",
    targetSha256: "a".repeat(64),
    spec: {
      url: "https://www.googleapis.com/oauth2/v2/userinfo",
      method: "GET",
      headers: {},
      body: null,
    },
  };
  const bucket = {
    ...prepared,
    rowId: "preflight/bucket",
    redacted: "GET bucket",
    spec: {
      ...prepared.spec,
      url: `https://storage.googleapis.com/storage/v1/b/${manifest.bucket}`,
    },
  };
  const lease = { dispatch: async (fn) => fn() };
  const transport = {
    validate: () => {},
    send: async (spec) => {
      sent.push(spec);
      if (fault.unknown) throw Error("lost response");
      return spec.url.endsWith("/token")
        ? bytes({
            access_token: "synthetic-owner-token-0000",
            token_type: "Bearer",
            expires_in: 3600,
          })
        : bytes({ id: "synthetic-owner" });
    },
  };
  const gate = createNativeGate({
    manifest,
    admission,
    reservations,
    capture,
    targets,
    provider,
    lease,
    transport,
    nowSeconds: () => 1001,
  });
  return {
    gate,
    provider,
    events,
    sent,
    prepared,
    bucket,
    capture,
    admission,
    get checks() {
      return checks;
    },
  };
}

test("owner refresh uses one leased counted OAuth row before a data request, with durable capture", async () => {
  const m = buildNativeManifest(nativeParams()),
    h = gateHarness(m);
  await h.gate.start();
  await h.gate.sendCredential("preflight/credential/owner/1");
  await h.gate.send(h.prepared);
  assert.equal(h.sent.length, 2);
  assert.equal(h.gate.snapshot().requests, 2);
  for (const id of ["preflight/credential/owner/1", "preflight/owner-userinfo"]) {
    const kinds = h.events.filter((e) => e[1].operationId === id).map((e) => e[0]);
    assert(kinds.indexOf("intent") < kinds.indexOf("reserved"));
    assert(kinds.includes("response"));
  }
  assert.equal(h.sent[1].headers["x-goog-user-project"], undefined);
  await assert.rejects(h.gate.sendCredential("preflight/credential/owner/1"), /used|duplicate/);
});

const { withNativeMockRecording, nativeRunnerDigest } =
  await import("./storage-rules/management-native-record.mjs");
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { nativeDigest } from "./storage-rules/management-native-manifest.mjs";

export function nativeApprovalFixture(m) {
  const pins = {
    packetSha256: "a".repeat(64),
    sourceCommit: m.sourceCommit,
    sourceTree: m.sourceTree,
    runnerSha256: nativeRunnerDigest(),
    manifestSha256: m.manifestSha256,
    fixtureSchemaSha256: "e".repeat(64),
  };
  const packet = {
    taskId: "STORAGE-RULES",
    packetName: "installed-invalid-mock",
    ...pins,
    projects: ["fireemu-oracle-query"],
    maxRequests: m.counts.total * 2,
    reserveUsd: 1,
    runId: m.runId,
    baselineSha256: m.baselineSha256,
    perRecordingCap: m.counts.total,
  };
  const review = {
    verdict: "APPROVE",
    must: [],
    should: [],
    ...pins,
    envelopeId: null,
    withinEnvelope: false,
  };
  const current = {
    kind: "MOCK_CURRENT_ADMISSION",
    go: "GO",
    runId: m.runId,
    packetSha256: pins.packetSha256,
    sourceCommit: m.sourceCommit,
    sourceTree: m.sourceTree,
    manifestSha256: m.manifestSha256,
    baselineSha256: m.baselineSha256,
    evidenceSha256: "f".repeat(64),
    validationSha256: "0".repeat(64),
    expiresAt: 1100,
    baselineObservedAt: 1000,
  };
  const fields = ["decision=APPROVE", ...Object.entries(pins).map(([k, v]) => `${k}=${v}`)].join(
    ";",
  );
  return {
    packet,
    review,
    current,
    ledger: `- 2026-10-03 | STORAGE-RULES installed-invalid-mock | ${fields} | オーナー（mock fixture） | synthetic-only approval\n`,
  };
}
export function nativeWireModel(m, fault = "none", delay = 0) {
  const objects = new Map(),
    wire = [],
    rulesets = new Map();
  let released =
      m.baseline.kind === "present"
        ? { ...m.baseline.release, createTime: "2026-10-03T00:00:00Z" }
        : null,
    invalid = false,
    publishes = 0,
    settleReads = 0;
  let created = false;
  if (released)
    rulesets.set(released.rulesetName, {
      name: released.rulesetName,
      createTime: "2026-10-03T00:00:00Z",
      source: { files: [{ name: "storage.rules", content: m.baseline.source }] },
    });
  const denied = bytes(
      { error: { code: 403, message: "Permission denied." } },
      fault === "contract-deny-status200" ? 200 : 403,
    ),
    noRelease = bytes({ error: { code: 400, message: "No active release." } }, 400),
    allowed = {
      status: 200,
      rawHeaders: ["content-type", "application/octet-stream", "content-length", "4"],
      bytes: Buffer.from("next"),
    };
  const metadataAbsence = Object.fromEntries(
    m.resources.objects.map((name) => [
      name,
      bytes({ error: { code: 404, status: "NOT_FOUND", message: `Missing ${name}` } }, 404),
    ]),
  );
  const mediaAbsence = Object.fromEntries(
    m.resources.objects.map((name) => [
      name,
      {
        status: 404,
        rawHeaders: [
          "content-type",
          "text/plain",
          "content-length",
          String(Buffer.byteLength(`No such object: ${m.bucket}/${name}`)),
        ],
        bytes: Buffer.from(`No such object: ${m.bucket}/${name}`),
      },
    ]),
  );
  const contracts = {
    allowed,
    denied: fault === "contract-allows-deny" ? allowed : denied,
    noRelease,
    adminMedia: allowed,
    objectDelete: { status: 204, rawHeaders: ["content-length", "0"], bytes: Buffer.alloc(0) },
    prefixEmpty: bytes({}),
    metadataAbsence,
    mediaAbsence,
  };
  const notFound = () =>
    bytes({ error: { code: 404, status: "NOT_FOUND", message: "Missing rules resource" } }, 404);
  const transport = {
    validate(spec) {
      assert(spec.url.startsWith("https://"));
    },
    async send(spec) {
      wire.push(spec);
      const u = new URL(spec.url),
        path = u.pathname,
        method = spec.method,
        json =
          spec.body && spec.headers["content-type"]?.startsWith("application/json")
            ? JSON.parse(spec.body.toString())
            : null;
      if (u.origin === "https://oauth2.googleapis.com") {
        if (fault === "hidden-provider-call") wire.push({ ...spec, hidden: true });
        return bytes({
          access_token: "synthetic-owner-token-0000",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      if (path === "/oauth2/v2/userinfo") return bytes({ id: "synthetic-owner" });
      if (u.origin === "https://storage.googleapis.com") {
        if (path === `/storage/v1/b/${m.bucket}`) return bytes({ name: m.bucket });
        if (path.startsWith("/upload/")) {
          const name = u.searchParams.get("name");
          const role = m.resources.objects.indexOf(name);
          objects.set(name, {
            name,
            bucket: m.bucket,
            generation: String(10 + role),
            size: "4",
            contentType: "application/octet-stream",
          });
          return bytes(objects.get(name));
        }
        if (path.endsWith("/o")) return contracts.prefixEmpty;
        const name = decodeURIComponent(path.split("/o/")[1]);
        if (method === "DELETE") {
          objects.delete(name);
          return contracts.objectDelete;
        }
        if (u.searchParams.get("alt") === "media")
          return objects.has(name)
            ? invalid && fault === "media-drift" && name === m.resources.objects[1]
              ? { ...allowed, bytes: Buffer.from("oops") }
              : allowed
            : mediaAbsence[name];
        if (!objects.has(name)) return metadataAbsence[name];
        const metadata = { ...objects.get(name) };
        if (invalid && fault === "generation-drift") metadata.generation = "12";
        return bytes(metadata);
      }
      if (u.origin === "https://firebaserules.googleapis.com") {
        if (path.endsWith(":test")) {
          if (json.source.files[0].content === m.sources.invalid.content) {
            invalid = true;
            if (fault === "invalid-unknown") throw Error("lost invalid response");
            if (fault === "invalid-success") return bytes({});
            return bytes({
              issues: [
                {
                  severity: "ERROR",
                  description: "invalid expression",
                  sourcePosition: { fileName: "storage.rules", line: 5, column: 21 },
                },
              ],
            });
          }
          return bytes({});
        }
        if (path.endsWith("/rulesets")) {
          if (method === "POST") {
            if (fault === "unknown-create") throw Error("lost source create");
            const name = "projects/fireemu-oracle-query/rulesets/owned-A";
            const source = { name, createTime: "2026-10-03T00:00:00Z", source: json.source };
            rulesets.set(name, source);
            created = true;
            return bytes(source);
          }
          return bytes({
            rulesets: [...rulesets.values()].map((r) => ({
              name: r.name,
              createTime: r.createTime,
              metadata: { services: ["firebase.storage"] },
            })),
          });
        }
        if (path.includes("/rulesets/")) {
          const name = path.slice(4);
          if (method === "DELETE") {
            if (fault === "unknown-delete") throw Error("lost source delete");
            rulesets.delete(name);
            return bytes({});
          }
          if (!rulesets.has(name)) return notFound();
          const source = structuredClone(rulesets.get(name));
          if (invalid && fault === "source-drift")
            source.source.files[0].content = "foreign source";
          return bytes(source);
        }
        if (path.includes("/releases")) {
          if (method === "POST" || method === "PATCH") {
            if (fault === "unknown-publish" && publishes === 0) throw Error("lost publication");
            publishes++;
            const name = (json.release ?? json).rulesetName;
            const next = {
              name: m.releaseName,
              rulesetName: name,
              createTime: "2026-10-03T00:00:00Z",
              updateTime: publishes === 1 ? "2026-10-03T00:01:00Z" : "2026-10-03T00:02:00Z",
            };
            if (!(fault === "restore-missing" && publishes > 1)) released = next;
            return bytes(next);
          }
          if (method === "DELETE") {
            if (fault !== "restore-missing") released = null;
            return bytes({});
          }
          if (path.endsWith("firebase.storage")) return notFound();
          if (fault === "baseline-branch-mixed" && created && publishes === 0)
            return m.baseline.kind === "absent"
              ? bytes({
                  name: m.releaseName,
                  rulesetName: "projects/fireemu-oracle-query/rulesets/foreign",
                  createTime: "2026-10-03T00:00:00Z",
                  updateTime: "2026-10-03T00:00:00Z",
                })
              : notFound();
          if (!released) return notFound();
          const state = { ...released };
          if (invalid && fault === "release-identity-drift")
            state.updateTime = "2026-10-03T00:03:00Z";
          return bytes(state);
        }
      }
      if (u.origin === "https://firebasestorage.googleapis.com") {
        const name = decodeURIComponent(path.split("/o/")[1]),
          allow = name === m.resources.objects[0];
        if (!released) return noRelease;
        if (released.rulesetName.endsWith("baseline")) return allowed;
        if (!invalid) {
          settleReads++;
          if (fault === "incomplete-settle" || settleReads <= delay * 2) return denied;
        }
        if (
          (!invalid &&
            settleReads > delay * 2 + 4 &&
            fault === `missing-before-${allow ? "allow" : "deny"}`) ||
          (invalid && fault === `missing-after-${allow ? "allow" : "deny"}`)
        )
          return bytes({ error: "missing witness" }, 500);
        if (fault === "duplicate-invalid" && invalid)
          return bytes({ error: "duplicate required invalid" }, 500);
        return allow ? allowed : fault === "contract-allows-deny" ? allowed : denied;
      }
      throw Error("undeclared wire route");
    },
  };
  return { transport, contracts, wire, objects, rulesets };
}
export async function runNativeMock(
  branch = "absent",
  fault = "none",
  delay = 0,
  changeProof = () => {},
) {
  const m = structuredClone(buildNativeManifest(nativeParams(branch))),
    proof = nativeApprovalFixture(m),
    model = nativeWireModel(m, fault, delay),
    dir = await mkdtemp(join(tmpdir(), "storage-native-mock-"));
  const previousFixture = proof.packet.fixtureSchemaSha256;
  proof.packet.fixtureSchemaSha256 = nativeDigest(model.contracts);
  proof.review.fixtureSchemaSha256 = proof.packet.fixtureSchemaSha256;
  proof.ledger = proof.ledger.replace(previousFixture, proof.packet.fixtureSchemaSha256);
  changeProof(proof);
  if (fault === "duplicate-invalid")
    m.rows.push(structuredClone(m.rows.find((row) => row.kind === "invalid-test")));
  await mkdir(join(dir, "run"), { mode: 0o700 });
  let result;
  try {
    result = await withNativeMockRecording(
      {
        manifest: m,
        packet: proof.packet,
        review: proof.review,
        readLedger: async () => proof.ledger,
        readCurrent: async () => proof.current,
        directory: join(dir, "run"),
        lockOptions: {
          lockDir: join(dir, "locks"),
          legacyLockPath: join(dir, "legacy.lock"),
          pid: process.pid,
          acquiredAt: "2026-10-03T00:00:00Z",
        },
        usagePath: join(dir, "usage.jsonl"),
        transport: model.transport,
        clock: { nowSeconds: () => 1001, sleep: async () => {} },
        refreshBody: mockProvider().prepare().body,
        responseContracts: model.contracts,
      },
      async (recording) => {
        const r = await recording.run();
        result = r;
        if (r.status === "finished") recording.confirmCleanClose(r);
        return r;
      },
    );
  } catch (error) {
    result = {
      ...result,
      status: "HOLD",
      supplementPassed: false,
      parentClaim: false,
      reason: result?.reason ?? error.message,
      lockReason: error.message,
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  return { result, model, m };
}
test("the real mock driver proves installed A before/after and typed restoration in both fixed branches", async () => {
  for (const branch of ["absent", "present"]) {
    const { result, model, m } = await runNativeMock(branch);
    assert.equal(result.status, "finished", result.reason);
    assert.equal(result.supplementPassed, true);
    assert.equal(result.parentClaim, false);
    assert.equal(model.objects.size, 0);
    assert(!model.rulesets.has("projects/fireemu-oracle-query/rulesets/owned-A"));
    assert.equal(result.usage.requests, model.wire.length);
    assert(result.usage.requests <= m.counts.total);
    assert.equal(
      model.wire.filter((s) => s.url === "https://oauth2.googleapis.com/token").length,
      1,
    );
  }
});

test("narrow approval binds current E/V/GO, exact source/tree/run/cap and refuses stale or revoked authority", () => {
  const m = buildNativeManifest(nativeParams()),
    originalFixture = nativeApprovalFixture(m);
  const check = (fixture = originalFixture, manifest = m) =>
    validateNativeApproval({
      ledgerText: fixture.ledger,
      packet: fixture.packet,
      review: fixture.review,
      manifest,
      current: fixture.current,
      nowSeconds: 1001,
    });
  assert.equal(check().sendAuthorized, false);
  for (const change of [
    (f) => {
      f.current.go = "UNKNOWN";
    },
    (f) => {
      f.current.expiresAt = 1001;
    },
    (f) => {
      f.current.sourceTree = "0".repeat(40);
    },
    (f) => {
      f.current.runId = "other-run";
    },
    (f) => {
      f.packet.perRecordingCap = 213;
    },
    (f) => {
      f.packet.projects = ["fireemu-oracle-idp", "fireemu-oracle-query"];
    },
    (f) => {
      f.review.must = ["open"];
    },
    (f) => {
      f.ledger +=
        "- 2026-10-03 | STORAGE-RULES | decision=REVOKED | オーナー（mock fixture） | withdraw current packet\n";
    },
    (f) => {
      f.ledger +=
        "- 2026-10-03 | sandbox-wide | decision=REVOKED | オーナー（mock fixture） | all sends cancelled\n";
    },
    (f) => {
      f.ledger = f.ledger.replace("オーナー（mock fixture）", "unauthorized actor");
    },
    (f) => {
      f.ledger = f.ledger.replace("オーナー（mock fixture）", "Claude（委任。枠の内の承認し直し）");
    },
  ]) {
    const copy = structuredClone(originalFixture);
    change(copy);
    assert.throws(() => check(copy));
  }
});

test("unknown OAuth or data capture retains its consumed attempt and blocks every further effect", async () => {
  for (const fault of [{ unknown: true }, { capture: true }]) {
    const h = gateHarness(buildNativeManifest(nativeParams()), fault);
    await h.gate.start();
    await assert.rejects(h.gate.sendCredential("preflight/credential/owner/1"));
    assert.equal(h.sent.length, 1);
    assert.equal(h.gate.snapshot().requests, 1);
    await assert.rejects(h.gate.sendCredential("preflight/credential/owner/1"));
    assert.equal(h.sent.length, 1);
    assert(h.gate.snapshot().unknown || h.gate.snapshot().poisoned);
  }
});

test("the null live entry performs no input reads or effects", async () => {
  const output = [];
  assert.equal(await runNativeRecordCommand({ out: (line) => output.push(line) }), 3);
  assert.match(output[0], /^HOLD:/);
});

test("a consistently relabelled runner receipt cannot authorize bytes from another source", async () => {
  const { result, model } = await runNativeMock("absent", "none", 0, (f) => {
    const previous = f.packet.runnerSha256;
    f.packet.runnerSha256 = "0".repeat(64);
    f.review.runnerSha256 = f.packet.runnerSha256;
    f.ledger = f.ledger.replace(previous, f.packet.runnerSha256);
  });
  assert.equal(result.status, "HOLD");
  assert.equal(model.wire.length, 0);
});

test("a frozen response contract cannot relabel an allowed response as A denial", async () => {
  const { result, model } = await runNativeMock("absent", "contract-allows-deny");
  assert.equal(result.status, "HOLD");
  assert.equal(model.wire.length, 0);
});

// This state specification predicts complete proofs independently of the wire server and controller.
const referenceFaults = [
  "none",
  "unknown-create",
  "unknown-publish",
  "unknown-delete",
  "missing-before-allow",
  "missing-before-deny",
  "missing-after-allow",
  "missing-after-deny",
  "source-drift",
  "release-identity-drift",
  "generation-drift",
  "media-drift",
  "invalid-success",
  "invalid-unknown",
  "duplicate-invalid",
  "hidden-provider-call",
  "baseline-branch-mixed",
  "restore-missing",
  "incomplete-settle",
];
function referenceComplete(state) {
  return (
    state.before.allow &&
    state.before.deny &&
    state.after.allow &&
    state.after.deny &&
    state.identitySame &&
    state.sourceSame &&
    state.objectsSame &&
    state.invalidRefused &&
    state.singleInvalid &&
    state.physicalAccounted &&
    state.branchFixed &&
    state.restored &&
    state.twoCompleteCycles &&
    !state.unknown
  );
}
function referencePrediction(fault) {
  const state = {
    before: { allow: true, deny: true },
    after: { allow: true, deny: true },
    identitySame: true,
    sourceSame: true,
    objectsSame: true,
    invalidRefused: true,
    singleInvalid: true,
    physicalAccounted: true,
    branchFixed: true,
    restored: true,
    twoCompleteCycles: true,
    unknown: false,
  };
  if (fault.startsWith("unknown-") || fault === "invalid-unknown") state.unknown = true;
  const witness = /^missing-(before|after)-(allow|deny)$/.exec(fault);
  if (witness) state[witness[1]][witness[2]] = false;
  if (fault === "source-drift") state.sourceSame = false;
  if (fault === "release-identity-drift") state.identitySame = false;
  if (["generation-drift", "media-drift"].includes(fault)) state.objectsSame = false;
  if (fault === "invalid-success") state.invalidRefused = false;
  if (fault === "duplicate-invalid") state.singleInvalid = false;
  if (fault === "hidden-provider-call") state.physicalAccounted = false;
  if (fault === "baseline-branch-mixed") state.branchFixed = false;
  if (fault === "restore-missing") state.restored = false;
  if (fault === "incomplete-settle") state.twoCompleteCycles = false;
  return referenceComplete(state);
}
test("114 independent state and delay cases agree with the actual controller and physical mock audit", async (t) => {
  let cases = 0,
    clean = 0,
    refused = 0,
    transportBoundary = 0;
  const rows = [];
  for (const branch of ["absent", "present"])
    for (const fault of referenceFaults)
      for (const delay of [0, 1, 2]) {
        const { result, model, m } = await runNativeMock(branch, fault, delay);
        const physicalAccounted = result.usage?.requests === model.wire.length;
        const observed =
          result.status === "finished" && result.supplementPassed && physicalAccounted;
        assert.equal(
          observed,
          referencePrediction(fault),
          `${branch}/${fault}/${delay}: ${result.reason}`,
        );
        assert.equal(result.parentClaim, false);
        assert(result.usage?.requests === undefined || result.usage.requests <= m.counts.total);
        if (fault === "hidden-provider-call") {
          assert.equal(result.status, "finished");
          assert.equal(physicalAccounted, false);
          transportBoundary++;
        }
        if (
          ["unknown-create", "unknown-publish", "unknown-delete", "invalid-unknown"].includes(fault)
        )
          assert.equal(result.usage.unknown, true);
        rows.push({
          branch,
          fault,
          delay,
          expectedClean: referencePrediction(fault),
          controllerStatus: result.status,
          observedClean: observed,
          physicalAccounted,
          requests: result.usage?.requests ?? 0,
          physicalAttempts: model.wire.length,
          cap: m.counts.total,
          unknown: result.usage?.unknown ?? false,
          parentClaim: false,
        });
        if (observed) clean++;
        else refused++;
        cases++;
      }
  assert.deepEqual(
    { cases, clean, refused, transportBoundary },
    { cases: 114, clean: 6, refused: 108, transportBoundary: 6 },
  );
  t.diagnostic(
    JSON.stringify({
      kind: "ACTUAL_SYNTHETIC_STATE_COMPARISON",
      sourceSha256: nativeRunnerDigest(),
      cases,
      clean,
      refused,
      transportBoundary,
      parentClaim: false,
      rows,
    }),
  );
});

for (const fault of [
  "invalid-success",
  "release-identity-drift",
  "generation-drift",
  "media-drift",
  "source-drift",
  "restore-missing",
  "incomplete-settle",
  "unknown-create",
])
  test(`the actual controller refuses ${fault}`, async () => {
    const { result, model } = await runNativeMock("absent", fault);
    assert.equal(result.status, "HOLD", result.reason);
    assert.equal(result.parentClaim, false);
    if (fault === "incomplete-settle")
      assert(!result.evidence.some((row) => row.id.startsWith("before/")));
    if (fault === "unknown-create") {
      assert.equal(result.usage.unknown, true);
      assert.equal(
        model.wire.filter((r) => r.method === "POST" && r.url.endsWith("/rulesets")).length,
        1,
      );
      assert(!model.wire.some((r) => r.method === "DELETE"));
    }
  });
test("empty, missing, duplicate, extra, out-of-order and relabelled rows cannot be resealed", () => {
  for (const edit of [
    (m) => {
      m.rows = [];
    },
    (m) => {
      m.rows.splice(5, 1);
    },
    (m) => {
      m.rows.push(structuredClone(m.rows[0]));
    },
    (m) => {
      m.rows[0].id = "undeclared";
    },
    (m) => {
      [m.rows[0], m.rows[1]] = [m.rows[1], m.rows[0]];
    },
    (m) => {
      m.rows[0].phase = "recovery";
    },
    (m) => {
      m.sources.invalid.sha256 = "0".repeat(64);
    },
  ]) {
    const altered = structuredClone(buildNativeManifest(nativeParams()));
    edit(altered);
    delete altered.manifestSha256;
    altered.manifestSha256 = nativeDigest(altered);
    assert.throws(() => buildNativeSchedule(altered));
  }
});
test("run namespace and finite limits transform inventory without introducing routes or accounts", () => {
  for (const branch of ["absent", "present"])
    for (const cycles of [2, 30]) {
      const p = nativeParams(branch);
      p.runId = "transformed-run";
      p.limits.settleCycles = cycles;
      const m = buildNativeManifest(p),
        s = buildNativeSchedule(m);
      assert.equal(m.rows.length, m.counts.total);
      assert.equal(s.allIds.length, m.counts.total);
      assert(
        m.resources.objects.every((name) => name.startsWith("STORAGE-RULES/transformed-run/")),
      );
      assert.equal(m.accountProof.accountApiRequests, 0);
      assert.equal(m.rows.filter((row) => row.kind === "invalid-test").length, 1);
    }
});

test("unknown data outcome and failed data capture block a different unused route", async () => {
  for (const kind of ["unknown", "capture"]) {
    const fault = {},
      h = gateHarness(buildNativeManifest(nativeParams()), fault);
    await h.gate.start();
    await h.gate.sendCredential("preflight/credential/owner/1");
    fault[kind] = true;
    await assert.rejects(h.gate.send(h.prepared));
    assert.equal(h.sent.length, 2);
    assert.equal(h.gate.snapshot().requests, 2);
    fault[kind] = false;
    await assert.rejects(h.gate.send(h.bucket));
    assert.equal(h.sent.length, 2);
  }
});

test("native 200 with error.code 403 cannot be frozen as a denial contract", async () => {
  const { result, model } = await runNativeMock("absent", "contract-deny-status200");
  assert.equal(result.status, "HOLD");
  assert.equal(model.wire.length, 0);
});
