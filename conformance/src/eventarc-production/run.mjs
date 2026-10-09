// Installed-binary collection. Raw replay verdicts remain separate from actual lifecycle facets.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  readdirSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { createServer } from "node:net";
import { isDeepStrictEqual } from "node:util";
import { replay, summarize, skipReason, requestBody } from "./compare.mjs";
import { findPackagedRunner } from "../packaged-runner.mjs";
import {
  loadNativeRequests,
  createCollector,
  collectOwnCursorWalk,
  issueOperation,
  collectOperationTerminal,
  observeUnfinishedCreate,
  collectPairedOperationTerminals,
} from "./lifecycle-evidence.mjs";
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const digest = (path) => sha(readFileSync(path));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const save = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
const hex = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const labels = ["A1", "A2", "B", "C", "D"];
const byteFields = ["bodyBase64", "bodyBytes", "bodySha256", "originalBodySha256"];
function loopback(base) {
  const url = new URL(base);
  assert.equal(url.protocol, "http:");
  assert.ok(["127.0.0.1", "[::1]"].includes(url.hostname), "numeric loopback required");
  assert.equal(url.pathname, "/");
  assert.ok(!url.username && !url.password && !url.search && !url.hash);
  return url;
}
/** Parsed-only original records retain explicit physical-evidence absence. */
export function validateProjectedRows(rows, { journalSha256 }) {
  assert.ok(hex(journalSha256) && Array.isArray(rows) && rows.length);
  let previous = 0,
    previousStart = -Infinity;
  for (const row of rows) {
    assert.ok(Number.isSafeInteger(row.n) && row.n > previous, "ordered unique native ordinal");
    previous = row.n;
    assert.equal(row.projectionSource?.n, row.n);
    assert.equal(row.projectionSource.journalSha256, journalSha256);
    assert.ok(Array.isArray(row.projectionSource.absentFields));
    assert.ok(
      row.request && typeof row.request.path === "string" && row.request.path.startsWith("/"),
    );
    assert.ok(["GET", "POST", "DELETE", "PATCH", "PUT"].includes(row.request.method));
    assert.ok(Number.isInteger(row.response?.status));
    if (skipReason(row) === null && requestBody(row) !== null) {
      assert.ok(Number.isFinite(Date.parse(row.at)), "original cadence at");
      assert.ok(Number.isFinite(row.ms) && row.ms >= 0, "original finite cadence ms");
      const requestStart = Date.parse(row.at) - row.ms;
      assert.ok(requestStart >= previousStart, "nonmonotonic original request starts");
      previousStart = requestStart;
    }
    const native = row.projectionSource.originalResponseBytesPresent;
    assert.equal(typeof native, "boolean");
    if (native) {
      assert.equal(typeof row.response.bodyBase64, "string");
      const bytes = Buffer.from(row.response.bodyBase64, "base64");
      assert.equal(bytes.toString("base64"), row.response.bodyBase64, "canonical native bytes");
      assert.equal(bytes.length, row.response.bodyBytes);
      assert.equal(sha(bytes), row.response.bodySha256);
      assert.ok(hex(row.response.originalBodySha256));
      assert.ok(row.response.headers && typeof row.response.headers === "object");
      if (bytes.length)
        assert.ok(
          isDeepStrictEqual(JSON.parse(bytes.toString("utf8")), row.response.body),
          "native parsed body",
        );
      else assert.equal(row.response.body, null);
    } else {
      for (const key of [...byteFields, "headers"]) {
        assert.ok(!Object.hasOwn(row.response, key), "fabricated native physical evidence");
        assert.ok(row.projectionSource.absentFields.includes(`response.${key}`));
      }
    }
  }
  return rows;
}
export function loadInputs(directory = join(here, "fixtures/ad")) {
  const provenancePath = join(directory, "provenance.json"),
    planPath = join(directory, "witness-plan.json");
  const provenance = json(provenancePath),
    plan = json(planPath);
  assert.equal(provenance.kind, "eventarc-native-projection-v1");
  assert.deepEqual(
    provenance.originalAuthority,
    {
      indexSha256: "c7c78acb381ddff43292160092ac6ab613ce73646dc96ccc7bc7f9559b07eaef",
      mapSha256: "795debdc480c709a6ddc86d78b7a7627117a86cdbbc207f046b4766c3d104eae",
    },
    "native corpus authority",
  );
  assert.equal(provenance.numericAlias, "123456789012");
  assert.equal(plan.kind, "eventarc-own-witness-plan-v1");
  assert.deepEqual(
    provenance.corpora.map((x) => x.label),
    labels,
  );
  const corpora = {},
    projectionPins = {
      "provenance.json": digest(provenancePath),
      "witness-plan.json": digest(planPath),
    };
  const recordings = {
    A1: "d011709742b6",
    A2: "9e560c404162",
    B: "43a83839852f",
    C: "fe404dee592e",
    D: "bd0b44db5477",
  };
  for (const entry of provenance.corpora) {
    assert.equal(entry.source.recording, recordings[entry.label], "foreign native recording");
    assert.equal(entry.projection.file, `${entry.label}.jsonl`);
    const path = join(directory, entry.projection.file),
      bytes = readFileSync(path);
    assert.equal(sha(bytes), entry.projection.sha256, "projection digest");
    const rows = validateProjectedRows(
      bytes
        .toString("utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .filter((row) => typeof row.op === "string"),
      { journalSha256: entry.source.journalSha256 },
    );
    assert.equal(rows.length, entry.projection.rows);
    assert.deepEqual(
      rows.map((row) => row.n),
      entry.projection.ordinals,
      "original native selectors",
    );
    assert.equal(
      rows.filter((row) => row.projectionSource.originalResponseBytesPresent).length,
      entry.projection.nativeRows,
    );
    corpora[entry.label] = {
      path,
      sha256: sha(bytes),
      rows,
      journalSha256: entry.source.journalSha256,
    };
    projectionPins[entry.projection.file] = sha(bytes);
  }
  const selected = {
    B: { setupN: [16, 20], walks: [[27, 26, 20]], terminalN: [202], slices: [] },
    C: {
      setupN: [16, 20, 41, 46, 64, 76, 80, 84, 88, 92, 96],
      walks: [
        [27, 26, 20],
        [102, 101, 96],
        [110, 101, 96],
        [115, 101, 96],
      ],
      terminalN: [398],
      slices: [],
    },
    D: {
      setupN: [16, 19, 23, 27, 31, 35],
      walks: [
        [41, 40, 35],
        [47, 40, 35],
        [50, 40, 35],
      ],
      terminalN: [16, 66, 186],
      slices: [
        [61, 66, true],
        [87, 186, false],
      ],
    },
  };
  for (const label of ["B", "C", "D"]) {
    const p = plan.corpora[label];
    assert.ok(p, "missing witness plan");
    assert.equal(p.projectionSha256, corpora[label].sha256, "foreign witness projection");
    assert.deepEqual(
      {
        setupN: p.setupN,
        walks: p.walks.map((walk) => [walk.rootN, walk.inventoryN, walk.setupThroughN]),
        terminalN: p.terminalN,
        slices: (p.independentLifecycleSlices ?? []).map((slice) => [
          slice.createN,
          slice.deleteN,
          slice.overlap,
        ]),
      },
      selected[label],
      "selected witness plan",
    );
    const ordinals = [
      ...p.setupN,
      ...p.walks.flatMap((x) => [x.rootN, x.inventoryN]),
      ...p.terminalN,
      ...(p.independentLifecycleSlices ?? []).flatMap((x) => [x.createN, x.deleteN]),
    ];
    const available = new Set(corpora[label].rows.map((x) => x.n));
    assert.ok(
      ordinals.every((n) => available.has(n)),
      "unavailable witness selector",
    );
  }
  return { directory, provenance, plan, corpora, pins: projectionPins };
}
/** Pace original client start offsets before creating the fresh per-request deadline. */
export async function replayWithWire(rows, { base, fetchImpl = fetch, requestTimeoutMs = 30000 }) {
  assert.ok(
    Number.isSafeInteger(requestTimeoutMs) && requestTimeoutMs > 0 && requestTimeoutMs <= 30000,
  );
  loopback(base);
  const queue = rows.filter((row) => skipReason(row) === null && requestBody(row) !== null);
  const offsets = queue.map((row) => {
    assert.ok(Number.isFinite(Date.parse(row.at)) && Number.isFinite(row.ms) && row.ms >= 0);
    return Date.parse(row.at) - row.ms;
  });
  assert.ok(
    offsets.every((n, i) => i === 0 || n >= offsets[i - 1]),
    "nonmonotonic original request starts",
  );
  const start = performance.now(),
    wire = [];
  let index = 0;
  const results = await replay(rows, {
    base,
    fetchImpl: async (url, init) => {
      const row = queue[index++];
      assert.ok(row, "unissued replay request");
      const remaining = offsets[index - 1] - offsets[0] - (performance.now() - start);
      if (remaining > 0) await delay(remaining);
      const actual = new URL(url);
      assert.equal(actual.origin, new URL(base).origin, "foreign replay authority");
      const receipt = {
        n: row.n,
        journalSha256: row.projectionSource?.journalSha256,
        originalNativeBodySha256: row.response.originalBodySha256 ?? null,
        originalPhysicalEvidence: row.projectionSource?.originalResponseBytesPresent ?? false,
        method: init.method,
        path: actual.pathname + actual.search,
        requestBase64: Buffer.from(init.body ?? "").toString("base64"),
        requestSha256: sha(init.body ?? ""),
        requestHeaders: { ...init.headers },
        originalTokenMode: Object.hasOwn(row, "tokenMode") ? row.tokenMode : null,
        startedMonotonicMs: performance.now() - start,
      };
      wire.push(receipt);
      let timer;
      const controller = new AbortController();
      try {
        const { reply, bytes } = await Promise.race([
          (async () => {
            const fetched = await fetchImpl(url, {
              ...init,
              redirect: "error",
              signal: controller.signal,
            });
            assert.ok(!fetched.redirected, "redirected response");
            const fetchedBytes = Buffer.from(await fetched.clone().arrayBuffer());
            return { reply: fetched, bytes: fetchedBytes };
          })(),
          new Promise((_, reject) => {
            timer = setTimeout(() => {
              controller.abort();
              reject(new Error("raw transport timeout"));
            }, requestTimeoutMs);
          }),
        ]);
        Object.assign(receipt, {
          status: reply.status,
          headers: Object.fromEntries(reply.headers),
          responseBase64: bytes.toString("base64"),
          responseBytes: bytes.length,
          responseSha256: sha(bytes),
          finishedMonotonicMs: performance.now() - start,
        });
        return reply;
      } catch (error) {
        receipt.failure = { name: error.name, message: error.message };
        receipt.finishedMonotonicMs = performance.now() - start;
        throw error;
      } finally {
        clearTimeout(timer);
      }
    },
  });
  assert.equal(index, queue.length);
  return { complete: wire.every((x) => !x.failure), results, ...summarize(results), wire };
}
// Authority declared by the existing Rust replay fixture and its recording READMEs.
export function selectSessionProject(rows) {
  const project = "fireemu-oracle-idp";
  assert.ok(
    rows.some((row) => row.request.path.startsWith(`/v1/projects/${project}/locations/`)),
    "public named project authority",
  );
  return project;
}
export function sessionConfiguration({ project, ports, runner, guard, fixture }) {
  assert.ok(typeof project === "string" && /^[a-zA-Z0-9-]+$/.test(project));
  assert.ok(
    Array.isArray(ports) &&
      ports.length === 7 &&
      new Set(ports).size === 7 &&
      ports.every((p) => Number.isInteger(p) && p > 0 && p <= 65535),
  );
  const [httpPort, firestorePort, functionsPort, eventarcPort, loggingPort, hubPort, tasksPort] =
    ports;
  return {
    tasksPort,
    fireemu: {
      schemaVersion: 1,
      profile: "strict",
      daemon: {
        authProject: project,
        httpPort,
        firestorePort,
        functionsPort,
        eventarcPort,
        loggingPort,
        hubPort,
        uiPort: 0,
        authProjectNumbers: { [project]: "123456789012" },
      },
      functions: { runner: [process.execPath, "--require", guard, runner] },
      eventarc: {
        oauthCredentials: {
          [sha("ya29.replay-token")]: {
            scopes: ["https://www.googleapis.com/auth/cloud-platform"],
          },
          [sha("ya29.a-token-of-another-scope")]: { scopes: [] },
        },
      },
    },
    firebase: {
      functions: [{ source: fixture, codebase: "neutral", runtime: "nodejs22" }],
      emulators: { eventarc: { host: "127.0.0.1", port: eventarcPort } },
    },
  };
}
function identity(pid) {
  try {
    const value = execFileSync("ps", ["-p", String(pid), "-o", "pid=,pgid=,lstart=,comm=,args="], {
      encoding: "utf8",
      timeout: 1000,
    }).trim();
    return value ? { status: "VERIFIED", pid, value } : { status: "UNKNOWN", pid };
  } catch {
    return { status: "UNKNOWN", pid };
  }
}
function groupAbsent(pid) {
  try {
    process.kill(-pid, 0);
    return false;
  } catch (error) {
    return error.code === "ESRCH";
  }
}
function groupMembers(pid) {
  try {
    const output = execFileSync("pgrep", ["-g", String(pid)], {
      encoding: "utf8",
      timeout: 1000,
    }).trim();
    const members = output ? output.split(/\s+/).map(Number) : [];
    assert.ok(
      members.length <= 64 && members.every((n) => Number.isSafeInteger(n) && n > 0),
      "owned process group bound",
    );
    return members;
  } catch (error) {
    if (error.status === 1) return [];
    throw error;
  }
}
/** Own one installed exec group, including pipe-holding children after its leader exits. */
export async function runExecSession({
  binary,
  args,
  cwd,
  env,
  timeoutMs = 900000,
  graceMs = 5000,
}) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 900000);
  assert.ok(Number.isSafeInteger(graceMs) && graceMs > 0 && graceMs <= 60000);
  const child = spawn(binary, args, {
    cwd,
    env,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.resume();
  child.stderr.resume();
  const receipt = {
    pid: child.pid,
    identity: child.pid ? identity(child.pid) : { status: "UNKNOWN" },
    descendants: [],
    timedOut: false,
    exitCode: null,
  };
  const owned = new Map();
  if (receipt.identity.status === "VERIFIED") owned.set(child.pid, receipt.identity);
  let closed = false;
  const capture = () => {
    if (receipt.identity.status !== "VERIFIED") {
      receipt.cleanupFailure = "initial owned PID identity UNKNOWN";
      return;
    }
    try {
      for (const pid of groupMembers(child.pid))
        if (!owned.has(pid)) {
          const observed = identity(pid);
          owned.set(pid, observed);
          if (pid !== child.pid) receipt.descendants.push(observed);
        }
    } catch (error) {
      receipt.cleanupFailure = error.message;
    }
  };
  const completion = new Promise((resolveCompletion) => {
    child.once("error", (error) => {
      receipt.failure = { name: error.name, message: error.message };
    });
    child.once("exit", () => capture());
    child.once("close", (code, signal) => {
      closed = true;
      receipt.exitCode = code;
      receipt.signal = signal;
      resolveCompletion();
    });
  });
  const terminate = (signal) => {
    capture();
    for (const [pid, original] of owned) {
      const current = identity(pid);
      if (current.status === "UNKNOWN") {
        try {
          process.kill(pid, 0);
          receipt.cleanupFailure = "live owned PID identity UNKNOWN";
        } catch (error) {
          if (error.code !== "ESRCH") receipt.cleanupFailure = "owned PID absence UNKNOWN";
        }
      } else if (original.status === "VERIFIED" && current.value === original.value) {
        try {
          process.kill(pid, signal);
        } catch (error) {
          if (error.code !== "ESRCH") receipt.cleanupFailure = error.message;
        }
      } else receipt.cleanupFailure = "owned PID identity changed";
    }
  };
  const handlers = ["SIGINT", "SIGTERM"].map((signal) => [
    signal,
    () => {
      receipt.interrupted = signal;
      terminate("SIGTERM");
    },
  ]);
  for (const [signal, handler] of handlers) process.on(signal, handler);
  const timer = setTimeout(() => {
    receipt.timedOut = true;
    terminate("SIGTERM");
  }, timeoutMs);
  const hardTimer = setTimeout(() => {
    if (!closed || !groupAbsent(child.pid)) terminate("SIGKILL");
  }, timeoutMs + graceMs);
  let finishTimer;
  try {
    await Promise.race([
      completion,
      new Promise((done) => {
        finishTimer = setTimeout(done, timeoutMs + graceMs + 1500);
      }),
    ]);
    if (!closed) {
      receipt.cleanupFailure ??= "owned child did not close within cleanup bound";
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
    }
    if (child.pid && !groupAbsent(child.pid)) {
      terminate("SIGTERM");
      const deadline = performance.now() + graceMs;
      while (!groupAbsent(child.pid) && performance.now() < deadline) await delay(10);
      if (!groupAbsent(child.pid)) terminate("SIGKILL");
      const finalDeadline = performance.now() + 1000;
      while (!groupAbsent(child.pid) && performance.now() < finalDeadline) await delay(10);
    }
  } finally {
    clearTimeout(timer);
    clearTimeout(hardTimer);
    clearTimeout(finishTimer);
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  }
  receipt.processGroupAbsent = child.pid ? groupAbsent(child.pid) : true;
  if (!receipt.processGroupAbsent) receipt.cleanupFailure ??= "owned process group remains";
  return receipt;
}
const pending = [
  "C102/C110 native continuation tails",
  "Three production publish-404 witnesses",
  "Parsed-only A1/A2 original physical evidence",
  "Unchanged eleven criteria and two-record requirement",
  "Raw differences require separately authorized case disposition",
  "Release registration and final same-binary evidence",
];
function publicPins(values, kind) {
  return Object.fromEntries(
    Object.entries(values ?? {}).map(([path, hash]) => {
      assert.ok(hex(hash));
      const name =
        kind === "source"
          ? path.slice(root.length + 1)
          : kind === "sessions"
            ? `${basename(dirname(path))}/${basename(path)}`
            : `${kind}/${basename(path)}`;
      if (kind === "source")
        assert.ok(path.startsWith(root + "/") && !name.startsWith("../"), "foreign source pin");
      return [name, hash];
    }),
  );
}
function publicFacet(report, evidence) {
  const result = structuredClone(report);
  const visit = (value) => {
    if (!value || typeof value !== "object") return;
    for (const [key, item] of Object.entries(value)) {
      if (
        ["source", "inventorySource", "createSource", "deleteSource"].includes(key) &&
        item?.path !== undefined
      ) {
        assert.equal(evidence.physicalInputPins?.[item.path], item.sha256, "unbound facet source");
        assert.ok(
          labels.some((label) => basename(item.path) === `${label}.jsonl`),
          "foreign facet corpus",
        );
        item.path = `conformance/src/eventarc-production/fixtures/ad/${basename(item.path)}`;
      } else visit(item);
    }
  };
  visit(result);
  return result;
}
export function comparisonFromEvidence(evidence) {
  assert.equal(evidence.complete, true, "incomplete evidence");
  assert.ok(
    evidence.sessions?.every((x) => x.report.complete),
    "incomplete session",
  );
  const closure = json(join(root, "spec/compatibility/closure/EVENTARC.json"));
  const rows = closure.conditions.flatMap((condition) =>
    condition.cases.flatMap((caseId) =>
      condition.transports.map((transport) => ({
        row: `${condition.recipeIds[0]}#${caseId}`,
        conditionId: condition.conditionId,
        caseId,
        transport,
        status: "PENDING",
        reason: "Collection does not grant criterion closure",
      })),
    ),
  );
  return {
    schemaVersion: 1,
    kind: "eventarc-production-comparison-v1",
    parent: "EVENTARC",
    artifactSha256: evidence.artifactSha256,
    ownerDisposition: "owner-1145: list order/page position/intermediate done only",
    rows,
    summary: { PENDING: rows.length },
    fixtureSha256: sha(JSON.stringify(publicPins(evidence.fixturePins, "neutral-functions"))),
    raw: evidence.sessions
      .filter((x) => x.phase === "raw")
      .map((x) => Object.assign({}, x.report, { label: x.label })),
    facets: evidence.sessions
      .filter((x) => x.phase === "facets")
      .map((x) => Object.assign(publicFacet(x.report, evidence), { label: x.label })),
    inputPins: evidence.inputPins,
    sourcePins: publicPins(evidence.sourcePins, "source"),
    fixturePins: publicPins(evidence.fixturePins, "neutral-functions"),
    runnerPins: publicPins(evidence.runnerPins, "runner-node"),
    sessionPins: publicPins(evidence.sessionPins, "sessions"),
    pending,
  };
}
function pins(paths) {
  return Object.fromEntries(paths.map((path) => [path, digest(path)]));
}
function verifyPins(values) {
  for (const [path, expected] of Object.entries(values))
    assert.equal(digest(path), expected, `changed pinned input: ${path}`);
}
export function exportComparison({ evidencePath, output, binary }) {
  const evidence = json(evidencePath);
  assert.equal(evidence.kind, "eventarc-installed-check-v1");
  const expectedSessions = [
    ...labels.map((label) => `raw/${label}`),
    ...["B", "C", "D"].map((label) => `facets/${label}`),
  ];
  assert.deepEqual(
    evidence.sessions?.map((x) => `${x.phase}/${x.label}`),
    expectedSessions,
    "actual session set",
  );
  assert.equal(
    evidence.artifactSha256,
    digest(realpathSync(binary)),
    "different installed artifact",
  );
  for (const values of [
    evidence.sourcePins,
    evidence.fixturePins,
    evidence.runnerPins,
    evidence.physicalInputPins,
    evidence.sessionPins,
  ]) {
    assert.ok(values && Object.keys(values).length);
    verifyPins(values);
  }
  const installedRunner = findPackagedRunner(realpathSync(binary));
  assert.ok(installedRunner, "installed packaged runner required");
  assert.deepEqual(
    runnerPins(installedRunner),
    evidence.runnerPins,
    "foreign installed runner tree",
  );
  for (const entry of evidence.sessions) {
    const find = (file) => {
      const matches = Object.keys(evidence.sessionPins).filter(
        (path) => basename(dirname(path)) === entry.id && basename(path) === file,
      );
      assert.equal(matches.length, 1, "missing or ambiguous physical session record");
      return matches[0];
    };
    assert.deepEqual(json(find("report.json")), entry.report, "changed embedded actual report");
    const receiptPath = find("process-receipt.json"),
      receipt = json(receiptPath);
    assert.equal(digest(receiptPath), entry.processReceiptSha256);
    assert.equal(receipt.identity?.status, "VERIFIED");
    assert.equal(receipt.exitCode, 0);
    assert.equal(receipt.processGroupAbsent, true);
    assert.ok(!receipt.timedOut && !receipt.cleanupFailure && !receipt.interrupted);
  }
  const comparison = comparisonFromEvidence(evidence);
  comparison.checkEvidenceSha256 = digest(evidencePath);
  save(output, comparison);
  return comparison;
}
export function buildExecArgs({ work, project, tasksPort, guard, session: sessionPath }) {
  return [
    "exec",
    "--config",
    join(work, "fireemu.json"),
    "--firebase-json",
    join(work, "firebase.json"),
    "--project",
    project,
    "--tasks-port",
    String(tasksPort),
    "--only",
    "functions,eventarc",
    "--",
    process.execPath,
    "--require",
    guard,
    fileURLToPath(import.meta.url),
    "--session",
    sessionPath,
  ];
}
export const offlineGuardSource = `const net=require('node:net'),dns=require('node:dns');
const allowed=h=>['127.0.0.1','::1','localhost'].includes(h);
const connect=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...a){const x=net._normalizeArgs(a)[0];if(x.path||!allowed(x.host||'localhost'))throw Error('offline: remote socket refused');return connect.apply(this,a)};
const lookup=dns.lookup;dns.lookup=function(h,...a){if(!allowed(h))throw Error('offline: remote DNS refused');return lookup.call(this,h,...a)};
const originalFetch=globalThis.fetch;globalThis.fetch=(u,o)=>{const x=new URL(typeof u==='string'?u:u.url||u);if(x.protocol!=='http:'||!allowed(x.hostname))throw Error('offline: remote fetch refused');return originalFetch(u,{...o,redirect:'error'})};
`;
async function reservePorts() {
  const reservations = [];
  try {
    for (let i = 0; i < 7; i++) {
      const server = createServer();
      await new Promise((done, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", done);
      });
      reservations.push({ server, port: server.address().port });
    }
    return reservations.map((x) => x.port);
  } finally {
    await Promise.all(reservations.map(({ server }) => new Promise((done) => server.close(done))));
  }
}
function runnerPins(runner) {
  const directory = dirname(runner),
    files = readdirSync(directory).filter(
      (name) => (name.endsWith(".mjs") && !name.endsWith(".test.mjs")) || name === "package.json",
    );
  assert.ok(files.length > 0 && files.length <= 64, "bounded installed runner tree");
  const paths = files.map((name) => join(directory, name));
  assert.ok(paths.every((path) => statSync(path).isFile()));
  assert.ok(paths.reduce((n, path) => n + statSync(path).size, 0) <= 4 * 1024 * 1024);
  assert.ok(paths.includes(runner));
  return pins(paths);
}
async function physicalFetch(collector, request, provenance, exchanges) {
  const start = performance.now(),
    receipt = {
      id: exchanges.length,
      source: provenance,
      request,
      requestBase64: Buffer.from(
        request.body === undefined ? "" : JSON.stringify(request.body),
      ).toString("base64"),
      sentMonotonicMs: start,
    };
  exchanges.push(receipt);
  receipt.requestSha256 = sha(Buffer.from(receipt.requestBase64, "base64"));
  try {
    const response = await (collector.fetchImpl ?? fetch)(`${collector.base}${request.path}`, {
      method: request.method,
      headers: {
        authorization: "Bearer ya29.replay-token",
        ...(request.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: request.body === undefined ? undefined : JSON.stringify(request.body),
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    assert.equal(response.redirected, false);
    const bytes = Buffer.from(await response.arrayBuffer());
    receipt.response = {
      status: response.status,
      headers: Object.fromEntries(response.headers),
      base64: bytes.toString("base64"),
      bytes: bytes.length,
      sha256: sha(bytes),
      text: bytes.toString("utf8"),
    };
    receipt.body = bytes.length ? JSON.parse(bytes.toString("utf8")) : null;
    return receipt;
  } catch (error) {
    receipt.failure = { name: error.name, message: error.message };
    throw error;
  } finally {
    receipt.finishedMonotonicMs = performance.now();
  }
}
/** Cleanup derives only targets issued successfully by this session; receipts are not native rows. */
async function cleanupTargets(base, targets, exchanges, fetchImpl = fetch) {
  const results = [];
  for (const target of targets) {
    try {
      const issued = await physicalFetch(
        { base, fetchImpl },
        { method: "DELETE", path: `/v1/${target}` },
        { kind: "owned-target-cleanup", target },
        exchanges,
      );
      if (issued.response.status !== 404) {
        assert.equal(issued.response.status, 200);
        const name = issued.body?.name,
          parent = target.slice(0, target.lastIndexOf("/channels/"));
        assert.ok(typeof name === "string" && name.startsWith(`${parent}/operations/`));
        assert.equal(issued.body.metadata?.target, target);
        assert.equal(issued.body.metadata?.verb, "delete");
        const deadline = performance.now() + 30000;
        let terminal = issued;
        while (!terminal.body.done) {
          assert.ok(performance.now() < deadline, "cleanup terminal deadline");
          await delay(100);
          terminal = await physicalFetch(
            { base, fetchImpl },
            { method: "GET", path: `/v1/${name}` },
            { kind: "own-cleanup-operation", issuedExchange: issued.id },
            exchanges,
          );
          assert.equal(terminal.response.status, 200);
          assert.equal(terminal.body.name, name);
          assert.equal(terminal.body.metadata?.target, target);
          assert.equal(terminal.body.metadata?.verb, "delete");
        }
        assert.equal(terminal.body.response?.name, target);
        assert.equal(terminal.body.response?.state, "INACTIVE");
        assert.ok(!terminal.body.error);
      }
      const absent = await physicalFetch(
        { base, fetchImpl },
        { method: "GET", path: `/v1/${target}` },
        { kind: "owned-target-absence", target },
        exchanges,
      );
      assert.equal(absent.response.status, 404);
      assert.equal(absent.body.error?.code, 404);
      assert.equal(absent.body.error?.status, "NOT_FOUND");
      assert.equal(typeof absent.body.error?.message, "string");
      results.push({ target, complete: true, absentExchange: absent.id });
    } catch (error) {
      results.push({
        target,
        complete: false,
        failure: { name: error.name, message: error.message },
      });
    }
  }
  return results;
}
export async function collectFacets(inputs, label, base, { fetchImpl = fetch } = {}) {
  const corpus = inputs.corpora[label],
    plan = inputs.plan.corpora[label];
  const ordinals = [
    ...new Set([
      ...plan.setupN,
      ...plan.walks.flatMap((x) => [x.rootN, x.inventoryN]),
      ...plan.terminalN,
      ...(plan.independentLifecycleSlices ?? []).flatMap((x) => [x.createN, x.deleteN]),
    ]),
  ];
  const native = loadNativeRequests({ path: corpus.path, sha256: corpus.sha256, ordinals });
  const collector = createCollector({ base, fetchImpl, maxElapsedMs: 180000, maxRequests: 600 });
  const issued = new Map(),
    proofs = [],
    cleanupExchanges = [];
  let failure;
  try {
    for (const stage of [...new Set(plan.walks.map((x) => x.setupThroughN))].toSorted(
      (a, b) => a - b,
    )) {
      const batch = plan.setupN
        .filter((n) => n <= stage && !issued.has(n))
        .toSorted((a, b) => a - b);
      for (const n of batch)
        issued.set(n, await issueOperation({ collector, input: native.get(n) }));
      for (const n of batch) {
        const terminal = await collectOperationTerminal({ collector, issued: issued.get(n) });
        if (plan.terminalN.includes(n)) proofs.push({ key: `${label}${n}`, ...terminal });
      }
      for (const walk of plan.walks.filter((x) => x.setupThroughN === stage))
        proofs.push({
          key: `${label}${walk.rootN}`,
          ...(await collectOwnCursorWalk({
            collector,
            root: native.get(walk.rootN),
            inventory: native.get(walk.inventoryN),
          })),
        });
    }
    for (const slice of plan.independentLifecycleSlices ?? []) {
      const created = await issueOperation({ collector, input: native.get(slice.createN) });
      issued.set(slice.createN, created);
      if (slice.overlap) {
        await observeUnfinishedCreate({ collector, issued: created });
        const deleted = await issueOperation({ collector, input: native.get(slice.deleteN) });
        proofs.push({
          key: `${label}${slice.deleteN}`,
          ...(await collectPairedOperationTerminals({ collector, create: created, deleted })),
        });
      } else {
        await collectOperationTerminal({ collector, issued: created });
        const deleted = await issueOperation({ collector, input: native.get(slice.deleteN) });
        proofs.push({
          key: `${label}${slice.deleteN}`,
          ...(await collectOperationTerminal({ collector, issued: deleted })),
        });
      }
    }
    for (const n of plan.terminalN.filter(
      (ordinal) => !proofs.some((x) => x.key === `${label}${ordinal}`),
    )) {
      const operation = await issueOperation({ collector, input: native.get(n) });
      assert.equal(operation.verb, "delete", "unplanned independent create terminal");
      proofs.push({
        key: `${label}${n}`,
        ...(await collectOperationTerminal({ collector, issued: operation })),
      });
    }
  } catch (error) {
    failure = { name: error.name, message: error.message };
  }
  const caseProofs = proofs.map((proof) =>
    Object.assign({}, proof, {
      conditionId: "EVENTARC/channel-lifecycle",
      caseId:
        proof.kind === "own-cursor-walk"
          ? "list-channels"
          : proof.verb === "create"
            ? "readiness-shape"
            : "delete-owned-channel",
      transport: "rest",
    }),
  );
  const targets = [...new Set([...issued.values()].map((x) => x.target))];
  const cleanup = await cleanupTargets(base, targets, cleanupExchanges, fetchImpl);
  return {
    complete: !failure && cleanup.every((x) => x.complete),
    proofs: caseProofs,
    exchanges: collector.exchanges,
    cleanup,
    cleanupExchanges,
    ...(failure ? { failure } : {}),
  };
}
export function sessionEndpoint(host) {
  assert.ok(host, "missing owned exec endpoint");
  const base = host;
  loopback(base);
  return base;
}
async function session(path) {
  const options = json(path),
    inputs = loadInputs(options.inputDirectory);
  const base = sessionEndpoint(process.env.CLOUD_EVENTARC_EMULATOR_HOST);
  let report;
  try {
    if (options.phase === "raw") {
      report = await replayWithWire(inputs.corpora[options.label].rows, { base });
      const targets = new Set();
      for (const wire of report.wire.filter(
        (x) => x.status === 200 && x.method === "POST" && /\/channels\?/.test(x.path),
      )) {
        const body = JSON.parse(Buffer.from(wire.responseBase64, "base64").toString("utf8"));
        if (body.metadata?.verb === "create" && typeof body.metadata.target === "string")
          targets.add(body.metadata.target);
      }
      report.cleanupExchanges = [];
      report.cleanup = await cleanupTargets(base, targets, report.cleanupExchanges);
      report.complete &&= report.cleanup.every((x) => x.complete);
    } else {
      assert.equal(options.phase, "facets");
      report = await collectFacets(inputs, options.label, base);
    }
  } catch (error) {
    report = { complete: false, failure: { name: error.name, message: error.message } };
  }
  save(options.reportPath, report);
  if (!report.complete) process.exitCode = 1;
}
const localSessionMs = 900000;
const localTeardownMs = 5000 + 1500 + 5000 + 1000;
const localPreparationMs = 60000;
const localOverallMs = 8 * (localSessionMs + localTeardownMs) + localPreparationMs;
/** Finite local allowances preserve cadence; they do not guarantee successful execution. */
export function deriveLocalBudget(inputs, overallMs = localOverallMs) {
  assert.ok(
    Number.isSafeInteger(overallMs) && overallMs > 0 && overallMs <= localOverallMs,
    "finite local budget cap",
  );
  const sessions = labels.map((label) => {
    const rows = inputs.corpora[label].rows.filter(
      (row) => skipReason(row) === null && requestBody(row) !== null,
    );
    assert.ok(rows.length, `raw ${label} has no paced requests`);
    const starts = rows.map((row) => Date.parse(row.at) - row.ms);
    assert.ok(
      starts.every((n, i) => Number.isFinite(n) && (i === 0 || n >= starts[i - 1])),
      "finite monotonic budget cadence",
    );
    const cadenceMs = starts.at(-1) - starts[0];
    const minimumWorkMs = cadenceMs + 30000;
    assert.ok(minimumWorkMs <= localSessionMs, `raw ${label} budget infeasible`);
    return {
      phase: "raw",
      label,
      firstN: rows[0].n,
      lastN: rows.at(-1).n,
      cadenceMs,
      timeoutMs: localSessionMs,
      remainingWorkAllowanceMs: localSessionMs - minimumWorkMs,
    };
  });
  const exactRawCadenceMs = sessions.reduce((sum, s) => sum + s.cadenceMs, 0);
  for (const label of ["B", "C", "D"])
    sessions.push({
      phase: "facets",
      label,
      collectorMs: 180000,
      timeoutMs: localSessionMs,
      remainingWorkAllowanceMs: localSessionMs - 180000,
    });
  const requiredMs = sessions.reduce(
    (sum, s) => sum + s.timeoutMs + localTeardownMs,
    localPreparationMs,
  );
  assert.ok(overallMs >= requiredMs, "local budget infeasible before binary spawn");
  return {
    overallMs,
    exactRawCadenceMs,
    teardownPerSessionMs: localTeardownMs,
    preparationAllowanceMs: localPreparationMs,
    sessions,
  };
}
export async function check({
  binary,
  out,
  inputDirectory = join(here, "fixtures/ad"),
  budgetMs = localOverallMs,
}) {
  const inputs = loadInputs(inputDirectory);
  const budget = deriveLocalBudget(inputs, budgetMs);
  binary = realpathSync(binary);
  const runner = findPackagedRunner(binary);
  assert.ok(runner, "installed packaged runner required");
  const fixture = join(here, "fixtures/neutral-functions");
  const fixturePins = pins(
    ["index.js", "package.json", "package-lock.json"].map((name) => join(fixture, name)),
  );
  const sourcePins = pins([
    fileURLToPath(import.meta.url),
    join(here, "compare.mjs"),
    join(here, "lifecycle-evidence.mjs"),
    resolve(here, "../packaged-runner.mjs"),
  ]);
  const installedRunnerPins = runnerPins(runner);
  const physicalInputPins = pins(
    Object.keys(inputs.pins).map((name) => join(inputDirectory, name)),
  );
  const evidence = {
    schemaVersion: 1,
    kind: "eventarc-installed-check-v1",
    complete: false,
    artifactSha256: digest(binary),
    inputPins: inputs.pins,
    physicalInputPins,
    sourcePins,
    fixturePins,
    runnerPins: installedRunnerPins,
    budget,
    sessions: [],
    sessionPins: {},
  };
  mkdirSync(out, { recursive: true });
  const deadline = performance.now() + budget.overallMs;
  for (const [phase, corpusLabels] of [
    ["raw", labels],
    ["facets", ["B", "C", "D"]],
  ]) {
    for (const label of corpusLabels) {
      assert.ok(performance.now() < deadline, "finite overall check deadline");
      const work = mkdtempSync(join(out, `${phase}-${label}-`));
      const guard = join(work, "offline.cjs"),
        reportPath = join(work, "report.json"),
        sessionPath = join(work, "session.json");
      writeFileSync(guard, offlineGuardSource);
      const rows = inputs.corpora[label].rows;
      const project = selectSessionProject(rows);
      const ports = await reservePorts(),
        config = sessionConfiguration({ project, ports, runner, guard, fixture });
      save(join(work, "fireemu.json"), config.fireemu);
      save(join(work, "firebase.json"), config.firebase);
      const home = join(work, "home"),
        tmp = join(work, "tmp");
      mkdirSync(home);
      mkdirSync(tmp);
      save(sessionPath, {
        inputDirectory: resolve(inputDirectory),
        phase,
        label,
        reportPath: resolve(reportPath),
      });
      assert.ok(
        deadline - performance.now() >= localSessionMs + localTeardownMs,
        "local session budget infeasible before binary spawn",
      );
      const processReceipt = await runExecSession({
        binary,
        args: buildExecArgs({
          work: resolve(work),
          project,
          tasksPort: config.tasksPort,
          guard: resolve(guard),
          session: resolve(sessionPath),
        }),
        cwd: resolve(work),
        env: { PATH: process.env.PATH, HOME: resolve(home), TMPDIR: resolve(tmp) },
        timeoutMs: localSessionMs,
      });
      let report;
      try {
        report = json(reportPath);
      } catch {
        report = { complete: false, failure: { message: "missing session report" } };
        save(reportPath, report);
      }
      report.complete &&=
        processReceipt.exitCode === 0 &&
        !processReceipt.timedOut &&
        processReceipt.identity.status === "VERIFIED" &&
        processReceipt.processGroupAbsent &&
        !processReceipt.cleanupFailure &&
        !processReceipt.interrupted;
      const receiptPath = join(work, "process-receipt.json");
      save(receiptPath, processReceipt);
      evidence.sessions.push({
        id: basename(work),
        phase,
        label,
        report,
        processReceiptSha256: digest(receiptPath),
      });
      Object.assign(
        evidence.sessionPins,
        pins([
          reportPath,
          receiptPath,
          guard,
          sessionPath,
          join(work, "fireemu.json"),
          join(work, "firebase.json"),
        ]),
      );
      save(join(out, "check-evidence.json"), evidence);
      if (!report.complete) return evidence;
    }
  }
  for (const p of [sourcePins, fixturePins, installedRunnerPins, physicalInputPins]) verifyPins(p);
  assert.equal(digest(binary), evidence.artifactSha256);
  evidence.complete = true;
  save(join(out, "check-evidence.json"), evidence);
  return evidence;
}
async function main(args) {
  const flag = (name) => {
    const i = args.indexOf(`--${name}`);
    return i < 0 ? undefined : args[i + 1];
  };
  if (args[0] === "--session") return session(args[1]);
  assert.ok(
    ["check", "export-comparison"].includes(args[0]),
    "expected check or export-comparison",
  );
  const binary = flag("binary"),
    out = flag("out");
  assert.ok(binary && out, "--binary and --out required");
  if (args[0] === "check") {
    const result = await check({ binary, out: resolve(out) });
    if (!result.complete) process.exitCode = 1;
  } else
    exportComparison({
      binary,
      evidencePath: flag("evidence") ?? join(resolve(out), "check-evidence.json"),
      output: flag("comparison") ?? join(resolve(out), "comparison.json"),
    });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
