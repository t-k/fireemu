// Local rehearsal and the explicitly admitted fixed S5b production producer.
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { DRIVERS, spawnSdk } from "../../../conformance/src/auth-fs-cross/sdk-client.mjs";

const ROOT = new URL("../../../", import.meta.url);
const SOURCE_PATHS = [
  "tools/compat-broad/fs-write-txn/web_sdk_retry.mjs",
  "conformance/src/auth-fs-cross/sdk-client.mjs",
  "conformance/src/auth-fs-cross/sdk-driver.mjs",
  "conformance/src/auth-fs-cross/sdk-driver-wire.mjs",
  "conformance/src/auth-fs-cross/sdk-wire.mjs",
  "conformance/src/auth-fs-cross/sdk-operations.mjs",
  "conformance/src/auth-fs-cross/browser-driver.mjs",
  "conformance/src/auth-fs-cross/browser-page.mjs",
  "conformance/package.json",
  "conformance/pnpm-lock.yaml",
];
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Admission precedes SDK loading and the first request. Configuration is entirely fake/local. */
export function localConfig({ projectId, firestoreHost, authHost }) {
  if (projectId !== "demo-web-retry") throw new Error("S5b requires demo-web-retry");
  const endpoint = (host) => {
    if (typeof host !== "string" || !/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(host))
      throw new Error("S5b requires an IPv4 loopback endpoint");
    const port = Number(host.split(":")[1]);
    if (port > 65535) throw new Error("invalid port");
    return port;
  };
  const port = endpoint(firestoreHost);
  endpoint(authHost);
  return {
    mode: "local",
    transactionCapture: true,
    web: { apiKey: "fake-local-key", projectId, authDomain: "localhost" },
    authEmulator: `http://${authHost}`,
    firestoreEmulator: { host: "127.0.0.1", port },
    wireCap: 40,
    connectionCap: 20,
  };
}

/** Equivalent RFC3339/protobuf versions compare without losing submillisecond precision. */
export function versionKey(value) {
  if (typeof value === "string") {
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
    if (!match) return null;
    const millis = Date.parse(`${match[1]}Z`);
    if (!Number.isFinite(millis) || new Date(millis).toISOString().slice(0, 19) !== match[1])
      return null;
    return `${millis / 1000}:${(match[2] ?? "").padEnd(9, "0")}`;
  }
  if (
    value &&
    /^-?\d+$/.test(String(value.seconds)) &&
    Number.isInteger(value.nanos) &&
    value.nanos >= 0 &&
    value.nanos < 1_000_000_000
  )
    return `${BigInt(value.seconds)}:${String(value.nanos).padStart(9, "0")}`;
  return null;
}

/** Pair by admitted request number, never by response completion order. */
export function scenarioComplete(scenario) {
  const wire = scenario.events
    .filter((e) => e.event === "transaction-wire")
    .toSorted((a, b) => a.n - b.n);
  const reads = scenario.events.filter(
    (e) => e.event === "transaction-read" && e.name === scenario.name,
  );
  const attempts = scenario.scenario === "conflict" ? 2 : scenario.scenario === "control" ? 1 : 0;
  if (
    !attempts ||
    !scenario.answer?.ok ||
    scenario.answer.attempts !== attempts ||
    reads.length !== attempts ||
    wire.length !== attempts * 2
  )
    return false;
  const seedVersion = versionKey(scenario.seed?.updateTime);
  const witnessVersion = versionKey(scenario.witness?.updateTime);
  const finalVersion = versionKey(scenario.final?.updateTime);
  if (
    !seedVersion ||
    !witnessVersion ||
    !finalVersion ||
    scenario.seed?.status !== 200 ||
    scenario.seed.path !== scenario.path ||
    scenario.witness?.status !== 200 ||
    (scenario.scenario === "conflict" && witnessVersion === seedVersion)
  )
    return false;
  const admitted = scenario.events.filter((e) => e.event === "wire");
  if (
    admitted.length !== wire.length ||
    new Set(wire.map((e) => e.n)).size !== wire.length ||
    scenario.events.some((e) =>
      ["wire-refused", "driver-error", "page-error", "unparsable-output"].includes(e.event),
    )
  )
    return false;
  for (let i = 0; i < attempts; i += 1) {
    const batch = wire[i * 2],
      commit = wire[i * 2 + 1];
    if (
      !batch.complete ||
      !commit.complete ||
      batch.method !== "BatchGetDocuments" ||
      commit.method !== "Commit" ||
      !admitted.some((e) => e.n === batch.n) ||
      !admitted.some((e) => e.n === commit.n)
    )
      return false;
    const document = batch.response?.documents?.[0];
    const write = commit.request?.writes?.[0];
    if (
      batch.request?.documents?.length !== 1 ||
      batch.request.documents[0] !== scenario.document ||
      document?.name !== scenario.document ||
      write?.update?.name !== scenario.document ||
      commit.request.writes.length !== 1 ||
      !versionKey(document.updateTime) ||
      versionKey(document.updateTime) !== versionKey(write.currentDocument?.updateTime) ||
      versionKey(document.updateTime) !== (i === 0 ? seedVersion : witnessVersion) ||
      commit.request.transactionPresent === true ||
      batch.request.transactionPresent === true
    )
      return false;
    if (
      reads[i].attempt !== i + 1 ||
      reads[i].docs?.[0]?.path !== scenario.path ||
      reads[i].docs[0].data?.value !== (i === 0 ? 1 : 2)
    )
      return false;
    const refused = scenario.scenario === "conflict" && i === 0;
    if (
      !refused &&
      (commit.response?.writeResults?.length !== 1 ||
        versionKey(commit.response.writeResults[0].updateTime) !== finalVersion ||
        finalVersion === versionKey(document.updateTime))
    )
      return false;
    if (
      refused
        ? commit.response?.error?.code !== 9 &&
          commit.response?.error?.status !== "FAILED_PRECONDITION"
        : Boolean(commit.response?.error) || !commit.response?.commitTime
    )
      return false;
  }
  return Boolean(
    scenario.final?.status === 200 &&
    scenario.final.value === 3 &&
    scenario.witness?.value === 2 &&
    scenario.witness.path === (scenario.scenario === "conflict" ? scenario.path : scenario.other) &&
    scenario.cleanup?.every(
      (item) =>
        item.absent === true &&
        item.deleted === true &&
        item.readStatus === 200 &&
        item.deleteStatus === 200 &&
        item.absenceStatus === 404 &&
        Boolean(item.updateTime) &&
        item.path ===
          (scenario.scenario === "control" && scenario.cleanup.indexOf(item) === 1
            ? scenario.other
            : scenario.path),
    ) &&
    scenario.cleanup.length === (scenario.scenario === "control" ? 2 : 1),
  );
}

// Diagnostic text is omitted: SDK messages, stderr, URLs and arbitrary labels can carry credentials.
const DIAGNOSTIC_CODES = new Set(["cancelled", "unknown", "invalid-argument", "deadline-exceeded",
  "not-found", "already-exists", "permission-denied", "resource-exhausted", "failed-precondition",
  "aborted", "out-of-range", "unimplemented", "internal", "unavailable", "data-loss", "unauthenticated"]);
const diagnosticCode = (code) => Number.isInteger(code) && code >= 0 && code <= 16 ? code :
  typeof code === "string" && DIAGNOSTIC_CODES.has(code.replace(/^firestore\//, "")) ? code : undefined;
const diagnosticName = (name) => ["Error", "TypeError", "RangeError", "SyntaxError", "FirebaseError"].includes(name) ? name : "Error";
const diagnosticEvents = (events) => events.filter((event) => ["ready", "connection", "wire",
  "transaction-dispatch", "transaction-wire", "transaction-read", "wire-refused", "driver-error",
  "page-error", "unparsable-output", "result", "exit"].includes(event?.event)).slice(-32).map((event) => {
    const safe = { event: event.event };
    for (const field of ["n", "attempt", "length", "status", "grpcCode"])
      if (Number.isSafeInteger(event[field]) && event[field] >= 0) safe[field] = event[field];
    for (const field of ["ok", "complete"])
      if (typeof event[field] === "boolean") safe[field] = event[field];
    if (event.name !== undefined && event.event === "driver-error") safe.name = diagnosticName(event.name);
    const code = diagnosticCode(event.code);
    if (code !== undefined) safe.code = code;
    return safe;
  });

export async function runLocalRetry(target, { artifact, artifactSource, receiptPath } = {}) {
  const config = localConfig(target);
  const receipt = {
    schemaVersion: 1,
    localOnly: true,
    complete: false,
    projectId: target.projectId,
    bindings: {},
    transports: [],
  };
  const sources = {};
  for (const path of SOURCE_PATHS) sources[path] = sha(await readFile(new URL(path, ROOT)));
  receipt.bindings.sources = sources;
  if (!artifact || !/^[0-9a-f]{40}$/.test(artifactSource ?? ""))
    throw new Error("an artifact and its source commit are required");
  receipt.bindings.artifact = {
    sha256: sha(await readFile(artifact)),
    sourceCommit: artifactSource,
  };
  const collection = `s5b_${randomUUID().replaceAll("-", "")}`;
  const base = `http://${target.firestoreHost}/v1/projects/${target.projectId}/databases/(default)/documents`;
  const request = async (path, init = {}) => {
    const response = await fetch(`${base}/${path}`, { ...init, signal: AbortSignal.timeout(5000) });
    return { status: response.status, body: await response.json() };
  };
  for (const transport of ["node-sdk", "browser"]) {
    const report = { transport, scenarios: [], closed: false };
    receipt.transports.push(report);
    const sdk = spawnSdk(config, { driver: DRIVERS[transport], timeoutMs: 15000 });
    try {
      await sdk.ready();
      for (const scenario of ["control", "conflict"]) {
        const name = `${transport}_${scenario}`;
        const path = `${collection}/${name}`,
          other = `${path}_other`;
        const owned = [];
        const outcome = {
          scenario,
          name,
          path,
          other,
          document: `projects/${target.projectId}/databases/(default)/documents/${path}`,
          events: [],
          cleanup: [],
        };
        report.scenarios.push(outcome);
        const put = async (path, value) => {
          const answer = await request(path, {
            method: "PATCH",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ fields: { value: { integerValue: String(value) } } }),
          });
          if (answer.status !== 200 || !answer.body.updateTime)
            throw new Error("witness write incomplete");
          if (!owned.includes(path)) owned.push(path);
          return { path, value, status: answer.status, updateTime: answer.body.updateTime };
        };
        const start = sdk.events.length;
        try {
          outcome.seed = await put(path, 1);
          const result = sdk.send("transaction", {
            name,
            reads: [path],
            write: { path, data: { value: 3 } },
          });
          // Keep rejection observed even if the read or witness fails before resumption.
          result.catch(() => {});
          await sdk.waitFor(
            (e) => e.event === "transaction-read" && e.name === name && e.attempt === 1,
          );
          outcome.witness = await put(scenario === "conflict" ? path : other, 2);
          await sdk.send("continueTransaction", { name });
          outcome.answer = await result;
          const final = await request(path);
          outcome.final = {
            status: final.status,
            value: Number(final.body.fields?.value?.integerValue),
            updateTime: final.body.updateTime,
          };
        } finally {
          outcome.events = sdk.events
            .slice(start)
            .filter((e) =>
              [
                "wire",
                "transaction-wire",
                "transaction-read",
                "wire-refused",
                "driver-error",
                "page-error",
                "unparsable-output",
              ].includes(e.event),
            );
          for (const path of owned) {
            const item = { path, phase: "read", deleted: false, absent: false };
            outcome.cleanup.push(item);
            try {
              const read = await request(path);
              item.readStatus = read.status;
              item.updateTime = read.body.updateTime;
              if (read.status !== 200 || !read.body.updateTime) continue;
              item.phase = "delete";
              const deleted = await request(
                `${path}?currentDocument.updateTime=${encodeURIComponent(read.body.updateTime)}`,
                { method: "DELETE" },
              );
              item.deleteStatus = deleted.status;
              item.deleted = deleted.status === 200;
              item.phase = "absence";
              const absent = await request(path);
              item.absenceStatus = absent.status;
              item.absent = absent.status === 404;
              item.phase = "done";
            } catch {
              item.failure = "cleanup-request-failed";
            }
          }
        }
        outcome.complete = scenarioComplete(outcome);
      }
    } catch {
      report.failure = "local-scenario-incomplete";
    } finally {
      await sdk.send("shutdown", {}, { timeout: 3000 }).catch(() => {});
      await sdk.waitFor((e) => e.event === "exit", { timeout: 5000 }).catch(() => {});
      const exit = await sdk.close();
      report.closed = exit.code === 0;
      report.bundles = sdk.events.filter((e) => e.event === "bundle");
    }
  }
  receipt.complete =
    receipt.transports.length === 2 &&
    receipt.transports.every(
      (report) =>
        report.closed && report.scenarios.length === 2 && report.scenarios.every((s) => s.complete),
    );
  if (receiptPath) await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}

/** The fixed production corpus is callable only by the admitted transaction parent. */
export async function recordWebRetries({ admission, parentCall, authorizeSdk, statusSdk, journal, check, spawn = spawnSdk }) {
  const { authorized, nonce, ownerId, web, origin, bindings, observationDeadlineMs } = admission ?? {};
  if (authorized !== true || !/^[a-f0-9]{32}$/.test(nonce ?? "") ||
      !/^[a-f0-9]{32}$/.test(ownerId ?? "") || web?.projectId !== "fireemu-oracle-query" ||
      typeof web.apiKey !== "string" || !web.apiKey ||
      !/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}$/.test(origin ?? "") ||
      Number(new URL(origin).port) > 65535 || !bindings ||
      !Number.isFinite(observationDeadlineMs) || observationDeadlineMs <= performance.now() ||
      observationDeadlineMs > performance.now() + 180_000 ||
      ![parentCall, authorizeSdk, statusSdk, journal, check].every((value) => typeof value === "function"))
    throw new Error("S5b fixed parent admission required");
  const database = "projects/fireemu-oracle-query/databases/(default)";
  const roles = ["node", "browser"].flatMap((transport) =>
    ["control", "control_other", "conflict", "probe"].map((role) => `${transport}_${role}`));
  const names = Object.fromEntries(roles.map((role) => [role, `${database}/documents/conf_txn/s5b_${nonce}_${role}`]));
  const receipt = { kind: "txn-s5b-web-recording-v1", nonce, ownerId, complete: false,
    bindings, timingMode: "wall-clock", timingSource: "sdk-parent-before-payload", transports: [],
    documents: {}, unknownWrites: [], cleanup: [] };
  let observationStopped = false;
  const calls = [];
  const owned = (doc, role) => doc?.name === names[role] && doc.fields?.owner?.stringValue === ownerId &&
    doc.fields?.nonce?.stringValue === nonce && doc.fields?.case?.stringValue === role.split("_").slice(1).join("_") && versionKey(doc.updateTime);
  const dispatch = async (method, request, phase = "observation") => {
    if (phase === "observation" && observationStopped) throw new Error("S5b observations stopped");
    await check();
    const answer = await parentCall({ method, request, phase });
    calls.push({ method, phase, complete: answer?.complete, code: answer?.code });
    if (!answer?.complete || !Number.isInteger(answer.code) || [1, 2, 4, 13, 14].includes(answer.code)) {
      observationStopped = true;
      if (["Commit", "DeleteDocument"].includes(method)) receipt.unknownWrites.push({ method, request, phase });
      throw new Error("S5b parent answer unknown");
    }
    return answer;
  };
  const get = (role, phase) => dispatch("GetDocument", { name: names[role] }, phase);
  const put = async (role, value, version) => {
    const fields = { owner: { stringValue: ownerId }, nonce: { stringValue: nonce },
      case: { stringValue: role.split("_").slice(1).join("_") }, value: { integerValue: String(value) } };
    receipt.documents[role] ??= { name: names[role], createConfirmed: false, deleted: false, absent: false };
    await journal({ event: "responsibility", documents: receipt.documents, nonce, ownerId });
    const answer = await dispatch("Commit", { database, writes: [{ update: { name: names[role], fields },
      currentDocument: version ? { updateTime: version } : { exists: false } }] });
    const updateTime = answer.response?.writeResults?.[0]?.updateTime;
    if (answer.code !== 0 || !versionKey(updateTime)) throw new Error("S5b parent write refused or incomplete");
    receipt.documents[role].createConfirmed = true;
    receipt.documents[role].updateTime = updateTime;
    await journal({ event: "responsibility", documents: receipt.documents, nonce, ownerId });
    return { status: 200, path: names[role].split("/documents/")[1], value, updateTime };
  };
  const close = async (sdk) => {
    await sdk.send("shutdown", {}, { timeout: 3000 }).catch(() => {});
    await sdk.waitFor((event) => event.event === "exit", { timeout: 5000 }).catch(() => {});
    return (await sdk.close()).code === 0;
  };
  const open = async (transport, probe, report) => {
    const client = `${transport}-${probe ? "probe" : "main"}`;
    let sdk;
    const statuses = new Set();
    const reportStatus = async (n) => {
      if (statuses.has(n)) return;
      const event = await sdk.waitFor((value) => value.event === "transaction-wire" && value.n === n);
      await statusSdk({ client, evidence: event });
      statuses.add(n);
      if (event.complete !== true || event.grpcCode !== undefined && [1, 2, 4, 13, 14].includes(event.grpcCode) ||
          event.status < 200 || event.status >= 500 || event.status >= 300 && event.status < 400)
        throw new Error("S5b SDK capture or status unknown");
    };
    await check();
    sdk = spawn({ mode: "production", web, origin, transactionCapture: true, wireCap: probe ? 1 : 6,
      connectionCap: 20, chromiumExecutable: bindings.runtime?.chromiumExecutable, s5bAdmission: { authorized: true, nonce, ownerId, transport, probe } }, {
      driver: DRIVERS[transport === "node" ? "node-sdk" : "browser"], timeoutMs: 15000,
      onTransactionAdmission: async (event) => {
        if (event.record.n > 1) await reportStatus(event.record.n - 1);
        await check();
        return authorizeSdk({ client, ...event });
      },
    });
    report.client = client;
    await journal({ event: "driver-lifecycle", client, phase: "launch", pid: sdk.pid });
    return { sdk, reportStatus };
  };
  try {
    for (const role of roles) {
      const answer = await get(role);
      if (answer.code !== 5) throw new Error("S5b exact name is not typed absent");
    }
    // Both transport probes succeed before any seed write; neither transaction is resumed.
    for (const transport of ["node", "browser"]) {
      const report = { transport, probe: {}, scenarios: [], closed: false };
      receipt.transports.push(report);
      const { sdk, reportStatus } = await open(transport, true, report.probe);
      let stage = "ready";
      try {
        await sdk.ready();
        stage = "browser-processes";
        if (transport === "browser") await journal({ event: "browser-processes", client: report.probe.client, ...(await sdk.waitFor((event) => event.event === "browser-processes")) });
        const role = `${transport}_probe`, path = names[role].split("/documents/")[1];
        stage = "transaction-send";
        const result = sdk.send("transaction", { name: role, reads: [path], maxAttempts: 2, write: { path, data: {} } });
        result.catch(() => {});
        stage = "transaction-read";
        const read = await sdk.waitFor((event) => event.event === "transaction-read" && event.name === role && event.attempt === 1);
        stage = "transaction-wire-status";
        await reportStatus(1);
        report.probe.events = sdk.events.filter((event) => ["wire", "transaction-wire", "transaction-read"].includes(event.event));
        const evidence = report.probe.events.find((event) => event.event === "transaction-wire");
        stage = "probe-validation";
        report.probe.complete = read.docs?.length === 1 && read.docs[0].exists === false &&
          evidence?.complete === true && evidence.response?.documents?.length === 1 && evidence.response.documents[0].missing === names[role] &&
          report.probe.events.filter((event) => event.event === "wire").length === 1;
        if (!report.probe.complete) throw new Error("S5b no-write probe refused");
      } catch (error) {
        report.probe.failure = { stage, name: diagnosticName(error?.name) };
        const code = diagnosticCode(error?.code);
        if (code !== undefined) report.probe.failure.code = code;
        throw error;
      } finally { report.probe.closed = await close(sdk);
        if (report.probe.failure) report.probe.diagnostics = diagnosticEvents(sdk.events); await journal({ event: "driver-lifecycle", client: report.probe.client, phase: "exit", pid: sdk.pid, closed: report.probe.closed }); }
      if (!report.probe.closed) throw new Error("S5b probe driver did not close");
    }
    for (const report of receipt.transports) {
      const transport = report.transport;
      const { sdk, reportStatus } = await open(transport, false, report);
      let stage = "ready", outcome;
      try {
        await sdk.ready();
        stage = "browser-processes";
        if (transport === "browser") await journal({ event: "browser-processes", client: report.client, ...(await sdk.waitFor((event) => event.event === "browser-processes")) });
        for (const scenario of ["control", "conflict"]) {
          const role = `${transport}_${scenario}`, otherRole = `${transport}_control_other`;
          const path = names[role].split("/documents/")[1], other = names[otherRole].split("/documents/")[1];
          outcome = { name: role, scenario, path, other, document: names[role], events: [], cleanup: [] };
          report.scenarios.push(outcome);
          const start = sdk.events.length;
          stage = "seed";
          outcome.seed = await put(role, 1);
          stage = "transaction-send";
          const startedMs = performance.now();
          const timeoutMs = Math.floor(observationDeadlineMs - startedMs);
          if (timeoutMs <= 0) throw new Error("S5b observation deadline reached");
          const id = `${role}-transaction`, command = { id, startedMs, deadlineMs: observationDeadlineMs, timeoutMs };
          outcome.command = command;
          const result = sdk.send("transaction", { id, name: role, reads: [path], maxAttempts: 2,
            write: { path, data: { owner: ownerId, nonce, case: scenario, value: 3 } } }, { timeout: timeoutMs }).then((answer) => {
            const resultMs = performance.now(), late = resultMs >= observationDeadlineMs;
            command.result = { state: late ? "rejected" : "resolved", resultMs,
              ...(late ? { reason: "observation-deadline" } : { ok: answer.ok === true }) };
            if (late) throw new Error("S5b observation deadline reached");
            return answer;
          }, (error) => {
            const resultMs = performance.now();
            command.result = { state: "rejected", resultMs,
              reason: resultMs >= observationDeadlineMs ? "observation-deadline" : "sdk-result-rejected",
              name: diagnosticName(error?.name) };
            const code = diagnosticCode(error?.code);
            if (code !== undefined) command.result.code = code;
            throw error;
          });
          result.catch(() => {});
          stage = "transaction-read";
          await sdk.waitFor((event) => event.event === "transaction-read" && event.name === role && event.attempt === 1);
          const latestWire = sdk.events.filter((event) => event.event === "wire").at(-1);
          stage = "first-wire-status";
          await reportStatus(latestWire.n);
          stage = "witness";
          outcome.witness = await put(scenario === "control" ? otherRole : role, 2, scenario === "conflict" ? outcome.seed.updateTime : undefined);
          stage = "continue-transaction";
          await sdk.send("continueTransaction", { name: role });
          stage = "transaction-result";
          outcome.answer = await result;
          const lastWire = sdk.events.filter((event) => event.event === "wire").at(-1);
          stage = "final-wire-status";
          await reportStatus(lastWire.n);
          stage = "final-read";
          const final = await get(role);
          if (final.code !== 0 || !owned(final.response, role)) throw new Error("S5b final owner/version differs");
          outcome.final = { status: 200, value: Number(final.response.fields.value?.integerValue), updateTime: final.response.updateTime };
          outcome.events = sdk.events.slice(start).filter((event) => ["wire", "transaction-wire", "transaction-read", "wire-refused", "driver-error", "page-error", "unparsable-output"].includes(event.event));
        }
      } catch (error) {
        report.failure = { stage, name: diagnosticName(error?.name) };
        const code = diagnosticCode(error?.code);
        if (code !== undefined) report.failure.code = code;
        if (outcome) outcome.failure = { ...report.failure };
        throw error;
      } finally {
        report.closed = await close(sdk);
        if (report.failure) report.diagnostics = diagnosticEvents(sdk.events);
        await journal({ event: "driver-lifecycle", client: report.client, phase: "exit", pid: sdk.pid, closed: report.closed });
        report.bundles = sdk.events.filter((event) => event.event === "bundle");
      }
      if (!report.closed) throw new Error("S5b main driver did not close");
    }
  } catch { observationStopped = true; receipt.failure = "observation-incomplete"; }
  // Known names remain independently cleanable after another name fails. Unknown writes stay sticky.
  for (const [role, responsibility] of Object.entries(receipt.documents)) {
    if (!responsibility.createConfirmed) continue;
    const item = { path: names[role].split("/documents/")[1], deleted: false, absent: false };
    receipt.cleanup.push(item);
    try {
      const read = await get(role, "documentCleanup");
      item.readStatus = read.code === 0 ? 200 : read.code === 5 ? 404 : null;
      if (read.code !== 0 || !owned(read.response, role)) continue;
      item.updateTime = read.response.updateTime;
      const deleted = await dispatch("DeleteDocument", { name: names[role], currentDocument: { updateTime: item.updateTime } }, "documentCleanup");
      item.deleteStatus = deleted.code === 0 ? 200 : null;
      item.deleted = deleted.code === 0;
      if (!item.deleted) continue;
      const absent = await get(role, "documentCleanup");
      item.absenceStatus = absent.code === 5 ? 404 : null;
      item.absent = absent.code === 5;
      responsibility.deleted = item.deleted; responsibility.absent = item.absent;
      await journal({ event: "responsibility", documents: receipt.documents, nonce, ownerId });
    } catch { item.failure = "cleanup-incomplete"; }
  }
  for (const report of receipt.transports) for (const outcome of report.scenarios) {
    outcome.cleanup = [outcome.path, ...(outcome.scenario === "control" ? [outcome.other] : [])].map((path) => receipt.cleanup.find((item) => item.path === path)).filter(Boolean);
    outcome.complete = scenarioComplete(outcome);
  }
  receipt.complete = !observationStopped && receipt.unknownWrites.length === 0 && receipt.cleanup.length === 6 &&
    receipt.cleanup.every((item) => item.deleted && item.absent) && receipt.transports.length === 2 &&
    receipt.transports.every((report) => report.closed && report.probe.complete && report.probe.closed && report.scenarios.length === 2 && report.scenarios.every((outcome) => outcome.complete));
  receipt.parentRequests = calls;
  return receipt;
}

async function productionEntry() {
  const { createInterface } = await import("node:readline");
  const pending = new Map();
  let next = 0;
  const lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    try {
      const reply = JSON.parse(line), waiting = pending.get(reply.id);
      if (!waiting) throw new Error("unknown parent reply");
      pending.delete(reply.id); clearTimeout(waiting.timer);
      if (reply.authorized !== true) waiting.reject(new Error("parent refused"));
      else waiting.resolve(reply);
    } catch { for (const waiting of pending.values()) { clearTimeout(waiting.timer); waiting.reject(new Error("parent IPC failed")); } pending.clear(); }
  });
  const exchange = (event) => new Promise((resolve, reject) => {
    const id = `web-${++next}`;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("parent acknowledgment missing")); }, 13_000);
    pending.set(id, { resolve, reject, timer });
    process.stdout.write(`${JSON.stringify({ ...event, id })}\n`);
  });
  try {
    const readyStartedMs = performance.now();
    const admission = await exchange({ event: "ready" });
    if (!Number.isFinite(admission.observationRemaining) || admission.observationRemaining <= 0 || admission.observationRemaining > 180)
      throw new Error("S5b remaining observation admission required");
    // Anchor before the exchange so IPC time cannot extend the parent's original window.
    admission.observationDeadlineMs = readyStartedMs + Math.floor(admission.observationRemaining * 1000);
    const receipt = await recordWebRetries({ admission,
      parentCall: async (call) => (await exchange({ event: "parent-call", ...call })).answer,
      authorizeSdk: async (event) => (await exchange({ event: "dispatch", row: event })).authorized,
      statusSdk: (event) => exchange({ event: "status", row: event }),
      journal: (event) => exchange(event), check: () => exchange({ event: "check" }) });
    process.stdout.write(`${JSON.stringify({ event: "receipt", receipt })}\n`);
    process.exitCode = receipt.complete ? 0 : 1;
  } finally { lines.close(); }
}


if (process.argv[1] === fileURLToPath(import.meta.url) && process.argv[2] === "production") {
  productionEntry().catch(() => { process.stderr.write("S5b production recording incomplete\n"); process.exitCode = 1; });
} else if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runLocalRetry(
    {
      projectId: process.env.GOOGLE_CLOUD_PROJECT,
      firestoreHost: process.env.FIRESTORE_EMULATOR_HOST,
      authHost: process.env.FIREBASE_AUTH_EMULATOR_HOST,
    },
    {
      artifact: process.env.S5B_FIREEMU,
      artifactSource: process.env.S5B_ARTIFACT_SOURCE,
      receiptPath: process.env.S5B_RECEIPT,
    },
  )
    .then((receipt) => {
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
      process.exitCode = receipt.complete ? 0 : 1;
    })
    .catch(() => {
      process.stderr.write("S5b local admission or binding failed\n");
      process.exitCode = 1;
    });
}
