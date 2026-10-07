// Local rehearsal of the Web SDK optimistic retry condition; never a production recorder.
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

if (process.argv[1] === fileURLToPath(import.meta.url)) {
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
