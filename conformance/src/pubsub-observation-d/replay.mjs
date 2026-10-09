import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync, lstatSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { pinnedBytes } from "../pubsub-observation-b/replay.mjs";
import { sameVirtualInstant } from "../pubsub-observation-b/replay-core.mjs";
import {
  validateRuntime,
  verifyStrictWorker,
  runStrictRuntime,
} from "../pubsub-production/stream-dlq-compare.mjs";
import { createMeter } from "./meter.mjs";
import { CAPS, iamCategory, minimumCallMs } from "./plan.mjs";
import { readResponse } from "../pubsub-observation-c/wire.mjs";
import { FRAMING_RESERVE } from "../pubsub-observation/metadata.mjs";
import { createWire } from "../pubsub-observation-c/wire.mjs";
import { importRecording, replayRecording, bindTerminal } from "./replay-core.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function pinned(path, sha, max = 10_000_000) {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink()) throw new Error("regular pinned D input required");
  return pinnedBytes(path, sha, max);
}
function lines(bytes) {
  const rows = bytes.toString("utf8").split(/\r?\n/).filter(Boolean);
  if (rows.length > 10000) throw new Error("D journal row bound");
  return rows.map((row) => JSON.parse(row));
}
export function readSource(binding) {
  const load = (name) => JSON.parse(pinned(binding[name].path, binding[name].sha256));
  const packet = load("packet"),
    descriptor = load("descriptor"),
    summary = load("summary");
  execFileSync("git", ["-C", root, "verify-commit", descriptor.head], {
    stdio: "pipe",
    timeout: 5000,
  });
  if (!Array.isArray(descriptor.sources) || descriptor.sources.length > 1000)
    throw new Error("bounded D source descriptor required");
  let bytes = 0;
  for (const item of descriptor.sources) {
    if (typeof item.path !== "string" || item.path.includes("..") || item.path.startsWith("/"))
      throw new Error("recording source path refused");
    const data = execFileSync("git", ["-C", root, "show", `${descriptor.head}:${item.path}`], {
      maxBuffer: 2_000_000,
      timeout: 5000,
    });
    bytes += data.length;
    if (bytes > 20_000_000 || digest(data) !== item.sha256)
      throw new Error("recording source digest refused");
  }
  for (const name of ["capture", "issued", "iam"])
    if (summary[`${name}Sha256`] !== binding[name].sha256)
      throw new Error("D summary journal digest refused");
  const input = importRecording({
    packet,
    descriptor,
    summary,
    rows: lines(pinned(binding.capture.path, binding.capture.sha256)),
    issued: lines(pinned(binding.issued.path, binding.issued.sha256)),
    iam: lines(pinned(binding.iam.path, binding.iam.sha256)),
    recovery: lines(pinned(binding.recovery.path, binding.recovery.sha256)),
    packetSha256: binding.packet.sha256,
    descriptorSha256: binding.descriptor.sha256,
  });
  const terminalBytes = pinned(binding.terminal.path, binding.terminal.sha256, 8192);
  const terminalRows = lines(terminalBytes);
  if (terminalRows.length !== 1) throw new Error("D exact single source terminal required");
  const terminal = bindTerminal(terminalRows[0], input, binding.summary.sha256);
  return {
    ...input,
    terminalBytes,
    retainedTerminal: {
      path: binding.terminal.path,
      sha256: binding.terminal.sha256,
      bytes: terminalBytes.length,
      row: terminal,
    },
  };
}
function compiledInputs(pin) {
  const manifest = JSON.parse(pinned(pin.binaryInputsPath, pin.binaryInputsSha256));
  if (
    manifest.sourceHead !== pin.head ||
    manifest.sourceTree !== pin.tree ||
    Object.keys(manifest.files ?? {}).length !== 338 ||
    !Object.hasOwn(manifest.files ?? {}, "crates/fireemu-core-pubsub/src/iam.rs")
  )
    throw new Error("D compiled input coverage refused");
  let bytes = 0;
  for (const [path, sha] of Object.entries(manifest.files)) {
    const target = resolve(root, path);
    if (!target.startsWith(`${root}/`)) throw new Error("compiled input path refused");
    bytes += pinned(target, sha, 20_000_000).length;
    if (bytes > 20_000_000) throw new Error("compiled input byte bound");
  }
}
export function sourceProjectNumbers(input) {
  const numbers = {};
  for (const cell of input.cells.filter((c) => c.arm === "managed-grant-readback-wait")) {
    const grants = cell.exchanges.filter((e) => e.category === "iamSetupWrite");
    if (grants.length !== 2) throw new Error("D exact managed source grants required");
    let sourceProject, principal;
    const kinds = new Set();
    for (const exchange of grants) {
      const match = exchange.request.resource?.match(
        /^projects\/([^/]+)\/(subscriptions|topics)\/[^/]+$/,
      );
      if (match && kinds.has(match[2]))
        throw new Error("D distinct source and destination grants required");
      if (match) kinds.add(match[2]);
      const role =
        match?.[2] === "subscriptions" ? "roles/pubsub.subscriber" : "roles/pubsub.publisher";
      const binding = exchange.request.policy?.bindings?.find((b) => b.role === role);
      const member = binding?.members?.find((m) =>
        /^serviceAccount:service-[1-9]\d{0,19}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(m),
      );
      if (!match || !member || (principal && principal !== member))
        throw new Error("D matching source service-agent grants required");
      principal = member;
      if (match[2] === "subscriptions") sourceProject = match[1];
    }
    if (!sourceProject || sourceProject !== input.metadata.project)
      throw new Error("D source-project identity mismatch");
    const number = principal.match(/^serviceAccount:service-([1-9]\d{0,19})@/)[1];
    if (numbers[sourceProject] && numbers[sourceProject] !== number)
      throw new Error("D inconsistent source service-agent identity");
    numbers[sourceProject] = number;
  }
  if (Object.keys(numbers).length !== 1)
    throw new Error("D explicit source-project identity required");
  return numbers;
}

export async function replayLocal(
  input,
  environment,
  pin,
  {
    fetch = globalThis.fetch,
    wireFactory = createWire,
    persist = () => {},
    now = () => performance.now(),
    timestampDisposition,
  } = {},
) {
  validateRuntime(pin, environment);
  const runtimeInputs = { binarySha256: pin.sha256, inputsSha256: pin.binaryInputsSha256 };
  const meter = createMeter({ plan: input.packet.plan, now }),
    localRows = [],
    clockReceipts = [];
  let logicalTime = Date.parse(input.metadata.at),
    activeSource = null;
  const journal = {
    write(row) {
      const boundRow = {
        ...row,
        sourceRequestId: activeSource?.requestId,
        sourceN: activeSource?.n,
      };
      localRows.push(boundRow);
      persist("row", boundRow);
    },
  };
  const wire = wireFactory({
    meter,
    journal,
    localRuntime: {
      pin,
      environment,
      clock: () => logicalTime - Date.parse(input.metadata.at),
      captureBody: (transport, requestId, bytes) =>
        persist("body", { transport, requestId, bytes }),
    },
  });
  let iamSequence = 0;
  const iamControllers = new Set();
  const callIam = async (call) => {
    if (
      call.transport !== "rest" ||
      !["GetIamPolicy", "SetIamPolicy"].includes(call.method) ||
      !/^projects\/[^/]+\/(topics|subscriptions)\/[^/]+$/.test(call.request.resource ?? "")
    )
      throw new Error("D finite local IAM route required");
    const maintenance = call.category.startsWith("cleanup"),
      remaining = () => meter.remaining(maintenance);
    meter.start(call.category, "rest");
    if (remaining() < minimumCallMs(call.method))
      throw new Error("D IAM latency margin unavailable");
    const set = call.method === "SetIamPolicy",
      url = `http://${environment.PUBSUB_EMULATOR_HOST}/v1/${call.request.resource.split("/").map(encodeURIComponent).join("/")}:${set ? "setIamPolicy" : "getIamPolicy?options.requestedPolicyVersion=3"}`,
      raw = set ? Buffer.from(JSON.stringify({ policy: call.request.policy })) : Buffer.alloc(0),
      metadataBytesOut = Buffer.byteLength(url) + 256 + FRAMING_RESERVE;
    if (raw.length + metadataBytesOut > CAPS.metadataBytesEachDirection)
      throw new Error("D IAM request byte cap");
    const requestId = `iam-${++iamSequence}`,
      started = meter.clock(),
      controller = new AbortController();
    iamControllers.add(controller);
    const timer = setTimeout(() => controller.abort(), Math.min(30000, remaining()));
    let reply;
    try {
      journal.write({
        event: "request-dispatch",
        cellId: call.cellId,
        requestId,
        transport: "rest",
        category: call.category,
        method: call.method,
        request: call.request,
        metadataBytesOut,
        clockMs: started,
      });
      const response = await fetch(url, {
        method: set ? "POST" : "GET",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        ...(set ? { body: raw } : {}),
        signal: controller.signal,
      });
      const bytes = await readResponse(response),
        body = JSON.parse(bytes);
      if (!body || typeof body !== "object" || Array.isArray(body))
        throw new Error("D IAM unreadable response object");
      persist("body", { transport: "rest", requestId, bytes });
      const metadataBytesIn = [...response.headers].reduce(
        (sum, [key, value]) => sum + Buffer.byteLength(key) + Buffer.byteLength(value) + 4,
        FRAMING_RESERVE,
      );
      reply = {
        ok: response.ok,
        status: response.status,
        code: body.error?.status ?? (response.ok ? "OK" : "UNKNOWN"),
        body,
        bodyBytes: bytes.length,
        bodySha256: digest(bytes),
        metadataBytesIn,
        unknown:
          response.status < 200 ||
          (response.status >= 300 && response.status < 400) ||
          response.status >= 500 ||
          response.status === 499,
      };
    } catch {
      reply = { ok: false, code: "UNKNOWN", unknown: true, body: {}, bodyBytes: null };
    } finally {
      clearTimeout(timer);
      iamControllers.delete(controller);
    }
    reply.durationMs = meter.clock() - started;
    journal.write({
      event: "response",
      cellId: call.cellId,
      requestId,
      transport: "rest",
      method: call.method,
      durationMs: reply.durationMs,
      reply,
    });
    try {
      remaining();
    } catch {
      reply.budgetOverrun = true;
    }
    return reply;
  };
  const bound = async (operation, ms) => {
    let timer;
    try {
      return await Promise.race([
        operation(),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            wire.abortSource();
            for (const controller of iamControllers) controller.abort();
            reject(new Error("D local cell time exhausted"));
          }, ms);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    const report = await replayRecording(
      { ...input, runtimeInputs },
      async (call, source) => {
        activeSource = source;
        const next = Date.parse(source.at);
        if (!Number.isFinite(next) || next < logicalTime)
          throw new Error("D dispatch clock regressed");
        const maintenance = call.category.startsWith("cleanup");
        const remaining = () => meter.remaining(maintenance);
        const clock = await bound(
          () =>
            fetch(`${environment.FIREEMU_CONTROL_URL}sessions/default/clock:advanceTo`, {
              method: "POST",
              headers: {
                authorization: `Bearer ${environment.FIREEMU_CONTROL_TOKEN}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ instant: source.at }),
              redirect: "manual",
              signal: AbortSignal.timeout(Math.min(30000, remaining())),
            }),
          Math.min(30000, remaining()),
        );
        const bytes = await bound(
          async () => Buffer.from(await clock.arrayBuffer()),
          Math.min(30000, remaining()),
        );
        if (clock.status !== 200 || bytes.length > 16384)
          throw new Error("D clock readback refused");
        const readback = JSON.parse(bytes);
        if (!sameVirtualInstant(source.at, readback.clock))
          throw new Error("D clock readback differs");
        logicalTime = next;
        const receipt = {
          sourceRequestId: source.requestId,
          sourceN: source.n,
          requestedInstant: source.at,
          status: clock.status,
          body: readback,
          bodyBytes: bytes.length,
          bodySha256: digest(bytes),
        };
        clockReceipts.push(receipt);
        persist("clock", receipt);
        return await bound(
          () => (iamCategory(call.category) ? callIam(call) : wire.call(call)),
          remaining(),
        );
      },
      {
        enter: (cell) => meter.enter(input.packet.plan.cells.find((c) => c.id === cell.id)),
        observe: (entry) => persist("comparison", entry),
        timestampDisposition,
        clockReceiptFor: (source) =>
          clockReceipts.find(
            (receipt) =>
              receipt.sourceRequestId === source.requestId && receipt.sourceN === source.n,
          ),
      },
    );
    return {
      ...report,
      clockReceipts,
      localRows,
      meter: meter.snapshot(),
      runtimeInputs,
    };
  } finally {
    for (const controller of iamControllers) controller.abort();
    wire.abortSource();
    wire.close();
  }
}
function options(argv) {
  const allowed = ["input", "input-sha256", "build-pin", "build-pin-sha256", "out"],
    opts = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!allowed.includes(key) || opts[key] || !argv[i + 1])
      throw new Error("exact D replay pins and output required");
    opts[key] = argv[i + 1];
  }
  if (Object.keys(opts).length !== allowed.length)
    throw new Error("D replay input/build pins and output required");
  return opts;
}
export function persistRuntimeStart(out, launch, clockStart) {
  const bytes = pinned(launch.config, launch.configSha256, 1_000_000);
  const config = JSON.parse(bytes);
  if (config.daemon.clockStart !== clockStart) throw new Error("D strict clock start refused");
  const strictConfigPath = resolve(out, "strict-config.json");
  writeFileSync(strictConfigPath, bytes, { flag: "wx", mode: 0o600, flush: true });
  writeFileSync(
    join(out, "runtime-start.json"),
    JSON.stringify({
      serverPid: launch.serverPid,
      workerPid: process.pid,
      strictConfigPath,
      strictConfigBytes: bytes.length,
      strictConfigSha256: launch.configSha256,
    }) + "\n",
    { flag: "wx", mode: 0o600, flush: true },
  );
}
export async function main(argv = process.argv.slice(2), environment = process.env, launch = null) {
  const opts = options(argv),
    binding = JSON.parse(pinned(opts.input, opts["input-sha256"])),
    input = readSource(binding);
  const pin = JSON.parse(pinned(opts["build-pin"], opts["build-pin-sha256"]));
  validateRuntime(pin, {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:2/v1/",
    FIREEMU_CONTROL_TOKEN: "admission-only",
  });
  pinned(pin.path, pin.sha256, 100_000_000);
  compiledInputs(pin);
  if (launch === null) {
    mkdirSync(opts.out, { mode: 0o700 });
    return runStrictRuntime({
      pin,
      project: input.metadata.project,
      clockStart: input.metadata.at,
      argv,
      environment,
      workerModule: import.meta.url,
      pubsubProjectNumbers: sourceProjectNumbers(input),
    });
  }
  verifyStrictWorker({
    pin,
    project: input.metadata.project,
    launch,
    pubsubProjectNumbers: sourceProjectNumbers(input),
  });
  persistRuntimeStart(opts.out, launch, input.metadata.at);
  writeFileSync(join(opts.out, "source-terminal.jsonl"), input.terminalBytes, { flag: "wx" });
  let bodySequence = 0;
  const persist = (kind, value) => {
    if (kind === "body")
      writeFileSync(
        join(
          opts.out,
          `local-body-${String(++bodySequence).padStart(4, "0")}-${value.transport}-${value.requestId}.bin`,
        ),
        value.bytes,
        { flag: "wx" },
      );
    else
      writeFileSync(join(opts.out, `${kind}.jsonl`), JSON.stringify(value) + "\n", { flag: "a" });
  };
  const report = await replayLocal(input, environment, pin, {
    persist,
    timestampDisposition: binding.timestampDisposition,
  });
  report.inputPins = binding;
  report.retainedTerminal = input.retainedTerminal;
  report.buildPinSha256 = opts["build-pin-sha256"];
  writeFileSync(join(opts.out, "comparison.json"), JSON.stringify(report, null, 2) + "\n", {
    flag: "wx",
  });
  return 0;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error.message);
      process.exitCode = 2;
    },
  );
