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
import { createWire } from "./wire.mjs";
import { importRecording, replayRecording } from "./replay-core.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function pinned(path, sha, max = 10_000_000) {
  const s = lstatSync(path);
  if (!s.isFile() || s.isSymbolicLink()) throw new Error("regular pinned C input required");
  return pinnedBytes(path, sha, max);
}
function lines(bytes) {
  const rows = bytes.toString("utf8").split(/\r?\n/).filter(Boolean);
  if (rows.length > 10000) throw new Error("C journal row bound");
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
    throw new Error("bounded C source descriptor required");
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
  return importRecording({
    packet,
    descriptor,
    summary,
    rows: lines(pinned(binding.capture.path, binding.capture.sha256)),
    issued: lines(pinned(binding.issued.path, binding.issued.sha256)),
    packetSha256: binding.packet.sha256,
    descriptorSha256: binding.descriptor.sha256,
  });
}
function compiledInputs(pin) {
  const manifest = JSON.parse(pinned(pin.binaryInputsPath, pin.binaryInputsSha256));
  if (
    manifest.sourceHead !== pin.head ||
    manifest.sourceTree !== pin.tree ||
    Object.keys(manifest.files ?? {}).length !== 337
  )
    throw new Error("C compiled input coverage refused");
  let bytes = 0;
  for (const [path, sha] of Object.entries(manifest.files)) {
    const target = resolve(root, path);
    if (!target.startsWith(`${root}/`)) throw new Error("compiled input path refused");
    bytes += pinned(target, sha, 20_000_000).length;
    if (bytes > 20_000_000) throw new Error("compiled input byte bound");
  }
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
  } = {},
) {
  validateRuntime(pin, environment);
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
  const bound = async (operation, ms) => {
    let timer;
    try {
      return await Promise.race([
        operation(),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            wire.abortSource();
            reject(new Error("C local cell time exhausted"));
          }, ms);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    const report = await replayRecording(
      input,
      async (call, source) => {
        activeSource = source;
        const next = Date.parse(source.at);
        if (!Number.isFinite(next) || next < logicalTime)
          throw new Error("C dispatch clock regressed");
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
          throw new Error("C clock readback refused");
        const readback = JSON.parse(bytes);
        if (!sameVirtualInstant(source.at, readback.clock))
          throw new Error("C clock readback differs");
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
        return await bound(() => wire.call(call), remaining());
      },
      {
        enter: (cell) => meter.enter(input.packet.plan.cells.find((c) => c.id === cell.id)),
        observe: (entry) => persist("comparison", entry),
      },
    );
    return {
      ...report,
      clockReceipts,
      localRows,
      meter: meter.snapshot(),
      runtimeInputs: { binarySha256: pin.sha256, inputsSha256: pin.binaryInputsSha256 },
    };
  } finally {
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
      throw new Error("exact C replay pins and output required");
    opts[key] = argv[i + 1];
  }
  if (Object.keys(opts).length !== allowed.length)
    throw new Error("C replay input/build pins and output required");
  return opts;
}
export function persistRuntimeStart(out, launch, clockStart) {
  const bytes = pinned(launch.config, launch.configSha256, 1_000_000);
  const config = JSON.parse(bytes);
  if (config.daemon.clockStart !== clockStart) throw new Error("C strict clock start refused");
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
    });
  }
  verifyStrictWorker({ pin, project: input.metadata.project, launch });
  persistRuntimeStart(opts.out, launch, input.metadata.at);
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
  const report = await replayLocal(input, environment, pin, { persist });
  report.inputPins = binding;
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
