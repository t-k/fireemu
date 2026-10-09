// B evidence uses its original journal/summary contract and the existing strict local transports.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { spawn, execFileSync } from "node:child_process";
import { join, resolve, basename } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { readPinnedJsonl, validateRuntime } from "../pubsub-production/stream-dlq-compare.mjs";
import { createRest } from "../pubsub-production/rest.mjs";
import { createGrpc } from "../pubsub-production/grpc.mjs";
import { createCapture, createBudget } from "../pubsub-production/capture.mjs";
import { route } from "./wire.mjs";
import { CAPS } from "./plan.mjs";
import { importRecording, replayRecording } from "./replay-core.mjs";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function pinnedBytes(path, sha256, maximum = 10_000_000) {
  if (!/^[a-f0-9]{64}$/.test(sha256 ?? "")) throw new Error("SHA256 input pin required");
  const bytes = readFileSync(path);
  if (bytes.length > maximum || digest(bytes) !== sha256) throw new Error("input byte pin refused");
  return bytes;
}
export function nativeRequest(method, request) {
  const result = structuredClone(request);
  if (result.name !== undefined && /^(Get|Delete)(Topic|Subscription|Snapshot)$/.test(method)) {
    const field = method.endsWith("Topic")
      ? "topic"
      : method.endsWith("Subscription")
        ? "subscription"
        : "snapshot";
    result[field] = result.name;
    delete result.name;
  }
  return result;
}
export async function replayLocal(input, environment, pin, factories = {}) {
  validateRuntime(pin, environment);
  const captured = [],
    budget = createBudget(input.summary.meter.requests);
  const capture = createCapture({ journal: { write: (row) => captured.push(row) } });
  const getToken = null;
  const rest = (factories.rest ?? createRest)({
    base: `http://${environment.PUBSUB_EMULATOR_HOST}`,
    budget,
    capture,
    getToken,
  });
  const grpc = (factories.grpc ?? createGrpc)({
    target: environment.PUBSUB_EMULATOR_HOST,
    secure: false,
    budget,
    capture,
    getToken,
  });
  const advance = factories.fetch ?? fetch;
  let logicalTime = -Infinity;
  try {
    const report = await replayRecording(input, async (request) => {
      const time = Date.parse(request.at);
      if (!Number.isFinite(time) || time < logicalTime)
        throw new Error("recorded dispatch clock regressed");
      logicalTime = time;
      const clock = await advance(
        `${environment.FIREEMU_CONTROL_URL}sessions/default/clock:advanceTo`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${environment.FIREEMU_CONTROL_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ instant: new Date(time).toISOString() }),
          redirect: "manual",
          signal: AbortSignal.timeout(30000),
        },
      );
      if (!clock.ok) throw new Error("local clock advance refused");
      await clock.arrayBuffer();
      const label = { case: request.cellId, step: request.requestId };
      if (request.transport === "grpc")
        return grpc.call({
          label,
          op: request.method,
          service: request.service,
          method: request.method,
          request: nativeRequest(request.method, request.request),
        });
      const address = route(request.method, request.request);
      const url = new URL(address.url);
      const reply = await rest.request({
        label,
        op: request.method,
        method: address.verb,
        path: url.pathname + url.search,
        body: address.body,
      });
      return {
        ...reply,
        code: reply.status >= 200 && reply.status < 300 ? "OK" : reply.body?.error?.status,
        ok: reply.status >= 200 && reply.status < 300,
      };
    });
    report.localRequests = captured.length;
    report.localCapture = captured;
    return report;
  } finally {
    grpc.close();
  }
}
function options(argv) {
  const allowed = new Set([
      "capture",
      "capture-sha256",
      "summary",
      "summary-sha256",
      "build-pin",
      "build-pin-sha256",
      "out",
    ]),
    result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!argv[i]?.startsWith("--") || !allowed.has(key) || result[key] || !argv[i + 1])
      throw new Error("exact B replay options required");
    result[key] = argv[i + 1];
  }
  if (Object.keys(result).length !== allowed.size)
    throw new Error("all B replay pins and output required");
  return result;
}
export function validateLaunch(launch, pin, input, ancestry, ppid) {
  if (
    ppid !== launch.serverPid ||
    !ancestry.trim().startsWith(`${launch.parentPid} `) ||
    !ancestry.includes(`${pin.path} exec --config ${launch.config} --only pubsub --`)
  )
    throw new Error("internal pinned exec provenance refused");
  const config = JSON.parse(pinnedBytes(launch.config, launch.configSha256));
  if (
    config.profile !== "strict" ||
    config.bind !== "127.0.0.1" ||
    config.daemon?.pubsubPort !== 0 ||
    config.daemon.authProject !== input.metadata.project ||
    config.daemon.clockStart !== input.metadata.at
  )
    throw new Error("internal strict B config refused");
}
// Exec owns its worker descendants; escalation here targets only the exact launched parent.
export function waitForExec(
  child,
  expected,
  {
    setupMs = 30000,
    replayMs = CAPS.sourceWallMs,
    graceMs = 12000,
    killMs = 2000,
    ready = () => false,
    signals = process,
    start = () => {},
    inspect = () =>
      execFileSync("ps", ["-ww", "-p", String(child.pid), "-o", "ppid=,comm=,args="], {
        encoding: "utf8",
        timeout: 1000,
        killSignal: "SIGKILL",
        maxBuffer: 16384,
      }),
  } = {},
) {
  for (const bound of [setupMs, replayMs, graceMs, killMs])
    if (!Number.isSafeInteger(bound) || bound < 1) throw new Error("finite B exec bounds required");
  return new Promise((resolveResult, reject) => {
    const timers = new Set();
    let settled = false,
      stopping = false,
      failure = null,
      exited = false,
      identityVerified = false,
      observedIdentity = null;
    const timer = (fn, ms) => {
      const handle = setTimeout(() => {
        timers.delete(handle);
        fn();
      }, ms);
      timers.add(handle);
    };
    const finish = (error, code) => {
      if (settled) return;
      settled = true;
      for (const handle of timers) clearTimeout(handle);
      timers.clear();
      signals.off("SIGTERM", stop);
      signals.off("SIGINT", interrupt);
      child.off("exit", exit);
      child.off("error", errorEvent);
      if (error && !exited && Number.isSafeInteger(child.pid)) {
        error.unresolvedProcess = {
          pid: child.pid,
          expectedParentPid: expected.parentPid,
          expectedExecutable: expected.path,
          expectedArgs: expected.args,
          identityVerified,
          observedIdentity,
          terminationConfirmed: false,
        };
        // Releasing command handles does not settle unresolved process ownership.
        for (const stream of new Set(child.stdio ?? [child.stdin, child.stdout, child.stderr]))
          stream?.destroy?.();
        child.unref?.();
      }
      if (error) reject(error);
      else resolveResult(code);
    };
    const shutdown = (reason) => {
      if (settled || stopping) return;
      stopping = true;
      failure = new Error(reason);
      timer(() => {
        if (settled) return;
        try {
          observedIdentity = inspect().trim();
          const identity = observedIdentity.match(/^(\d+)\s+(\S+)\s+([\s\S]+)$/);
          if (
            !identity ||
            Number(identity[1]) !== expected.parentPid ||
            basename(identity[2]) !== basename(expected.path) ||
            identity[3] !== [expected.path, ...expected.args].join(" ")
          )
            throw new Error("owned exec identity refused before escalation");
          identityVerified = true;
          timer(() => finish(new Error("B exec shutdown completion deadline exceeded")), killMs);
          child.kill("SIGKILL");
        } catch (error) {
          finish(error);
        }
      }, graceMs);
      try {
        child.kill("SIGTERM");
      } catch (error) {
        failure = error;
      }
    };
    const stop = () => shutdown("B exec interrupted"),
      interrupt = stop;
    const exit = (code) => {
        exited = true;
        finish(failure, code ?? 2);
      },
      errorEvent = (error) => finish(error);
    child.once("exit", exit);
    child.once("error", errorEvent);
    signals.on("SIGTERM", stop);
    signals.on("SIGINT", interrupt);
    timer(() => {
      try {
        if (!ready()) shutdown("B exec setup deadline exceeded");
      } catch (error) {
        shutdown(error.message);
      }
    }, setupMs);
    timer(() => shutdown("B exec replay deadline exceeded"), replayMs);
    try {
      start();
    } catch (error) {
      shutdown(error.message);
    }
  });
}

export async function main(argv = process.argv.slice(2), environment = process.env, launch = null) {
  const opts = options(argv);
  const capture = readPinnedJsonl(opts.capture, opts["capture-sha256"]);
  const summary = JSON.parse(pinnedBytes(opts.summary, opts["summary-sha256"]));
  const input = importRecording(capture, summary);
  const pin = JSON.parse(pinnedBytes(opts["build-pin"], opts["build-pin-sha256"]));
  validateRuntime(pin, {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:2/v1/",
    FIREEMU_CONTROL_TOKEN: "admission-only",
  });
  pinnedBytes(pin.path, pin.sha256, 100_000_000);
  if (launch !== null) {
    const ancestry = execFileSync(
      "ps",
      ["-ww", "-p", String(launch.serverPid), "-o", "ppid=,args="],
      { encoding: "utf8", timeout: 1000, killSignal: "SIGKILL", maxBuffer: 16384 },
    );
    validateLaunch(launch, pin, input, ancestry, process.ppid);
    writeFileSync(
      join(opts.out, "runtime-start.json"),
      JSON.stringify({
        serverPid: launch.serverPid,
        workerPid: process.pid,
        strictConfigSha256: launch.configSha256,
      }),
      { flag: "wx", mode: 0o600 },
    );
    const report = await replayLocal(input, environment, pin);
    report.inputPins = {
      capture: opts["capture-sha256"],
      summary: opts["summary-sha256"],
      buildPin: opts["build-pin-sha256"],
    };
    report.build = pin;
    report.runtime = { pinnedExecParent: true, strictConfigSha256: launch.configSha256 };
    writeFileSync(join(opts.out, "comparison.json"), JSON.stringify(report, null, 2) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    return 0;
  }
  mkdirSync(opts.out, { mode: 0o700 });
  const temporary = mkdtempSync(join(tmpdir(), "fireemu-pubsub-b-replay-"));
  try {
    const config = join(temporary, "fireemu.json");
    writeFileSync(
      config,
      JSON.stringify({
        schemaVersion: 1,
        profile: "strict",
        bind: "127.0.0.1",
        daemon: {
          pubsubPort: 0,
          httpPort: 0,
          hubPort: 0,
          loggingPort: 0,
          authProject: input.metadata.project,
          clockStart: input.metadata.at,
        },
      }),
      { mode: 0o600 },
    );
    const bootstrap = `import {readFileSync} from 'node:fs'; import {main} from ${JSON.stringify(import.meta.url)}; process.exitCode=await main(${JSON.stringify(argv)},process.env,JSON.parse(readFileSync(0,'utf8')));`;
    const args = [
      "exec",
      "--config",
      config,
      "--only",
      "pubsub",
      "--",
      process.execPath,
      "--input-type=module",
      "--eval",
      bootstrap,
    ];
    const configSha256 = digest(readFileSync(config));
    const child = spawn(pin.path, args, {
      stdio: ["pipe", "inherit", "inherit"],
      env: {
        PATH: environment.PATH,
        TMPDIR: environment.TMPDIR,
        LANG: "C",
        LC_ALL: "C",
        TZ: "UTC",
      },
    });
    child.stdin.on("error", () => {});
    try {
      return await waitForExec(
        child,
        { path: pin.path, args, parentPid: process.pid },
        {
          ready: () => existsSync(join(opts.out, "runtime-start.json")),
          start: () =>
            child.stdin.end(
              JSON.stringify({
                serverPid: child.pid,
                parentPid: process.pid,
                config,
                configSha256,
              }),
            ),
        },
      );
    } catch (error) {
      if (error.unresolvedProcess) {
        try {
          writeFileSync(
            join(opts.out, "lifecycle-failure.json"),
            JSON.stringify({
              error: error.message,
              unresolvedProcess: error.unresolvedProcess,
              cleanupComplete: false,
            }) + "\n",
            { flag: "wx", mode: 0o600 },
          );
        } catch (writeError) {
          error.receiptWriteError = writeError.name;
        }
      }
      throw error;
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`B replay: ${error.message}\n`);
      if (error.unresolvedProcess)
        process.stderr.write(
          JSON.stringify({
            unresolvedProcess: error.unresolvedProcess,
            cleanupComplete: false,
            receiptWriteError: error.receiptWriteError ?? null,
          }) + "\n",
        );
      process.exitCode = 2;
    });
