// Offline comparison. This module has no credential provider or production transport.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync, lstatSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, relative, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn, execFileSync } from "node:child_process";
import grpcLib from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { createGrpc } from "./grpc.mjs";
import { createStreamingPull } from "./stream.mjs";
import { createRest } from "./rest.mjs";
import { createCapture, createBudget } from "./capture.mjs";
import {
  compareRecording,
  createFieldNormalization,
  recordingTimingDebts,
  recordedRequestInstant,
  recordedSilenceProbe,
} from "./stream-dlq-compare-core.mjs";
import { createOwnership } from "./names.mjs";
import { isDeepStrictEqual } from "node:util";
import { removeTree } from "../remove-tree.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SHA = /^[a-f0-9]{64}$/;
function pinnedBytes(path, sha, max = 10_000_000) {
  if (!SHA.test(sha)) throw new Error("SHA256 pin required");
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.size > max) throw new Error("input file bound exceeded");
  const bytes = readFileSync(path);
  if (digest(bytes) !== sha) throw new Error("input digest mismatch");
  return bytes;
}
export function readPinnedJsonl(path, sha) {
  const text = pinnedBytes(path, sha).toString("utf8");
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length > 5000) throw new Error("input row bound exceeded");
  return lines.map((line) => JSON.parse(line));
}
export function validateRuntime(pin, environment) {
  if (
    pin.profile !== "release" ||
    pin.rustcWrapper !== "" ||
    !SHA.test(pin.sha256) ||
    !/^[a-f0-9]{40}$/.test(pin.head) ||
    !Array.isArray(pin.command) ||
    pin.command[0] !== "cargo" ||
    !pin.command.includes("build") ||
    !pin.command.includes("--release") ||
    !/[\\/]release[\\/]fireemu(?:\.exe)?$/.test(pin.path)
  )
    throw new Error("verified release build pin with empty wrapper required");
  if (
    !/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(environment.PUBSUB_EMULATOR_HOST ?? "") ||
    Number(environment.PUBSUB_EMULATOR_HOST.split(":")[1]) > 65535
  )
    throw new Error("loopback Pub/Sub target required");
  const control = new URL(environment.FIREEMU_CONTROL_URL ?? "invalid:");
  if (
    control.protocol !== "http:" ||
    control.hostname !== "127.0.0.1" ||
    !control.port ||
    control.username ||
    control.password ||
    control.pathname !== "/v1/" ||
    control.search ||
    control.hash ||
    !environment.FIREEMU_CONTROL_TOKEN
  )
    throw new Error("loopback control target required");
}
export function guardReceived(expected, actual, bindings) {
  if (expected?.receivedMessages?.length !== 1 || actual?.receivedMessages?.length !== 1)
    throw new Error("native receive requires one causal identity");
  bindings.linkReceive(expected, actual);
}
export function createReceiveGuard(frames, bindings) {
  const expected = frames.find(
    (frame) => frame.direction === "in" && frame.body?.receivedMessages?.length,
  )?.body;
  let received = false;
  return (actual) => {
    if (!(actual.receivedMessages?.length > 0)) return;
    if (received) throw new Error("second native receive before terminal status");
    guardReceived(expected, actual, bindings);
    received = true;
  };
}
export function validateStreamFrames(original, frames) {
  const Request = protos.google.pubsub.v1.StreamingPullRequest;
  const outbound = frames.filter((frame) => frame.direction === "out");
  if (!Array.isArray(original.request.frames) || !original.request.frames.length)
    throw new Error("native initial frames missing");
  original.request.frames.forEach((body, index) => {
    const matches = outbound.filter((frame) => frame.frame === index + 1);
    if (
      matches.length !== 1 ||
      digest(Request.encode(Request.fromObject(body)).finish()) !== matches[0].sha256
    )
      throw new Error("native request/raw frame mismatch");
  });
  if (
    original.request.afterReceive !== undefined &&
    !isDeepStrictEqual(original.request.afterReceive, { modifyDeadlineSeconds: -1 })
  )
    throw new Error("native followup shape refused");
  if (original.response.followUpSent) {
    const followup = outbound.find((frame) => frame.frame === 2);
    const causal = frames.find(
      (frame) => frame.direction === "in" && frame.frame === followup?.causedByInboundFrame,
    );
    const ack = causal?.body?.receivedMessages?.[0]?.ackId;
    if (
      original.request.frames.length !== 1 ||
      !original.request.afterReceive ||
      !ack ||
      !isDeepStrictEqual(followup?.body?.modifyDeadlineAckIds, [ack]) ||
      !isDeepStrictEqual(followup?.body?.modifyDeadlineSeconds, [-1])
    )
      throw new Error("native causal followup provenance refused");
  }
}
function options(argv) {
  const allowed = new Set([
    "capture",
    "capture-sha256",
    "issued",
    "issued-sha256",
    "iam",
    "iam-sha256",
    "build-pin",
    "out",
    "peer-capture",
    "peer-capture-sha256",
  ]);
  const parsed = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!allowed.has(key) || parsed[key] !== undefined || !argv[i + 1] || !argv[i].startsWith("--"))
      throw new Error(
        "expected capture/issued/iam paths and SHA256 pins, build-pin and new out directory",
      );
    parsed[key] = argv[i + 1];
  }
  if ([...allowed].filter((key) => !key.startsWith("peer-")).some((key) => !parsed[key]))
    throw new Error("all comparison inputs and pins are required");
  if (Boolean(parsed["peer-capture"]) !== Boolean(parsed["peer-capture-sha256"]))
    throw new Error("peer capture path and SHA256 required together");
  return parsed;
}
function inputs(opts) {
  const capture = readPinnedJsonl(opts.capture, opts["capture-sha256"]);
  const issued = readPinnedJsonl(opts.issued, opts["issued-sha256"]);
  const iam = readPinnedJsonl(opts.iam, opts["iam-sha256"]);
  const starts = capture.filter((row) => row.note === "run-start");
  if (
    starts.length !== 1 ||
    starts[0].suite !== "stream-dlq-v2" ||
    !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(starts[0].project) ||
    !/^[a-f0-9]{12}$/.test(starts[0].runId) ||
    capture.filter((row) => row.note === "run-end").length !== 1
  )
    throw new Error("closed stream-dlq-v2 input required");
  const timingDebts = recordingTimingDebts(capture);
  if (timingDebts.length)
    throw new Error(`invalid recording chronology: ${timingDebts.join("; ")}`);
  return { capture, issued, iam, metadata: starts[0] };
}
export function verifyFrames(capture, capturePath) {
  const verified = new Set();
  const directory = dirname(resolve(capturePath));
  const frames = capture.filter((row) => row.note === "stream-frame");
  if (frames.length > 24) throw new Error("native frame count bound exceeded");
  for (const frame of frames) {
    if (typeof frame.blob !== "string" || isAbsolute(frame.blob)) continue;
    const path = resolve(directory, frame.blob),
      rel = relative(directory, path);
    if (rel.startsWith("..") || isAbsolute(rel)) continue;
    try {
      const bytes = pinnedBytes(path, frame.sha256, 16 * 1024);
      if (bytes.length !== frame.bodyBytes) continue;
      const Type =
        frame.direction === "in"
          ? protos.google.pubsub.v1.StreamingPullResponse
          : frame.direction === "out"
            ? protos.google.pubsub.v1.StreamingPullRequest
            : null;
      if (!Type) continue;
      const body = Type.toObject(Type.decode(bytes), {
        longs: String,
        enums: String,
        bytes: String,
      });
      if (!isDeepStrictEqual(body, frame.body)) continue;
      verified.add(frame);
    } catch {
      /* Missing or altered bytes remain comparison debt. */
    }
  }
  return verified;
}
// The monotonic observation starts at the second outbound write, independently of reply status.
export function createNativeSilenceObserver(
  rpc,
  { now = () => performance.now(), schedule = setTimeout, clear = clearTimeout } = {},
) {
  let started = null,
    timer = null,
    completedWindow = false,
    cancelledByObserver = false;
  let inboundMessages = 0,
    outboundWrites = 0,
    terminalBeforeWindow = false,
    durationMs = 0;
  const stopTimer = () => {
    if (timer !== null) {
      clear(timer);
      timer = null;
    }
  };
  const elapsed = () => (started === null ? 0 : Math.max(0, now() - started));
  const finish = () => {
    timer = null;
    const left = 30000 - elapsed();
    if (left > 0) {
      timer = schedule(finish, Math.ceil(left));
      return;
    }
    durationMs = elapsed();
    completedWindow = true;
    cancelledByObserver = true;
    rpc.cancel();
  };
  rpc.on("data", () => {
    if (!completedWindow) inboundMessages += 1;
  });
  for (const event of ["status", "error", "close"])
    rpc.on(event, () => {
      if (!completedWindow) {
        terminalBeforeWindow = true;
        durationMs = elapsed();
        stopTimer();
      }
    });
  const write = rpc.write.bind(rpc);
  rpc.write = (...args) => {
    const accepted = write(...args);
    outboundWrites += 1;
    if (outboundWrites === 2 && !terminalBeforeWindow) {
      started = now();
      timer = schedule(finish, 30000);
    }
    return accepted;
  };
  return {
    snapshot: () => ({
      durationMs: completedWindow || terminalBeforeWindow ? durationMs : elapsed(),
      inboundMessages,
      outboundWrites,
      terminalBeforeWindow,
      completedWindow,
      cancelledByObserver,
    }),
    close: stopTimer,
  };
}

export async function replayLocal(input, environment, pin) {
  validateRuntime(pin, environment);
  const captured = [],
    wireFrames = [];
  const capturedJournal = createCapture({ journal: { write: (row) => captured.push(row) } });
  // Parsed frames and independently measured protobuf lengths; never reconstruct production bytes.
  const capture = {
    ...capturedJournal,
    frame: (label, bytes) => wireFrames.push({ ...label, bodyBytes: bytes.length }),
  };
  const budget = createBudget(1026);
  const target = environment.PUBSUB_EMULATOR_HOST;
  const ownership = createOwnership({
    project: input.metadata.project,
    runId: input.metadata.runId,
  });
  const localCredential = null;
  const rest = createRest({ base: `http://${target}`, budget, capture, getToken: localCredential });
  const grpc = createGrpc({ target, secure: false, budget, capture, getToken: localCredential });
  let logicalTime = -Infinity;
  const clockRequests = [];
  async function advance(row) {
    const time = recordedRequestInstant(row);
    if (time < logicalTime) throw new Error("request logical time regressed");
    logicalTime = time;
    const response = await fetch(
      `${environment.FIREEMU_CONTROL_URL}sessions/default/clock:advanceTo`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${environment.FIREEMU_CONTROL_TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ instant: new Date(logicalTime).toISOString() }),
        redirect: "manual",
        signal: AbortSignal.timeout(30000),
      },
    );
    if (!response.ok) throw new Error("local clock advance refused");
    await response.arrayBuffer();
    clockRequests.push({ n: row.n ?? null, instant: new Date(time).toISOString() });
  }
  try {
    await advance({ at: input.metadata.at, ms: 0 });
    const report = await compareRecording(input, {
      fieldNormalization: input.fieldNormalization,
      frameVerified: (frame) => input.verifiedFrames.has(frame),
      async replay(original, request, { bindings, frames, dispatch }) {
        if (original.op === "streamingPull") validateStreamFrames(original, frames);
        const ownedFields = new Set([
          "name",
          "topic",
          "subscription",
          "snapshot",
          "deadLetterTopic",
        ]);
        const check = (body) => {
          if (!body || typeof body !== "object") return;
          for (const [key, value] of Object.entries(body)) {
            if (ownedFields.has(key) && typeof value === "string") ownership.assertOwned(value);
            else if (["deadLetterPolicy", "frames"].includes(key)) {
              if (Array.isArray(value)) value.forEach(check);
              else check(value);
            }
          }
        };
        check(request.body);
        check(request);
        if (!dispatch) throw new Error("recorded dispatch instant missing");
        await advance({ n: original.n, at: dispatch.at, ms: 0 });
        const label = { case: original.case, step: original.step };
        const prior = captured.length,
          frameStart = wireFrames.length;
        if (original.transport === "rest") {
          const path = request.path;
          if (
            !path?.startsWith(`/v1/projects/${input.metadata.project}/`) ||
            /(?:\.\.|\\|#)/.test(path)
          )
            throw new Error("local project path refused");
          await rest.request({ ...request, label, op: original.op });
        } else if (original.op !== "streamingPull") {
          const [service, method] = request.rpc?.split("/") ?? [];
          await grpc.call({ label, op: original.op, service, method, request: request.body });
        } else {
          let guardFailure, silenceObserver;
          const silenceProbe = recordedSilenceProbe(original, frames, (frame) =>
            input.verifiedFrames.has(frame),
          );
          const receiveGuard = createReceiveGuard(frames, bindings);
          class GuardedClient extends grpcLib.Client {
            makeBidiStreamRequest(...args) {
              if (silenceProbe) args[4] = { ...args[4], deadline: new Date(Date.now() + 31000) };
              const rpc = super.makeBidiStreamRequest(...args);
              if (silenceProbe) silenceObserver = createNativeSilenceObserver(rpc);
              const on = rpc.on.bind(rpc);
              rpc.on = (event, listener) =>
                on(
                  event,
                  event !== "data" || request.afterReceive === undefined
                    ? listener
                    : (bytes) => {
                        try {
                          const Type = protos.google.pubsub.v1.StreamingPullResponse;
                          receiveGuard(
                            Type.toObject(Type.decode(bytes), {
                              longs: String,
                              enums: String,
                              bytes: String,
                            }),
                            bindings,
                          );
                          listener(bytes);
                        } catch {
                          guardFailure = "native causal receive binding refused";
                          rpc.cancel();
                        }
                      },
                );
              return rpc;
            }
          }
          const stream = createStreamingPull({
            target,
            secure: false,
            budget,
            capture,
            getToken: localCredential,
            grpc: { ...grpcLib, Client: GuardedClient },
          });
          try {
            await stream.stream({
              label,
              frames: request.frames,
              ...(request.afterReceive === undefined ? {} : { afterReceive: request.afterReceive }),
            });
          } finally {
            if (silenceObserver) {
              silenceObserver.close();
            }
            stream.close();
          }
          if (silenceObserver)
            original = { ...original, localObservation: silenceObserver.snapshot() };
          if (guardFailure) return { notReplayed: true, reason: guardFailure };
        }
        const actual = captured.slice(prior).find((row) => row.response);
        if (!actual) return { notReplayed: true, reason: "local response missing" };
        return {
          ...actual,
          ...(original.localObservation ? { nativeObservation: original.localObservation } : {}),
          ...(original.op === "streamingPull" ? { frames: wireFrames.slice(frameStart) } : {}),
        };
      },
    });
    return { ...report, clock: { basis: "recorded request-dispatch at", requests: clockRequests } };
  } finally {
    grpc.close();
  }
}

function strictProcessIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("invalid strict process PID");
  const text = execFileSync(
    "ps",
    ["-ww", "-p", String(pid), "-o", "pid=,ppid=,lstart=,comm=,args="],
    { encoding: "utf8", timeout: 1000, maxBuffer: 65536 },
  ).trim();
  const match = text.match(/^(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d+\s+\S+\s+\d+)\s+(\S+)\s+(.+)$/);
  if (!match) throw new Error("strict process identity unavailable");
  return {
    pid: Number(match[1]),
    ppid: Number(match[2]),
    birth: match[3].replace(/\s+/g, " "),
    comm: match[4],
    args: match[5],
  };
}

function strictRuntimeConfig(project, clockStart, pubsubProjectNumbers) {
  const config = {
    schemaVersion: 1,
    profile: "strict",
    bind: "127.0.0.1",
    daemon: {
      pubsubPort: 0,
      httpPort: 0,
      hubPort: 0,
      loggingPort: 0,
      authProject: project,
      clockStart,
    },
  };
  if (pubsubProjectNumbers !== undefined) {
    if (
      !pubsubProjectNumbers ||
      Array.isArray(pubsubProjectNumbers) ||
      Object.keys(pubsubProjectNumbers).length !== 1 ||
      typeof pubsubProjectNumbers[project] !== "string" ||
      !/^[1-9]\d{0,19}$/.test(pubsubProjectNumbers[project])
    )
      throw new Error("explicit source-project PubSub identity mapping required");
    config.pubsub = { projectNumbers: { [project]: pubsubProjectNumbers[project] } };
  }
  return config;
}

function verifyStandaloneWorker({
  pin,
  project,
  launch,
  environment,
  worker,
  observe,
  pubsubProjectNumbers,
}) {
  const refuse = () => {
    throw new Error("standalone strict launch provenance refused");
  };
  const owner = observe(launch.parentPid);
  const server = observe(launch.serverPid);
  const supervisor = observe(launch.supervisorIdentity?.pid);
  if (
    worker.ppid !== launch.parentPid ||
    worker.pid === launch.serverPid ||
    !owner ||
    !server ||
    !supervisor ||
    !isDeepStrictEqual(owner, launch.ownerIdentity) ||
    !isDeepStrictEqual(server, launch.serverIdentity) ||
    !isDeepStrictEqual(supervisor, launch.supervisorIdentity) ||
    server.ppid !== owner.pid ||
    owner.ppid !== supervisor.pid ||
    owner.args !== `${launch.nodePath} ${launch.adapter.path}` ||
    supervisor.args !== `${launch.pythonPath} ${launch.supervisor.path}` ||
    server.args !==
      `${pin.path} up --config ${launch.config} --only pubsub --ready-file ${launch.ready} --owner-stdin`
  )
    refuse();
  pinnedBytes(pin.path, pin.sha256, 100_000_000);
  pinnedBytes(launch.adapter.path, launch.adapter.sha256);
  pinnedBytes(launch.supervisor.path, launch.supervisor.sha256);
  const config = JSON.parse(pinnedBytes(launch.config, launch.configSha256));
  if (
    !isDeepStrictEqual(
      config,
      strictRuntimeConfig(project, launch.clockStart, pubsubProjectNumbers),
    ) ||
    !Number.isFinite(Date.parse(launch.clockStart))
  )
    refuse();
  const stat = lstatSync(launch.ready);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid()) refuse();
  const ready = JSON.parse(pinnedBytes(launch.ready, launch.readySha256, 1_000_000));
  if (
    ready.schemaVersion !== 1 ||
    ready.pid !== server.pid ||
    ready.projectId !== project ||
    ready.controlUrl + "/v1/" !== environment.FIREEMU_CONTROL_URL ||
    ready.controlToken !== environment.FIREEMU_CONTROL_TOKEN ||
    ready.environment?.GOOGLE_CLOUD_PROJECT !== project ||
    ready.environment?.GCLOUD_PROJECT !== project ||
    Object.entries(ready.environment ?? {}).some(
      ([key, value]) => typeof value !== "string" || environment[key] !== value,
    ) ||
    Object.keys(environment).some(
      (key) =>
        /CREDENTIAL|TOKEN|NODE_OPTIONS|NODE_PATH/.test(key) && key !== "FIREEMU_CONTROL_TOKEN",
    ) ||
    !/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(environment.PUBSUB_EMULATOR_HOST ?? "") ||
    Number(environment.PUBSUB_EMULATOR_HOST.split(":")[1]) > 65535 ||
    !/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}\/v1\/$/.test(environment.FIREEMU_CONTROL_URL ?? "") ||
    !environment.FIREEMU_CONTROL_TOKEN
  )
    refuse();
}

export function verifyStrictWorker({
  pin,
  project,
  launch,
  environment = process.env,
  worker = process,
  observe = strictProcessIdentity,
  pubsubProjectNumbers,
}) {
  if (launch.mode === "standalone") {
    verifyStandaloneWorker({
      pin,
      project,
      launch,
      environment,
      worker,
      observe,
      pubsubProjectNumbers,
    });
    return;
  }

  if (process.ppid !== launch.serverPid)
    throw new Error("internal worker must be the pinned fireemu child");
  const ancestry = execFileSync(
    "ps",
    ["-ww", "-p", String(launch.serverPid), "-o", "ppid=,args="],
    { encoding: "utf8" },
  ).trim();
  if (
    !ancestry.startsWith(`${launch.parentPid} `) ||
    !ancestry.includes(`${pin.path} exec --config ${launch.config} --only pubsub --`)
  )
    throw new Error("internal strict launch provenance refused");
  const configBytes = pinnedBytes(launch.config, launch.configSha256);
  const config = JSON.parse(configBytes);
  if (
    !isDeepStrictEqual(
      config,
      strictRuntimeConfig(project, launch.clockStart, pubsubProjectNumbers),
    )
  )
    throw new Error("internal strict launch config refused");
}

export async function runStrictRuntime({
  pubsubProjectNumbers,
  pin,
  project,
  clockStart,
  argv,
  environment = process.env,
  workerModule,
}) {
  validateRuntime(pin, {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:2/v1/",
    FIREEMU_CONTROL_TOKEN: "admission-only",
  });
  pinnedBytes(pin.path, pin.sha256, 100_000_000);
  const temporary = mkdtempSync(join(tmpdir(), "fireemu-pubsub-compare-"));
  try {
    const config = join(temporary, "fireemu.json");
    writeFileSync(
      config,
      JSON.stringify(strictRuntimeConfig(project, clockStart, pubsubProjectNumbers)),
    );
    const bootstrap = `import {readFileSync} from 'node:fs'; import {main} from ${JSON.stringify(workerModule)}; const launch=JSON.parse(readFileSync(0,'utf8')); process.exitCode=await main(${JSON.stringify(argv)},process.env,launch);`;
    const child = spawn(
      pin.path,
      [
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
      ],
      {
        stdio: ["pipe", "inherit", "inherit"],
        env: {
          PATH: environment.PATH,
          TMPDIR: environment.TMPDIR,
          LANG: "C",
          LC_ALL: "C",
          TZ: "UTC",
        },
      },
    );
    child.stdin.on("error", () => {});
    child.stdin.end(
      JSON.stringify({
        serverPid: child.pid,
        parentPid: process.pid,
        config,
        configSha256: digest(readFileSync(config)),
        clockStart,
      }),
    );
    const stop = () => child.kill("SIGTERM");
    const interrupt = () => child.kill("SIGINT");
    process.on("SIGTERM", stop);
    process.on("SIGINT", interrupt);
    try {
      return await new Promise((resolveResult, reject) => {
        child.once("error", reject);
        child.once("exit", (code) => resolveResult(code ?? 2));
      });
    } finally {
      process.off("SIGTERM", stop);
      process.off("SIGINT", interrupt);
    }
  } finally {
    removeTree(temporary);
  }
}

export async function main(argv = process.argv.slice(2), environment = process.env, launch = null) {
  const worker = launch !== null;
  const opts = options(argv);
  const input = inputs(opts);
  if (opts["peer-capture"]) {
    const peer = readPinnedJsonl(opts["peer-capture"], opts["peer-capture-sha256"]);
    if (recordingTimingDebts(peer).length || peer.filter((r) => r.note === "run-end").length !== 1)
      throw new Error("closed peer recording required");
    const verified = verifyFrames(peer, opts["peer-capture"]);
    if (peer.some((r) => r.note === "stream-frame" && !verified.has(r)))
      throw new Error("peer native raw provenance missing");
    input.fieldNormalization = createFieldNormalization(input.capture, peer);
  }
  const pin = JSON.parse(readFileSync(opts["build-pin"], "utf8"));
  // Pin validation happens before starting a server as well as inside its child.
  validateRuntime(pin, {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:2/v1/",
    FIREEMU_CONTROL_TOKEN: "admission-only",
  });
  pinnedBytes(pin.path, pin.sha256, 100_000_000);
  if (worker) {
    verifyStrictWorker({ pin, project: input.metadata.project, launch });
    input.verifiedFrames = verifyFrames(input.capture, opts.capture);
    writeFileSync(
      join(opts.out, "runtime-start.json"),
      `${JSON.stringify({ serverPid: launch.serverPid, workerPid: process.pid, strictConfigSha256: launch.configSha256 })}\n`,
      { flag: "wx", mode: 0o600 },
    );
    const report = await replayLocal(input, environment, pin);
    report.inputPins = {
      capture: opts["capture-sha256"],
      issued: opts["issued-sha256"],
      iam: opts["iam-sha256"],
      ...(opts["peer-capture"] ? { peerCapture: opts["peer-capture-sha256"] } : {}),
    };
    report.fieldNormalization = input.fieldNormalization?.evidence ?? [];
    report.build = {
      head: pin.head,
      sha256: pin.sha256,
      profile: pin.profile,
      rustcWrapper: pin.rustcWrapper,
      command: pin.command,
    };
    report.runtime = { pinnedExecParent: true, strictConfigSha256: launch.configSha256 };
    writeFileSync(join(opts.out, "comparison.json"), `${JSON.stringify(report, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    return 0;
  }
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

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`stream-dlq comparison: ${error.message}\n`);
      process.exitCode = 2;
    });
