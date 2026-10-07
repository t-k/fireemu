// Offline H v5/H2 replay. The listener must be a local strict fireemu session with the frozen fixture.
// node h-compare.mjs --recording <closed run directory> --base http://127.0.0.1:<port> --local <local capture.json> --out target/codex-out/H2-A.json
// A local capture has {complete, finalRead, frames}; frames use the H journal's {frame} envelope.
import { createHash } from "node:crypto";
import {
  readFileSync,
  readdirSync,
  mkdirSync,
  writeFileSync,
  realpathSync,
  copyFileSync,
  symlinkSync,
  existsSync,
  lstatSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { basename, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compareAnswer,
  compareCloudEventKeys,
  maskRequestIds,
  sameJson,
  requestBody,
} from "./compare.mjs";

export const DECLARED_DIFFERENCES = Object.freeze([
  "channel-list-unrecorded-order",
  "numeric-project-alias",
  "remote-credential-validity-scope",
  "channel-publication-propagation",
  "generated-traceparent",
  "cloudevent-member-order",
  "delivery-latency-arrival-order",
]);
const root = fileURLToPath(new URL("../../../", import.meta.url));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const result = (verdict, reason, declaredDifferences = []) => ({
  verdict,
  reason,
  declaredDifferences,
});

/** Only named recording artifacts are read; launch inputs, dotenv and credentials are never opened. */
export function loadHRecording(directory) {
  const names = readdirSync(directory).toSorted();
  const original = names.filter((n) => /^issued-[a-f0-9]{12}\.jsonl$/.test(n));
  if (original.length !== 1) throw new Error("one original H issued journal is required");
  const runId = original[0].slice(7, -6);
  const files = names.filter((n) =>
    new RegExp(`^(issued|capture)-${runId}(-a2-\\d{8}T\\d{6}Z)?\\.jsonl$`).test(n),
  );
  const issued = [],
    rows = [],
    digests = [];
  for (const name of files) {
    const bytes = readFileSync(join(directory, name));
    if (!bytes.toString().endsWith("\n")) throw new Error("unfinished H journal");
    const entries = bytes
      .toString()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    (name.startsWith("issued-") ? issued : rows).push(...entries);
    digests.push({ file: name, sha256: hash(bytes) });
  }
  const state = issued.filter((r) => ["h-state", "h-run-end"].includes(r.kind)).at(-1)?.value;
  const observed = issued.filter((r) => r.kind === "h-run-end").at(-1)?.value;
  if (!state || !observed || observed.manifest?.runId !== runId)
    throw new Error("H recording has no completed execution");
  // A2 may complete cleanup after the original execution; its state does not replace the observations.
  const summaries = names.filter((n) => /^summary(?:-a2-\d{8}T\d{6}Z)?\.json$/.test(n));
  const latest = summaries.length
    ? JSON.parse(
        readFileSync(
          join(directory, summaries.filter((n) => n !== "summary.json").at(-1) ?? "summary.json"),
        ),
      )
    : state;
  const closed = latest.cleanupReady === true || latest.closureReady === true;
  const publications = rows.filter((r) => ["publishEvents", "sdk.publishEvents"].includes(r.op));
  const observations = observed.publishes;
  if (
    !Array.isArray(observations) ||
    observations.length !== publications.length ||
    !observed.capture
  )
    throw new Error("H publication journal is incomplete");
  for (const [i, o] of observations.entries()) {
    if (
      !sameJson(o.body, publications[i].request.body) ||
      o.status !== publications[i].response.status
    )
      throw new Error("H capture and issued publication disagree");
  }
  return {
    manifest: observed.manifest,
    observations,
    capture: observed.capture,
    segments: observed.segments ?? [],
    publications,
    production: { runId, closed, sha256: hash(JSON.stringify(digests)), journals: digests },
  };
}

/** Judge declarations only at their recorded boundary; arbitrary differences never become passes. */
export function compareDeclaredAnswer(row, actual) {
  const compared = compareAnswer(row.response, actual);
  if (compared.verdict === "match") return result("MATCH", "wire-answer");
  if (/\/projects\/\d+\//.test(row.request.path))
    return result("NOT_COMPARABLE", "project-number-not-configured", ["numeric-project-alias"]);
  if (
    ["expired", "wrong-scope", "no-scope", "invalid"].includes(row.tokenMode) &&
    [401, 403].includes(row.response.status)
  )
    return result("NOT_COMPARABLE", "remote-credential-state", [
      "remote-credential-validity-scope",
    ]);
  if (row.op === "listChannels" && row.response.status === 200 && actual.status === 200) {
    const wanted = maskRequestIds(row.response.body),
      got = maskRequestIds(actual.body);
    if (Array.isArray(wanted?.channels) && Array.isArray(got?.channels)) {
      const order = (v) => ({
        ...v,
        channels: [...v.channels].sort((a, b) => String(a.name).localeCompare(String(b.name))),
      });
      if (sameJson(order(wanted), order(got)))
        return result("MATCH", "list-membership-count-envelope", ["channel-list-unrecorded-order"]);
    }
  }
  return { ...result("DIVERGES", compared.reason), paths: compared.paths };
}

const eventValue = (e) =>
  Object.fromEntries(
    Object.entries(e)
      .filter(([k]) => k !== "traceparent")
      .sort(([a], [b]) => a.localeCompare(b)),
  );
const validFrame = (f) =>
  f?.event &&
  f.generation === 2 &&
  ["failed", "succeeded"].includes(f.attempt) &&
  typeof f.invocationId === "string" &&
  f.invocationId.length > 0 &&
  f.correlation?.id === f.event.id &&
  f.correlation?.source === f.event.source &&
  sameJson(f.eventKeys, Object.keys(f.event)) &&
  /^00-(?!0{32}-)[a-f0-9]{32}-(?!0{16}-)[a-f0-9]{16}-[a-f0-9]{2}$/.test(f.event.traceparent ?? "");

/** Pair by event identity, handler and attempt, retaining nested data order and every event member. */
export function compareDelivery(o, recorded, local, observations = []) {
  if (!o.known || !recorded.complete || !recorded.finalRead || !local.complete || !local.finalRead)
    return result("NOT_COMPARABLE", "incomplete-observation");
  const events = o.body?.events ?? [];
  const select = (capture) =>
    capture.frames.filter(({ frame }) =>
      events.some((e) => e.id === frame?.event?.id && e.source === frame?.event?.source),
    );
  const wanted = select(recorded),
    got = select(local);
  const controls = (position) =>
    observations.filter(
      (p) =>
        p.control &&
        (o.bracket
          ? p.bracket === o.bracket && p.position === position
          : p.case === `${o.case}-${position}`),
    );
  const bracketed =
    o.before &&
    o.after &&
    o.windowMs > 0 &&
    o.endedAt - o.sentAt >= o.windowMs &&
    ["before", "after"].every((position) => {
      const list = controls(position);
      return (
        list.length === (o.case.startsWith("isolation-") ? 2 : 1) &&
        list.every(
          (p) =>
            p.known &&
            p.status >= 200 &&
            p.status < 300 &&
            (position === "before" ? p.sentAt <= o.sentAt : p.sentAt >= o.endedAt) &&
            p.expectedRecipients?.length &&
            p.expectedRecipients.every((r) =>
              [recorded, local].every((c) =>
                c.frames.some(
                  ({ frame }) =>
                    validFrame(frame) &&
                    frame.handler === r.handler &&
                    frame.event.id === r.id &&
                    frame.event.source === r.source,
                ),
              ),
            ),
        )
      );
    });
  if (!wanted.length && !bracketed)
    return result("NOT_COMPARABLE", "unbracketed-production-absence");
  if (wanted.length !== got.length) return result("DIVERGES", "delivery-cardinality");
  const remaining = [...got];
  const declarations = new Set(["delivery-latency-arrival-order"]);
  for (const { frame: a } of wanted) {
    const i = remaining.findIndex(
      ({ frame: b }) =>
        a.handler === b.handler &&
        a.attempt === b.attempt &&
        a.event.id === b.event.id &&
        a.event.source === b.event.source,
    );
    if (i < 0) return result("DIVERGES", "recipient-or-attempt");
    const b = remaining.splice(i, 1)[0].frame;
    if (
      !validFrame(a) ||
      !validFrame(b) ||
      a.run !== b.run ||
      a.recording !== b.recording ||
      a.case !== b.case
    )
      return result("DIVERGES", "frame-shape-or-correlation");
    const keys = compareCloudEventKeys(a.eventKeys, b.eventKeys);
    if (keys.verdict !== "MATCH" || !sameJson(eventValue(a.event), eventValue(b.event)))
      return result("DIVERGES", "handler-event");
    if (keys.order !== "MATCH") declarations.add("cloudevent-member-order");
    if (a.event.traceparent !== b.event.traceparent) declarations.add("generated-traceparent");
  }
  if (o.retry) {
    for (const list of [wanted, got]) {
      const attempts = list.filter(
        ({ frame }) => frame.handler === (o.retryHandler ?? list[0]?.frame.handler),
      );
      const failed = attempts.find(({ frame }) => frame.attempt === "failed"),
        success = attempts.find(({ frame }) => frame.attempt === "succeeded");
      if (
        !failed ||
        !success ||
        failed.frame.invocationId === success.frame.invocationId ||
        !sameJson(eventValue(failed.frame.event), eventValue(success.frame.event))
      )
        return result("DIVERGES", "retry-identity");
    }
  }
  return result("MATCH", wanted.length ? "handler-delivery" : "bounded-non-delivery", [
    ...declarations,
  ]);
}

/** Replay only the captured publications, including SDK-emitted bodies; never invoke a production SDK. */
export async function replayH(
  recording,
  { base, fetchImpl = fetch, localCapture, pause = async () => {}, afterPublish = async () => {} },
) {
  const url = new URL(base);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname) ||
    !url.port ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  )
    throw new Error("H replay requires a numeric loopback HTTP origin");
  const rows = [];
  for (const [i, row] of recording.publications.entries()) {
    const o = recording.observations[i];
    const body = requestBody(row);
    if (body === null) {
      rows.push({ case: o.case, ...result("NOT_COMPARABLE", "unreplayable-body") });
      continue;
    }
    if (
      !/^\/v1\/projects\/[^/]+\/locations\/[^/]+\/channels\/[^/:?]+:publishEvents$/.test(
        row.request.path,
      )
    )
      throw new Error("invalid H publish path");
    const reply = await fetchImpl(url.origin + row.request.path, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json", authorization: "Bearer ya29.offline-replay" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
    const text = await reply.text();
    let parsed;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
    rows.push({
      case: o.case,
      sequence: o.sequence,
      segment: o.segment ?? "core",
      recordedStatus: row.response.status,
      actualStatus: reply.status,
      wire: compareDeclaredAnswer(row, { status: reply.status, body: parsed }),
    });
    await afterPublish(o);
    await pause(500);
  }
  // Overlapping production windows are evaluated only after all local publications and retry draining.
  const capture = typeof localCapture === "function" ? await localCapture() : localCapture;
  for (const [i, row] of rows.entries()) {
    if (!row.wire) continue;
    const delivery = compareDelivery(
      recording.observations[i],
      recording.capture,
      capture ?? { complete: false },
      recording.observations,
    );
    const wireOnlyRefusal =
      recording.observations[i].status >= 400 &&
      recording.observations[i].status < 500 &&
      !recording.observations[i].shape &&
      !recording.observations[i].refused;
    Object.assign(row, row.wire.verdict === "DIVERGES" || wireOnlyRefusal ? row.wire : delivery, {
      delivery,
      coverage: wireOnlyRefusal ? "wire-only" : "wire-and-handler",
    });
    row.declaredDifferences = [
      ...new Set([...row.wire.declaredDifferences, ...row.declaredDifferences]),
    ];
  }
  for (const segment of recording.segments.filter((s) => s.status !== "observed"))
    rows.push({
      case: `${segment.segment}-capability`,
      segment: segment.segment,
      ...result("NOT_COMPARABLE", `native-${segment.status}-requires-control-plane-comparison`),
    });
  for (const row of rows) row.facets = hFacets(row);
  const counts = { MATCH: 0, DIVERGES: 0, NOT_COMPARABLE: 0 };
  for (const row of rows) counts[row.verdict]++;
  return {
    schemaVersion: 1,
    parent: "EVENTARC",
    packet: recording.manifest.recording.toUpperCase(),
    production: recording.production,
    rows,
    counts,
  };
}

/** Only actual H measurements are mapped; the unchanged inventory also contains cases H never asks. */
export function hFacets(row) {
  const facets = [],
    add = (condition, ...cases) => facets.push(...cases.map((c) => `EVENTARC/${condition}/${c}`));
  const content = {
    object: "json-object",
    scalar: "json-scalar",
    null: "json-null",
    array: "json-array",
    text: "text",
    binary: "binary-data",
  }[row.case];
  if (content) add("publish-content", content);
  if (row.wire) add("publish-envelope", "response-shape");
  if (row.case.startsWith("sdk-")) {
    const sdk = {
      "sdk-default": "default-channel",
      "sdk-full": "full-channel",
      "sdk-relative": "relative-channel",
      "sdk-generated": "generated-metadata",
      "sdk-metadata": "caller-metadata",
    }[row.case];
    if (sdk) add("admin-sdk-publish", sdk);
  }
  if (row.coverage === "wire-only") return facets;
  if (row.case === "retry")
    add("delivery-retry-identity", "fail-then-succeed", "stable-id-and-data");
  if (["object", "scalar", "null", "array"].includes(row.case))
    add("custom-handler-envelope", "json-data");
  if (row.case === "text") add("custom-handler-envelope", "text-data");
  if (row.case === "binary") add("custom-handler-envelope", "binary-data");
  if (row.case === "object") {
    add(
      "custom-handler-envelope",
      "required-attributes",
      "extension-attributes",
      "stable-id-correlation",
    );
    add("publish-envelope", "single-event", "event-id-correlation");
  }
  if (row.case === "multi") add("publish-envelope", "multiple-events");
  if (row.case === "wrong-type") add("trigger-filters", "type", "nonmatch");
  if (row.segment === "extension" && !row.case.endsWith("-before") && !row.case.endsWith("-after"))
    add("trigger-filters", "extension-attribute");
  if (row.segment === "multi" && !row.case.endsWith("-before") && !row.case.endsWith("-after"))
    add("trigger-filters", "multiple-filters");
  if (/^(extension|multi)-missing-/.test(row.case)) add("trigger-filters", "missing-attribute");
  if (row.case === "isolation-default" || row.case === "isolation-named")
    add("trigger-filters", "channel-isolation", "multiple-handlers");
  if (["refused-middle", "refused-first", "refused-last", "refused-101"].includes(row.case))
    add("publish-limits", "batch-delivered-subset");
  return facets;
}

/** Private outputs stay inside this worktree, including when the caller supplies an output path. */
export function writeEvidence(path, value) {
  const out = resolve(path),
    allowed = resolve(root, "target/codex-out");
  if (!out.startsWith(allowed + "/")) throw new Error("output must be under target/codex-out");
  if (existsSync(out) && lstatSync(out).isSymbolicLink())
    throw new Error("output must not be a symlink");
  mkdirSync(dirname(out), { recursive: true });
  if (
    !realpathSync(dirname(out)).startsWith(realpathSync(allowed) + "/") &&
    realpathSync(dirname(out)) !== realpathSync(allowed)
  )
    throw new Error("output escapes target/codex-out");
  writeFileSync(out, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}

/** The owned fireemu exec session supplies all endpoints and shuts down its runners on exit. */
async function localSession(path) {
  const session = JSON.parse(readFileSync(path)),
    h = loadHRecording(session.recording);
  const control = process.env.FIREEMU_CONTROL_URL;
  const eventarc = process.env.CLOUD_EVENTARC_EMULATOR_HOST;
  const logging = process.env.FIREBASE_LOGGING_EMULATOR_HOST;
  if (!control || !eventarc || !logging) throw new Error("missing owned session endpoints");
  const frames = [],
    observations = [];
  const socket = new WebSocket(`ws://${logging}`);
  await new Promise((done, reject) => {
    socket.addEventListener("open", done, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let incomplete = false;
  socket.addEventListener("message", ({ data }) => {
    try {
      const message = JSON.parse(data).message;
      const at = message?.indexOf("FE_EVENTS_FRAME ");
      if (!(at >= 0)) return;
      const frame = JSON.parse(message.slice(at + "FE_EVENTS_FRAME ".length));
      frames.push({ frame, logTimestamp: new Date().toISOString() });
    } catch {
      incomplete = true;
    }
  });
  const advance = async (millis) => {
    const reply = await fetch(`${control}sessions/default/clock:advance`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.FIREEMU_CONTROL_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ millis }),
      redirect: "error",
    });
    if (!reply.ok) throw new Error("local clock advance failed");
    await new Promise((done) => setTimeout(done, 500));
  };
  try {
    const report = await replayH(h, {
      base: eventarc,
      pause: (ms) => new Promise((done) => setTimeout(done, ms)),
      afterPublish: async (o) => {
        const windowMs = o.windowMs ?? 0;
        if (windowMs) await advance(windowMs);
        observations.push({ case: o.case, windowMs, clock: "virtual", complete: true });
      },
      localCapture: async () => {
        await advance(600000);
        // Retain every late frame; a later arrival still defeats a negative result.
        return { complete: !incomplete, finalRead: true, frames, observations };
      },
    });
    report.artifact = session.artifact;
    report.local = { profile: "strict", clock: "virtual", observations, frameCount: frames.length };
    writeEvidence(session.out, report);
    process.stdout.write(JSON.stringify(report.counts) + "\n");
    return report.counts.DIVERGES ? 1 : report.counts.NOT_COMPARABLE ? 2 : 0;
  } finally {
    await new Promise((done) => {
      socket.addEventListener("close", done, { once: true });
      socket.close();
    });
  }
}

/** Copy only frozen source files, reuse pinned installed dependencies and deny non-loopback Node I/O. */
export async function runLocal({ recording, binary, out }) {
  const h = loadHRecording(recording);
  if (!h.production.closed) throw new Error("recording cleanup is still open");
  const work = resolve(root, "target/codex-out", `h-replay-${h.manifest.runId}`);
  mkdirSync(work, { recursive: true });
  const guard = join(work, "offline.cjs");
  writeFileSync(
    guard,
    `const net=require('node:net'),dns=require('node:dns');
const allowed=h=>['127.0.0.1','::1','localhost',undefined].includes(h);
const connect=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...args){const o=net._normalizeArgs(args)[0];if(!o.path&&!allowed(o.host))throw Error('offline-network');return connect.apply(this,args)};
const lookup=dns.lookup;dns.lookup=function(host,...args){if(!allowed(host))throw Error('offline-dns');return lookup.call(this,host,...args)};
const send=globalThis.fetch;globalThis.fetch=(url,init={})=>{const u=new URL(url);if(!allowed(u.hostname)||u.protocol!=='http:')throw Error('offline-fetch');return send(url,{...init,redirect:'error'})};
`,
  );
  const sources = h.manifest.functions
    ? [
        "core",
        ...h.segments
          .filter((s) => s.status === "observed" && s.segment !== "core")
          .map((s) => s.segment),
      ]
    : ["core"];
  const codebases = [],
    fixtureDigests = [];
  for (const segment of sources) {
    const source = join(recording, h.manifest.functions ? `source-${segment}` : "source"),
      target = join(work, segment);
    mkdirSync(target, { recursive: true });
    for (const file of ["index.js", "package.json"]) {
      copyFileSync(join(source, file), join(target, file));
      fixtureDigests.push({ segment, file, sha256: hash(readFileSync(join(target, file))) });
    }
    const dependencies = realpathSync(join(source, "node_modules"));
    for (const [name, version] of [
      ["firebase-functions", "7.3.2"],
      ["firebase-admin", "14.3.0"],
      ["@google-cloud/functions-framework", "5.0.5"],
    ])
      if (JSON.parse(readFileSync(join(dependencies, name, "package.json"))).version !== version)
        throw new Error("frozen SDK dependency mismatch");
    if (!existsSync(join(target, "node_modules")))
      symlinkSync(dependencies, join(target, "node_modules"), "dir");
    writeFileSync(
      join(target, "entry.cjs"),
      `process.env.EVENTARC_H_RUN_ID=${JSON.stringify(h.manifest.runId)};process.env.EVENTARC_H_RECORDING=${JSON.stringify(h.manifest.recording)};process.env.EVENTARC_H_SEGMENT=${JSON.stringify(segment)};module.exports=require('./index.js');\n`,
    );
    const pkg = JSON.parse(readFileSync(join(target, "package.json")));
    pkg.main = "entry.cjs";
    writeFileSync(join(target, "package.json"), JSON.stringify(pkg));
    codebases.push({ source: target, codebase: `h-${segment}`, runtime: "nodejs22" });
  }
  const ports = [];
  for (let i = 0; i < 6; i++) {
    const server = createServer();
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    ports.push({ server, port: server.address().port });
  }
  const [httpPort, firestorePort, functionsPort, eventarcPort, loggingPort, hubPort] = ports.map(
    (p) => p.port,
  );
  for (const { server } of ports) await new Promise((done) => server.close(done));
  const runner = resolve(root, "tools/runner-node/index.mjs");
  const artifact = {
    profile: "strict",
    binarySha256: hash(readFileSync(binary)),
    runnerSha256: hash(readFileSync(runner)),
    fixtureDigests,
  };
  writeFileSync(
    join(work, "firebase.json"),
    JSON.stringify({
      functions: codebases,
      emulators: { eventarc: { host: "127.0.0.1", port: eventarcPort } },
    }),
  );
  writeFileSync(
    join(work, "fireemu.json"),
    JSON.stringify({
      schemaVersion: 1,
      profile: "strict",
      daemon: {
        authProject: h.manifest.project,
        httpPort,
        firestorePort,
        functionsPort,
        eventarcPort,
        loggingPort,
        hubPort,
        uiPort: 0,
      },
      functions: { runner: [process.execPath, "--require", guard, runner] },
    }),
  );
  const session = join(work, "session.json");
  writeFileSync(
    session,
    JSON.stringify({ recording: resolve(recording), out: resolve(out), artifact }),
  );
  const home = join(work, "home"),
    tmp = join(work, "tmp");
  mkdirSync(home, { recursive: true });
  mkdirSync(tmp, { recursive: true });
  const child = spawn(
    resolve(binary),
    [
      "exec",
      "--config",
      join(work, "fireemu.json"),
      "--firebase-json",
      join(work, "firebase.json"),
      "--project",
      h.manifest.project,
      "--only",
      "firestore,functions,eventarc",
      "--",
      process.execPath,
      "--require",
      guard,
      fileURLToPath(import.meta.url),
      "--session",
      session,
    ],
    {
      cwd: work,
      env: { PATH: process.env.PATH, HOME: home, TMPDIR: tmp },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  // Neither the control token nor runtime diagnostics are printed or retained.
  child.stdout.resume();
  child.stderr.resume();
  const forward = (signal) => child.kill(signal);
  const handlers = ["SIGINT", "SIGTERM"].map((s) => [s, () => forward(s)]);
  for (const [s, f] of handlers) process.on(s, f);
  try {
    const code = await new Promise((done, reject) => {
      child.once("error", reject);
      child.once("close", (code) => done(code));
    });
    if (![0, 1, 2].includes(code) || !existsSync(out)) throw new Error("owned local replay failed");
    const report = JSON.parse(readFileSync(out));
    process.stdout.write(JSON.stringify(report.counts) + "\n");
    return code;
  } finally {
    for (const [s, f] of handlers) process.off(s, f);
  }
}

export async function main(argv) {
  if (argv.length === 2 && argv[0] === "--session") return localSession(argv[1]);
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (
      !["--recording", "--binary", "--base", "--local", "--out"].includes(argv[i]) ||
      !argv[i + 1]
    )
      throw new Error("usage: --recording --binary --out (or --base --local)");
    options[argv[i].slice(2)] = argv[i + 1];
  }
  if (options.binary) return runLocal(options);
  if (!options.recording || !options.base || !options.local || !options.out)
    throw new Error("usage: --recording --base --local --out");
  if (/private-inputs|credential|secret|token|\.env/i.test(basename(options.local)))
    throw new Error("local capture must not be a credential or launch-input file");
  const recording = loadHRecording(options.recording);
  if (!recording.production.closed) throw new Error("recording cleanup is still open");
  const local = JSON.parse(readFileSync(options.local));
  if (
    local.provenance?.profile !== "strict" ||
    !local.provenance.binarySha256 ||
    !local.provenance.runnerSha256
  )
    throw new Error("local capture needs strict binary and runner provenance");
  const report = await replayH(recording, {
    base: options.base,
    localCapture: () => JSON.parse(readFileSync(options.local)).capture,
    pause: (ms) => new Promise((done) => setTimeout(done, ms)),
  });
  report.artifact = local.provenance;
  writeEvidence(options.out, report);
  process.stdout.write(JSON.stringify(report.counts) + "\n");
  return report.counts.DIVERGES ? 1 : report.counts.NOT_COMPARABLE ? 2 : 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write("H comparison failed; check local inputs and closed journals\n");
      process.exitCode = 1;
    });
