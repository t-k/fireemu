import { prepareObservation, observationOutcome } from "./compare-core.mjs";

export function validateReplaySource(input) {
  const source = prepareObservation(input);
  if (input.rows.some((row) => row.event === "stream-frame" && !input.verifiedFrames.has(row.n)))
    throw new Error("source native raw frame proof required");
  return source;
}

import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { lstatSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { readPinnedBundle } from "./compare.mjs";
import { compareExecutedObservation } from "./compare-core.mjs";
import { createWire } from "./wire.mjs";
import { createMeter } from "./meter.mjs";
import { PROJECT } from "./plan.mjs";
import { boundaryPayload } from "./payload.mjs";
import { sanitize } from "../pubsub-production/capture.mjs";
import { createBindings } from "../pubsub-production/stream-dlq-compare-core.mjs";
import {
  validateRuntime,
  runStrictRuntime,
  verifyStrictWorker,
} from "../pubsub-production/stream-dlq-compare.mjs";
import {
  createActionClock,
  createNativeReplay,
  createReplayClient,
  publishTimeAuthorized,
} from "./replay-native.mjs";
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function pinned(path, digest, max = 1000000) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > max || !/^[a-f0-9]{64}$/.test(digest))
    throw new Error("replay file pin required");
  const bytes = readFileSync(path);
  if (sha(bytes) !== digest) throw new Error("replay file digest mismatch");
  return bytes;
}
const owned = (value, runId) =>
  typeof value === "string" &&
  new RegExp(`^projects/${PROJECT}/(topics|subscriptions)/fe${runId}-[a-z0-9-]+$`).test(value);
export function restoreRequest(row, cell) {
  const body = structuredClone(row.request);
  if (!body.messages?.some((m) => m.data?.omitted)) return body;
  if (row.method !== "Publish" || !/^(request|message)-\d+$/.test(cell.variant))
    throw new Error("omitted payload reconstruction refused");
  const [kind, target] = cell.variant.split("-");
  const candidates = [-1, 0, 1].map(
    (delta) =>
      boundaryPayload({
        topic: body.topic,
        transport: row.transport,
        kind,
        target: Number(target) + delta,
      }).messages,
  );
  const matching = candidates.filter((messages) =>
    messages.every((m, i) => {
      const recorded = body.messages[i];
      return (
        recorded?.data?.omitted?.length === m.data.length &&
        recorded.data.omitted.sha256 === sha(m.data) &&
        JSON.stringify(recorded.attributes) === JSON.stringify(m.attributes)
      );
    }),
  );
  if (matching.length !== 1) throw new Error("omitted payload exact hash proof missing");
  body.messages = matching[0];
  return body;
}
export async function replayA(
  input,
  environment,
  pin,
  {
    wireFactory = createWire,
    advance = null,
    now,
    wait,
    persist = () => {},
    publishTimeDisposition = null,
  } = {},
) {
  validateRuntime(pin, environment);
  const source = validateReplaySource(input),
    cells = input.packet.plan.cells;
  const bindings = createBindings(),
    meter = createMeter(),
    raw = [],
    localFrameBytes = new Map(),
    publications = [],
    deliveries = [],
    localCells = source.cells.map((c) => ({
      ...c,
      exchanges: [],
      frames: [],
      events: [],
      result: structuredClone(c.result),
      debts: [...c.debts],
    }));
  let currentCell,
    dispatchN = null,
    wire,
    native;
  const clock = createActionClock({
    now,
    wait,
    advance: async (receipt) => {
      const result = await (
        advance ??
        (async (requested) => {
          const response = await fetch(
            `${environment.FIREEMU_CONTROL_URL}sessions/default/clock:advanceTo`,
            {
              method: "POST",
              headers: {
                authorization: `Bearer ${environment.FIREEMU_CONTROL_TOKEN}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ instant: requested.instant }),
              redirect: "manual",
              signal: AbortSignal.timeout(30000),
            },
          );
          if (!response.ok) throw new Error("local clock advance refused");
          const bytes = Buffer.from(await response.arrayBuffer());
          if (!publishTimeDisposition) return undefined;
          return { status: response.status, bytes, body: JSON.parse(bytes.toString("utf8")) };
        })
      )(receipt);
      if (publishTimeDisposition) {
        const bytes = result?.bytes;
        const record = {
          sourceDispatchN: receipt.n,
          session: "default",
          instant: receipt.instant,
          status: result?.status,
          body: result?.body,
          ...(Buffer.isBuffer(bytes)
            ? { responseBytes: bytes.toString("base64"), responseSha256: sha(bytes) }
            : {}),
        };
        journal.write({ event: "clock-control", ...record });
        return record;
      }
      return result;
    },
  });
  const terminalDetails = new Map();
  let sequence = 0,
    frame = 0;
  const journal = {
    write(value) {
      const entry = {
        n: ++sequence,
        at: new Date().toISOString(),
        sourceDispatchN: dispatchN,
        ...sanitize({
          ...value,
          ...(["stream-error", "stream-status"].includes(value.event) &&
          terminalDetails.has(value.event)
            ? { details: terminalDetails.get(value.event) }
            : {}),
        }),
      };
      raw.push(entry);
      if (entry.event?.startsWith("stream-"))
        localCells.find((c) => c.id === entry.cellId)?.events.push(entry);
      persist(entry);
      return entry;
    },
    frame(bytes, value) {
      native?.recordFrame(value);
      const identity = {
        path: `local-frame-${String(++frame).padStart(4, "0")}.pb`,
        bytes: bytes.length,
        sha256: sha(bytes),
      };
      persist({ blob: identity }, bytes);
      const entry = journal.write({ ...value, blob: identity });
      localFrameBytes.set(entry.n, Buffer.from(bytes));
      localCells.find((c) => c.id === value.cellId)?.frames.push({ ...entry, verified: true });
    },
  };
  const client = createReplayClient(environment.PUBSUB_EMULATOR_HOST, {
    onTerminalDetails: (event, details) => {
      if (typeof details === "string" && Buffer.byteLength(details) <= 20480)
        terminalDetails.set(event, details);
      else terminalDetails.delete(event);
    },
  });
  try {
    wire = wireFactory({
      meter,
      journal,
      client,
      getToken: async () => "synthetic-local-replay",
      fetch: (url, options) => {
        const destination = new URL(url);
        if (
          destination.origin !== "https://pubsub.googleapis.com" ||
          destination.search ||
          destination.hash ||
          !destination.pathname.startsWith(`/v1/projects/${PROJECT}/`)
        )
          throw new Error("replay REST route refused");
        const { authorization: _localSynthetic, ...headers } = options.headers;
        return fetch(`http://${environment.PUBSUB_EMULATOR_HOST}${destination.pathname}`, {
          ...options,
          headers,
        });
      },
    });
    native = createNativeReplay({
      wire,
      bindings,
      clock,
      cells,
      sourceCells: source.cells,
      journal,
      publishTime: publishTimeDisposition
        ? (cellId, opener) => {
            if (cellId !== "S03") return null;
            const sourceCell = source.cells.find((c) => c.id === cellId),
              localCell = localCells.find((c) => c.id === cellId);
            const sourceSetup = sourceCell.exchanges.find(
              (e) =>
                e.method === "CreateSubscription" &&
                e.request.body.name === opener &&
                e.response.ok &&
                !e.response.unknown,
            );
            const localSetup = localCell.exchanges.find(
              (e) =>
                e.method === "CreateSubscription" &&
                e.request.body.name === opener &&
                e.response.ok &&
                !e.response.unknown,
            );
            return {
              ...publishTimeDisposition.publishTime,
              publications,
              deliveries,
              subscription:
                sourceSetup && localSetup
                  ? {
                      opener,
                      sourceRequest: sourceSetup.request.body,
                      localRequest: localSetup.request.body,
                      sourceReply: sourceSetup.response,
                      localReply: localSetup.response,
                    }
                  : null,
            };
          }
        : null,
    });
    await clock.dispatch(input.rows[0]);
    for (const row of input.rows) {
      if (row.event === "request-dispatch" || row.event === "stream-frame") {
        if (currentCell !== row.cellId) {
          native.closeCell(currentCell);
          currentCell = row.cellId;
          meter.enter(cells.find((c) => c.id === currentCell));
        }
      }
      if (row.event === "request-dispatch") {
        const cell = cells.find((c) => c.id === row.cellId),
          local = localCells.find((c) => c.id === row.cellId);
        const expected = source.cells
          .find((c) => c.id === row.cellId)
          .exchanges.find((e) => e.dispatchN === row.n);
        if (!expected) throw new Error("source reply required for executable dispatch");
        const request = restoreRequest(row, cell);
        for (const value of [
          request.name,
          request.topic,
          typeof request.subscription === "string"
            ? request.subscription
            : request.subscription?.name,
          row.routeName,
        ])
          if (value !== undefined && !owned(value, source.runId))
            throw new Error("foreign replay resource refused");
        expected.request.body = request;
        const rewritten = bindings.request(expected);
        const clockReceipt = await clock.dispatch(row);
        dispatchN = row.n;
        const observed = await wire.call({
          category: row.category,
          transport: row.transport,
          service: /Topic|Publish/.test(row.method) ? "Publisher" : "Subscriber",
          method: row.method,
          request: rewritten.body,
          ...(rewritten.routeName ? { routeName: rewritten.routeName } : {}),
          cellId: row.cellId,
        });
        const reply = observationOutcome(observed, row.method, rewritten.body);
        if (
          row.method === "Publish" &&
          expected.response.ok &&
          reply.ok &&
          !expected.response.unknown &&
          !reply.unknown
        ) {
          bindings.linkPublish(request, expected.response.body, reply.body);
          publications.push({
            sourceDispatchN: row.n,
            sourceRequest: structuredClone(request),
            localRequest: structuredClone(rewritten.body),
            sourceReply: structuredClone(expected.response),
            localReply: structuredClone(reply),
            clock: clockReceipt,
          });
        }
        if (
          row.method === "Pull" &&
          expected.response.body?.receivedMessages?.length &&
          reply.body?.receivedMessages?.length
        )
          bindings.linkReceive(expected.response.body, reply.body);
        local.exchanges.push({
          ...expected,
          request: rewritten,
          response: reply,
          n: raw.at(-1)?.n ?? 0,
          dispatchN:
            raw.findLast(
              (entry) => entry.event === "request-dispatch" && entry.sourceDispatchN === row.n,
            )?.n ?? null,
          durationMs: reply.durationMs,
        });
      } else if (row.event === "stream-frame") {
        if (row.direction === "out" && !native.witnesses.has(row.cellId)) terminalDetails.clear();
        await native.frame(row);
      } else if (
        ["stream-write-end", "stream-cancel", "stream-case-observation"].includes(row.event)
      )
        await native.action(row);
      else if (row.event === "case-result" || row.event === "case-budget-overrun")
        native.closeCell(row.cellId);
    }
    const local = {
      ...source,
      evidenceKind: input.evidenceKind === "fixture" ? "fixture" : "local",
      cells: localCells,
    };
    let disposition;
    if (publishTimeDisposition) {
      const evidence = native.witnesses.get("S03")?.publishTime;
      disposition = {
        ...publishTimeDisposition,
        publishTime: evidence ?? publishTimeDisposition.publishTime,
        rawFrames: source.cells.flatMap((cell) =>
          cell.frames.map((f, i) => ({
            sourceN: f.n,
            localN: local.cells.find((c) => c.id === cell.id)?.frames[i]?.n,
            sourceBytes: publishTimeDisposition.sourceFrameBytes.get(f.n),
            localBytes: localFrameBytes.get(
              local.cells.find((c) => c.id === cell.id)?.frames[i]?.n,
            ),
          })),
        ),
      };
    }
    const report = compareExecutedObservation(
      source,
      local,
      Object.fromEntries(native.witnesses),
      disposition,
    );
    return {
      ...report,
      kind: "pubsub-observation-a-executed-replay",
      evidenceKind: input.evidenceKind === "fixture" ? "fixture" : "production-vs-strict-local",
      replayExecuted: true,
      localRuntimeVerified: false,
      parentClosureReady: false,
      authentication: {
        localMode: "credential-free-loopback",
        productionComparable: false,
        debt: "production OAuth credential verification is unsupported locally",
      },
      clock: { basis: "explicit dispatch and native relative action", requests: clock.requests },
      nativeWitnesses: Object.fromEntries(native.witnesses),
      localRows: raw,
    };
  } finally {
    try {
      native?.close();
    } finally {
      try {
        wire?.close();
      } finally {
        client.close();
      }
    }
  }
}
function options(argv) {
  const result = {},
    allowed = ["input", "input-sha256", "build-pin", "build-pin-sha256", "out"];
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!argv[i]?.startsWith("--") || !allowed.includes(key) || result[key] || !argv[i + 1])
      throw new Error("replay unique input/build pins and out required");
    result[key] = argv[i + 1];
  }
  if (allowed.some((key) => !result[key]))
    throw new Error("replay input/build pins and out required");
  return result;
}
export async function main(argv = process.argv.slice(2), environment = process.env, launch = null) {
  const opts = options(argv),
    index = JSON.parse(pinned(opts.input, opts["input-sha256"]));
  if (
    !index.source ||
    Object.keys(index).some((k) => !["source", "publishTimeDisposition"].includes(k))
  )
    throw new Error("replay index requires pinned source and optional publishTime disposition");
  const input = readPinnedBundle(index.source),
    source = validateReplaySource(input);
  const pin = JSON.parse(pinned(opts["build-pin"], opts["build-pin-sha256"]));
  if (!launch) {
    mkdirSync(opts.out, { mode: 0o700 });
    return runStrictRuntime({
      pin,
      project: PROJECT,
      clockStart: input.rows[0].at,
      argv,
      environment,
      workerModule: import.meta.url,
    });
  }
  validateRuntime(pin, environment);
  verifyStrictWorker({ pin, project: PROJECT, launch });
  pinned(pin.path, pin.sha256, 100000000);
  writeFileSync(
    resolve(opts.out, "runtime-start.json"),
    `${JSON.stringify({ serverPid: launch.serverPid, workerPid: process.pid, strictConfigSha256: launch.configSha256, inputSha256: opts["input-sha256"], buildPinSha256: opts["build-pin-sha256"] })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  let publishTimeDisposition = null;
  if (index.publishTimeDisposition) {
    const config = JSON.parse(
      pinned(index.publishTimeDisposition.path, index.publishTimeDisposition.sha256),
    );
    if (Object.keys(config).some((key) => !["authority", "source", "runtime"].includes(key)))
      throw new Error("publishTime disposition fields refused");
    const authorityBytes = pinned(config.authority.path, config.authority.sha256, 65536);
    const inputs = JSON.parse(pinned(pin.binaryInputsPath, pin.binaryInputsSha256));
    const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
    const entries = Object.entries(inputs.files);
    if (
      entries.length < 8 ||
      entries.length > 4000 ||
      ![
        "crates/fireemu-core-session/src/clock.rs",
        "crates/fireemu-adapter-pubsub/src/publisher.rs",
        "crates/fireemu-adapter-pubsub/src/lib.rs",
        "crates/fireemu-core-pubsub/src/state.rs",
        "crates/fireemu-core-pubsub/src/message.rs",
        "crates/fireemu-core-pubsub/src/subscription.rs",
        "crates/fireemu-adapter-pubsub/src/convert.rs",
        "crates/fireemu-adapter-http/src/control.rs",
      ].every((path) => Object.hasOwn(inputs.files, path))
    )
      throw new Error("compiled clock/storage input coverage required");
    let inputBytes = 0;
    for (const [path, digest] of entries) {
      if (resolve(root, path).startsWith(`${root}/`) !== true)
        throw new Error("compiled input path refused");
      inputBytes += pinned(resolve(root, path), digest, 400000000).length;
      if (inputBytes > 400 * 1024 * 1024) throw new Error("compiled input byte bound");
    }
    const compiledInputs = { binarySha256: pin.sha256, inputsSha256: pin.binaryInputsSha256 };
    const proof = {
      authority: { bytes: authorityBytes, sha256: config.authority.sha256 },
      source: config.source,
      runtime: config.runtime,
      compiledInputs,
    };
    if (
      !publishTimeAuthorized(proof) ||
      !isDeepStrictEqual(config.source, {
        runId: source.runId,
        packetSha256: source.packetSha256,
        descriptorSha256: source.descriptorSha256,
      })
    )
      throw new Error("publishTime authority/source/runtime binding refused");
    const sourceFrameBytes = new Map(
      input.rows
        .filter((row) => row.event === "stream-frame")
        .map((row) => [
          row.n,
          pinned(
            resolve(dirname(index.source.capture.path), row.blob.path),
            row.blob.sha256,
            65536,
          ),
        ]),
    );
    publishTimeDisposition = {
      authority: proof.authority,
      source: config.source,
      publishTime: proof,
      sourceFrameBytes,
      remainingDebts: {},
    };
  }
  const journalPath = resolve(opts.out, "local.jsonl");
  writeFileSync(journalPath, "", { flag: "wx", mode: 0o600 });
  const { appendFileSync } = await import("node:fs");
  const report = await replayA(input, environment, pin, {
    publishTimeDisposition,
    persist: (row, bytes) => {
      if (bytes)
        writeFileSync(resolve(opts.out, row.blob.path), bytes, { flag: "wx", mode: 0o600 });
      else appendFileSync(journalPath, `${JSON.stringify(row)}\n`);
    },
  });
  report.localRuntimeVerified = true;
  report.runtime = {
    pinnedExecParent: true,
    strictConfigSha256: launch.configSha256,
    buildPinSha256: opts["build-pin-sha256"],
    head: pin.head,
    binarySha256: pin.sha256,
  };
  report.inputSha256 = opts["input-sha256"];
  report.sourceRunId = source.runId;
  writeFileSync(resolve(opts.out, "comparison.json"), `${JSON.stringify(report, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return 0;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`A local replay: ${error.message}\n`);
      process.exitCode = 2;
    });
