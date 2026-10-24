// Executes FS-QUERY-INDEX and FS-DATA-WRITE-LIST programs against one target and returns what it answered.
//
// Every program starts and ends with a wipe of the whole `(default)` database, which the lane
// owns in the sandbox project and fireemu owns locally. Seeds are written with :commit batches.
// Harness calls (wipe, seed) are not recorded as rows but are counted.

import { createRequire } from "node:module";

import {
  buildGrpcRequest,
  buildRestRequest,
  databaseName,
  documentsName,
  guardGrpcRequest,
  guardRestRequest,
  isTransient,
  normalizeStep,
  PRODUCTION_GRPC,
  resolveQuery,
  resolveValue,
} from "./harness.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");
const { v1 } = require("@google-cloud/firestore");

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const COMMIT_BATCH = 500;
const WIPE_ROUNDS = 40;

function grpcChannel(ctx) {
  if (ctx.target.kind === "production") {
    return {
      address: `${PRODUCTION_GRPC.host}:${PRODUCTION_GRPC.port}`,
      credentials: grpc.credentials.createSsl(),
    };
  }
  return {
    address: `${ctx.target.grpcHost}:${ctx.target.grpcPort}`,
    credentials: grpc.credentials.createInsecure(),
  };
}

/** Decodes google.rpc.Status details from the trailer production and fireemu send. */
function statusDetails(protos, metadata) {
  const bin = metadata?.get?.("grpc-status-details-bin")?.[0];
  if (!bin) return [];
  try {
    const status = protos.google.rpc.Status.deserialize(bin);
    return (status.details ?? []).map((any) => ({
      typeUrl: any.type_url ?? any.typeUrl,
      bytes: Buffer.from(any.value ?? []).toString("base64"),
    }));
  } catch {
    return [{ undecodable: true }];
  }
}

export function createSession(
  ctx,
  {
    timeoutMs = 120_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    log = () => {},
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;
  let unresolved = false;
  let lastHarnessRaw;
  const definiteHttp = (status) =>
    Number.isInteger(status) &&
    ((status >= 200 && status < 300) ||
      (status >= 400 && status < 500 && ![408, 429, 499].includes(status)));
  const definiteGrpc = (code) => [0, 3, 5, 6, 7, 9, 10, 11, 12, 16].includes(code);
  const gapic = new v1.FirestoreClient({ projectId: ctx.project });
  const protos = gapic._protos;
  const channel = grpcChannel(ctx);
  const grpcClient = new grpc.Client(channel.address, channel.credentials);

  function claim(harness) {
    // Recorded steps and the harness's own cleanup have separate ceilings, so a corpus that
    // runs away can never block the wipe that follows it.
    if (harness) {
      if (harnessRequests >= maxHarnessRequests)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  }

  async function sendRest(step, raw, { harness = false, anchors = new Map() } = {}) {
    const request = buildRestRequest(step, ctx, raw);
    guardRestRequest(request, ctx, { harness });
    claim(harness);
    unresolved = true;
    const sent = {
      transport: "rest",
      // Only parsed bodies and query parameters can carry chained instants; raw bodies are
      // fixed text.
      ...(step.rawBody === undefined && request.init.body !== undefined
        ? { request: JSON.parse(request.init.body) }
        : {}),
      ...(step.query !== undefined ? { request: resolveQuery(step, ctx, raw) } : {}),
    };
    let response;
    try {
      response = await fetch(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const failed = {
        ...sent,
        response: { transportError: error?.cause?.code ?? error?.name ?? "error" },
      };
      return { recorded: normalizeStep(failed, ctx, anchors), json: null, raw: failed };
    }
    let text;
    try {
      text = await response.text();
    } catch (error) {
      const failed = {
        ...sent,
        response: { status: response.status, bodyReadError: error?.name ?? "error" },
      };
      return { recorded: normalizeStep(failed, ctx, anchors), json: null, raw: failed };
    }
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded as non-JSON */
    }
    const received = { ...sent, response: { status: response.status, text } };
    try {
      const entries = Array.isArray(json) ? json : [json];
      const uncertainStatus =
        !definiteHttp(response.status) ||
        entries.some((entry) => entry?.error && !definiteHttp(entry.error.code));
      if (response.status >= 200 && response.status < 300) {
        if (json === null || typeof json !== "object")
          throw new Error("invalid successful JSON response");
        if (
          ["executePipeline", "runQuery", "runAggregationQuery"].includes(step.rpc) &&
          (!Array.isArray(json) ||
            json.some((entry) => !entry || typeof entry !== "object" || Array.isArray(entry)))
        )
          throw new Error("invalid streaming response shape");
        if (
          step.rpc === "commit" &&
          (!Array.isArray(json.writeResults) ||
            json.writeResults.length !== (sent.request?.writes?.length ?? 0) ||
            typeof json.commitTime !== "string")
        )
          throw new Error("invalid commit acknowledgment");
      }
      const recorded = normalizeStep(received, ctx, anchors);
      // Uncertainty clears only after shape validation and normalization have both completed.
      unresolved = uncertainStatus;
      return { recorded, json, raw: received };
    } catch (error) {
      return {
        recorded: {
          status: 0,
          observedStatus: response.status,
          responseError: String(error.message ?? error),
        },
        json: null,
        raw: received,
      };
    }
  }

  function sendGrpc(step, raw, anchors) {
    const built = buildGrpcRequest(step, ctx, raw);
    guardGrpcRequest(built, ctx);
    const sent = { transport: "grpc", request: resolveValue(step.body ?? {}, ctx, raw) };
    claim(false);
    unresolved = true;
    const requestType = protos.google.firestore.v1[`${built.method}Request`];
    const responseType = protos.google.firestore.v1[`${built.method}Response`];
    const path = `/google.firestore.v1.Firestore/${built.method}`;
    const metadata = new grpc.Metadata();
    metadata.set(
      "authorization",
      `Bearer ${ctx.target.kind === "production" ? ctx.target.token : "owner"}`,
    );
    if (ctx.target.kind === "production")
      metadata.set("x-goog-user-project", ctx.target.quotaProject);
    metadata.set(
      "x-goog-request-params",
      `${built.request.parent ? "parent" : "database"}=${encodeURIComponent(built.request.parent ?? built.request.database)}`,
    );
    const options = { deadline: new Date(Date.now() + timeoutMs) };
    const serialize = (message) => requestType.serialize(message);
    const deserialize = (bytes) => responseType.deserialize(bytes);
    return new Promise((resolve) => {
      const messages = [];
      const finish = (error, trailers) => {
        const received = {
          ...sent,
          response: {
            // Through JSON, as saved: Buffers become {type, data} and Longs are strings.
            messages: JSON.parse(JSON.stringify(messages)),
            code: error ? error.code : 0,
            details: error ? error.details : "",
            errorDetails: error ? statusDetails(protos, error.metadata ?? trailers) : [],
          },
        };
        try {
          const recorded = normalizeStep(received, ctx, anchors);
          unresolved = !definiteGrpc(received.response.code);
          resolve({
            recorded,
            json: messages.length === 1 && !built.stream ? messages[0] : messages,
            raw: received,
          });
        } catch (error) {
          resolve({
            recorded: { status: 0, responseError: String(error.message ?? error) },
            json: null,
            raw: received,
          });
        }
      };
      if (built.stream) {
        const call = grpcClient.makeServerStreamRequest(
          path,
          serialize,
          deserialize,
          built.request,
          metadata,
          options,
        );
        let failed;
        call.on("data", (message) => messages.push(message));
        call.on("error", (error) => {
          failed = error;
        });
        call.on("status", (status) =>
          finish(failed ?? (status.code ? status : undefined), status.metadata),
        );
      } else {
        grpcClient.makeUnaryRequest(
          path,
          serialize,
          deserialize,
          built.request,
          metadata,
          options,
          (error, message) => {
            if (message) messages.push(message);
            finish(error ?? undefined);
          },
        );
      }
    });
  }

  async function harnessRest(step) {
    const outcome = await sendRest({ id: "harness", ...step }, new Map(), {
      harness: true,
    });
    lastHarnessRaw = outcome.raw;
    const { recorded, json } = outcome;
    if (unresolved) {
      throw Object.assign(fatal("unknown harness response; resource retained"), {
        harnessRaw: outcome.raw,
      });
    }
    if (recorded.status !== 200) {
      throw fatal(
        `harness ${step.rpc ?? step.path}: HTTP ${recorded.status} ${JSON.stringify(recorded.body ?? recorded).slice(0, 400)}`,
      );
    }
    return json;
  }

  async function commit(writes) {
    for (let i = 0; i < writes.length; i += COMMIT_BATCH) {
      await harnessRest({ rpc: "commit", body: { writes: writes.slice(i, i + COMMIT_BATCH) } });
    }
  }

  /**
   * Deletes every document in the database. Locally the emulator's reset endpoint; in
   * production a kindless all-descendants query for names, then deletes, until it is empty.
   */
  async function wipe() {
    if (ctx.target.kind === "local") {
      claim(true);
      const request = {
        url: `${ctx.target.origin}/emulator/v1/${databaseName(ctx)}/documents`,
        init: { method: "DELETE", headers: { authorization: "Bearer owner" } },
      };
      guardRestRequest(request, ctx, { harness: true });
      const response = await fetch(request.url, request.init);
      if (!response.ok) throw fatal(`local wipe: HTTP ${response.status}`);
      return;
    }
    for (let round = 0; round < WIPE_ROUNDS; round += 1) {
      const page = await harnessRest({
        rpc: "runQuery",
        body: {
          structuredQuery: {
            from: [{ allDescendants: true }],
            select: { fields: [{ fieldPath: "__name__" }] },
            orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
            limit: COMMIT_BATCH,
          },
        },
      });
      if (
        !Array.isArray(page) ||
        page.length === 0 ||
        page.some(
          (entry) =>
            !entry ||
            typeof entry !== "object" ||
            entry.error ||
            (!entry.document && typeof entry.readTime !== "string") ||
            (entry.document &&
              (typeof entry.document.name !== "string" ||
                !entry.document.name.startsWith(documentsName(ctx) + "/"))),
        )
      ) {
        unresolved = true;
        throw Object.assign(fatal("unknown wipe inventory; resource retained"), {
          harnessRaw: lastHarnessRaw,
        });
      }
      const names = page.filter((e) => e.document).map((e) => e.document.name);
      if (names.length === 0) return;
      await commit(names.map((name) => ({ delete: name })));
    }
    throw fatal(`wipe: documents remain after ${WIPE_ROUNDS} rounds`);
  }

  async function seed(documents) {
    if (!documents?.length) return;
    await commit(
      documents.map(([name, fields]) => ({
        update: { name: `${documentsName(ctx)}/${name}`, fields },
      })),
    );
  }

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
    const sent = {};
    // Instants a request carried keep one symbol across the program (see stepSymbols).
    const anchors = new Map();
    await wipe();
    let failure;
    try {
      await seed(program.seed);
      for (const step of program.steps) {
        let outcome;
        try {
          outcome =
            (step.transport ?? "rest") === "grpc"
              ? await sendGrpc(step, raw, anchors)
              : await sendRest(step, raw, { anchors });
        } catch (error) {
          if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
          // An earlier step did not return what this one needs: record that, keep going.
          const dependency = /^step (\S+) recorded nothing/.exec(String(error.message))?.[1];
          outcome = {
            recorded: {
              status: -1,
              unresolved: String(error.message),
              dependencyTransient: isTransient(steps[dependency]),
            },
            json: null,
          };
        }
        raw.set(step.id, outcome.json);
        steps[step.id] = outcome.recorded;
        if (outcome.raw) sent[step.id] = outcome.raw;
        log(
          `${program.id}#${step.id} ${outcome.recorded.status ?? `grpc ${outcome.recorded.code}`}`,
        );
        if (unresolved) throw fatal("unknown recorded response; resource retained");
      }
    } catch (error) {
      failure = error;
    }
    if (unresolved) {
      throw Object.assign(fatal("unknown program response; resource retained"), {
        programPartial: { steps, raw: sent },
        ...(failure?.harnessRaw ? { harnessRaw: failure.harnessRaw } : {}),
      });
    }
    try {
      await wipe();
    } catch (error) {
      if (unresolved) error.programPartial = { steps, raw: sent };
      throw error;
    }
    if (failure) throw failure;
    return { steps, raw: sent };
  }

  return {
    runProgram,
    wipe,
    close: async () => {
      grpcClient.close();
      await gapic.close();
    },
    counts: () => ({ requests, harnessRequests }),
  };
}

/** Runs every program; a program that throws is recorded as a harness failure, not a row. */
export async function runCorpus(programs, ctx, options = {}) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  let failure;
  try {
    for (const program of programs) {
      try {
        results[program.id] = await session.runProgram(program);
      } catch (error) {
        if (error.fatal) {
          if (error.programPartial) results[program.id] = error.programPartial;
          throw error;
        }
        failures.push({ program: program.id, error: String(error.message ?? error) });
      }
    }
    await session.wipe();
  } catch (error) {
    failure = error;
  } finally {
    try {
      await session.close();
    } catch (error) {
      failure ??= Object.assign(fatal("session close failed"), {
        closeError: String(error.message ?? error),
      });
    }
  }
  if (failure) {
    if (failure.fatal) {
      failure.partial = {
        ...failure.partial,
        results: { ...results, ...failure.partial?.results },
        failures,
        ...session.counts(),
        ...(failure.harnessRaw ? { harnessRaw: failure.harnessRaw } : {}),
      };
    }
    throw failure;
  }
  return {
    context: { run: ctx.run, startedMs: ctx.startedMs },
    results,
    failures,
    ...session.counts(),
  };
}
