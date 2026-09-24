// Executes FS-CONFIG-LIFECYCLE programs against one target and returns what it answered.
//
// Each program owns the named databases it lists; the session deletes every one of them after
// the program, whatever happened (disabling delete protection first), and reads each back as
// absent. The run owns one Cloud Storage bucket, created before the first program and emptied
// and deleted after the last. Harness calls are counted but not recorded as rows.

import { createRequire } from "node:module";

import { buildGrpcRequest, guardGrpcRequest, projectMessage, statusDetails } from "./grpc.mjs";
import {
  buildRestRequest,
  filterDatabaseList,
  normalizeValue,
  PRODUCTION_GRPC,
  databaseId,
  guardRestRequest,
  isTransient,
  normalizeRestResponse,
  programSymbols,
  collapseTrace,
  UNCREATED_DATABASES,
  UNTIL,
} from "./harness.mjs";
import { capturePairs, normalizeCapture, restoreCapture } from "./exports.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function createSession(
  ctx,
  {
    timeoutMs = 120_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    pollScale = 1,
    captures = {},
    // Production only: returns a fresh access token. Called before a request once the current
    // token is older than `tokenMaxAgeMs`, and before every cleanup.
    refreshToken,
    tokenMaxAgeMs = 40 * 60_000,
    log = () => {},
  } = {},
) {
  let tokenAt = Date.now();
  async function ensureToken(force = false) {
    if (!refreshToken || ctx.target.kind !== "production") return;
    if (!force && Date.now() - tokenAt < tokenMaxAgeMs) return;
    ctx.target.token = await refreshToken();
    tokenAt = Date.now();
  }
  let requests = 0;
  let harnessRequests = 0;
  const grpcClient =
    ctx.target.kind === "production"
      ? new grpc.Client(
          `${PRODUCTION_GRPC.host}:${PRODUCTION_GRPC.port}`,
          grpc.credentials.createSsl(),
        )
      : new grpc.Client(
          `${ctx.target.grpcHost}:${ctx.target.grpcPort}`,
          grpc.credentials.createInsecure(),
        );

  function claim(harness) {
    if (harness) {
      if (harnessRequests >= maxHarnessRequests)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  }

  /** Sends one request; returns the parsed JSON (or null), the status and the raw text. */
  async function send(step, program, raw, { harness = false } = {}) {
    await ensureToken();
    const request = buildRestRequest(step, ctx, program, raw);
    guardRestRequest(request, ctx, program, { harness });
    claim(harness);
    try {
      const response = await fetch(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await response.text();
      let json = null;
      try {
        json = text === "" ? null : JSON.parse(text);
      } catch {
        /* recorded as non-JSON */
      }
      return { status: response.status, text, json };
    } catch (error) {
      return { status: 0, text: "", json: null, transportError: error?.cause?.code ?? error?.name };
    }
  }

  /** Sends one gRPC step; the answer is projected to proto3 JSON before it is recorded. */
  async function sendGrpc(step, program, raw) {
    await ensureToken();
    const built = buildGrpcRequest(step, ctx, program, raw);
    guardGrpcRequest(built, ctx, program, UNCREATED_DATABASES);
    claim(false);
    const metadata = new grpc.Metadata();
    metadata.set(
      "authorization",
      `Bearer ${ctx.target.kind === "production" ? ctx.target.token : "owner"}`,
    );
    if (ctx.target.kind === "production") metadata.set("x-goog-user-project", ctx.project);
    if (built.routingValue)
      metadata.set(
        "x-goog-request-params",
        `${built.routing}=${encodeURIComponent(built.routingValue)}`,
      );
    return new Promise((resolve) => {
      grpcClient.makeUnaryRequest(
        built.path,
        built.serialize,
        built.deserialize,
        built.request,
        metadata,
        { deadline: new Date(Date.now() + timeoutMs) },
        (error, message) => {
          const json = message ? projectMessage(message, built.responseType) : null;
          resolve({
            grpc: true,
            code: error ? error.code : 0,
            details: error ? error.details : "",
            errorDetails: error ? statusDetails(error.metadata) : [],
            json,
            status: error ? -2 : 200,
          });
        },
      );
    });
  }

  function record(program, step, symbols, answer) {
    if (answer.grpc) {
      const body = step.filterDatabases
        ? filterDatabaseList(answer.json, ctx, program)
        : answer.json;
      const local = new Map();
      return {
        transport: "grpc",
        code: answer.code,
        ...(answer.details
          ? { message: normalizeValue(answer.details, "", ctx, symbols, local) }
          : {}),
        ...(answer.errorDetails.length ? { errorDetails: answer.errorDetails } : {}),
        ...(body ? { body: normalizeValue(body, "", ctx, symbols, local) } : {}),
      };
    }
    if (answer.transportError) return { status: 0, transportError: answer.transportError };
    return normalizeRestResponse(answer.status, answer.text, ctx, program, symbols, step);
  }

  async function runStep(program, step, raw, symbols) {
    if (step.delayMs) await sleep(step.delayMs * pollScale);
    const exchange = () => (step.grpc ? sendGrpc(step, program, raw) : send(step, program, raw));
    if (!step.poll) {
      const answer = await exchange();
      return { recorded: record(program, step, symbols, answer), json: answer.json };
    }
    const until = UNTIL[step.poll.until];
    if (!until) throw new Error(`${program.id}#${step.id}: unknown poll predicate`);
    const states = [];
    let last;
    let settled = false;
    for (let i = 0; i < step.poll.max; i += 1) {
      if (i > 0) await sleep(step.poll.intervalMs * pollScale);
      last = await exchange();
      states.push(record(program, step, symbols, last));
      if (until(last.json, last.status)) {
        settled = true;
        break;
      }
      if (last.status === 0 || last.status === 429) break;
    }
    const trace = collapseTrace(states);
    return {
      recorded: { trace, settled: trace.at(-1), ...(settled ? {} : { unsettled: true }) },
      json: last?.json ?? null,
    };
  }

  /**
   * Deletes a database this program may have created: disables delete protection, deletes,
   * then reads it back until it is absent. Throws a fatal error if it cannot prove absence.
   */
  async function removeDatabase(program, id) {
    const step = (s) => ({ id: "harness", ...s });
    const path = `v1/{project}/databases/${id}`;
    // Bounded backoff, about three minutes in all: unprotecting and deleting are themselves
    // long-running operations that production may refuse while another change is in flight.
    const backoff = [2, 3, 5, 8, 12, 15, 20, 25, 30, 30, 30].map((s) => s * 1_000 * pollScale);
    for (const wait of backoff) {
      const current = await send(step({ path }), program, new Map(), { harness: true });
      if (current.status === 404) return;
      if (current.status !== 200) {
        await sleep(wait);
        continue;
      }
      if (current.json?.deleteProtectionState === "DELETE_PROTECTION_ENABLED") {
        await send(
          step({
            path,
            method: "PATCH",
            query: { updateMask: "deleteProtectionState" },
            body: { deleteProtectionState: "DELETE_PROTECTION_DISABLED" },
          }),
          program,
          new Map(),
          { harness: true },
        );
        await sleep(wait);
        continue;
      }
      await send(step({ path, method: "DELETE" }), program, new Map(), { harness: true });
      await sleep(wait);
    }
    throw new Error(`database ${id} could not be proved absent`);
  }

  /**
   * Deletes every database the program owns. Every id is attempted; one fatal error names all
   * that may remain. (Invalid ids cannot exist; the end-of-run sweep catches anything else
   * created under the run's prefix.)
   */
  async function cleanupProgram(program) {
    await ensureToken(true);
    const remaining = [];
    for (const letter of program.databases ?? []) {
      const id = databaseId(ctx, program, letter);
      try {
        await removeDatabase(program, id);
      } catch (error) {
        remaining.push(`${id} (${error.message})`);
      }
    }
    if (remaining.length)
      throw fatal(`${program.id}: databases may remain: ${remaining.join(", ")}`);
  }

  /** Fails when any database of this run is still listed after every program's cleanup. */
  async function sweepRun() {
    await ensureToken(true);
    const probe = {
      id: "harness/sweep",
      ordinal: 0,
      slug: "harness",
      databases: [],
      project: ctx.project,
    };
    const listing = await send(
      { id: "harness", path: "v1/{project}/databases" },
      probe,
      new Map(),
      {
        harness: true,
      },
    );
    if (listing.status !== 200) throw fatal(`final sweep: HTTP ${listing.status}`);
    const left = (listing.json?.databases ?? [])
      .map((d) => String(d.name).split("/").at(-1))
      .filter((id) => id.startsWith(`cfg${ctx.run}-`));
    if (left.length) throw fatal(`databases of run ${ctx.run} remain: ${left.join(", ")}`);
  }

  const storageStep = (s) => ({ id: "harness", service: "storage", ...s });

  /** Every object under `{objects}/<prefix>/`, by name relative to `{objects}/`, with its bytes. */
  async function downloadObjects(program, prefix) {
    const listing = await send(
      storageStep({ path: "storage/v1/b/{bucket}/o", query: { prefix: `{objects}/${prefix}/` } }),
      program,
      new Map(),
      { harness: true },
    );
    if (listing.status !== 200) throw new Error(`object listing: HTTP ${listing.status}`);
    const files = {};
    for (const item of listing.json?.items ?? []) {
      const request = buildRestRequest(
        storageStep({
          path: `storage/v1/b/{bucket}/o/${encodeURIComponent(item.name)}`,
          query: { alt: "media" },
        }),
        ctx,
        program,
        new Map(),
      );
      guardRestRequest(request, ctx, program, { harness: true });
      claim(true);
      const response = await fetch(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`object download ${item.name}: HTTP ${response.status}`);
      files[String(item.name).replace(`${program.slug}/`, "")] = Buffer.from(
        await response.arrayBuffer(),
      );
    }
    return files;
  }

  /** Uploads a committed capture, restored for this run's ids, under `{objects}/`. */
  async function uploadCapture(program, key) {
    const capture = captures[key];
    if (!capture) throw new Error(`no capture ${key}`);
    const files = restoreCapture(
      capture,
      capturePairs(ctx, program).map(([a, b]) => [b, a]),
    );
    for (const [name, bytes] of Object.entries(files)) {
      const request = buildRestRequest(
        storageStep({
          path: "upload/storage/v1/b/{bucket}/o",
          method: "POST",
          query: { uploadType: "media", name: `{objects}/${name}` },
        }),
        ctx,
        program,
        new Map(),
      );
      request.init.headers["content-type"] = "application/octet-stream";
      request.init.body = bytes;
      guardRestRequest({ ...request, init: { ...request.init, body: undefined } }, ctx, program, {
        harness: true,
      });
      claim(true);
      const response = await fetch(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok)
        throw new Error(
          `object upload ${name}: HTTP ${response.status} ${(await response.text()).slice(0, 200)}`,
        );
    }
    return Object.keys(files).length;
  }

  /** Runs a harness step of an interop program; returns a row only for `reproduce`. */
  async function runInteropStep(program, step, captured) {
    if (step.capture) {
      captured[step.capture.as] = await downloadObjects(program, step.capture.prefix);
      return undefined;
    }
    if (step.upload) {
      await uploadCapture(program, step.upload.from);
      return undefined;
    }
    // reproduce: fireemu's own export of the same data must equal the capture production accepted.
    const files = await downloadObjects(program, step.reproduce.prefix);
    const mine = normalizeCapture(files, capturePairs(ctx, program)).files;
    const theirs = captures[step.reproduce.capture]?.files ?? {};
    const names = [...new Set([...Object.keys(mine), ...Object.keys(theirs)])].toSorted();
    const differing = names.filter((n) => mine[n] !== theirs[n]);
    return {
      status: 200,
      body: { identical: differing.length === 0 && names.length > 0, differing },
    };
  }

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
    const captured = {};
    const symbols = programSymbols(ctx, program);
    let failure;
    try {
      for (const step of program.steps) {
        if (step.onlyOn && step.onlyOn !== ctx.target.kind) continue;
        if (step.capture || step.upload || step.reproduce) {
          const row = await runInteropStep(program, step, captured);
          if (row) steps[step.id] = row;
          log(`${program.id}#${step.id} ${row ? JSON.stringify(row.body) : "done"}`);
          continue;
        }
        let outcome;
        try {
          outcome = await runStep(program, step, raw, symbols);
        } catch (error) {
          if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
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
        const shown = outcome.recorded.trace
          ? `trace ${outcome.recorded.trace.length}${outcome.recorded.unsettled ? " unsettled" : ""}`
          : outcome.recorded.status;
        log(`${program.id}#${step.id} ${shown}`);
      }
    } catch (error) {
      failure = error;
    }
    await cleanupProgram(program);
    if (failure) throw failure;
    return {
      steps,
      ...(Object.keys(captured).length
        ? {
            captures: Object.fromEntries(
              Object.entries(captured).map(([as, files]) => [
                as,
                normalizeCapture(files, capturePairs(ctx, program)),
              ]),
            ),
          }
        : {}),
    };
  }

  const bucketProgram = {
    id: "harness/bucket",
    ordinal: 0,
    slug: "harness",
    databases: [],
    project: ctx.project,
  };

  async function createBucket() {
    const answer = await send(
      {
        id: "harness",
        service: "storage",
        path: "storage/v1/b",
        method: "POST",
        query: { project: ctx.project },
        body: {
          name: ctx.bucket,
          location: "US-CENTRAL1",
          iamConfiguration: {
            uniformBucketLevelAccess: { enabled: true },
            publicAccessPrevention: "enforced",
          },
          // No soft-deleted copies are kept after the run deletes its objects.
          softDeletePolicy: { retentionDurationSeconds: "0" },
        },
      },
      bucketProgram,
      new Map(),
      { harness: true },
    );
    // Until fireemu serves buckets.insert, its Storage emulator treats every bucket as present.
    if (ctx.target.kind === "local" && answer.status === 501) return;
    if (answer.status !== 200)
      throw fatal(`bucket create: HTTP ${answer.status} ${answer.text.slice(0, 300)}`);
  }

  /** Deletes every object in the run bucket, then the bucket, and reads it back as absent. */
  async function deleteBucket() {
    await ensureToken(true);
    const step = (s) => ({ id: "harness", service: "storage", ...s });
    for (let round = 0; round < 20; round += 1) {
      const listing = await send(
        step({ path: "storage/v1/b/{bucket}/o" }),
        bucketProgram,
        new Map(),
        {
          harness: true,
        },
      );
      if (listing.status === 404) return;
      const names = (listing.json?.items ?? []).map((item) => item.name);
      if (names.length === 0) break;
      for (const name of names) {
        await send(
          step({ path: `storage/v1/b/{bucket}/o/${encodeURIComponent(name)}`, method: "DELETE" }),
          bucketProgram,
          new Map(),
          { harness: true },
        );
      }
    }
    await send(
      step({ path: "storage/v1/b/{bucket}", method: "DELETE" }),
      bucketProgram,
      new Map(),
      {
        harness: true,
      },
    );
    const after = await send(step({ path: "storage/v1/b/{bucket}" }), bucketProgram, new Map(), {
      harness: true,
    });
    if (ctx.target.kind === "local" && after.status === 501) return;
    if (after.status !== 404)
      throw fatal(`bucket ${ctx.bucket} is still present (${after.status})`);
  }

  return {
    runProgram,
    createBucket,
    deleteBucket,
    sweepRun,
    counts: () => ({ requests, harnessRequests }),
    close: () => grpcClient.close(),
  };
}

/**
 * Runs every program, `concurrency` at a time; a program that throws is recorded as a harness
 * failure, not a row. The bucket is always deleted at the end.
 */
export async function runCorpus(
  programs,
  ctx,
  { concurrency = 4, bucket = true, ...options } = {},
) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  let fatalError;
  const context = {
    run: ctx.run,
    startedMs: ctx.startedMs,
    project: ctx.project,
    bucket: bucket ? ctx.bucket : null,
  };
  try {
    if (bucket) await session.createBucket();
    const queue = [...programs];
    const worker = async () => {
      while (queue.length && !fatalError) {
        const program = queue.shift();
        try {
          results[program.id] = await session.runProgram(program);
        } catch (error) {
          if (error.fatal) fatalError = error;
          else failures.push({ program: program.id, error: String(error.message ?? error) });
        }
      }
    };
    await Promise.all(Array.from({ length: concurrency }, worker));
    if (!fatalError) await session.sweepRun();
  } catch (error) {
    fatalError ??= Object.assign(error, { fatal: true });
  } finally {
    try {
      if (bucket) await session.deleteBucket();
    } catch (error) {
      const message = `bucket ${ctx.bucket} may remain: ${error.message}`;
      fatalError = fatalError
        ? Object.assign(fatalError, { message: `${fatalError.message}; ${message}` })
        : Object.assign(new Error(message), { fatal: true });
    } finally {
      session.close();
    }
  }
  if (fatalError)
    throw Object.assign(fatalError, {
      partial: { context, results, failures, ...session.counts() },
    });
  return {
    context,
    results,
    failures,
    ...session.counts(),
  };
}
