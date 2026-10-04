// Runs the native Listen programs (FS-LISTEN-SDK packet L1) against a client and records one row
// per `record` step. The runner only records: nothing here decides whether a row is right, and
// every deadline is a bound on waiting, not an expectation (a wait that runs out is recorded as
// `timedOut`, never as an absence). Effects go through the injected `client`, so the executor is
// tested with a scripted one.

import { commitGroups, frameRows } from "./frames.mjs";
import { createLedger, isDefinitiveRefusal } from "./native-ledger.mjs";

const sleepReal = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** JS values to Firestore `Value`s (the shapes the programs write). */
export function toFields(fields) {
  const value = (item) => {
    if (item === null) return { nullValue: "NULL_VALUE" };
    if (typeof item === "boolean") return { booleanValue: item };
    if (typeof item === "number")
      return Number.isInteger(item) ? { integerValue: String(item) } : { doubleValue: item };
    if (typeof item === "string") return { stringValue: item };
    throw new Error(`unsupported field value ${JSON.stringify(item)}`);
  };
  return Object.fromEntries(Object.entries(fields).map(([key, item]) => [key, value(item)]));
}

/** Bytes from a Buffer, from the base64 text `describeFrame` writes, or from `{ type, data }`. */
const asBuffer = (value) =>
  typeof value === "string" ? Buffer.from(value, "base64") : Buffer.from(value);

const fieldFilter = ([path, value]) => ({
  fieldFilter: {
    field: { fieldPath: path },
    op: "EQUAL",
    value: typeof value === "number" ? { integerValue: String(value) } : { stringValue: value },
  },
});

/** The `Target` a program's target spec stands for. */
export function targetFor(spec, ctx) {
  const target = { targetId: spec.id };
  if (spec.doc !== undefined) {
    target.documents = {
      documents: [`${ctx.root}/${ctx.docs[spec.doc].replaceAll("{run}", ctx.run)}`],
    };
  } else {
    const collectionId = spec.collectionGroup ?? spec.query.collection;
    const structuredQuery = {
      from: [spec.collectionGroup ? { collectionId, allDescendants: true } : { collectionId }],
    };
    const where = spec.query?.where ?? spec.where ?? [];
    if (where.length === 1) structuredQuery.where = fieldFilter(where[0]);
    if (where.length > 1)
      structuredQuery.where = {
        compositeFilter: { op: "AND", filters: where.map(fieldFilter) },
      };
    const orderBy = spec.query?.orderBy;
    if (orderBy)
      structuredQuery.orderBy = [{ field: { fieldPath: orderBy }, direction: "ASCENDING" }];
    target.query = { parent: ctx.root, structuredQuery };
  }
  if (spec.once) target.once = true;
  if (spec.resume !== undefined) {
    const saved = ctx.tokens.get(spec.resume);
    if (!saved?.token) throw new Error(`no saved token ${spec.resume}`);
    target.resumeToken = saved.token;
  }
  if (spec.rawToken !== undefined) target.resumeToken = Buffer.from(spec.rawToken);
  if (spec.readTimeFrom !== undefined) {
    const saved = ctx.tokens.get(spec.readTimeFrom);
    if (!saved?.readTime) throw new Error(`no saved read time ${spec.readTimeFrom}`);
    target.readTime = saved.readTime;
  }
  if (spec.expectedCount !== undefined) target.expectedCount = { value: spec.expectedCount };
  return target;
}

const targetChanges = (frames) =>
  frames.filter((f) => f.kind === "targetChange").map((f) => f.targetChange ?? {});
const covers = (change, id) =>
  (change.targetIds ?? []).length === 0 || change.targetIds.includes(id);

/** Whether a wait's condition holds over the frames since the stream's mark. */
export function waitHolds(until, frames, ended) {
  if (until.ended) return Boolean(ended);
  if (until.current !== undefined)
    return targetChanges(frames).some(
      (c) => c.targetChangeType === "CURRENT" && (c.targetIds ?? []).includes(until.current),
    );
  if (until.type !== undefined)
    return targetChanges(frames).some(
      (c) => c.targetChangeType === until.type && (c.targetIds ?? []).includes(until.id),
    );
  if (until.docChanges !== undefined)
    return frames.filter((f) => f.kind === "documentChange").length >= until.docChanges;
  if (until.frames !== undefined) return frames.length >= until.frames;
  throw new Error(`unknown wait condition ${JSON.stringify(until)}`);
}

/** A program's documents as full names, and the reverse map the row writer uses. */
function resolveDocs(program, { root, run }) {
  const full = {};
  const names = new Map();
  for (const [logical, template] of Object.entries(program.docs ?? {})) {
    const name = `${root}/${template.replaceAll("{run}", run)}`;
    full[logical] = name;
    names.set(name, logical);
  }
  return { full, names };
}

export async function runNative(
  programs,
  {
    client,
    project,
    run,
    sleep = sleepReal,
    now = () => Date.now(),
    settleMs = 1500,
    maxRequests = 400,
    log = () => {},
    ledger = createLedger(),
  },
) {
  const root = `projects/${project}/databases/(default)/documents`;
  const database = `projects/${project}/databases/(default)`;
  const rows = {};
  const errors = {};
  /** One Commit whose names are issued first and whose answer is recorded as ok, refused or unknown. */
  const commitTracked = async (request) => {
    ledger.issue(request.writes);
    try {
      const answer = await client.commit(request);
      ledger.answered(request.writes, "ok");
      return answer;
    } catch (error) {
      ledger.answered(request.writes, isDefinitiveRefusal(error) ? "refused" : "unknown");
      throw error;
    }
  };
  let requests = 0;
  const charge = (what) => {
    requests += 1;
    if (requests > maxRequests)
      throw new Error(`request ceiling ${maxRequests} reached at ${what}`);
  };

  for (const program of programs) {
    const { full, names } = resolveDocs(program, { root, run });
    const streams = new Map();
    const marks = new Map();
    const timedOut = new Map();
    const tokens = new Map();
    const ctx = { root, run, docs: program.docs ?? {}, tokens };
    const writeOf = (w) =>
      w.delete
        ? { delete: full[w.delete] }
        : { update: { name: full[w.doc], fields: toFields(w.fields) } };
    try {
      for (const step of program.steps) {
        log(`${program.id}: ${step.do}`);
        switch (step.do) {
          case "seed":
          case "write":
            charge(step.do);
            await commitTracked({ writes: [writeOf(step)] });
            break;
          case "delete":
            charge(step.do);
            await commitTracked({ writes: [writeOf({ delete: step.doc })] });
            break;
          case "commit":
            charge(step.do);
            await commitTracked({ writes: step.writes.map(writeOf) });
            break;
          case "txn": {
            charge("begin");
            const transaction = await client.beginTransaction();
            charge(step.do);
            await commitTracked({ writes: step.writes.map(writeOf), transaction });
            break;
          }
          case "open": {
            charge(`open ${step.stream}`);
            const stream = client.openStream();
            streams.set(step.stream, stream);
            marks.set(step.stream, 0);
            for (const spec of step.targets)
              stream.send({ database, addTarget: targetFor(spec, ctx) });
            break;
          }
          case "add":
            streams.get(step.stream).send({ database, addTarget: targetFor(step.target, ctx) });
            break;
          case "remove":
            streams.get(step.stream).send({ database, removeTarget: step.id });
            break;
          case "wait": {
            const stream = streams.get(step.stream);
            const limit = now() + (step.timeoutMs ?? 30_000);
            let held = false;
            for (;;) {
              held = waitHolds(
                step.until,
                stream.frames.slice(marks.get(step.stream)),
                stream.ended(),
              );
              if (held || stream.ended() || now() >= limit) break;
              await sleep(50);
            }
            // An ended stream satisfies only a wait for its end; any other wait on it ran out.
            if (!held) timedOut.set(step.stream, true);
            if (step.settleMs !== 0) await sleep(step.settleMs ?? settleMs);
            break;
          }
          case "settle":
            await sleep(step.ms ?? settleMs);
            break;
          case "record": {
            const stream = streams.get(step.stream);
            const frames = stream.frames.slice(marks.get(step.stream));
            marks.set(step.stream, stream.frames.length);
            const end = stream.ended();
            rows[step.row] = {
              conditions: program.conditions,
              rows: frameRows(frames, { names, project, run }),
              ...(step.groups ? { groups: commitGroups(frames, { names }) } : {}),
              end: end ? { reason: end.reason, code: end.code ?? null } : null,
              timedOut: timedOut.get(step.stream) === true,
            };
            timedOut.set(step.stream, false);
            break;
          }
          case "save": {
            const frames = streams.get(step.stream).frames;
            const changes = targetChanges(frames).filter((c) => covers(c, step.id));
            const saved = {};
            const withToken = changes.findLast((c) => c.resumeToken);
            if (withToken) saved.token = asBuffer(withToken.resumeToken);
            const withTime = changes.findLast((c) => c.readTime);
            if (withTime) saved.readTime = withTime.readTime;
            for (const name of [step.token, step.time])
              if (name !== undefined) tokens.set(name, saved);
            break;
          }
          case "close":
            await streams.get(step.stream).close();
            break;
          case "sleep":
            await sleep(step.ms);
            break;
          case "refresh":
            // A long wait outlives an access token: the client gets a fresh one if it can.
            await client.refresh?.();
            break;
          default:
            throw new Error(`unknown step ${step.do}`);
        }
      }
    } catch (error) {
      errors[program.id] = String(error?.message ?? error);
    } finally {
      for (const stream of streams.values()) await stream.close();
    }
  }
  return { rows, errors, requests, issued: ledger.entries() };
}
