// A model of the Eventarc channel service for the tests of the recorder: a stateful transport that
// answers like production where production was recorded, and refuses what production refuses.
//
// What is recorded (stage A, r2 rows 4, 5, 28 and 29; `fixtures/stage-b-world/recorded-refusals.json`)
// is returned byte for byte: a create whose body has no `name` is a 400 `channel.name is empty`, a
// publish without events is a 400 `No events provided.`, a missing channel is a 404. What is not
// recorded yet (the success answers, the operation of a create, a duplicate, a name that does not match
// the path, the pages of a list) is a flow model only: it has the shape the recorder needs to follow
// the request, and it is never evidence of production's answer.
//
// The model refuses a write whose required fields are missing, as production does (checklist section 2,
// "Request shapes"): `world.refusals` lists every such refusal, so that a test can assert that the
// recorder sent none of them except the probes it names on purpose.

import { readFileSync } from "node:fs";

const RECORDED = JSON.parse(
  readFileSync(
    new URL("../fixtures/stage-b-world/recorded-refusals.json", import.meta.url),
    "utf8",
  ),
).rows;

/** The recorded answers, as `{ status, body }` copies. */
export const recorded = (key) => structuredClone(RECORDED[key].response);

const reply = (status, body) => ({ status, body, unknown: false });
const invalid = (message) =>
  reply(400, { error: { code: 400, message, status: "INVALID_ARGUMENT" } });
const notFound = (name) =>
  reply(404, {
    error: {
      code: 404,
      message: `Resource '${name}' was not found`,
      status: "NOT_FOUND",
      details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
    },
  });

const CHANNEL_ID = /^[a-z][a-z0-9-]{2,62}$/;
const CHANNEL_PATH = /^projects\/([^/]+)\/locations\/([^/]+)\/channels\/([^/]+)$/;
const CREATE_PATH = /^projects\/([^/]+)\/locations\/([^/]+)\/channels$/;

/**
 * What production refuses about the shape of a channel creation, or null: a body that is not an object, or
 * whose `name` is missing, empty or not a string (the recorded 400 `channel.name is empty`), or whose
 * name is not the full resource name of the path's parent and `channelId` (a 400 whose wording is a model).
 */
export function createShapeRefusal({ path, body }) {
  const url = new URL(`http://world${path}`);
  const parent = url.pathname.replace(/^\/v1\//, "").replace(/\/channels$/, "");
  const id = url.searchParams.get("channelId");
  if (typeof body !== "object" || body === null || Array.isArray(body))
    return { kind: "create-no-body", answer: recorded("createChannel-no-name") };
  if (typeof body.name !== "string" || body.name === "")
    return { kind: "create-no-name", answer: recorded("createChannel-no-name") };
  if (id === null || body.name !== `${parent}/channels/${id}`)
    return {
      kind: "create-name-mismatch",
      answer: invalid(
        "The request was invalid: channel.name does not match the parent and channelId",
      ),
    };
  return null;
}

export function createWorld({
  project,
  locations = ["us-central1", "europe-west1"],
  doneAfter = 1,
  /** How a second create of a name answers: a 409, or a 200 whose operation ends with ALREADY_EXISTS. */
  duplicate = "operation",
  /** Names that exist before the run (not created by it). */
  existing = [],
  /** The most events in one publish and the longest text of one event (the model's limits, not production's). */
  eventLimit = 255,
  textLimit = 600_000,
  /**
   * How a creation of a name answers: `ok` (a 200 operation), `unknown-appears` (a 503, and the channel
   * exists), `unknown-absent` (a 503, and it does not), `invisible` (a 200 operation done without an
   * error, and the channel never shows: read-after-write lag or a channel that is gone).
   */
  createAnswer = "ok",
  /** How a deletion answers: `ok`, `unknown-effective` (a 503, the channel is gone) or `unknown-noeffect`. */
  deleteAnswer = "ok",
  /**
   * The `state` a created channel reads as: `undefined` (no member), `ACTIVE`, or a number of reads for
   * which it is PENDING first (`pendingReads`), and `PENDING` for good with `stuckPending`.
   */
  pendingReads = 0,
  stuckPending = false,
  withState = false,
  /**
   * The most attributes in one event counting the four required ones (`ce-id`, `ce-source`, `ce-spec_version`,
   * `ce-type`) and the longest key (`ce-` and the name), as stage B recorded them (rows 148 and 149; a model
   * of the wording only, never evidence of the boundary).
   */
  attributeLimit = Infinity,
  keyLimit = Infinity,
  /**
   * Operations that are still running (stage C): off by default (a channel is ready, and gone, at once).
   * With `reject` or `accept` a channel being created or deleted stays in that phase until its operation is
   * read done (`doneAfter` reads): it is visible to a read and a list, a publish to a channel being created
   * is a 404, a creation of the same name is refused as a duplicate, and a deletion while an operation runs
   * is a 409 (`reject`) or starts an operation of its own (`accept`). A flow model, never evidence.
   */
  busy = "off",
  /**
   * The deliberate variant of a creation (a body that names another channel than the path's ID) is accepted and
   * creates the channel the body names, with an operation (the most requests a run can send), instead of being
   * refused.
   */
  acceptVariants = false,
  /** Every ID is accepted, so that every ID probe creates a channel (the most requests a run can send). */
  acceptAnyId = false,
} = {}) {
  const channels = new Map(existing.map((name) => [name, { createTime: "2026-01-01T00:00:00Z" }]));
  const operations = new Map();
  const phases = new Map();
  const refusals = [];
  const calls = [];
  let counter = 0;
  const refuse = (call, kind, answer) => {
    refusals.push({ kind, case: call.label?.case, step: call.label?.step, op: call.op });
    return answer;
  };
  const limits = [];
  const limited = (call, kind, answer) => {
    limits.push({ kind, case: call.label?.case, op: call.op });
    return answer;
  };
  const operation = (parent, outcome) => {
    counter += 1;
    const name = `${parent}/operations/operation-${counter}`;
    operations.set(name, { reads: 0, ...outcome });
    return {
      name,
      done: false,
      metadata: { "@type": "type.googleapis.com/google.cloud.eventarc.v1.OperationMetadata" },
    };
  };
  const create = (call, url) => {
    const parent = CREATE_PATH.exec(decodeURIComponent(url.pathname.replace(/^\/v1\//, "")));
    const id = url.searchParams.get("channelId");
    if (parent === null) return invalid("The request was invalid: malformed parent");
    if (parent[1] !== project || !locations.includes(parent[2]))
      return reply(403, {
        error: { code: 403, status: "PERMISSION_DENIED", message: "Location is not supported" },
      });
    const shape = createShapeRefusal(call);
    const variant = shape?.kind === "create-name-mismatch" && acceptVariants;
    if (shape !== null && !variant) return refuse(call, shape.kind, shape.answer);
    const name = variant ? call.body.name : `${parent[0]}/${id}`;
    const named = name.split("/").at(-1);
    if (!acceptAnyId && (!CHANNEL_ID.test(named) || named.startsWith("goog")))
      return invalid("The request was invalid: invalid channel ID");
    if (channels.has(name)) {
      if (duplicate === "409")
        return reply(409, {
          error: { code: 409, status: "ALREADY_EXISTS", message: "already exists" },
        });
      return reply(
        200,
        operation(`projects/${parent[1]}/locations/${parent[2]}`, {
          error: { code: 6, message: "already exists" },
        }),
      );
    }
    if (createAnswer === "unknown-absent") return { status: 503, body: {}, unknown: true };
    if (createAnswer !== "invisible") channels.set(name, { createTime: "2026-10-05T00:00:00Z" });
    if (createAnswer === "unknown-appears") return { status: 503, body: {}, unknown: true };
    const parentName = `projects/${parent[1]}/locations/${parent[2]}`;
    if (busy === "off" || createAnswer === "invisible")
      return reply(200, operation(parentName, {}));
    phases.set(name, "creating");
    return reply(200, operation(parentName, { onDone: () => phases.delete(name) }));
  };
  const publish = (call, name) => {
    const events = call.body?.events;
    if (!Array.isArray(events) || events.length === 0)
      return refuse(
        call,
        "publish-no-events",
        recorded(
          Array.isArray(events) ? "publishEvents-empty-list" : "publishEvents-no-events-member",
        ),
      );
    if (events.length > eventLimit)
      return limited(call, "publish-too-many", {
        ...recorded("publishEvents-too-many-events"),
        unknown: false,
      });
    if (events.some((event) => (event?.textData?.length ?? 0) > textLimit))
      return limited(call, "publish-too-large", {
        ...recorded("publishEvents-event-too-large"),
        unknown: false,
      });
    for (const event of events) {
      const keys = Object.keys(event?.attributes ?? {});
      const attributes = keys.length + 4;
      if (attributes > attributeLimit)
        return limited(
          call,
          "publish-too-many-attributes",
          invalid(
            `There are too many attributes in the request. The request contains ${attributes} attributes, but the maximum allowed is ${attributeLimit}. Refer to https://cloud.google.com/pubsub/quotas for more information.`,
          ),
        );
      const key = keys.find((name) => `ce-${name}`.length > keyLimit);
      if (key !== undefined)
        return limited(
          call,
          "publish-key-too-large",
          invalid(
            `The attribute "ce-${key}" in the request has a key that is too large. The size is ${`ce-${key}`.length} bytes, but the maximum allowed is ${keyLimit}. Refer to https://cloud.google.com/pubsub/quotas for more information.`,
          ),
        );
    }
    if (!channels.has(name) || phases.get(name) === "creating")
      return reply(404, {
        error: { code: 404, status: "NOT_FOUND", message: "Associated channel does not exist." },
      });
    return reply(200, {});
  };
  const list = (parent, url) => {
    const location = parent.split("/")[3];
    if (location !== "-" && !locations.includes(location))
      return reply(403, {
        error: { code: 403, status: "PERMISSION_DENIED", message: "Location is not supported" },
      });
    const asked = url.searchParams.get("pageSize");
    if (asked !== null && !/^-?\d+$/.test(asked))
      return invalid("The request was invalid: invalid page size");
    if (Number(asked ?? 50) < 0) return invalid("The request was invalid: page size is negative");
    const size = Math.min(Number(asked ?? 0) || 50, 1000);
    const after = url.searchParams.get("pageToken");
    const names = [...channels.keys()]
      .filter((n) => n.startsWith(`${parent}/channels/`))
      .toSorted();
    const from =
      after === null ? 0 : names.findIndex((n) => n > Buffer.from(after, "base64url").toString());
    if (from < 0 && after !== null) return reply(200, {});
    const page = names.slice(from, from + size);
    const next =
      from + size < names.length ? Buffer.from(page.at(-1)).toString("base64url") : undefined;
    if (page.length === 0) return reply(200, {});
    return reply(200, {
      channels: page.map((n) => Object.assign({ name: n }, channels.get(n))),
      ...(next ? { nextPageToken: next } : {}),
    });
  };
  return {
    channels,
    /** Every operation a request started, with how many times it was read (done at `doneAfter` reads). */
    operations,
    refusals,
    /** The publishes the model refused for a limit (not for a missing required field). */
    limits,
    calls,
    async request(call) {
      calls.push({
        op: call.op,
        method: call.method,
        path: call.path,
        body: call.body,
        token: call.token,
        caseId: call.label?.case,
      });
      const url = new URL(`http://world${call.path}`);
      const bare = decodeURIComponent(url.pathname.replace(/^\/v1\//, "").replace(/^\//, ""));
      if (call.op === "getService") return reply(200, { state: "ENABLED" });
      if (call.op === "getOperation") {
        const state = operations.get(bare);
        if (state === undefined) return notFound(bare);
        state.reads += 1;
        const done = state.reads >= doneAfter;
        if (done) state.onDone?.();
        return reply(200, {
          name: bare,
          ...(done
            ? { done: true, ...(state.error ? { error: state.error } : { response: {} }) }
            : { done: false }),
        });
      }
      if (call.op === "createChannel") return create(call, url);
      if (call.op === "getChannel") {
        const found = channels.get(bare);
        if (found === undefined) return notFound(bare);
        if (!withState) return reply(200, { name: bare, ...found });
        found.reads = (found.reads ?? 0) + 1;
        const state = stuckPending || found.reads <= pendingReads ? "PENDING" : "ACTIVE";
        return reply(200, { name: bare, ...found, reads: undefined, state });
      }
      if (call.op === "listChannels") return list(bare.replace(/\/channels$/, ""), url);
      if (call.op === "deleteChannel") {
        if (!CHANNEL_PATH.test(bare) || !channels.has(bare)) return notFound(bare);
        if (deleteAnswer === "unknown-noeffect") return { status: 503, body: {}, unknown: true };
        if (busy !== "off" && deleteAnswer === "ok") {
          const parentName = bare.replace(/\/channels\/[^/]+$/, "");
          if (phases.has(bare) && busy === "reject")
            return reply(409, {
              error: {
                code: 409,
                status: "FAILED_PRECONDITION",
                message: "an operation is running",
              },
            });
          phases.set(bare, "deleting");
          return reply(
            200,
            operation(parentName, {
              onDone: () => {
                phases.delete(bare);
                channels.delete(bare);
              },
            }),
          );
        }
        channels.delete(bare);
        if (deleteAnswer === "unknown-effective") return { status: 503, body: {}, unknown: true };
        return reply(200, operation(bare.replace(/\/channels\/[^/]+$/, ""), {}));
      }
      if (call.op === "publishEvents" || call.op === "sdk.publishEvents")
        return publish(call, bare.replace(/:publishEvents$/, ""));
      throw new Error(`the world does not know ${call.op}`);
    },
  };
}
