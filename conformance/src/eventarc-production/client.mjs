// The operations of a recording, over the three hosts they live on: Eventarc (channels and their
// operations), Eventarc Publishing (publishEvents) and Service Usage (the state of the publishing API).
// Every changing operation on a channel names a channel of the run (or a probe registered before it was
// sent) and is refused before anything is sent otherwise. The client normalizes each answer like the
// Pub/Sub client does: a canonical code, `ok`, and the step number the capture carries.

import { restCode } from "../pubsub-production/client.mjs";
import { createLedger, kindOf } from "../pubsub-production/ledger.mjs";

export const PUBLISHING_API = "eventarcpublishing.googleapis.com";

/**
 * Whether an answer is the recorded production answer for a missing resource: a 404 with a JSON body
 * whose `error.status` is `NOT_FOUND` (preflight 002, `channels/firebase`: 373 bytes). A 404 with any
 * other body (a text, an HTML page) says nothing about the resource and settles nothing.
 */
export function isRecordedNotFound(reply) {
  return (
    reply?.unknown !== true &&
    reply?.status === 404 &&
    typeof reply.body === "object" &&
    reply.body !== null &&
    reply.body.error?.status === "NOT_FOUND"
  );
}

/**
 * The kind of an answer to a channel creation or deletion: a 2xx whose long-running operation is not
 * known to be done (or is done with an error) is not "ok" yet. It is `unknown` until the operation is
 * read (see `settleOperation`), because the 2xx alone does not say that this run created (or removed)
 * the channel: an operation can end with ALREADY_EXISTS. When the 2xx names the operation, the kind
 * carries its name (`unknown@<operation>`): that operation, and no other request for the same channel
 * (the deliberate duplicate creation, for one), is what settles this answer.
 */
function kindOfAnswer(result) {
  const kind = kindOf(result);
  if (kind !== "ok") return kind;
  if (result.body?.done === true && result.body?.error === undefined) return "ok";
  return typeof result.body?.name === "string" ? `unknown@${result.body.name}` : "unknown";
}

/** The kind the final read of an operation settles a creation or deletion to. */
export function kindOfOperation(operation) {
  if (!operation?.ok || operation.body?.done !== true) return "unknown";
  const error = operation.body?.error;
  if (error === undefined) return "ok";
  return error.code === 6 || error.status === "ALREADY_EXISTS" ? "conflict" : "error";
}

const encodeName = (name) => name.split("/").map(encodeURIComponent).join("/");
const query = (page = {}) => {
  const parts = [];
  if (page.pageSize !== undefined) parts.push(`pageSize=${encodeURIComponent(page.pageSize)}`);
  if (page.pageToken !== undefined) parts.push(`pageToken=${encodeURIComponent(page.pageToken)}`);
  return parts.length === 0 ? "" : `?${parts.join("&")}`;
};

/**
 * Each operation as `{ host, method, path, body, changes }`. `usageProject` is the project in the Service
 * Usage URLs (an ID or a number, given at run time); `publishPrefix` is `/v1` against production and
 * empty against the local emulator, which serves the route the Admin SDK uses.
 */
const operations = ({ usageProject, publishPrefix }) => ({
  getService: () => ({
    host: "usage",
    method: "GET",
    path: `/v1/projects/${usageProject}/services/${PUBLISHING_API}`,
  }),
  enableService: () => ({
    host: "usage",
    method: "POST",
    path: `/v1/projects/${usageProject}/services/${PUBLISHING_API}:enable`,
    body: {},
  }),
  // The services that are enabled, a page at a time: read before and after the enabling, so that a
  // dependent API the enabling turns on is recorded.
  listEnabledServices: (page = {}) => ({
    host: "usage",
    method: "GET",
    path: `/v1/projects/${usageProject}/services?filter=${encodeURIComponent("state:ENABLED")}&pageSize=200${page.pageToken ? `&pageToken=${encodeURIComponent(page.pageToken)}` : ""}`,
  }),
  getOperation: (host, name) => ({ host, method: "GET", path: `/v1/${encodeName(name)}` }),
  createChannel: (project, location, channelId, body = {}) => ({
    host: "eventarc",
    method: "POST",
    path: `/v1/projects/${project}/locations/${location}/channels?channelId=${encodeURIComponent(channelId)}`,
    body,
    changes: [`projects/${project}/locations/${location}/channels/${channelId}`],
    ledger: {
      action: "create",
      name: `projects/${project}/locations/${location}/channels/${channelId}`,
    },
  }),
  getChannel: (name) => ({ host: "eventarc", method: "GET", path: `/v1/${encodeName(name)}` }),
  listChannels: (project, location, page) => ({
    host: "eventarc",
    method: "GET",
    path: `/v1/projects/${project}/locations/${location}/channels${query(page)}`,
  }),
  deleteChannel: (name) => ({
    host: "eventarc",
    method: "DELETE",
    path: `/v1/${encodeName(name)}`,
    changes: [name],
    ledger: { action: "delete", name },
  }),
  publishEvents: (channel, body) => ({
    host: "publishing",
    method: "POST",
    path: `${publishPrefix}/${encodeName(channel)}:publishEvents`,
    body,
    publishes: channel,
  }),
});

export const OPERATION_NAMES = Object.freeze(
  Object.keys(operations({ usageProject: "p", publishPrefix: "" })),
);

export function createClient({
  transports,
  ownership,
  caseId,
  usageProject,
  publishPrefix = "/v1",
  ledger = createLedger(),
}) {
  const table = operations({ usageProject, publishPrefix });
  let step = 0;
  const run = async (operation, args, options = {}) => {
    const spec = table[operation](...args);
    for (const name of spec.changes ?? []) ownership.assertOwned(name);
    if (spec.publishes !== undefined) ownership.assertPublishable(spec.publishes);
    const transport = transports[spec.host];
    if (transport === undefined) throw new Error(`no transport for ${spec.host}`);
    step += 1;
    const label = { case: caseId, step: String(step).padStart(2, "0") };
    // The ledger line is written before the request is sent: a run that dies in the middle of it still
    // names the channel that may have been created or deleted.
    const entry = spec.ledger && { ...spec.ledger, transport: "rest" };
    if (entry) ledger.sent(entry);
    const reply = await transport.request({
      label,
      op: operation,
      method: spec.method,
      path: spec.path,
      body: spec.body,
      ...options,
    });
    const code = restCode(reply.status, reply.body);
    // A 2xx whose body cannot be read does not say what was done, so it is not a success.
    const result = {
      ...reply,
      code,
      ok: code === "OK" && reply.unknown !== true,
      step: label.step,
    };
    if (entry) ledger.answered({ ...entry, kind: kindOfAnswer(result) });
    return result;
  };
  const methods = (options) =>
    Object.fromEntries(
      OPERATION_NAMES.map((name) => [name, (...args) => run(name, args, options)]),
    );
  return Object.freeze({
    ...methods(),
    with: (options) => methods(options),
    /**
     * Writes into the ledger what the last read of the operation of a creation or deletion says: `ok`
     * when it is done without an error, `conflict` for ALREADY_EXISTS, `error` for another error, and
     * `unknown` when it was not read as done. The kind carries the name of the operation (`ok@<operation>`),
     * so that it settles that request and no other.
     */
    settleOperation: (name, action, operation, operationName) =>
      ledger.answered({
        name,
        action,
        transport: "rest",
        kind:
          typeof operationName === "string"
            ? `${kindOfOperation(operation)}@${operationName}`
            : kindOfOperation(operation),
      }),
  });
}
