// The operations of a recording, over the three hosts they live on: Eventarc (channels and their
// operations), Eventarc Publishing (publishEvents) and Service Usage (the state of the publishing API).
// Every changing operation on a channel names a channel of the run (or a probe registered before it was
// sent) and is refused before anything is sent otherwise. The client normalizes each answer like the
// Pub/Sub client does: a canonical code, `ok`, and the step number the capture carries.

import { restCode } from "../pubsub-production/client.mjs";

export const PUBLISHING_API = "eventarcpublishing.googleapis.com";

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
  getOperation: (host, name) => ({ host, method: "GET", path: `/v1/${encodeName(name)}` }),
  createChannel: (project, location, channelId, body = {}) => ({
    host: "eventarc",
    method: "POST",
    path: `/v1/projects/${project}/locations/${location}/channels?channelId=${encodeURIComponent(channelId)}`,
    body,
    changes: [`projects/${project}/locations/${location}/channels/${channelId}`],
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
    const reply = await transport.request({
      label,
      op: operation,
      method: spec.method,
      path: spec.path,
      body: spec.body,
      ...options,
    });
    const code = restCode(reply.status, reply.body);
    return { ...reply, code, ok: code === "OK", step: label.step };
  };
  const methods = (options) =>
    Object.fromEntries(
      OPERATION_NAMES.map((name) => [name, (...args) => run(name, args, options)]),
    );
  return Object.freeze({ ...methods(), with: (options) => methods(options) });
}
