// Builds the REST request of a step. Every body carries the API's required fields (CreateSubscription
// needs `topic`, CreateSnapshot needs `subscription`, Patch needs `updateMask`, Pull needs `maxMessages`,
// Seek needs a target), and every name is checked for ownership before anything is sent.

import { PROJECT, fullName, isOwned, kindOfName, NEVER_CREATED } from "./names.mjs";

const BASE = "/v1/";

export class Refusal extends Error {}

/**
 * @returns {{method:string, path:string, body?:object, targets:string[], kind?:string, create:boolean, grpc?:boolean}}
 * `targets` are the names the request can create or delete; `create` marks a request that can create `targets[0]`.
 */
export function buildRequest(step, { runId, cellId }) {
  const name = (role, kind) => {
    const full = fullName(runId, cellId, role, kind);
    if (!isOwned(full, runId)) throw new Refusal(`foreign name ${full}`);
    return full;
  };
  const target = step.target;
  const query = step.query ?? "";
  const sub = () => name(target, "subscription");
  const snap = () => name(target, "snapshot");
  switch (step.op) {
    case "getSub":
      return { method: "GET", path: `${BASE}${sub()}${query}`, targets: [], create: false };
    case "getSnap":
      return { method: "GET", path: `${BASE}${snap()}`, targets: [], create: false };
    case "getTopic":
      return { method: "GET", path: `${BASE}${name(target, "topic")}`, targets: [], create: false };
    case "grpcGetSub":
      return { grpc: true, method: "GRPC", path: sub(), targets: [], create: false };
    case "putSub": {
      const body = { topic: name(step.topic, "topic") };
      if (step.bodyName !== undefined) body.name = name(step.bodyName, "subscription");
      return { method: "PUT", path: `${BASE}${sub()}`, body, targets: [sub()], create: true };
    }
    case "putSnap": {
      const body = { subscription: name(step.from, "subscription") };
      return { method: "PUT", path: `${BASE}${snap()}`, body, targets: [snap()], create: true };
    }
    case "deleteSub":
      return {
        method: "DELETE",
        path: `${BASE}${sub()}`,
        targets: [sub()],
        create: false,
        delete: true,
      };
    case "deleteSnap":
      return {
        method: "DELETE",
        path: `${BASE}${snap()}`,
        targets: [snap()],
        create: false,
        delete: true,
      };
    case "patchSub":
      return {
        method: "PATCH",
        path: `${BASE}${sub()}`,
        body: { subscription: { name: sub(), labels: step.labels }, updateMask: "labels" },
        targets: [],
        create: false,
      };
    case "pullSub":
      return {
        method: "POST",
        path: `${BASE}${sub()}:pull`,
        body: { maxMessages: 1 },
        targets: [],
        create: false,
      };
    case "getIamSub":
      return { method: "GET", path: `${BASE}${sub()}:getIamPolicy`, targets: [], create: false };
    case "seekSub":
      return {
        method: "POST",
        path: `${BASE}${sub()}:seek`,
        body: { snapshot: name(step.snapshot, "snapshot") },
        targets: [],
        create: false,
      };
    case "listSub":
      return {
        method: "GET",
        path: `${BASE}projects/${PROJECT}/subscriptions?pageSize=100`,
        targets: [],
        create: false,
        list: "subscription",
      };
    default:
      throw new Refusal(`unlisted op ${step.op}`);
  }
}

/** Setup requests of a run: its one topic T and its one source subscription S. */
export function setupRequests({ runId }) {
  const topic = fullName(runId, "run", "T");
  const sub = fullName(runId, "run", "S");
  return [
    {
      id: "setup-topic",
      method: "PUT",
      path: `${BASE}${topic}`,
      body: {},
      targets: [topic],
      create: true,
    },
    {
      id: "setup-sub",
      method: "PUT",
      path: `${BASE}${sub}`,
      body: { topic },
      targets: [sub],
      create: true,
    },
  ];
}

export const listRequest = (kind, pageToken) => ({
  method: "GET",
  path: `${BASE}projects/${PROJECT}/${kind === "topic" ? "topics" : kind === "snapshot" ? "snapshots" : "subscriptions"}?pageSize=100${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`,
  targets: [],
  create: false,
  list: kind,
});

export const deleteRequest = (name, runId) => {
  if (!isOwned(name, runId)) throw new Refusal(`foreign name ${name}`);
  return { method: "DELETE", path: `${BASE}${name}`, targets: [name], create: false, delete: true };
};

export const getRequest = (name, runId) => {
  if (!isOwned(name, runId)) throw new Refusal(`foreign name ${name}`);
  return { method: "GET", path: `${BASE}${name}`, targets: [], create: false };
};

export { NEVER_CREATED, kindOfName };
