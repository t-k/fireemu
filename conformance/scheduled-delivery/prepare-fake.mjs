// Test support for the preparation packet: a fake Cloud Service Usage, IAM, Firebase, App Engine,
// Logging and list endpoints that answer in the recorded shapes (bodies built from the real ones
// in fixtures/prepare-recorded.json). Not part of the packet; it sends nothing.
import { readFileSync } from "node:fs";
import { PROJECT, TARGET_SERVICES, collect } from "./prepare.mjs";

export const NUMBER = "123456789012";
export const recorded = JSON.parse(
  readFileSync(new URL("./fixtures/prepare-recorded.json", import.meta.url), "utf8"),
).answers;
export const pretty = (json) => JSON.stringify(json, null, 2) + "\n";
export function reply(status, json) {
  return new Response(pretty(json), { status, headers: { "content-type": "application/json" } });
}

const OPERATION = "operations/acf.p2-" + NUMBER + "-e627f9a7-0f50-48e6-856c-93ad311e8f0e";

/** The sandbox before the preparation: Firestore-era APIs plus Scheduler, Pub/Sub and App Engine. */
export const BASE_ENABLED = [
  "appengine.googleapis.com",
  "billingbudgets.googleapis.com",
  "cloudscheduler.googleapis.com",
  "firebase.googleapis.com",
  "firebaserules.googleapis.com",
  "firestore.googleapis.com",
  "iamcredentials.googleapis.com",
  "identitytoolkit.googleapis.com",
  "pubsub.googleapis.com",
  "securetoken.googleapis.com",
  "serviceusage.googleapis.com",
];

export function fakeServer({
  enabled = BASE_ENABLED,
  hooks = {},
  pageSize = 200,
  pendingPolls = 1,
} = {}) {
  const state = {
    enabled: new Set(enabled),
    calls: [],
    policy: structuredClone(recorded.iamPolicy.body),
    polls: 0,
    adminSdkConfig: { projectId: PROJECT, storageBucket: PROJECT + ".appspot.com" },
  };
  const entry = (id) => ({
    name: "projects/" + NUMBER + "/services/" + id,
    config: { name: id, title: id },
    state: "ENABLED",
    parent: "projects/" + NUMBER,
  });
  const send = async (request) => {
    const url = request.url;
    const method = request.method;
    const key = method + " " + url.replace(/^https:\/\/[^/]+\//, "").replace(NUMBER, "<number>");
    state.calls.push(key);
    const body = request.body ? JSON.parse(request.body) : undefined;
    const hook = hooks[key] ?? Object.entries(hooks).find(([k]) => key.startsWith(k + "?"))?.[1];
    if (hook) {
      const out = await hook({ state, body, url, method, entry });
      if (out === "throw") throw new Error("transport");
      if (out) return out;
    }
    if (url.includes("firebaserules.googleapis.com"))
      return reply(200, {
        name: "projects/" + PROJECT + "/releases/cloud.firestore",
        rulesetName: "projects/" + PROJECT + "/rulesets/abc",
      });
    if (url.includes("/services?filter=")) {
      const ids = [...state.enabled].toSorted();
      const token = new URL(url).searchParams.get("pageToken");
      const start = token ? Number(token) : 0;
      const page = ids.slice(start, start + pageSize);
      return reply(200, {
        services: page.map(entry),
        ...(start + pageSize < ids.length ? { nextPageToken: String(start + pageSize) } : {}),
      });
    }
    if (url.endsWith(":batchEnable")) {
      state.pending = body.serviceIds;
      state.polls = 0;
      return reply(200, {
        name: OPERATION,
        metadata: {
          "@type": "type.googleapis.com/google.api.serviceusage.v1.OperationMetadata",
          resourceNames: body.serviceIds.map(
            (id) => "services/" + id + "/projectSettings/" + NUMBER,
          ),
        },
      });
    }
    if (url.includes("/v1/operations/")) {
      state.polls++;
      if (state.polls <= pendingPolls)
        return reply(200, {
          name: OPERATION,
          metadata: { "@type": "type.googleapis.com/google.protobuf.Empty" },
        });
      for (const id of state.pending ?? []) state.enabled.add(id);
      if (state.pending?.includes("compute.googleapis.com")) {
        const editor = state.policy.bindings.find((b) => b.role === "roles/editor");
        const compute = "serviceAccount:" + NUMBER + "-compute@developer.gserviceaccount.com";
        if (!editor.members.includes(compute)) editor.members.push(compute);
        state.policy.bindings.push({
          role: "roles/compute.serviceAgent.fake",
          members: ["serviceAccount:service-" + NUMBER + "@compute-system.iam.gserviceaccount.com"],
        });
      }
      state.pending = [];
      return reply(200, {
        name: OPERATION,
        metadata: { "@type": "type.googleapis.com/google.protobuf.Empty" },
        done: true,
        response: {
          "@type": "type.googleapis.com/google.api.serviceusage.v1.BatchEnableServicesResponse",
          services: [...state.enabled].map((id) => ({
            name: "projects/" + NUMBER + "/services/" + id,
            state: "ENABLED",
          })),
        },
      });
    }
    if (url.endsWith(":getIamPolicy")) return reply(200, state.policy);
    if (url.endsWith("/adminSdkConfig")) return reply(200, state.adminSdkConfig);
    if (url.includes("appengine.googleapis.com")) return reply(404, recorded.appEngineAbsent.body);
    if (url.endsWith("/entries:list")) return reply(200, {});
    if (/\/(functions|services|repositories)$/.test(url)) return reply(200, {});
    throw new Error("fake server: unexpected " + key);
  };
  return { send, state };
}

export async function run(server, extra = {}) {
  const journal = [];
  const sleeps = [];
  let now = Date.parse("2026-10-06T00:00:00Z");
  const result = await collect({
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: server.send,
    clock: () => (now += 100),
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    ...extra,
  });
  return { result, journal, sleeps };
}
export { TARGET_SERVICES };
