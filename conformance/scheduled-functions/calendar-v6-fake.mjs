// Test support for the calendar v6 collector: a fake Cloud Scheduler and Pub/Sub that answer in
// the recorded layouts. Not part of the packet; it sends nothing.
import { PROJECT, REFUSED_400, collect, resources } from "./calendar-v6.mjs";

export const RUN = "0123456789abcdef";
export const pretty = (json) => JSON.stringify(json, null, 2) + "\n";
export function reply(status, json) {
  return new Response(pretty(json), { status, headers: { "content-type": "application/json" } });
}

/** A fake Cloud Scheduler and Pub/Sub that answers in the recorded layouts. */
export function fakeServer({ refuse = () => false, hooks = {}, runId = RUN } = {}) {
  const own = resources(runId);
  const state = {
    topic: false,
    jobs: new Map(),
    everCreated: new Set(),
    calls: [],
    pausedAt: new Map(),
  };
  let tick = 0;
  const jobBody = (name, data) => ({
    name,
    pubsubTarget: { topicName: own.topic, data: "Y2FsZW5kYXItdjY=" },
    userUpdateTime: "2026-10-06T00:00:00.000000Z",
    state: data.state,
    status: { code: -1 },
    ...(data.state === "ENABLED" ? { scheduleTime: "2026-10-06T00:01:00Z" } : {}),
    schedule: data.schedule,
    timeZone: data.timeZone,
  });
  const absent = (name) =>
    state.everCreated.has(name)
      ? reply(404, { error: { code: 404, message: "Job not found.", status: "NOT_FOUND" } })
      : reply(404, {
          error: {
            code: 404,
            message: "Resource '" + name + "' was not found",
            status: "NOT_FOUND",
            details: [
              { "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name },
            ],
          },
        });
  const send = async (request) => {
    const url = request.url.replace(/^https:\/\/[^/]+\/v1\//, "");
    const method = request.method;
    state.calls.push(method + " " + url);
    const body = request.body ? JSON.parse(request.body) : undefined;
    const hook = hooks[method + " " + url] ?? hooks[method + " " + url.replace(runId, "<run>")];
    if (hook) {
      const out = await hook({ state, body, url, method, own });
      if (out === "throw") throw new Error("transport");
      if (out) return out;
    }
    if (url.startsWith("projects/" + PROJECT + "/releases/")) {
      return reply(200, {
        name: "projects/" + PROJECT + "/releases/cloud.firestore",
        rulesetName: "projects/" + PROJECT + "/rulesets/abc",
      });
    }
    if (url.includes("/services/")) return reply(200, { state: "ENABLED" });
    if (url.endsWith("/jobs?pageSize=500"))
      return state.jobs.size
        ? reply(200, { jobs: [...state.jobs.keys()].map((name) => ({ name })) })
        : reply(200, {});
    if (url.endsWith("/topics?pageSize=1000"))
      return state.topic ? reply(200, { topics: [{ name: own.topic }] }) : reply(200, {});
    if (url === own.topic) {
      if (method === "PUT") {
        state.topic = true;
        return reply(200, { name: own.topic });
      }
      if (method === "GET")
        return state.topic
          ? reply(200, { name: own.topic })
          : reply(404, {
              error: {
                code: 404,
                message: "Resource not found (resource=" + own.prefix + ").",
                status: "NOT_FOUND",
              },
            });
      if (method === "DELETE") {
        state.topic = false;
        return reply(200, {});
      }
    }
    if (method === "POST" && url.endsWith("/jobs")) {
      if (refuse(body)) return reply(400, REFUSED_400);
      state.jobs.set(body.name, { ...body, state: "ENABLED" });
      state.everCreated.add(body.name);
      return reply(200, jobBody(body.name, state.jobs.get(body.name)));
    }
    if (method === "POST" && url.endsWith(":pause")) {
      const name = url.slice(0, -":pause".length);
      const job = state.jobs.get(name);
      job.state = "PAUSED";
      state.pausedAt.set(name, ++tick);
      return reply(200, jobBody(name, job));
    }
    if (url.includes("/jobs/")) {
      const job = state.jobs.get(url);
      if (method === "GET") return job ? reply(200, jobBody(url, job)) : absent(url);
      if (method === "DELETE") {
        if (!job) return absent(url);
        state.jobs.delete(url);
        return reply(200, {});
      }
    }
    throw new Error("fake server: unexpected " + method + " " + url);
  };
  return { send, state, own };
}

export async function run(server, extra = {}) {
  const journal = [];
  const sleeps = [];
  let now = Date.parse("2026-10-06T00:00:00Z");
  const result = await collect({
    runId: RUN,
    projectNumber: "123456789012",
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
export const refuseSecond = (body) =>
  /^(cr08|cr09|cr10|gr09|gr10|tz04|rt03|rt08)$/.test(body.name.split("-").pop());
