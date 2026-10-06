// Test support for the calendar v6 runner: loaded with `node --import` into the runner's own
// process, it answers every request from the fake Cloud Scheduler and Pub/Sub instead of the
// network, and makes the long waits instant. Not part of the packet; it sends nothing.
import { fakeServer, reply } from "./calendar-v6-fake.mjs";

const mode = process.env.FAKE_MODE ?? "clean";
const hooksFor = () => {
  const job = (id) => "projects/fireemu-oracle-sbx/locations/us-central1/jobs/fe-cal6-<run>-" + id;
  if (mode === "unknown-delete")
    return {
      ["DELETE " + job("cr01")]: async ({ state, url }) => {
        state.jobs.delete(url);
        return reply(503, { error: { code: 503, message: "later", status: "UNAVAILABLE" } });
      },
    };
  if (mode === "reflect")
    return {
      "GET projects/fireemu-oracle-sbx/releases/cloud.firestore": async () =>
        reply(200, { leaked: "test-token" }),
    };
  return {};
};

let server = fakeServer({ runId: "0".repeat(16), hooks: hooksFor() });
let bound = false;
globalThis.fetch = async (url, init) => {
  const found = /fe-cal6-([0-9a-f]{16})/.exec(url + (init?.body ?? ""));
  if (found && !bound) {
    server = fakeServer({ runId: found[1], hooks: hooksFor() });
    bound = true;
  }
  return server.send({ ...init, url });
};
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...rest) => realSetTimeout(fn, ms >= 1000 ? 0 : ms, ...rest);
