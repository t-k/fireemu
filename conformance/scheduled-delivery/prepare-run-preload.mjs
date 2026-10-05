// Test support for the preparation runner: loaded with `node --import` into the runner's own
// process, it answers every request from the fake instead of the network and makes long waits
// instant. Not part of the packet; it sends nothing.
import { fakeServer, reply } from "./prepare-fake.mjs";

const mode = process.env.FAKE_MODE ?? "clean";
const hooks = {};
if (mode === "unknown-enable")
  hooks["POST v1/projects/<number>/services:batchEnable"] = async () =>
    reply(503, { error: { code: 503, message: "later", status: "UNAVAILABLE" } });
if (mode === "reflect")
  hooks["GET v1/projects/fireemu-oracle-sbx/releases/cloud.firestore"] = async () =>
    reply(200, { leaked: "test-token" });
if (mode === "denied")
  hooks["POST v1/projects/<number>/services:batchEnable"] = async () =>
    reply(403, { error: { code: 403, message: "denied", status: "PERMISSION_DENIED" } });
const server = fakeServer({ hooks });
globalThis.fetch = async (url, init) => server.send({ ...init, url });
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...rest) => realSetTimeout(fn, ms >= 1000 ? 0 : ms, ...rest);
