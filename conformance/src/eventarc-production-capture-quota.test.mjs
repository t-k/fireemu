import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { createRawRest as createRest } from "./eventarc-production/rest.mjs";

async function server() {
  const http = createServer((_, response) => response.end("{}"));
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${http.address().port}`, close: () => http.close() };
}

test("a captured request records the quota project exactly when the header was sent with it", async (t) => {
  const s = await server();
  t.after(s.close);
  const lines = [];
  const make = (extra) =>
    createRest({
      base: s.base,
      budget: createBudget(10),
      capture: createCapture({ journal: { write: (line) => lines.push(line) } }),
      ...extra,
    });
  const request = (rest, token) =>
    rest.request({ label: {}, op: "x", method: "GET", path: "/a", ...(token ? { token } : {}) });
  // A credential and a quota project: the header goes out and the entry names it.
  await request(make({ getToken: async () => "ya29.token", quotaProject: "demo-project" }));
  // A deliberately invalid credential still carries the header.
  await request(
    make({ getToken: async () => "ya29.token", quotaProject: "demo-project" }),
    "invalid",
  );
  // No credential: no header, nothing recorded. No quota project: nothing recorded.
  await request(make({ getToken: async () => "ya29.token", quotaProject: "demo-project" }), "none");
  await request(make({ getToken: async () => "ya29.token" }));
  await request(make({}));
  assert.deepEqual(
    lines.map((line) => line.quotaProject),
    ["demo-project", "demo-project", undefined, undefined, undefined],
  );
});
