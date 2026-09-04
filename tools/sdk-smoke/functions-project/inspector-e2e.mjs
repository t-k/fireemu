import assert from "node:assert/strict";

const inspectorPort = Number(process.argv[2]);
const control = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
const functionsHost = process.env.FIREEMU_FUNCTIONS_HOST;
const project = process.env.GOOGLE_CLOUD_PROJECT;

assert.ok(Number.isInteger(inspectorPort), "the inspector port argument is required");
assert.ok(control, "FIREEMU_CONTROL_URL is required");
assert.ok(controlToken, "FIREEMU_CONTROL_TOKEN is required");
assert.ok(functionsHost, "FIREEMU_FUNCTIONS_HOST is required");
assert.ok(project, "GOOGLE_CLOUD_PROJECT is required");

const signal = AbortSignal.timeout(10_000);
const targets = await fetch(`http://127.0.0.1:${inspectorPort}/json/list`, { signal });
assert.equal(targets.status, 200);
const targetList = await targets.json();
assert.ok(Array.isArray(targetList) && targetList.length > 0, "Node inspector has no targets");
assert.match(targetList[0].webSocketDebuggerUrl, /^ws:\/\/127\.0\.0\.1:/);

const controlHeaders = {
  authorization: `Bearer ${controlToken}`,
  "content-type": "application/json",
};
const runs = ["alpha", "beta"].map((name) =>
  fetch(`${control}sessions/default/functions/${name}:run`, {
    method: "POST",
    headers: controlHeaders,
    body: "{}",
    signal,
  }),
);
runs.push(
  fetch(`http://${functionsHost}/${project}/us-central1/http`, {
    method: "POST",
    signal,
  }),
);
// Debug mode disables the deployed function timeout so breakpoints do not kill the runtime.
runs.push(
  fetch(`http://${functionsHost}/${project}/us-central1/slowHttp`, {
    method: "POST",
    signal,
  }),
);
const responses = await Promise.all(runs);
for (const response of responses) assert.equal(response.status, 200);

const idle = await fetch(`${control}sessions/default:awaitIdle`, {
  method: "POST",
  headers: controlHeaders,
  body: JSON.stringify({ timeoutSeconds: 5 }),
  signal,
});
assert.equal(idle.status, 200);
