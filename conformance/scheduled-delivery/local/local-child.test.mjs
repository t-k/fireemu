// The process `fireemu exec` runs next to the daemon, against a fake control API: what it calls and in which order,
// the clock file a logical-time handler reads, the manual runs at a step, and the lines it prints for the timeline.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const readClock = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
};

/** Runs the child against a fake control API; resolves with its output and the calls the API saw. */
async function runChild(env, { clockFile } = {}) {
  const calls = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      calls.push({
        method: request.method,
        path: request.url,
        authorization: request.headers.authorization,
        body: body ? JSON.parse(body) : null,
        // the file may not exist yet: that is what a call made before the first write sees
        clock: clockFile ? readClock(clockFile) : null,
      });
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(request.method === "GET" ? { functions: [] } : { ok: true }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const child = spawn(process.execPath, [join(here, "local-child.mjs")], {
    env: {
      PATH: process.env.PATH,
      FIREEMU_CONTROL_URL: `http://127.0.0.1:${port}/v1/`,
      FIREEMU_CONTROL_TOKEN: "t0ken",
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.stderr.on("data", (d) => (output += d));
  // a child that never exits is a failure of the test, not a hang of the run
  const killer = setTimeout(() => child.kill("SIGKILL"), 20_000);
  const code = await new Promise((resolve) => child.on("exit", resolve));
  clearTimeout(killer);
  server.close();
  server.closeAllConnections();
  return { code, output, calls };
}
const lines = (output, prefix) => output.split("\n").filter((l) => l.startsWith(prefix));

test("it advances the clock one second at a time, waits for idle when asked, and prints one STEP line per step", async () => {
  const { code, output, calls } = await runChild({
    LOCAL_START: "2026-10-05T08:40:30Z",
    LOCAL_SECONDS: "3",
    LOCAL_AWAIT_IDLE: "1",
    LOCAL_PAUSE_MS: "1",
  });
  assert.equal(code, 0, output);
  assert.deepEqual(
    calls.map((c) => `${c.method} ${c.path}`),
    [
      "POST /v1/sessions/default:awaitIdle",
      "POST /v1/sessions/default/clock:advanceTo",
      "POST /v1/sessions/default:awaitIdle",
      "POST /v1/sessions/default/clock:advanceTo",
      "POST /v1/sessions/default:awaitIdle",
      "POST /v1/sessions/default/clock:advanceTo",
      "POST /v1/sessions/default:awaitIdle",
      "GET /v1/sessions/default/functions",
    ],
  );
  assert.ok(calls.every((c) => c.authorization === "Bearer t0ken"));
  assert.deepEqual(
    calls.filter((c) => c.path.endsWith("advanceTo")).map((c) => c.body.instant),
    ["2026-10-05T08:40:31Z", "2026-10-05T08:40:32Z", "2026-10-05T08:40:33Z"],
  );
  assert.deepEqual(calls[0].body, { timeoutSeconds: 30 });
  assert.deepEqual(lines(output, "STEP "), [
    "STEP 2026-10-05T08:40:31Z",
    "STEP 2026-10-05T08:40:32Z",
    "STEP 2026-10-05T08:40:33Z",
  ]);
  assert.match(lines(output, "STATE ")[0], /^STATE \{"functions":\[\]\}$/);
});

test("without awaitIdle it never calls awaitIdle", async () => {
  const { code, calls } = await runChild({
    LOCAL_START: "2026-10-05T08:40:30Z",
    LOCAL_SECONDS: "2",
    LOCAL_AWAIT_IDLE: "0",
    LOCAL_PAUSE_MS: "1",
  });
  assert.equal(code, 0);
  assert.equal(calls.filter((c) => c.path.endsWith("awaitIdle")).length, 0);
  assert.equal(calls.filter((c) => c.path.endsWith("advanceTo")).length, 2);
});

test("manual runs before the clock moves are printed with the instant they were made at", async () => {
  const { code, output, calls } = await runChild({
    LOCAL_START: "2026-10-05T08:40:30Z",
    LOCAL_SECONDS: "1",
    LOCAL_AWAIT_IDLE: "0",
    LOCAL_PAUSE_MS: "1",
    LOCAL_MANUAL: "a,b",
  });
  assert.equal(code, 0, output);
  assert.deepEqual(
    calls.slice(0, 3).map((c) => c.path),
    [
      "/v1/sessions/default/functions/a:run",
      "/v1/sessions/default/functions/b:run",
      "/v1/sessions/default/clock:advanceTo",
    ],
  );
  assert.deepEqual(lines(output, "MANUAL "), [
    'MANUAL a 2026-10-05T08:40:30Z {"status":200,"json":{"ok":true}}',
    'MANUAL b 2026-10-05T08:40:30Z {"status":200,"json":{"ok":true}}',
  ]);
});

test("a manual run at a step happens after that step and before the next, and is printed with that step's instant", async () => {
  const { code, output, calls } = await runChild({
    LOCAL_START: "2026-10-05T08:40:30Z",
    LOCAL_SECONDS: "4",
    LOCAL_AWAIT_IDLE: "0",
    LOCAL_PAUSE_MS: "1",
    LOCAL_MANUAL_AT: "slow@2,other@2,late@4",
  });
  assert.equal(code, 0, output);
  const order = calls.map((c) =>
    c.path.endsWith(":run") ? c.path.split("/").at(-1) : (c.body?.instant ?? "state"),
  );
  assert.deepEqual(order, [
    "2026-10-05T08:40:31Z",
    "2026-10-05T08:40:32Z",
    "slow:run",
    "other:run",
    "2026-10-05T08:40:33Z",
    "2026-10-05T08:40:34Z",
    "late:run",
    "state",
  ]);
  assert.deepEqual(
    lines(output, "MANUAL ").map((l) => l.split(" ").slice(0, 3).join(" ")),
    [
      "MANUAL slow 2026-10-05T08:40:32Z",
      "MANUAL other 2026-10-05T08:40:32Z",
      "MANUAL late 2026-10-05T08:40:34Z",
    ],
  );
  // the printed order is the call order: STEP 32, then the manual runs, then STEP 33
  const printed = output
    .split("\n")
    .filter((l) => /^(STEP|MANUAL) /.test(l))
    .map((l) => l.split(" ").slice(0, 3).join(" "));
  assert.deepEqual(printed.slice(0, 5), [
    "STEP 2026-10-05T08:40:31Z",
    "STEP 2026-10-05T08:40:32Z",
    "MANUAL slow 2026-10-05T08:40:32Z",
    "MANUAL other 2026-10-05T08:40:32Z",
    "STEP 2026-10-05T08:40:33Z",
  ]);
});

test("the clock file holds the logical epoch seconds the clock is about to move to, before each advance", async () => {
  const dir = mkdtempSync(join(tmpdir(), "local-child-test-"));
  try {
    const clockFile = join(dir, "clock.txt");
    const start = Date.parse("2026-10-05T08:40:30Z") / 1000;
    const { code, output, calls } = await runChild(
      {
        LOCAL_START: "2026-10-05T08:40:30Z",
        LOCAL_SECONDS: "3",
        LOCAL_AWAIT_IDLE: "0",
        LOCAL_PAUSE_MS: "1",
        LOCAL_MANUAL: "first",
        LOCAL_CLOCK_FILE: clockFile,
      },
      { clockFile },
    );
    assert.equal(code, 0, output);
    // a manual run before the first step sees the start; each advance sees its own target instant
    assert.equal(calls[0].path, "/v1/sessions/default/functions/first:run");
    assert.equal(calls[0].clock, String(start));
    assert.deepEqual(
      calls.filter((c) => c.path.endsWith("advanceTo")).map((c) => c.clock),
      [String(start + 1), String(start + 2), String(start + 3)],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("it refuses to start without the control URL, the token or a whole number of seconds", async () => {
  for (const env of [
    { LOCAL_START: "2026-10-05T08:40:30Z", LOCAL_SECONDS: "1.5" },
    { LOCAL_START: "not a time", LOCAL_SECONDS: "1" },
    { LOCAL_SECONDS: "1" },
  ]) {
    const { code, output } = await runChild(env);
    assert.notEqual(code, 0);
    assert.match(output, /the local child needs the control URL and token/);
  }
  const child = spawn(process.execPath, [join(here, "local-child.mjs")], {
    env: { PATH: process.env.PATH, LOCAL_START: "2026-10-05T08:40:30Z", LOCAL_SECONDS: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stderr.on("data", (d) => (output += d));
  const code = await new Promise((resolve) => child.on("exit", resolve));
  assert.notEqual(code, 0);
  assert.match(output, /the local child needs the control URL and token/);
});

/** A fake Pub/Sub REST surface: one subscription per topic that holds the messages it is given. */
async function fakePubSub(messagesByTopic, missingTopics = []) {
  const calls = [];
  const subscriptions = new Map();
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      const json = body ? JSON.parse(body) : null;
      calls.push({ method: request.method, path: request.url, body: json });
      response.setHeader("content-type", "application/json");
      const put = /^\/v1\/projects\/([^/]+)\/subscriptions\/([^/:]+)$/.exec(request.url);
      if (request.method === "PUT" && put) {
        const topic = json.topic.split("/").at(-1);
        if (missingTopics.includes(topic)) {
          response.statusCode = 404;
          return response.end(JSON.stringify({ error: { code: 404, status: "NOT_FOUND" } }));
        }
        subscriptions.set(put[2], topic);
        return response.end(JSON.stringify({ name: json.name ?? put[2], topic: json.topic }));
      }
      const pull = /^\/v1\/projects\/([^/]+)\/subscriptions\/([^/:]+):pull$/.exec(request.url);
      if (request.method === "POST" && pull) {
        const messages = messagesByTopic[subscriptions.get(pull[2])] ?? [];
        return response.end(
          JSON.stringify(
            messages.length
              ? { receivedMessages: messages.map((message) => ({ ackId: "a", message })) }
              : {},
          ),
        );
      }
      response.statusCode = 404;
      response.end("{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    host: `127.0.0.1:${server.address().port}`,
    calls,
    close: () => {
      server.close();
      server.closeAllConnections();
    },
  };
}

test("with pull topics it subscribes before the clock moves and pulls once after the last step, printing what each topic held", async () => {
  const topicA = "firebase-schedule-schedOkV1-us-central1";
  const topicB = "firebase-schedule-schedFailV1-us-central1";
  const message = {
    messageId: "21339796619509982",
    publishTime: "2026-10-05T08:40:31.123Z",
    attributes: { scheduled: "true" },
  };
  const pubsub = await fakePubSub({ [topicA]: [message] }, [topicB]);
  try {
    const { code, output, calls } = await runChild({
      LOCAL_START: "2026-10-05T08:40:30Z",
      LOCAL_SECONDS: "2",
      LOCAL_AWAIT_IDLE: "0",
      LOCAL_PAUSE_MS: "1",
      LOCAL_PROJECT: "demo-sched",
      LOCAL_PULL_TOPICS: `${topicA},${topicB}`,
      PUBSUB_EMULATOR_HOST: pubsub.host,
    });
    assert.equal(code, 0, output);
    assert.deepEqual(
      pubsub.calls.map((c) => `${c.method} ${c.path}`),
      [
        "PUT /v1/projects/demo-sched/subscriptions/watch-0",
        "PUT /v1/projects/demo-sched/subscriptions/watch-1",
        "POST /v1/projects/demo-sched/subscriptions/watch-0:pull",
      ],
      "a topic that could not be subscribed to is not pulled",
    );
    assert.deepEqual(pubsub.calls[0].body, {
      topic: `projects/demo-sched/topics/${topicA}`,
      ackDeadlineSeconds: 600,
    });
    assert.deepEqual(pubsub.calls[2].body, { maxMessages: 1000 });
    // the subscriptions exist before the first step, and the pull comes after the last
    const order = [...calls.map((c) => c.path.split("/").at(-1))];
    assert.deepEqual(order, ["clock:advanceTo", "clock:advanceTo", "functions"]);
    assert.deepEqual(lines(output, "SUBSCRIBED "), [
      `SUBSCRIBED ${topicA} 200`,
      `SUBSCRIBED ${topicB} 404`,
    ]);
    const pulled = lines(output, "PULLED ").map((l) => JSON.parse(l.slice("PULLED ".length)));
    assert.deepEqual(pulled, [
      { topic: topicA, status: 200, messages: [message] },
      { topic: topicB, status: 404, messages: [] },
    ]);
    // the pull lines come before the STATE line (the last line)
    const text = output.split("\n").filter(Boolean);
    assert.ok(
      text.findIndex((l) => l.startsWith("PULLED ")) <
        text.findIndex((l) => l.startsWith("STATE ")),
    );
  } finally {
    pubsub.close();
  }
});

test("without pull topics it makes no Pub/Sub call and prints no SUBSCRIBED or PULLED line", async () => {
  const pubsub = await fakePubSub({});
  try {
    const { code, output } = await runChild({
      LOCAL_START: "2026-10-05T08:40:30Z",
      LOCAL_SECONDS: "1",
      LOCAL_AWAIT_IDLE: "0",
      LOCAL_PAUSE_MS: "1",
      PUBSUB_EMULATOR_HOST: pubsub.host,
    });
    assert.equal(code, 0, output);
    assert.deepEqual(pubsub.calls, []);
    assert.deepEqual(lines(output, "SUBSCRIBED "), []);
    assert.deepEqual(lines(output, "PULLED "), []);
  } finally {
    pubsub.close();
  }
});

test("pull topics need the project and the Pub/Sub host", async () => {
  const { code, output } = await runChild({
    LOCAL_START: "2026-10-05T08:40:30Z",
    LOCAL_SECONDS: "1",
    LOCAL_PULL_TOPICS: "t",
  });
  assert.notEqual(code, 0);
  assert.match(output, /LOCAL_PROJECT|PUBSUB_EMULATOR_HOST/);
});
