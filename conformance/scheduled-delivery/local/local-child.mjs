// The process `fireemu exec` runs next to the daemon in a local comparison: it drives the virtual clock in whole
// seconds through the control API and prints one `STEP <instant>` line after each step, so that the handler lines the
// daemon forwards can be placed on the logical timeline. Loopback only; the control token comes from the daemon.
//
// `LOCAL_MANUAL` lists functions run by hand before the clock moves; `LOCAL_MANUAL_AT` (`name@step,...`) runs one by hand
// right after a step; each is printed as `MANUAL <name> <instant> <answer>` with the logical instant it was made at.
// `LOCAL_CLOCK_FILE` is a file that holds the logical epoch seconds the clock is about to move to (written before each
// advance, and with the start before a manual run), for a handler that must last logical rather than real time.
// `LOCAL_PULL_TOPICS` (comma-separated topic ids, with `LOCAL_PROJECT` and `PUBSUB_EMULATOR_HOST`) puts a pull
// subscription on each topic before anything runs (`SUBSCRIBED <topic> <status>`) and pulls each once after the last
// step (`PULLED {"topic", "status", "messages": [{messageId, publishTime, attributes, data?}]}`): what the topic held,
// or the status of the subscribe that refused (a topic that does not exist) with no messages.
import { writeFileSync } from "node:fs";
const url = process.env.FIREEMU_CONTROL_URL;
const token = process.env.FIREEMU_CONTROL_TOKEN;
const start = Date.parse(process.env.LOCAL_START);
const seconds = Number(process.env.LOCAL_SECONDS);
const awaitIdle = process.env.LOCAL_AWAIT_IDLE !== "0";
const pauseMs = Number(process.env.LOCAL_PAUSE_MS ?? 40);
const manual = (process.env.LOCAL_MANUAL ?? "").split(",").filter(Boolean);
const manualAt = (process.env.LOCAL_MANUAL_AT ?? "")
  .split(",")
  .filter(Boolean)
  .map((item) => {
    const [name, step] = item.split("@");
    return { name, step: Number(step) };
  });
const clockFile = process.env.LOCAL_CLOCK_FILE;
const pullTopics = (process.env.LOCAL_PULL_TOPICS ?? "").split(",").filter(Boolean);
const project = process.env.LOCAL_PROJECT;
const pubsubHost = process.env.PUBSUB_EMULATOR_HOST;
if (pullTopics.length && (!project || !pubsubHost))
  throw new Error("pull topics need LOCAL_PROJECT and PUBSUB_EMULATOR_HOST");
if (!url || !token || !Number.isFinite(start) || !Number.isInteger(seconds))
  throw new Error(
    "the local child needs the control URL and token and LOCAL_START and LOCAL_SECONDS",
  );
const call = async (path, body) => {
  const response = await fetch(new URL(path, url), {
    method: body ? "POST" : "GET",
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, json: await response.json().catch(() => null) };
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const iso = (ms) => new Date(ms).toISOString().replace(".000Z", "Z");
const writeClock = (ms) => clockFile && writeFileSync(clockFile, String(ms / 1000));
const runByHand = async (name, at) =>
  console.log(
    "MANUAL",
    name,
    at,
    JSON.stringify(await call(`sessions/default/functions/${name}:run`, {})),
  );
const pubsub = async (method, path, body) => {
  const response = await fetch(`http://${pubsubHost}/v1/projects/${project}/${path}`, {
    method,
    headers: { "content-type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, json: await response.json().catch(() => null) };
};
const subscribed = [];
for (const [index, topic] of pullTopics.entries()) {
  const answer = await pubsub("PUT", `subscriptions/watch-${index}`, {
    topic: `projects/${project}/topics/${topic}`,
    ackDeadlineSeconds: 600,
  });
  console.log("SUBSCRIBED", topic, answer.status);
  subscribed.push({ topic, index, status: answer.status });
}
writeClock(start);
for (const name of manual) await runByHand(name, iso(start));
if (awaitIdle) await call("sessions/default:awaitIdle", { timeoutSeconds: 30 });
await sleep(pauseMs * 4);
for (let step = 1; step <= seconds; step++) {
  const instant = iso(start + step * 1000);
  writeClock(start + step * 1000);
  await call("sessions/default/clock:advanceTo", { instant });
  if (awaitIdle) await call("sessions/default:awaitIdle", { timeoutSeconds: 30 });
  await sleep(pauseMs);
  console.log("STEP", instant);
  for (const entry of manualAt.filter((m) => m.step === step)) await runByHand(entry.name, instant);
}
for (const { topic, index, status } of subscribed) {
  const pulled =
    status === 200
      ? await pubsub("POST", `subscriptions/watch-${index}:pull`, { maxMessages: 1000 })
      : { status, json: null };
  const messages = (pulled.json?.receivedMessages ?? []).map((received) => received.message);
  console.log("PULLED", JSON.stringify({ topic, status: pulled.status, messages }));
}
console.log("STATE", JSON.stringify((await call("sessions/default/functions")).json));
if (process.env.LOCAL_UI_URL) {
  const response = await fetch(process.env.LOCAL_UI_URL, {
    headers: { authorization: "Bearer " + token },
  });
  if (!response.ok) throw new Error(`functions history: HTTP ${response.status}`);
  console.log("HISTORY", JSON.stringify((await response.json()).history));
}
