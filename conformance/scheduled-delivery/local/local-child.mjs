// The process `fireemu exec` runs next to the daemon in a local comparison: it drives the virtual clock in whole
// seconds through the control API and prints one `STEP <instant>` line after each step, so that the handler lines the
// daemon forwards can be placed on the logical timeline. Loopback only; the control token comes from the daemon.
const url = process.env.FIREEMU_CONTROL_URL;
const token = process.env.FIREEMU_CONTROL_TOKEN;
const start = Date.parse(process.env.LOCAL_START);
const seconds = Number(process.env.LOCAL_SECONDS);
const awaitIdle = process.env.LOCAL_AWAIT_IDLE !== "0";
const pauseMs = Number(process.env.LOCAL_PAUSE_MS ?? 40);
const manual = (process.env.LOCAL_MANUAL ?? "").split(",").filter(Boolean);
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
for (const name of manual)
  console.log(
    "MANUAL",
    name,
    JSON.stringify(await call(`sessions/default/functions/${name}:run`, {})),
  );
if (awaitIdle) await call("sessions/default:awaitIdle", { timeoutSeconds: 30 });
await sleep(pauseMs * 4);
for (let step = 1; step <= seconds; step++) {
  const instant = new Date(start + step * 1000).toISOString().replace(".000Z", "Z");
  await call("sessions/default/clock:advanceTo", { instant });
  if (awaitIdle) await call("sessions/default:awaitIdle", { timeoutSeconds: 30 });
  await sleep(pauseMs);
  console.log("STEP", instant);
}
console.log("STATE", JSON.stringify((await call("sessions/default/functions")).json));
