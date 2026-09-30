// Offline comparison of recorded native calendar answers with actual local callback receipts.
import { createHash } from "node:crypto";
import { calendarRequests, CALENDAR_CASES } from "./calendar.mjs";

const nanos = (value) => {
  const match =
    typeof value === "string" &&
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(
      value,
    );
  if (!match) throw new Error("invalid calendar proof instant");
  const milliseconds = Date.parse(match[1] + match[3]);
  const offset =
    match[3] === "Z"
      ? 0
      : (match[3][0] === "+" ? 1 : -1) *
        (Number(match[3].slice(1, 3)) * 60 + Number(match[3].slice(4))) *
        60000;
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds + offset).toISOString().slice(0, 19) !== match[1]
  )
    throw new Error("invalid calendar proof instant");
  return BigInt(milliseconds) * 1000000n + BigInt((match[2] ?? "").padEnd(9, "0"));
};
export { nanos as calendarInstantNanos };
const instant = (value) => Number(nanos(value) / 1000000n);
const formatNanos = (value) => {
  const seconds = value / 1000000000n;
  return (
    new Date(Number(seconds) * 1000).toISOString().replace(/\.000Z$/, "") +
    "." +
    String(value % 1000000000n).padStart(9, "0") +
    "Z"
  );
};

export function localCalendarClient({ controlUrl, functionsHost, token, send = fetch }) {
  const local = (value) => {
    const url = new URL(value);
    if (
      url.protocol !== "http:" ||
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
      !url.port ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error("calendar endpoint must be a loopback HTTP origin");
    return url;
  };
  const control = local(controlUrl),
    functions = local("http://" + functionsHost);
  if (
    control.pathname !== "/v1/" ||
    functions.pathname !== "/" ||
    typeof token !== "string" ||
    !token ||
    /[\r\n]/.test(token)
  )
    throw new Error("invalid local calendar control configuration");
  const answer = async (url, options) => {
    const response = await send(url, {
      ...options,
      redirect: "error",
      signal: AbortSignal.timeout(35000),
    });
    if (!response.body) throw new Error("missing local calendar response body");
    const parts = [];
    let length = 0;
    for await (const chunk of response.body) {
      length += chunk.byteLength;
      if (length > 1048576) throw new Error("local calendar response exceeds byte bound");
      parts.push(Buffer.from(chunk));
    }
    return { status: response.status, json: JSON.parse(Buffer.concat(parts).toString("utf8")) };
  };
  return {
    control: async (path, body) => {
      if (
        ![
          "sessions/default/functions",
          "sessions/default:awaitIdle",
          "sessions/default/clock:advanceTo",
        ].includes(path)
      )
        throw new Error("unknown local calendar control route");
      return answer(new URL(path, control), {
        method: body ? "POST" : "GET",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    },
    receipts: async () => {
      const response = await answer(
        new URL("demo-scheduled-calendar/us-central1/calendarReceipt", functions),
        { method: "GET", headers: {} },
      );
      if (response.status !== 200) throw new Error("local calendar receipt reader refused");
      return response.json;
    },
  };
}

export function nativeCalendarInput({ journal, runId, projectNumber, caseId }) {
  const item = CALENDAR_CASES.find((row) => row.id === caseId);
  if (!item || !Array.isArray(journal)) throw new Error("unknown native calendar case");
  const rows = journal.filter((row) => row.id === caseId + "-create");
  if (
    rows.length !== 3 ||
    rows.map((row) => row.state).join(",") !== "before-send,response-headers,response-persisted"
  )
    throw new Error("incomplete or duplicate native calendar journal");
  const [request, headers, response] = rows;
  const dispatch = nanos(request.dispatchAt),
    received = nanos(headers.responseAt),
    persisted = nanos(response.responseAt);
  const spec = calendarRequests(runId, projectNumber, instant(request.dispatchAt)).find(
    (row) => row.id === request.id,
  );
  if (
    request.method !== spec.method ||
    request.url !== spec.url ||
    JSON.stringify(request.json) !== JSON.stringify(spec.json) ||
    headers.status !== 200 ||
    response.status !== 200 ||
    response.dispatchAt !== request.dispatchAt ||
    dispatch > received ||
    received > persisted
  )
    throw new Error("native calendar request or response proof differs");
  if (typeof response.bodyBase64 !== "string") throw new Error("missing native calendar body");
  const bytes = Buffer.from(response.bodyBase64, "base64");
  if (bytes.toString("base64") !== response.bodyBase64 || bytes.length !== response.bodyBytes)
    throw new Error("native calendar body byte proof differs");
  let body;
  try {
    body = JSON.parse(bytes);
  } catch {
    throw new Error("invalid native calendar body");
  }
  if (
    body?.name !== spec.json.name ||
    body?.schedule !== item.schedule ||
    body?.timeZone !== item.timeZone ||
    body?.state !== "ENABLED" ||
    body?.pubsubTarget?.topicName !== spec.json.pubsubTarget.topicName ||
    body?.pubsubTarget?.data !== spec.json.pubsubTarget.data
  )
    throw new Error("native calendar resource identity differs");
  const next = nanos(body.scheduleTime);
  if (next <= dispatch) throw new Error("native calendar next time does not follow dispatch");
  return {
    caseId,
    schedule: item.schedule,
    timeZone: item.timeZone,
    scheduleTime: body.scheduleTime,
    anchors: [request.dispatchAt, headers.responseAt],
    bracketCrossesAdvertisedTime: next <= received,
    bodySha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

export function calendarFixture({ schedule, timeZone }) {
  if (typeof schedule !== "string" || typeof timeZone !== "string")
    throw new Error("invalid calendar fixture declaration");
  return `const { onSchedule } = require("firebase-functions/v2/scheduler");\nconst { onRequest } = require("firebase-functions/v2/https");\nconst receipts = [];\nexports.calendarProbe = onSchedule(${JSON.stringify({ schedule, timeZone })}, async (event) => { if (receipts.length >= 8) throw new Error("receipt bound exceeded"); receipts.push({ sequence: receipts.length + 1, scheduleTime: event.scheduleTime, jobName: event.jobName ?? null }); });\nexports.calendarReceipt = onRequest((_req, res) => res.json(receipts));\n`;
}

export async function exerciseCalendarSession({ input, anchor, control, receipts }) {
  const next = nanos(input.scheduleTime),
    start = nanos(anchor);
  const evidence = [];
  const result = (reason, observed = []) => ({
    matched: reason === null,
    reason,
    anchor,
    scheduleTime: input.scheduleTime,
    evidence,
    receipts: observed,
  });
  if (start >= next) return result("creation bracket crosses advertised boundary");
  const request = async (path, body) => {
    const answer = await control(path, body);
    evidence.push({ path, ...(body ? { body } : {}), status: answer?.status });
    if (answer?.status !== 200) throw new Error("local calendar control request refused");
    return answer.json;
  };
  const idle = async () => {
    const status = await request("sessions/default:awaitIdle", { timeoutSeconds: 30 });
    if (status?.idle !== true) throw new Error("local calendar runtime did not become idle");
  };
  const read = async () => {
    await idle();
    const rows = await receipts();
    if (!Array.isArray(rows) || rows.length > 8) throw new Error("invalid local calendar receipts");
    return rows;
  };
  let observed = [];
  try {
    const runtime = await request("sessions/default/functions");
    if (runtime?.runnerAlive !== true) return result("local calendar runner is absent or down");
    if (
      !Array.isArray(runtime.functions) ||
      !["calendarProbe", "calendarReceipt"].every((name) => runtime.functions.includes(name))
    )
      return result("local calendar exports are missing");
    observed = await read();
    if (observed.length !== 0) return result("callback already ran at anchor", observed);
    const before = next - 1n;
    if (before > start)
      await request("sessions/default/clock:advanceTo", {
        instant: formatNanos(before),
      });
    observed = await read();
    if (observed.length !== 0) return result("callback ran before advertised boundary", observed);
    await request("sessions/default/clock:advanceTo", { instant: input.scheduleTime });
    observed = await read();
    if (observed.length !== 1 || nanos(observed[0].scheduleTime) !== next)
      return result("callback count or supplied time differs", observed);
    await request("sessions/default/clock:advanceTo", { instant: input.scheduleTime });
    observed = await read();
    if (observed.length !== 1 || nanos(observed[0].scheduleTime) !== next)
      return result("duplicate callback or supplied time differs", observed);
    return result(null, observed);
  } catch (error) {
    return result(error.message, observed);
  }
}
