// One side of the Pub/Sub probe: it runs the identical program list against whichever
// emulator PUBSUB_EMULATOR_HOST names (the official Cloud Pub/Sub emulator on the oracle side,
// fireemu on the other) and writes its observations to PUBSUB_PROBE_OUT. The supervisor
// (run.mjs) starts each emulator and diffs the two run files.

import { writeFile } from "node:fs/promises";

import { PubSub } from "@google-cloud/pubsub";

import { PROGRAMS } from "./programs.mjs";

const project = process.env.PUBSUB_PROBE_PROJECT || "demo-pubsub-probe";
const outPath = process.env.PUBSUB_PROBE_OUT;
const emulatorHost = process.env.PUBSUB_EMULATOR_HOST;
const side = process.env.PUBSUB_PROBE_SIDE;

async function advanceClock(seconds) {
  if (side === "oracle") return;
  if (side !== "fireemu") throw new Error("Pub/Sub probe side is not configured");
  const control = new URL(process.env.FIREEMU_CONTROL_URL);
  if (!["127.0.0.1", "localhost", "[::1]"].includes(control.hostname)) {
    throw new Error("control API must be loopback");
  }
  const token = process.env.FIREEMU_CONTROL_TOKEN;
  if (!token) throw new Error("fireemu control token is missing");
  const response = await fetch(`${control.origin}/v1/sessions/default/clock:advance`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ seconds }),
  });
  if (!response.ok) throw new Error(`clock advance failed: ${response.status}`);
}

async function rest(method, path, body = {}) {
  const init = {
    method,
    headers: { "content-type": "application/json" },
  };
  if (method !== "GET" && method !== "HEAD") init.body = JSON.stringify(body);
  const response = await fetch(`http://${emulatorHost}${path}`, init);
  const text = await response.text();
  let responseBody = {};
  if (text !== "") {
    try {
      responseBody = JSON.parse(text);
    } catch {
      responseBody = { raw: text };
    }
  }
  return { status: response.status, body: responseBody };
}

/**
 * Collects up to `n` messages from a subscription within a bounded window, then either acks or
 * nacks each and closes the stream. The window is a delivery cadence only; it never decides an
 * ack deadline.
 */
function receiveFactory() {
  return (sub, n, action, ms = 2500) =>
    new Promise((resolve) => {
      const got = [];
      const finish = () => {
        sub.removeAllListeners("message");
        sub.removeAllListeners("error");
        sub.close().catch(() => {});
        resolve(got);
      };
      const timer = setTimeout(finish, ms);
      sub.on("error", () => {});
      sub.on("message", (m) => {
        got.push(m);
        if (action === "nack") m.nack();
        else m.ack();
        if (got.length >= n) {
          clearTimeout(timer);
          // Give the ack/nack a moment to flush before closing the stream.
          setTimeout(finish, 150);
        }
      });
    });
}

async function main() {
  const result = { programs: {} };
  for (const program of PROGRAMS) {
    // A fresh client per program keeps subscription streams from leaking across programs.
    const pubsub = new PubSub({ projectId: project });
    const ctx = { project, pubsub, receive: receiveFactory(), rest, advanceClock };
    try {
      const steps = await program.run(ctx);
      result.programs[program.id] = {
        area: program.area,
        order: Object.keys(steps),
        steps,
      };
    } catch (err) {
      result.programs[program.id] = {
        area: program.area,
        order: ["fault"],
        steps: { fault: { message: String(err?.message || err) } },
        fault: String(err?.message || err),
      };
    } finally {
      await pubsub.close().catch(() => {});
    }
  }
  await writeFile(outPath, `${JSON.stringify(result, null, 2)}\n`);
}

await main();
