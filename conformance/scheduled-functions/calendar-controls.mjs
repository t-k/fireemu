// Negative-control fixtures for the stage3 launch-accounting harness (design v4 section 7). They
// are generated text run by the Functions runner during discovery; nothing here starts a process.
import { calendarFixture } from "./calendar-local.mjs";

/** Which fixture variant, escalation setting and named rule each negative control uses. */
export const CONTROL_VARIANTS = Object.freeze({
  orphan: Object.freeze({ fixture: "refusal", escalation: "off", rule: "session" }),
  escaper: Object.freeze({ fixture: "valid", escalation: "off", rule: "identity" }),
  listener: Object.freeze({ fixture: "refusal", escalation: "off", rule: "port" }),
  leftover: Object.freeze({ fixture: "valid", escalation: "on", rule: "harness-signal" }),
});

/**
 * CommonJS run first during discovery: start the helper, wait for its ready file (written once
 * it has left the runner's process group, F1), then block a further second so polling observes
 * the lineage before discovery returns (F2).
 */
export function controlPreamble({ mode, helperPath, readyPath, hold, portFile, boundPath }) {
  if (!Object.hasOwn(CONTROL_VARIANTS, mode)) throw new Error("unknown control mode");
  if (![helperPath, readyPath].every((path) => typeof path === "string" && path.startsWith("/")))
    throw new Error("control paths must be absolute");
  if (!Number.isFinite(hold) || hold <= 0) throw new Error("control hold must be positive");
  const args =
    mode === "listener"
      ? [mode, readyPath, portFile, boundPath, String(hold)]
      : [mode, readyPath, String(hold)];
  return `"use strict";
const { spawn } = require("node:child_process");
const { existsSync } = require("node:fs");
const helper = spawn("python3", ${JSON.stringify([helperPath, ...args])}, { stdio: "ignore" });
helper.unref();
const pause = new Int32Array(new SharedArrayBuffer(4));
const until = Date.now() + 10000;
while (!existsSync(${JSON.stringify(readyPath)})) {
  if (Date.now() > until) throw new Error("control helper did not become ready");
  Atomics.wait(pause, 0, 0, 20);
}
Atomics.wait(pause, 0, 0, 1000);
`;
}

/** A control fixture: the refusal or valid fixture, with the control preamble required first. */
export function controlFixture(input, control) {
  return {
    index: 'require("./controls.cjs");\n' + calendarFixture(input),
    controls: controlPreamble(control),
  };
}
