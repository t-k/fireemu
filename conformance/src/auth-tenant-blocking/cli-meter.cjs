// Counts and caps the external HTTP requests of a deployment subprocess (the pinned Firebase CLI,
// npm) for the campaign's single request budget (issue auth-tenant-campaign-total-request-cap).
//
// Loaded with `--require` through NODE_OPTIONS, so the CLI and every Node process it spawns count
// into one file: each request appends one byte before it is sent, and the file's size is the
// count. A request that would pass FIREEMU_CLI_METER_LIMIT kills its process before anything is
// sent (SIGKILL: the CLI cannot catch it and carry on). The meter sees the requests through the
// diagnostics channels Node and undici publish when a request is created: `fetch` and the
// CLI's own undici (`undici:request:create`), and `http`/`https` (`http.client.request.created`,
// which google-auth-library and npm use). Loopback requests (the CLI's local discovery of the
// functions' triggers) are not external and are not counted. A meter that cannot record kills
// its process too: an uncounted request is never sent.
"use strict";

const diagnostics = require("node:diagnostics_channel");
const fs = require("node:fs");

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/** Whether a request to `host` (a hostname, maybe with a port) leaves the machine. */
function isExternal(host) {
  if (typeof host !== "string" || host === "") return true;
  const name = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
  return !LOOPBACK.has(name.toLowerCase());
}

function hostOfUndici(request) {
  try {
    return new URL(request.origin).host;
  } catch {
    return undefined;
  }
}

function hostOfHttp(request) {
  try {
    return request.getHeader("host") ?? request.host;
  } catch {
    return undefined;
  }
}

function install(env = process.env) {
  const file = env.FIREEMU_CLI_METER_FILE;
  const limit = Number(env.FIREEMU_CLI_METER_LIMIT);
  const countLoopback = env.FIREEMU_CLI_METER_COUNT_LOOPBACK === "1";
  if (!file) return;
  const stop = (why) => {
    try {
      fs.writeSync(2, `cli-meter: ${why}; stopping before the request is sent\n`);
    } finally {
      process.kill(process.pid, "SIGKILL");
    }
  };
  if (!Number.isInteger(limit) || limit < 0) stop(`limit ${env.FIREEMU_CLI_METER_LIMIT}`);
  const charge = (host) => {
    if (!countLoopback && !isExternal(host)) return;
    let count;
    try {
      const fd = fs.openSync(file, "a", 0o600);
      try {
        fs.writeSync(fd, ".");
        count = fs.fstatSync(fd).size;
      } finally {
        fs.closeSync(fd);
      }
    } catch (error) {
      stop(`cannot record a request (${error.code ?? error.message})`);
    }
    if (count > limit) stop(`request ${count} would pass the allowance of ${limit}`);
  };
  diagnostics.subscribe("undici:request:create", ({ request }) => charge(hostOfUndici(request)));
  diagnostics.subscribe("http.client.request.created", ({ request }) =>
    charge(hostOfHttp(request)),
  );
}

module.exports = { isExternal, install };

if (process.env.FIREEMU_CLI_METER_FILE) install();
