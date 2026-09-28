// Shared plumbing for the real-browser Listen runners: a loopback static file
// server for the smoke pages, a headless Chromium owned by this process, and a
// WebChannel request log taken from the page's own network view.
//
// Nothing here talks to production. The server binds 127.0.0.1 on an
// OS-assigned port, serves only files under the mounted directories, never
// follows a `..` segment and never follows a symlink out of a mount: the real
// path of every target is checked against the real path of its mount root and
// the file is opened by that checked real path. The browser is launched with a
// throwaway profile and closed on every exit path through `closeAll`; the
// runner's tests check with `pgrep` that no Chromium survives it.

import { constants as fsConstants, promises as fs } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import path from "node:path";

const CONTENT_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
});

/** True when `candidate` is `root` itself or lies below it (both already normalised). */
const isWithin = (root, candidate) => candidate === root || candidate.startsWith(root + path.sep);

/**
 * Map a request path onto one of the mounted directories lexically: the
 * decoded path, the mount it belongs to and the target path under that
 * mount's root, or null. This is only the first gate; `openMounted` checks the
 * real path once the file system is consulted.
 */
export const resolveMountedEntry = (mounts, urlPath) => {
  if (typeof urlPath !== "string" || !urlPath.startsWith("/") || urlPath.includes("\0")) return null;
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (decoded.includes("\0") || decoded.includes("\\")) return null;
  const segments = decoded.split("/").slice(1);
  if (segments.some((segment) => segment === "." || segment === "..")) return null;
  // Longest mount prefix wins so `/collector/` is not shadowed by `/`.
  const entries = Object.entries(mounts).sort((a, b) => b[0].length - a[0].length);
  for (const [prefix, root] of entries) {
    if (!decoded.startsWith(prefix)) continue;
    const relative = decoded.slice(prefix.length);
    const absoluteRoot = path.resolve(root);
    const target = path.resolve(absoluteRoot, relative);
    if (!isWithin(absoluteRoot, target)) return null;
    return { prefix, root: absoluteRoot, target };
  }
  return null;
};

/** Map a request path onto one of the mounted directories, or null. */
export const resolveMounted = (mounts, urlPath) => resolveMountedEntry(mounts, urlPath)?.target ?? null;

/**
 * Open a lexically resolved target for reading only if its real path (every
 * symlink on the way followed) stays under the mount's real root. The handle
 * is opened by that real path with `O_NOFOLLOW`, so the path that was checked
 * is the path that is read. Returns null for anything that is not a regular
 * file inside the mount.
 */
export const openMounted = async (realRoot, target) => {
  let real;
  try {
    real = await fs.realpath(target);
  } catch {
    return null;
  }
  if (!isWithin(realRoot, real)) return null;
  let handle;
  try {
    handle = await fs.open(real, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error("not a regular file");
    return { handle, size: info.size };
  } catch {
    await handle.close().catch(() => {});
    return null;
  }
};

/**
 * Serve the mounted directories read-only on 127.0.0.1 with an OS-assigned
 * port. `mounts` maps URL prefixes (ending in `/`) to directories.
 */
export const serveStatic = async (mounts) => {
  // The real root is fixed at start so a later symlink swap under the mount
  // cannot widen what is served.
  const realRoots = {};
  for (const [prefix, root] of Object.entries(mounts)) {
    if (!prefix.startsWith("/") || !prefix.endsWith("/")) throw new Error(`mount prefix must be /.../: ${prefix}`);
    if (!(await fs.stat(root)).isDirectory()) throw new Error(`mount root is not a directory: ${prefix}`);
    realRoots[prefix] = await fs.realpath(root);
  }
  const sockets = new Set();
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { allow: "GET, HEAD" });
      response.end();
      return;
    }
    const entry = resolveMountedEntry(mounts, url.pathname);
    const contentType = entry ? CONTENT_TYPES[path.extname(entry.target)] : undefined;
    const opened = entry && contentType ? await openMounted(realRoots[entry.prefix], entry.target) : null;
    if (!opened) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("not found");
      return;
    }
    response.writeHead(200, {
      "content-type": contentType,
      "content-length": String(opened.size),
      "cache-control": "no-store",
    });
    if (request.method === "HEAD") {
      response.end();
      await opened.handle.close().catch(() => {});
      return;
    }
    // The stream owns the handle and closes it when the response ends.
    opened.handle.createReadStream().pipe(response);
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    port,
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
};

/** Load Playwright from the browser package directory and launch Chromium. */
export const launchChromium = async (playwrightDir, { userDataMarker } = {}) => {
  const require = createRequire(path.join(playwrightDir, "noop.cjs"));
  const { chromium } = require("playwright");
  const args = userDataMarker ? [`--fireemu-run=${userDataMarker}`] : [];
  const browser = await chromium.launch({ headless: true, args });
  return {
    name: "chromium",
    version: browser.version(),
    executable: path.basename(chromium.executablePath()),
    browser,
    close: () => browser.close(),
  };
};

const FIRESTORE_PATH = /\/google\.firestore\.v1\.Firestore\/(Listen|Write)\/channel$/;

/**
 * Normalise one WebChannel request the page issued to the emulator. Only the
 * protocol shape is kept: stream, method, the handshake/forward/backchannel
 * role, whether a session id was attached and the `CI` flag that separates
 * long polling (`1`) from a streamed backchannel (`0`). Session ids, bodies
 * and headers, which can carry the ID token, are never recorded.
 */
export const classifyWebChannelRequest = ({ url, method }, firestorePort) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.hostname !== "127.0.0.1" || Number(parsed.port) !== firestorePort) return null;
  const match = FIRESTORE_PATH.exec(parsed.pathname);
  if (!match) return null;
  const params = parsed.searchParams;
  const rid = params.get("RID");
  const type = params.get("TYPE");
  const role =
    type === "terminate" ? "terminate"
    : rid === "rpc" ? "backchannel"
    : params.get("SID") ? "forward"
    : "handshake";
  const ci = params.get("CI");
  return {
    stream: match[1],
    method,
    role,
    hasSession: params.has("SID"),
    ci: ci === null ? null : Number(ci),
    retry: params.has("t") ? Number(params.get("t")) : null,
  };
};

/** Attach a request log to a page for the emulator's Firestore WebChannel routes. */
export const captureWebChannel = (page, firestorePort, now = () => Math.trunc(performance.now())) => {
  const rows = [];
  page.on("request", (request) => {
    const row = classifyWebChannelRequest({ url: request.url(), method: request.method() }, firestorePort);
    if (!row) return;
    const entry = { atMs: now(), ...row, status: null };
    rows.push(entry);
    request.response().then(
      (response) => {
        entry.status = response ? response.status() : null;
      },
      () => {},
    );
  });
  return {
    rows,
    summary: () => summarizeWebChannel(rows),
  };
};

/** Column order of the compact request rows a receipt stores. */
export const REQUEST_ROW_COLUMNS = Object.freeze(["atMs", "stream", "method", "role", "ci", "status"]);

/**
 * Compact rows for a receipt: one space-separated line per request in column
 * order (`-` for an absent value), so a receipt with hundreds of requests stays
 * small. No session data is included.
 */
export const compactWebChannelRows = (rows, limit = 4000) =>
  rows.slice(0, limit).map((row) =>
    REQUEST_ROW_COLUMNS.map((column) => (row[column] === null || row[column] === undefined ? "-" : String(row[column]))).join(" "),
  );

/** Inverse of `compactWebChannelRows` for one line. */
export const parseWebChannelRow = (line) => {
  const parts = String(line).split(" ");
  if (parts.length !== REQUEST_ROW_COLUMNS.length) throw new Error("malformed request row");
  const numeric = new Set(["atMs", "ci", "status"]);
  return Object.fromEntries(REQUEST_ROW_COLUMNS.map((column, index) => [column,
    parts[index] === "-" ? null : numeric.has(column) ? Number(parts[index]) : parts[index]]));
};

export const summarizeWebChannel = (rows) => {
  const count = (predicate) => rows.filter(predicate).length;
  const backchannel = rows.filter((row) => row.role === "backchannel");
  return {
    requests: rows.length,
    listen: count((row) => row.stream === "Listen"),
    write: count((row) => row.stream === "Write"),
    handshakes: count((row) => row.role === "handshake"),
    forward: count((row) => row.role === "forward"),
    backchannel: backchannel.length,
    terminate: count((row) => row.role === "terminate"),
    backchannelCi: {
      streamed: backchannel.filter((row) => row.ci === 0).length,
      longPolled: backchannel.filter((row) => row.ci === 1).length,
    },
  };
};

/** Close every owned resource, keeping the first error but trying all of them. */
export const closeAll = async (closers) => {
  let failure = null;
  for (const close of closers.reverse()) {
    try {
      await close();
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
};
