// Automated runner for the browser smoke pages under `tools/sdk-smoke/web/`.
//
// Run it as the child of an owned `fireemu exec` (see README.md); it serves the
// page directory on a loopback port, drives each page in headless Chromium,
// waits for the page's own verdict (`body[data-status]`), and prints one JSON
// document with the page results and the WebChannel request log the browser
// saw. The listener-lifecycle page needs `listener-lifecycle.rules` loaded by
// the emulator; the listen-reconnect page installs its own rules through the
// control route with the child-scoped token, so it runs last.
//
// The control token never enters a page URL: the runner exposes a one-shot
// `__fireemuInstallRules(source)` binding to the listen-reconnect page and
// performs the PUT itself, so the page only ever sees `{ ok, status }`. Every
// error that could reach stderr, `pageErrors` or the receipt is reduced to a
// message with the token and any URL query string redacted, because Playwright
// quotes the navigation URL in its failure diagnostics.
//
// Chromium and the static server are closed on every exit path.

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { redact } from "../compat-broad/fs-listen-resume/listen_collector.mjs";
import {
  REQUEST_ROW_COLUMNS,
  captureWebChannel,
  closeAll,
  compactWebChannelRows,
  launchChromium,
  serveStatic,
} from "./browser_harness.mjs";

export const SCHEMA = "sdk-smoke-browser-v1";
export const TRANSPORT = "browser-webchannel";
export const PAGES = Object.freeze({
  "listener-lifecycle": Object.freeze({
    file: "listener-lifecycle.html",
    query: ({ firestorePort, authPort, projectId }) => ({ fs: firestorePort, auth: authPort, project: projectId }),
    timeoutMs: 90_000,
  }),
  "listen-reconnect": Object.freeze({
    file: "listen-reconnect.html",
    query: ({ firestorePort, authPort, projectId }) => ({ fs: firestorePort, auth: authPort, project: projectId }),
    // The page hands its rules text to the runner; the token stays in this process.
    installsRules: true,
    timeoutMs: 90_000,
  }),
});
const DEFAULT_ORDER = ["listener-lifecycle", "listen-reconnect"];
const REDACTED = "[redacted]";
const MAX_RULES_SOURCE = 64 * 1024;

/**
 * Reduce free text to something safe for stderr and the receipt: every
 * occurrence of a secret and every URL query string is replaced.
 */
export const safeText = (value, secrets = []) => {
  let text = typeof value === "string" ? value : String(value);
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length > 0) text = text.split(secret).join(REDACTED);
  }
  return text.replace(/(https?:\/\/[^\s?#"'<>)]*)\?[^\s#"'<>)]*/g, `$1?${REDACTED}`);
};

/** A new error carrying only the safe message (never the original stack or URL). */
export const safeError = (error, secrets = []) => {
  const message = safeText(error?.message ?? error, secrets);
  return Object.assign(new Error(message), typeof error?.code === "string" ? { code: error.code } : {});
};

/** Apply `safeText` to every string inside a plain JSON value. */
export const scrubStrings = (value, secrets) => {
  if (Array.isArray(value)) return value.map((item) => scrubStrings(item, secrets));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrubStrings(item, secrets)]));
  }
  return typeof value === "string" ? safeText(value, secrets) : value;
};

/**
 * The one operation the listen-reconnect page needs from the control route:
 * install a ruleset. The token is attached here, in Node, and the page gets
 * back only the status. One call per page; anything but a bounded string is
 * refused before a request is made; a transport failure is reported as
 * `unreachable` without the underlying message.
 */
export const createInstallRulesBinding = ({ authPort, controlToken, fetchImpl = fetch }) => {
  let used = false;
  return async (source) => {
    if (used) return { ok: false, status: 0, error: "rules binding already used" };
    used = true;
    if (typeof source !== "string" || source.length === 0 || source.length > MAX_RULES_SOURCE) {
      return { ok: false, status: 0, error: "rules source must be a non-empty bounded string" };
    }
    try {
      const response = await fetchImpl(`http://127.0.0.1:${authPort}/v1/rules`, {
        method: "PUT",
        headers: { "content-type": "application/json", authorization: `Bearer ${controlToken}` },
        body: JSON.stringify({ source }),
      });
      await response.arrayBuffer().catch(() => {});
      return { ok: response.ok, status: response.status };
    } catch {
      return { ok: false, status: 0, error: "unreachable" };
    }
  };
};

// Decoded from the module URL so spaces, `%` and non-ASCII in the checkout path survive.
const HERE = path.dirname(fileURLToPath(import.meta.url));

export const parseArgs = (argv, env) => {
  const options = { pages: DEFAULT_ORDER, output: null };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--pages") {
      const value = argv[++index] ?? "";
      const pages = value.split(",").map((item) => item.trim()).filter(Boolean);
      if (!pages.length || pages.some((page) => !PAGES[page]) || new Set(pages).size !== pages.length) {
        throw new Error(`--pages must be a unique subset of ${Object.keys(PAGES).join(",")}`);
      }
      options.pages = pages;
    } else if (arg === "--output") {
      options.output = argv[++index];
      if (!options.output) throw new Error("--output needs a file path");
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  const loopback = (value) => {
    const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(value ?? "");
    if (!match) throw new Error("127.0.0.1 emulator endpoints are required");
    return Number(match[1]);
  };
  options.firestorePort = loopback(env.FIRESTORE_EMULATOR_HOST);
  options.authPort = loopback(env.FIREBASE_AUTH_EMULATOR_HOST);
  options.projectId = env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
  if (!/^demo-[a-zA-Z0-9_-]{1,123}$/.test(options.projectId)) throw new Error("demo project required");
  options.controlToken = env.FIREEMU_CONTROL_TOKEN ?? "";
  options.playwrightDir = env.O6_PLAYWRIGHT_MODULE_DIR ?? HERE;
  options.webDir = env.SDK_SMOKE_WEB_DIR ?? path.join(HERE, "..", "sdk-smoke", "web");
  return options;
};

const secretsOf = (options) => [options.controlToken].filter((value) => typeof value === "string" && value.length > 0);

/** Drive one smoke page to its verdict; always closes the page. */
export const runPage = async (chromium, serverOrigin, name, options) => {
  const spec = PAGES[name];
  const secrets = secretsOf(options);
  const context = await chromium.browser.newContext();
  const page = await context.newPage();
  const webchannel = captureWebChannel(page, options.firestorePort);
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(safeText(error?.message ?? error, secrets)));
  const startedAt = performance.now();
  try {
    if (spec.installsRules) {
      await page.exposeFunction("__fireemuInstallRules",
        createInstallRulesBinding({ authPort: options.authPort, controlToken: options.controlToken }));
    }
    const url = new URL(`${serverOrigin}/${spec.file}`);
    for (const [key, value] of Object.entries(spec.query(options))) url.searchParams.set(key, String(value));
    await page.goto(url.href, { waitUntil: "load" });
    await page.waitForSelector("body[data-status]", { timeout: spec.timeoutMs });
    const status = await page.evaluate(() => document.body.dataset.status);
    const text = await page.evaluate(() => document.getElementById("result").textContent);
    let result;
    try {
      result = JSON.parse(text);
    } catch {
      result = { parseError: true };
    }
    return {
      page: name,
      passed: status === "passed" && result?.passed === true && pageErrors.length === 0,
      status,
      elapsedMs: Math.trunc(performance.now() - startedAt),
      result: scrubStrings(redact(result), secrets),
      pageErrors,
      webchannel: {
        summary: webchannel.summary(),
        columns: [...REQUEST_ROW_COLUMNS],
        rows: compactWebChannelRows(webchannel.rows),
      },
    };
  } catch (error) {
    // Playwright quotes the navigation URL and page text in its messages.
    throw safeError(error, secrets);
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
  }
};

export const main = async ({ argv = process.argv.slice(2), env = process.env,
  emit = (value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`),
  launch = launchChromium } = {}) => {
  const options = parseArgs(argv, env);
  const secrets = secretsOf(options);
  const server = await serveStatic({ "/": options.webDir });
  let chromium = null;
  const pages = {};
  try {
    chromium = await launch(options.playwrightDir);
    for (const name of options.pages) {
      pages[name] = await runPage(chromium, server.origin, name, options);
    }
  } catch (error) {
    throw safeError(error, secrets);
  } finally {
    await closeAll([server.close, ...(chromium ? [chromium.close] : [])]);
  }
  const document = {
    schema: SCHEMA,
    transport: TRANSPORT,
    productionExecuted: false,
    browser: { name: chromium.name, version: chromium.version },
    pages,
    complete: options.pages.every((name) => pages[name]?.passed === true),
  };
  if (options.output) writeFileSync(options.output, `${JSON.stringify(document, null, 2)}\n`);
  else await emit(document);
  if (!document.complete) process.exitCode = 2;
  return document;
};

const invokedDirectly = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${safeText(error?.message ?? error, [process.env.FIREEMU_CONTROL_TOKEN])}\n`);
    process.exitCode = 1;
  });
}
