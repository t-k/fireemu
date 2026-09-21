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
// Chromium and the static server are closed on every exit path.

import { writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
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
    query: ({ firestorePort, authPort, projectId, controlToken }) => ({
      fs: firestorePort, auth: authPort, project: projectId, token: controlToken,
    }),
    timeoutMs: 90_000,
  }),
});
const DEFAULT_ORDER = ["listener-lifecycle", "listen-reconnect"];

const HERE = path.dirname(new URL(import.meta.url).pathname);

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

/** Drive one smoke page to its verdict; always closes the page. */
export const runPage = async (chromium, serverOrigin, name, options) => {
  const spec = PAGES[name];
  const context = await chromium.browser.newContext();
  const page = await context.newPage();
  const webchannel = captureWebChannel(page, options.firestorePort);
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error?.message ?? String(error)));
  const startedAt = performance.now();
  try {
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
      result: redact(result),
      pageErrors,
      webchannel: {
        summary: webchannel.summary(),
        columns: [...REQUEST_ROW_COLUMNS],
        rows: compactWebChannelRows(webchannel.rows),
      },
    };
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
  }
};

export const main = async ({ argv = process.argv.slice(2), env = process.env,
  emit = (value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) } = {}) => {
  const options = parseArgs(argv, env);
  const server = await serveStatic({ "/": options.webDir });
  let chromium = null;
  const pages = {};
  try {
    chromium = await launchChromium(options.playwrightDir);
    for (const name of options.pages) {
      pages[name] = await runPage(chromium, server.origin, name, options);
    }
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
    process.stderr.write(`${error?.message ?? error}\n`);
    process.exitCode = 1;
  });
}
