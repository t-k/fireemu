import { execFileSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { connect } from "node:net";
import { expect, test, type Page } from "@playwright/test";
import { api, gotoApp, resetSession, waitForFunctionsRunner } from "./helpers";
import type { FunctionsOverview } from "../src/api/functions";

const modules = resolve(dirname(fileURLToPath(import.meta.url)), "../../conformance/node_modules");

const ipv6Host = async (host: string): Promise<string | null> => {
  const port = Number(host.slice(host.lastIndexOf(":") + 1));
  return new Promise((resolveHost) => {
    const socket = connect({ host: "::1", port });
    socket.setTimeout(1000);
    socket.once("connect", () => {
      socket.destroy();
      resolveHost(`[::1]:${port}`);
    });
    socket.once("error", () => {
      socket.destroy();
      resolveHost(null);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolveHost(null);
    });
  });
};

const emulatorHost = async (page: Page): Promise<string> => {
  await gotoApp(page, "/");
  const text = await page.getByTestId("env-dotenv").innerText();
  const host = /^FIRESTORE_EMULATOR_HOST=(.+)$/m.exec(text)?.[1];
  expect(host).toMatch(/^(127\.0\.0\.1|localhost|\[::1\]):\d+$/);
  return host!;
};

const node = (source: string, host: string): string =>
  execFileSync(process.execPath, ["-e", source], {
    encoding: "utf8",
    timeout: 20000,
    env: { PATH: process.env.PATH, NODE_PATH: modules, FIRESTORE_EMULATOR_HOST: host },
  });

test("copy reports success only for a written clipboard and exposes a selected fallback when denied", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await gotoApp(page, "/");
  const value = await page.getByTestId("env-dotenv").innerText();
  await page.evaluate(() => navigator.clipboard.writeText("before copy"));
  await page.getByTestId("env-dotenv-copy").click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(value);
  await expect(page.getByTestId("env-dotenv-copy-status")).toHaveText("Copied");
  await context.clearPermissions();
  await context.grantPermissions([]);
  await page.getByTestId("env-dotenv-copy").focus();
  await page.keyboard.press("Enter");
  const fallback = page.getByRole("textbox", {
    name: /Copy manually: clipboard access was unavailable/,
  });
  await expect(fallback).toBeVisible();
  await expect(fallback).toBeFocused();
  await expect(fallback).toHaveValue(value);
  expect(
    await fallback.evaluate((element: HTMLTextAreaElement) => [
      element.selectionStart,
      element.selectionEnd,
    ]),
  ).toEqual([0, value.length]);
  await expect(page.getByTestId("env-dotenv-copy-status")).not.toHaveText("Copied");
});

test("a named SDK database can be selected without losing an unsaved query draft", async ({
  page,
  request,
}) => {
  await resetSession(request);
  const host = await emulatorHost(page);
  node(
    `const { initializeApp, deleteApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { v1 } = require("@google-cloud/firestore");
const grpc = require("@grpc/grpc-js");
(async () => { const endpoint = new URL("http://" + process.env.FIRESTORE_EMULATOR_HOST);
const admin = new v1.FirestoreAdminClient({ projectId: "demo-app", apiEndpoint: endpoint.hostname.replace(/^\\[|\\]$/g, ""), port: Number(endpoint.port), sslCreds: grpc.credentials.createInsecure() });
await admin.createDatabase({ parent: "projects/demo-app", databaseId: "ui-draft-db", database: { type: "FIRESTORE_NATIVE", locationId: "nam5" } }, { otherArgs: { headers: { authorization: "Bearer owner" } } });
await admin.close();
const app = initializeApp({ projectId: "demo-app" });
await getFirestore(app, "ui-draft-db").collection("drafts").doc("one").set({ value: 1 });
await deleteApp(app); })().catch(e => { console.error(e); process.exitCode = 1; });`,
    host,
  );
  await gotoApp(page, "/firestore/drafts");
  await page.getByLabel("Result limit").fill("17");
  await page.getByTestId("database-input").fill("ui-draft-db");
  await page.getByRole("button", { name: "Open database" }).click();
  await expect(page.getByTestId("query-panel")).toContainText("Database ui-draft-db");
  await expect(page.getByRole("link", { name: /one/ }).first()).toBeVisible();
  await page.getByTestId("database-input").fill("(default)");
  await page.getByRole("button", { name: "Open database" }).click();
  await expect(page.getByTestId("query-panel")).toContainText("Database (default)");
  await expect(page.getByLabel("Result limit")).toHaveValue("17");
});

test("connection status announces failure and recovery of the control API", async ({ page }) => {
  await gotoApp(page, "/");
  const badge = page.getByTestId("connection-badge");
  const status = page.getByTestId("connection-status");
  await expect(badge).toHaveText("Control API responding");
  await expect(status).toContainText("Control API responding");
  await expect(page.getByTestId("control-last-success")).toContainText("Last successful check:");
  const lastSuccess = await page.getByTestId("control-last-success").innerText();
  const pattern = "**/ui/api/control/v1/sessions**";
  await page.route(pattern, (route) => route.abort("failed"));
  await expect(badge).toHaveText("Control API not answering", { timeout: 15000 });
  await expect(status).toContainText("Control API not answering");
  await expect(status).toContainText("Control API status only");
  await page.unroute(pattern);
  await expect(badge).toHaveText("Control API responding", { timeout: 15000 });
  await expect(status).toContainText("Control API responding");
  await expect(status).toContainText("Last successful check:");
  await expect(page.getByTestId("control-last-success")).toContainText("Last successful check:");
  await expect(page.getByTestId("control-last-success")).not.toHaveText(lastSuccess);
});

test("shared Functions filters and event links restore their views", async ({
  page,
  request,
  context,
}) => {
  await resetSession(request);
  await waitForFunctionsRunner(request);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await gotoApp(page, "/functions");
  await page.getByTestId("log-level-filter").selectOption("error");
  await page.getByTestId("log-text-filter").fill("shared search");
  await page.getByLabel("Include search text in the shared link").check();
  await page.getByRole("button", { name: "Copy filter link" }).click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(new URL(link).searchParams.get("q")).toBe("shared search");
  await page.goto(link);
  await expect(page.getByTestId("log-level-filter")).toHaveValue("error");
  await expect(page.getByTestId("log-text-filter")).toHaveValue("shared search");
  await api(
    request,
    "PATCH",
    "firestore/v1/projects/demo-app/databases/(default)/documents/todos/shared-event",
    { fields: { title: { stringValue: "event" } } },
  );
  await api(request, "POST", "control/v1/sessions/default:awaitIdle", { timeoutSeconds: 30 });
  const overview = (await api(request, "GET", "functions")) as FunctionsOverview;
  const event = overview.status?.causality?.events.find(
    (e) => e.function === "mirrorTodo" && e.epoch === overview.status?.causality?.epoch,
  );
  expect(event).toBeDefined();
  await page.reload();
  const eventLink = page.getByRole("link", { name: `Select event ${event!.eventId} / mirrorTodo` });
  await expect(eventLink).toBeVisible();
  await eventLink.click();
  await expect(page.getByTestId("timeline-detail")).toContainText(event!.eventId);
  await page.reload();
  await expect(page.getByTestId("timeline-detail")).toContainText(event!.eventId);
  const missing = new URL(page.url());
  missing.searchParams.set("event", "expired-event-id");
  await page.goto(missing.href);
  await expect(page.getByTestId("timeline-detail")).toContainText(
    "The selected event is outside the current retained window.",
  );
});

test("the copied SDK reproduction returns the same documents as the UI, including an empty query", async ({
  page,
  request,
  context,
}) => {
  await resetSession(request);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const host = await emulatorHost(page);
  node(
    `const { initializeApp, deleteApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
(async () => { const app = initializeApp({ projectId: "demo-app" }); const db = getFirestore(app);
await Promise.all([db.doc("sdk-repro/one").set({ category: "match" }), db.doc("sdk-repro/two").set({ category: "other" })]);
await deleteApp(app); })().catch(e => { console.error(e); process.exitCode = 1; });`,
    host,
  );
  await gotoApp(page, "/firestore/sdk-repro");
  await page.getByRole("button", { name: "Add condition", exact: true }).click();
  const filter = page.getByTestId("query-filter-0");
  await filter.getByLabel("Field path").fill("category");
  await page.getByText("Node.js SDK reproduction", { exact: true }).click();
  for (const value of ["match", "absent"]) {
    await filter.getByLabel("Typed value").fill(value);
    await page.getByRole("button", { name: "Run query", exact: true }).click();
    const results = page.getByTestId("query-results");
    await expect(results).toBeVisible();
    if (value === "absent") await expect(results).toContainText("The query returned no documents.");
    else await expect(results).toContainText("sdk-repro/one");
    const paths = await results.locator("a").allTextContents();
    await page.getByTestId("query-sdk").evaluate((element) => {
      const selection = window.getSelection()!;
      const range = document.createRange();
      range.selectNodeContents(element);
      selection.removeAllRanges();
      selection.addRange(range);
    });
    await page.keyboard.press(process.platform === "darwin" ? "Meta+C" : "Control+C");
    const source = await page.evaluate(() => navigator.clipboard.readText());
    expect(source).toContain('require("@google-cloud/firestore")');
    const ipv6 = await ipv6Host(host);
    for (const endpoint of new Set([host, ...(ipv6 ? [ipv6] : [])])) {
      const rows = node(source, endpoint)
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as { document?: { name: string } });
      const sdkPaths = rows.flatMap((row) =>
        row.document ? [row.document.name.split("/documents/")[1]] : [],
      );
      expect(sdkPaths.toSorted()).toEqual(paths.toSorted());
    }
  }
});
