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
    env: {
      PATH: process.env.PATH,
      NODE_PATH: modules,
      FIRESTORE_EMULATOR_HOST: host,
      METADATA_SERVER_DETECTION: "none",
    },
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

test("the SDK reproduction preserves named database values and missing-index errors", async ({
  page,
  request,
}) => {
  await resetSession(request);
  const host = await emulatorHost(page);
  node(
    `const { v1 } = require("@google-cloud/firestore");
const grpc = require("@grpc/grpc-js");
(async () => { const endpoint = new URL("http://" + process.env.FIRESTORE_EMULATOR_HOST);
const admin = new v1.FirestoreAdminClient({ projectId: "demo-app", apiEndpoint: endpoint.hostname, port: Number(endpoint.port), sslCreds: grpc.credentials.createInsecure() });
await admin.createDatabase({ parent: "projects/demo-app", databaseId: "sdk-parity-db", database: { type: "FIRESTORE_NATIVE", locationId: "nam5" } }, { otherArgs: { headers: { authorization: "Bearer owner" } } });
await admin.close(); })().catch(e => { console.error(e); process.exitCode = 1; });`,
    host,
  );
  const root = "projects/demo-app/databases/sdk-parity-db/documents";
  await api(request, "PATCH", `firestore/v1/${root}/sdk-parity/one`, {
    fields: {
      integer: { integerValue: "9007199254740993" },
      double: { doubleValue: 1.25 },
      timestamp: { timestampValue: "2026-01-01T00:00:00.123456789Z" },
      boolean: { booleanValue: true },
      nil: { nullValue: null },
      map: { mapValue: { fields: { nested: { stringValue: "value" } } } },
      array: { arrayValue: { values: [{ integerValue: "42" }, { booleanValue: false }] } },
      reference: { referenceValue: `${root}/sdk-parity/other` },
    },
  });
  await gotoApp(page, "/firestore/sdk-parity?db=sdk-parity-db");
  await page.getByText("Node.js SDK reproduction", { exact: true }).click();
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  const results = page.getByTestId("query-results");
  await expect(results).toContainText("sdk-parity/one");
  const restRows = JSON.parse(await results.locator("pre").innerText()) as {
    document?: { fields: Record<string, unknown> };
  }[];
  const source = await page.getByTestId("query-sdk").innerText();
  const sdkRows = node(source, host)
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const rest = restRows.find((row) => row.document)?.document?.fields as {
    integer: { integerValue: string };
    double: { doubleValue: number };
    timestamp: { timestampValue: string };
    boolean: { booleanValue: boolean };
    nil: { nullValue: null };
    map: { mapValue: { fields: { nested: { stringValue: string } } } };
    array: { arrayValue: { values: [{ integerValue: string }, { booleanValue: boolean }] } };
    reference: { referenceValue: string };
  };
  const sdk = sdkRows.find((row) => row.document)?.document.fields;
  expect(sdk.integer.integerValue).toBe(rest.integer.integerValue);
  expect(sdk.double.doubleValue).toBe(rest.double.doubleValue);
  const nanos = Number((/\.(\d+)Z$/.exec(rest.timestamp.timestampValue)?.[1] ?? "").padEnd(9, "0"));
  expect(nanos).toBeGreaterThan(0);
  expect(sdk.timestamp.timestampValue).toMatchObject({
    seconds: String(Math.floor(Date.parse(rest.timestamp.timestampValue) / 1000)),
    nanos,
  });
  expect(sdk.boolean.booleanValue).toBe(rest.boolean.booleanValue);
  expect(sdk.nil.nullValue).toBe("NULL_VALUE");
  expect(rest.nil.nullValue).toBeNull();
  expect(sdk.map.mapValue.fields.nested.stringValue).toBe(
    rest.map.mapValue.fields.nested.stringValue,
  );
  expect(sdk.array.arrayValue.values[0].integerValue).toBe(
    rest.array.arrayValue.values[0].integerValue,
  );
  expect(sdk.array.arrayValue.values[1].booleanValue).toBe(
    rest.array.arrayValue.values[1].booleanValue,
  );
  expect(sdk.reference.referenceValue).toBe(rest.reference.referenceValue);

  await page.getByRole("button", { name: "Add condition", exact: true }).click();
  const filter = page.getByTestId("query-filter-0");
  await filter.getByLabel("Field path").fill("integer");
  await filter.getByLabel("Value type").selectOption("integer");
  await filter.getByLabel("Typed value").fill("9007199254740993");
  await page.getByRole("button", { name: "Add order", exact: true }).click();
  await page.getByTestId("query-order-0").getByLabel("Field path").fill("double");
  await page.getByTestId("query-order-0").getByLabel("Direction").selectOption("DESCENDING");
  const response = page.waitForResponse(
    (r) => r.url().includes(":runQuery") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  const body = await (await response).json();
  const error = (Array.isArray(body) ? body[0] : body).error;
  expect(error.status).toBe("FAILED_PRECONDITION");
  await expect(page.getByTestId("query-error")).toContainText("The query requires an index.");
  await expect(page.getByTestId("query-error")).toContainText(error.message);
  await page.getByText("Node.js SDK reproduction", { exact: true }).click();
  const errorSource = (await page.getByTestId("query-sdk").innerText())
    .replace("async function main() {", "const responses = [];\nasync function main() {")
    .replace("console.log(JSON.stringify(response));", "responses.push(response);")
    .replace(
      "  } finally { await client.close(); }",
      "    console.log(JSON.stringify({ responses }));\n  } catch (error) {\n    console.log(JSON.stringify({ code: error.code, message: error.details }));\n  } finally { await client.close(); }",
    );
  expect(errorSource).toContain("console.log(JSON.stringify({ responses }))");
  expect(errorSource).toContain(
    "console.log(JSON.stringify({ code: error.code, message: error.details }))",
  );
  const sdkError = JSON.parse(node(errorSource, host).trim());
  expect(sdkError.code, JSON.stringify(sdkError)).toBe(9);
  expect(sdkError.message).toBe(error.message);
});
