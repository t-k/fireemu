import { expect, test, type Page } from "@playwright/test";

const SOURCE = "// 日😀\r\nallow get: if false;\r\nallow write: if true;";
const START = Buffer.byteLength(SOURCE.slice(0, SOURCE.indexOf("false")), "utf8");
const snapshot = (generation = "1") => ({
  capacity: 100,
  loaded: true,
  source: SOURCE,
  generation,
  requests: [
    {
      sequence: 1,
      service: "firestore",
      method: "get",
      path: "notes/a",
      allowed: false,
      reason: "permission denied",
      uid: null,
      expressions: [
        {
          line: 2,
          column: 15,
          currentOffset: START,
          endOffset: START + 5,
          values: [{ value: { kind: "bool", bool: false }, count: 1 }],
        },
        { line: 3, column: 1, currentOffset: 0, endOffset: 0, values: [] },
        {
          line: 3,
          column: 17,
          currentOffset: START,
          endOffset: START + 5,
          values: [
            { value: { kind: "undefined", cause: { message: "missing property" } }, count: 1 },
          ],
        },
      ],
    },
  ],
});

/** Mock only the API transport; the built app, DOM, focus and browser keyboard are real. */
const harness = async (page: Page) => {
  const state = {
    failure: 0,
    diagnosticFailure: 0,
    clearFailure: 0,
    interval: "0",
    clears: 0,
    generation: "1",
    loaded: true,
    source: "currently loaded editor source",
  };
  await page.addInitScript(() => {
    window.__FIREEMU__ = {
      project: "demo-a",
      controlToken: "local-test",
      sessions: [
        { name: "default", project: "demo-a" },
        { name: "other", project: "demo-a" },
      ],
    };
  });
  await page.route("**/ui/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname.split("/ui/api/")[1]!;
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (path === "control/v1/sessions")
      return json({
        sessions: [
          { name: "default", project: "demo-a" },
          { name: "other", project: "demo-a" },
        ],
      });
    if (/^control\/v1\/sessions\/[^/]+$/.test(path))
      return json({ clock: { clock: "2026-10-22T00:00:00Z" } });
    if (path.endsWith("/rules/diagnostics") || path.endsWith("/rules/diagnostics:clear")) {
      if (path.endsWith(":clear")) {
        state.clears++;
        const expected = route.request().postDataJSON() as {
          expectedGeneration: string;
          expectedInterval: string;
        };
        if (
          expected.expectedGeneration !== state.generation ||
          expected.expectedInterval !== state.interval
        )
          return json({ error: { message: "stale diagnostic identity" } }, 409);
        if (state.clearFailure === -1) return route.abort("connectionrefused");
        if (state.clearFailure)
          return json({ error: { message: "clear refused" } }, state.clearFailure);
        state.interval = String(Number(state.interval) + 1);
      } else if (state.diagnosticFailure)
        return json({ error: { message: "inspection offline" } }, state.diagnosticFailure);
      return json({
        service: "firestore",
        loaded: true,
        generation: state.generation,
        interval: state.interval,
        expressionCount: 2,
        distinctValueCount: 3,
        observationCount: 5,
        requestTraceCount: 1,
        requestTraceCapacity: 100,
        estimatedCoverageBytes: 512,
      });
    }
    if (state.failure === -1) return route.abort("connectionrefused");
    if (path.endsWith("/rules/requests")) {
      if (path.includes("/other/"))
        return json({ error: { message: "trace belongs to default session" } }, 400);
      if (state.failure)
        return json({ error: { message: "injected diagnostics failure" } }, state.failure);
      return json({
        ...snapshot(state.generation),
        loaded: state.loaded,
        requests: state.loaded ? snapshot().requests : [],
      });
    }
    if (path.includes(":ruleCoverage")) {
      if (state.failure)
        return json({ error: { message: "injected diagnostics failure" } }, state.failure);
      return json({
        rules: { files: [{ name: "firestore.rules", content: SOURCE }] },
        report: [
          {
            sourcePosition: { line: 2, column: 15, currentOffset: START, endOffset: START + 5 },
            values: [],
          },
        ],
      });
    }
    if (path === "control/v1/rules" || path === "control/v1/storage/rules") {
      if (state.failure)
        return json({ error: { message: "injected diagnostics failure" } }, state.failure);
      if (route.request().method() === "PUT") {
        state.source = (route.request().postDataJSON() as { source: string }).source;
        return json({});
      }
      if (route.request().method() === "DELETE") {
        state.source = "";
        return json({});
      }
      return json({ loaded: true, source: state.source });
    }
    return json({});
  });
  return state;
};

test("recorded Unicode source navigation uses keyboard and never the current editor", async ({
  page,
}, info) => {
  const state = await harness(page);
  await page.goto("/ui/rules");
  await page.getByTestId("rules-request-trace-1").click();
  const first = page.getByTestId("rules-request-expression-0");
  await first.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("rules-request-highlight")).toHaveText("false");
  expect(await page.getByTestId("rules-request-source").textContent()).toBe(SOURCE);
  await expect(page.getByTestId("rules-request-expressions")).toContainText("false ×1");
  await expect(page.getByTestId("rules-request-expressions")).toContainText("not reached");
  await expect(page.getByTestId("rules-request-expressions")).toContainText(
    "Evaluation error: undefined: missing property",
  );
  await page.keyboard.press("ArrowDown");
  await expect(page.getByTestId("rules-request-expression-1")).toBeFocused();
  await page.keyboard.press("End");
  await expect(page.getByTestId("rules-request-expression-2")).toBeFocused();
  await page.keyboard.press("Home");
  await expect(first).toBeFocused();
  await page.getByTestId("rules-coverage-expression-0").click();
  await expect(page.getByTestId("rules-coverage-highlight")).toHaveText("false");
  await page.screenshot({
    path: process.env.RULES_UI_EVIDENCE_DIR
      ? `${process.env.RULES_UI_EVIDENCE_DIR}/keyboard-recorded-source.png`
      : info.outputPath("keyboard-recorded-source.png"),
    fullPage: true,
  });
  state.failure = 500;
  await page.getByTestId("rules-requests-refresh").click();
  await expect(page.getByTestId("fetch-stale")).toBeVisible();
  await expect(page.getByTestId("rules-request-highlight")).toHaveText("false");
  state.failure = 0;
  await page.getByTestId("fetch-stale").getByRole("button", { name: "Retry" }).click();
  await expect(page.getByTestId("rules-request-expression-0")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  state.generation = "2";
  await page.getByTestId("rules-requests-refresh").click();
  await expect(page.getByTestId("rules-request-expressions")).toHaveCount(0);
});

test("initial failures are not empty states and retry recovers", async ({ page }) => {
  const state = await harness(page);
  state.failure = 401;
  await page.goto("/ui/rules");
  await expect(page.getByTestId("fetch-error")).toHaveCount(4);
  await expect(page.getByTestId("rules-requests")).toHaveCount(0);
  await expect(page.getByText("Not loaded: every request is allowed")).toHaveCount(0);
  state.failure = 0;
  for (let remaining = 4; remaining > 0; remaining--) {
    await page.getByTestId("fetch-retry").first().click();
    await expect(page.getByTestId("fetch-error")).toHaveCount(remaining - 1);
  }
  await expect(page.getByTestId("fetch-error")).toHaveCount(0);
  await expect(page.getByTestId("rules-requests")).toBeVisible();
});

test("draft survives refresh failure and scope changes require the existing leave guard", async ({
  page,
}) => {
  const state = await harness(page);
  await page.goto("/ui/rules");
  const editor = page.locator("#rules-firestore");
  await editor.fill("unsaved draft");
  state.failure = 500;
  await page.getByTestId("rules-firestore-refresh").click();
  await expect(page.getByTestId("fetch-stale")).toBeVisible();
  await expect(editor).toHaveValue("unsaved draft");
  await page.getByTestId("session-select").selectOption("other");
  await expect(page.getByTestId("unsaved-prompt")).toBeVisible();
  await page.getByTestId("unsaved-keep").click();
  await expect(editor).toHaveValue("unsaved draft");
  await expect(page.getByTestId("session-select")).toHaveValue("default");
  state.failure = 0;
  await page.getByTestId("session-select").selectOption("other");
  await page.getByTestId("unsaved-discard").click();
  await expect(page.getByTestId("session-select")).toHaveValue("other");
  await expect(editor).toHaveValue("currently loaded editor source");
  await expect(page.getByTestId("rules-request-expressions")).toHaveCount(0);
  await expect(page.getByTestId("fetch-error")).toContainText("trace belongs to default session");
});

test("network disconnection is an error, not a successful empty response", async ({ page }) => {
  const state = await harness(page);
  state.failure = -1;
  await page.goto("/ui/rules");
  await expect(page.getByTestId("fetch-error")).toHaveCount(4);
  await expect(page.getByTestId("rules-requests")).toHaveCount(0);
  state.failure = 0;
  for (let remaining = 4; remaining > 0; remaining--) {
    await page.getByTestId("fetch-retry").first().click();
    await expect(page.getByTestId("fetch-error")).toHaveCount(remaining - 1);
  }
  await expect(page.getByTestId("rules-coverage")).toBeVisible();
});

test("diagnostic interval clear is explicit, keyboard accessible and retains drafts", async ({
  page,
}, info) => {
  const state = await harness(page);
  await page.goto("/ui/rules");
  const editor = page.locator("#rules-firestore");
  await editor.fill("draft preserved across diagnostic clear");
  await page.getByTestId("rules-request-trace-1").click();
  await page.getByTestId("rules-request-expression-0").click();
  const clear = page.getByTestId("rules-diagnostics-clear");
  await clear.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("rules-diagnostics-stats")).toContainText("interval 1");
  await expect(editor).toHaveValue("draft preserved across diagnostic clear");
  await expect(page.getByTestId("rules-request-highlight")).toHaveCount(0);
  expect(state.clears).toBe(1);
  await expect(page.getByText(/process RSS/)).toBeVisible();
  await expect(page.getByText(/completed evaluations merge/)).toBeVisible();
  await page.screenshot({
    path: process.env.RULES_UI_EVIDENCE_DIR
      ? `${process.env.RULES_UI_EVIDENCE_DIR}/diagnostic-interval.png`
      : info.outputPath("diagnostic-interval.png"),
    fullPage: true,
  });
  state.clearFailure = -1;
  await clear.click();
  await expect(page.getByText(/result is unknown or refused/)).toBeVisible();
  await expect(clear).toBeDisabled();
  expect(state.clears).toBe(2);
  state.clearFailure = 0;
  await page.getByTestId("rules-diagnostics-refresh").click();
  await expect(clear).toBeEnabled();
  expect(state.clears).toBe(2);
  state.diagnosticFailure = 500;
  await page.getByTestId("rules-diagnostics-refresh").click();
  await expect(page.getByTestId("fetch-stale")).toBeVisible();
  await expect(clear).toBeDisabled();
  await expect(editor).toHaveValue("draft preserved across diagnostic clear");
});
