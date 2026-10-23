import { expect, test, type Page } from "@playwright/test";

const root = "projects/demo-query/databases/(default)/documents";
const document = (name: string, database = "(default)") => ({
  name: `${root.replace("(default)", database)}/cities/${name}`,
  fields: { score: { integerValue: "9223372036854775807" } },
});

const openQuery = async (page: Page, suffix = "") => {
  await page.addInitScript(() => {
    window.__FIREEMU__ = {
      project: "demo-query",
      controlToken: "test-query-token",
      sessions: [
        { name: "default", project: "demo-query" },
        { name: "trial", project: "demo-other" },
      ],
    };
  });
  await page.route("**/ui/api/**", async (route) => {
    const url = new URL(route.request().url());
    let body: unknown = {};
    if (url.pathname.endsWith("/control/v1/sessions"))
      body = {
        sessions: [
          { name: "default", project: "demo-query" },
          { name: "trial", project: "demo-other" },
        ],
      };
    else if (/\/control\/v1\/sessions\/(default|trial)$/.test(url.pathname))
      body = {
        session: "default",
        clock: { clock: "2026-10-23T00:00:00Z", backwardsSets: 0 },
        edition: "standard",
        requireDemoPrefix: true,
      };
    else if (url.pathname.endsWith(":listCollectionIds")) body = { collectionIds: [] };
    else if (url.pathname.includes("/documents/")) body = { documents: [] };
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto(`/ui/firestore/cities${suffix}`);
  await expect(page.getByRole("heading", { name: "Query collection" })).toBeVisible();
};

test("keyboard typed conditions send a server query and preserve exact results and executed conditions", async ({
  page,
}, testInfo) => {
  await openQuery(page, "?db=named-db");
  let sent: unknown;
  await page.route("**/ui/api/**:runQuery", async (route) => {
    sent = route.request().postDataJSON();
    await route.fulfill({
      json: [{ document: document("one", "named-db") }, { readTime: "2026-10-23T00:00:00Z" }],
    });
  });
  await page.getByRole("button", { name: "Add condition", exact: true }).focus();
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: "Add condition", exact: true }).click();
  await page.getByRole("button", { name: "Remove condition 2" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Add condition", exact: true })).toBeFocused();
  const row = page.getByTestId("query-filter-0");
  await row.getByLabel("Field path").fill("score");
  await row.getByLabel("Operator").selectOption("GREATER_THAN");
  await row.getByLabel("Value type").selectOption("integer");
  await row.getByLabel("Typed value").fill("9007199254740993");
  await page.getByRole("button", { name: "Add order", exact: true }).click();
  await page.getByTestId("query-order-0").getByLabel("Field path").fill("score");
  await page.getByLabel("Result limit").fill("7");
  await page.getByRole("button", { name: "Run query", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("query-results")).toContainText("9223372036854775807");
  await expect(page.getByRole("link", { name: "Open document cities/one" })).toHaveAttribute(
    "href",
    /\/firestore\/cities\/one\?db=named-db$/,
  );
  await expect(page.getByTestId("query-results")).toContainText(
    "1 documents; 1 metadata-only rows",
  );
  expect(sent).toEqual({
    structuredQuery: {
      from: [{ collectionId: "cities" }],
      where: {
        fieldFilter: {
          field: { fieldPath: "score" },
          op: "GREATER_THAN",
          value: { integerValue: "9007199254740993" },
        },
      },
      orderBy: [{ field: { fieldPath: "score" }, direction: "ASCENDING" }],
      limit: 7,
    },
  });
  await row.getByLabel("Typed value").fill("4");
  await expect(page.getByTestId("query-stale")).toBeVisible();
  await expect(page.getByTestId("query-executed")).toContainText("9007199254740993");
  await expect(
    page.getByTestId("query-panel").getByRole("button", { name: "Load more" }),
  ).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("typed-query-results.png"), fullPage: true });
});

test("genuine index errors and malformed responses never become an empty success", async ({
  page,
}, testInfo) => {
  await openQuery(page);
  await page.route("**/ui/api/**:runQuery", (route) =>
    route.fulfill({
      status: 400,
      json: [
        {
          error: {
            status: "FAILED_PRECONDITION",
            message: "The query requires an index: exact backend detail",
          },
        },
      ],
    }),
  );
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByTestId("query-error")).toContainText("FAILED_PRECONDITION");
  await expect(page.getByTestId("query-error")).toContainText("exact backend detail");
  await expect(page.getByText("The query returned no documents.", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("index-error.png"), fullPage: true });
  await page.route("**/ui/api/**:runQuery", (route) =>
    route.fulfill({ json: [{ readTime: "2026-10-23T00:00:00Z", skippedResults: 0 }] }),
  );
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByText("The query returned no documents.", { exact: true })).toBeVisible();
  await expect(page.getByTestId("query-results")).toContainText(
    "0 documents; 1 metadata-only rows",
  );
  await page.route("**/ui/api/**:runQuery", (route) => route.fulfill({ json: { unknown: [] } }));
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByTestId("query-error")).toContainText("Malformed");
  await expect(page.getByText("The query returned no documents.", { exact: true })).toHaveCount(0);
});

test("late results cannot replace a newer query or cross a named database scope", async ({
  page,
}) => {
  // Deliver delayed responses even after cancellation so execution identities are exercised.
  await page.addInitScript(() => {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const options = { ...init };
      if (typeof input === "string" && input.endsWith(":runQuery")) delete options.signal;
      return nativeFetch(input, options);
    };
  });
  await openQuery(page);
  let release: (() => void) | undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let calls = 0;
  await page.route("**/ui/api/**:runQuery", async (route) => {
    calls++;
    if (calls === 1) {
      await held;
      await route.fulfill({ json: [{ document: document("late") }] }).catch(() => {});
    } else await route.fulfill({ json: [{ document: document("latest") }] });
  });
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByTestId("query-loading")).toBeVisible();
  await page.getByLabel("Result limit").fill("8");
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByTestId("query-results")).toContainText("latest");
  const lateResponse = page.waitForResponse((response) => response.url().endsWith(":runQuery"));
  release?.();
  await (await lateResponse).finished();
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
  await expect(page.getByTestId("query-results")).toContainText("latest");
  await expect(page.getByTestId("query-results")).not.toContainText('late"');
  await page.getByTestId("database-input").fill("named-db");
  await page.getByTestId("database-input").press("Tab");
  await expect(page.getByTestId("query-results")).toHaveCount(0);
  await expect(page.getByTestId("query-panel")).toContainText("Database named-db");
  await page.getByTestId("database-input").fill("(default)");
  await page.getByTestId("database-input").press("Tab");
  await expect(page.getByTestId("query-results")).toHaveCount(0);
  await expect(page.getByTestId("query-executed")).toHaveCount(0);
  await page.getByTestId("session-select").selectOption("trial");
  await expect(page.getByTestId("query-panel")).toContainText("Project demo-other");
  await page.getByTestId("session-select").selectOption("default");
  await expect(page.getByTestId("query-panel")).toContainText("Project demo-query");
  await expect(page.getByTestId("query-executed")).toHaveCount(0);
  let releaseScope: (() => void) | undefined;
  const scopeHeld = new Promise<void>((resolve) => {
    releaseScope = resolve;
  });
  await page.route("**/ui/api/**:runQuery", async (route) => {
    await scopeHeld;
    await route.fulfill({ json: [{ document: document("scope-late") }] });
  });
  await page.getByRole("button", { name: "Run query", exact: true }).click();
  await expect(page.getByTestId("query-loading")).toBeVisible();
  await page.getByTestId("database-input").fill("named-db");
  await page.getByTestId("database-input").press("Tab");
  await expect(page.getByTestId("query-panel")).toContainText("Database named-db");
  await page.getByTestId("database-input").fill("(default)");
  await page.getByTestId("database-input").press("Tab");
  await expect(page.getByTestId("query-panel")).toContainText("Database (default)");
  const scopeResponse = page.waitForResponse((response) => response.url().endsWith(":runQuery"));
  releaseScope?.();
  await (await scopeResponse).finished();
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
  await expect(page.getByTestId("query-results")).toHaveCount(0);
  await expect(page.getByTestId("query-executed")).toHaveCount(0);
});

test("index diagnostics distinguish disabled mode and scoped truncated reports", async ({
  page,
}) => {
  await openQuery(page, "?db=named-db");
  await page.route("**/ui/api/control/v1/sessions/default/firestore/missingIndexes", (route) =>
    route.fulfill({ status: 409, json: { error: "FAILED_PRECONDITION : reporting is disabled" } }),
  );
  await page.getByRole("button", { name: "Load index reports" }).click();
  await expect(page.getByTestId("query-indexes")).toContainText("reporting is disabled");
  await expect(page.getByTestId("query-indexes")).toContainText(
    "does not prove production index completeness",
  );
  await page.route("**/ui/api/control/v1/sessions/default/firestore/missingIndexes", (route) =>
    route.fulfill({
      json: {
        count: 2,
        missingIndexes: [
          {
            project: "demo-query",
            database: "named-db",
            name: "projects/demo-query/databases/named-db",
            index: {},
            message: "named report",
          },
          {
            project: "demo-query",
            database: "(default)",
            name: "projects/demo-query/databases/(default)",
            index: {},
            message: "other report",
          },
        ],
        indexesJson: {},
        dropped: 2,
        truncated: true,
      },
    }),
  );
  await page.getByRole("button", { name: "Load index reports" }).click();
  await expect(page.getByTestId("query-indexes")).toContainText("named report");
  await expect(page.getByTestId("query-indexes")).not.toContainText("other report");
  await expect(page.getByTestId("query-indexes")).toContainText("2 reports were dropped");
});

test("sharing restores a versioned draft without credentials and rejects malformed input", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await openQuery(page);
  await page.getByLabel("Result limit").fill("9");
  await page.getByRole("button", { name: "Copy query link" }).click();
  const link = await page.evaluate(() => navigator.clipboard.readText());
  expect(new URL(link).searchParams.has("token")).toBe(false);
  expect(JSON.parse(new URL(link).searchParams.get("query") ?? "{}")).toMatchObject({
    version: 1,
    limit: "9",
  });
  await page.goto(link);
  await expect(page.getByLabel("Result limit")).toHaveValue("9");
  await page.goto("/ui/firestore/cities?query=broken");
  await expect(page.getByTestId("query-panel")).toContainText("The shared query is invalid");
});
