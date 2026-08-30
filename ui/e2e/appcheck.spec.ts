import { expect, test, type APIRequestContext } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";
import { PORTS } from "./global-setup";

// The App Check page against the smoke configuration, which registers one app of `demo-app`
// and puts every service in `unenforced`: the daemon then classifies and records every
// request without denying any, which is exactly the state the page has to describe.

const APP_ID = "1:1234567890:web:local-test-app";
const EXCHANGE = `http://127.0.0.1:${PORTS.http}/v1/projects/demo-app/apps/${encodeURIComponent(APP_ID)}:exchangeDebugToken`;

/** Exchanges a debug secret against the daemon's public route; returns the HTTP status. */
const exchange = async (request: APIRequestContext, secret: string): Promise<number> => {
  const response = await request.fetch(EXCHANGE, {
    method: "POST",
    headers: { "content-type": "application/json" },
    data: { debugToken: secret },
  });
  return response.status();
};

test.describe("App Check", () => {
  test.beforeEach(async ({ request }) => {
    // A reset rotates the project epoch and drops the dynamic debug-token registrations and
    // the observations with it, so each scenario starts from the static configuration alone.
    await resetSession(request);
  });

  test("shows the signing key, the baseline modes and the configured app", async ({ page }) => {
    await gotoApp(page, "/appcheck");
    await expect(page.getByTestId("appcheck-disabled")).toHaveCount(0);
    await expect(page.getByTestId("appcheck-kid")).toContainText("fireemu-app-check-");

    const modes = page.getByTestId("appcheck-mode-table");
    for (const service of ["auth", "firestore", "storage"]) {
      await expect(modes.getByRole("row").filter({ hasText: service })).toContainText("unenforced");
    }

    const apps = page.getByTestId("appcheck-app-table");
    await expect(apps).toContainText(APP_ID);
    await expect(apps).toContainText("1234567890");
    // One digest from configuration, no dynamic registration yet.
    const row = apps.getByRole("row").filter({ hasText: APP_ID });
    await expect(row).toContainText("yes");
  });

  test("registers a generated debug token, reveals the secret once and deletes it", async ({
    page,
    request,
  }) => {
    await gotoApp(page, "/appcheck");
    await expect(page.getByTestId("appcheck-secret")).toHaveCount(0);

    await page.locator("#appcheck-token-name").fill("e2e runner");
    await page.getByTestId("appcheck-create").click();

    const field = page.getByTestId("appcheck-secret");
    await expect(field).toBeVisible();
    const secret = await field.inputValue();
    expect(secret).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    // It is the real credential: the daemon's public exchange accepts it.
    expect(await exchange(request, secret)).toBe(200);

    // The list shows the record without the secret behind it.
    const table = page.getByTestId("appcheck-token-table");
    await expect(table).toContainText("e2e runner");
    await expect(table).not.toContainText(secret);

    // Dismissing drops it, and it never comes back: the daemon keeps only the digest.
    await page.getByTestId("appcheck-secret-dismiss").click();
    await expect(page.getByTestId("appcheck-secret")).toHaveCount(0);
    await gotoApp(page, "/appcheck");
    await expect(page.locator("body")).not.toContainText(secret);
    const stored = await page.evaluate(() =>
      JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
    );
    expect(stored).not.toContain(secret);
    const injected = await page.evaluate(() => JSON.stringify(window.__FIREEMU__ ?? {}));
    expect(injected).not.toContain(secret);

    // The summary counts it as a dynamic registration, not as a configured digest.
    const listed = (await api(request, "GET", "appcheck/config?project=demo-app")) as {
      apps: { staticDigestCount: number; dynamicTokenCount: number }[];
    };
    expect(listed.apps.at(0)?.staticDigestCount).toBe(1);
    expect(listed.apps.at(0)?.dynamicTokenCount).toBe(1);

    const row = table.getByRole("row").filter({ hasText: "e2e runner" });
    const tokenId = (await row.getByRole("cell").first().textContent())?.trim() ?? "";
    expect(tokenId).not.toBe("");
    await page.getByTestId(`appcheck-delete-${tokenId}`).click();
    await page.getByTestId(`appcheck-delete-${tokenId}-confirm`).click();
    await expect(page.getByTestId("appcheck-token-table")).toHaveCount(0);

    // Deletion takes effect for later exchanges.
    expect(await exchange(request, secret)).toBe(403);
  });

  test("refuses a supplied secret that is not a canonical UUIDv4", async ({ page }) => {
    await gotoApp(page, "/appcheck");
    await page.locator("#appcheck-generate").uncheck();
    await page.locator("#appcheck-secret-input").fill("not-a-uuid");
    await page.getByTestId("appcheck-create").click();
    await expect(page.getByRole("alert")).toContainText("canonical UUIDv4");
    await expect(page.getByTestId("appcheck-token-table")).toHaveCount(0);
  });

  test("counts what the runtime classified and lists the recent observations", async ({
    page,
    request,
  }) => {
    // One valid exchange of the statically configured debug secret, and one privileged read
    // through the UI front, which takes the documented owner bypass.
    expect(await exchange(request, "deadbeef-0000-4000-8000-000000000001")).toBe(200);
    await api(request, "GET", "firestore/v1/projects/demo-app/databases/(default)/documents/probe");

    await gotoApp(page, "/appcheck");
    await page.getByTestId("appcheck-refresh-observations").click();

    const counters = page.getByTestId("appcheck-counter-table");
    await expect(counters.getByRole("row").filter({ hasText: "app-check" })).toContainText("valid");
    await expect(counters.getByRole("row").filter({ hasText: "firestore" })).toContainText(
      "bypass",
    );
    await expect(page.getByTestId("appcheck-admitted")).toHaveText("2");
    await expect(page.getByTestId("appcheck-denied")).toHaveText("0");

    const observations = page.getByTestId("appcheck-observation-table");
    await expect(observations).toContainText("exchangeDebugToken");
    await expect(observations).toContainText(APP_ID);

    // A privileged view carries the failure reason but never a credential.
    await expect(page.locator("body")).not.toContainText("deadbeef-0000-4000-8000-000000000001");
    await expect(page.locator("body")).not.toContainText(
      "05f74b7cc5a65141f960e5bceb0291194480025a6579fe21b0d051979d47ce57",
    );
  });
});
