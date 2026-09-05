import { expect, test } from "@playwright/test";
import { api, controlToken, gotoApp, resetSession } from "./helpers";

const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.describe("Runtime controls", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
    await api(request, "DELETE", "control/v1/sessions/default/faultPlan");
  });

  test("advances the virtual clock", async ({ page }) => {
    await gotoApp(page, "/runtime");
    const before = await page.getByTestId("runtime-clock").textContent();
    await page.getByTestId("advance-seconds").fill("3600");
    await page.getByTestId("advance-clock").click();
    await expect(page.getByTestId("runtime-clock")).not.toHaveText(before ?? "");
    const after = await page.getByTestId("runtime-clock").textContent();
    expect(Date.parse(after ?? "") - Date.parse(before ?? "")).toBe(3600 * 1000);
  });

  test("captures and restores a snapshot", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/snap/a`, { fields: { v: { integerValue: "1" } } });
    await gotoApp(page, "/runtime");
    await page.getByTestId("snapshot-name").fill("seeded");
    await page.getByTestId("snapshot-capture").click();
    await expect(page.getByTestId("snapshot-table")).toContainText("seeded");
    await api(request, "DELETE", `${DOCS}/snap/a`);
    await page.getByTestId("snapshot-restore-seeded").click();
    await page.getByTestId("snapshot-restore-seeded-confirm").click();
    await expect(page.getByRole("status").filter({ hasNotText: "Loading" })).toContainText(
      "seeded",
    );
    const doc = (await api(request, "GET", `${DOCS}/snap/a`)) as {
      fields: { v: { integerValue: string } };
    };
    expect(doc.fields.v.integerValue).toBe("1");
  });

  test("installs a fault plan that fires on the second commit", async ({ page, request }) => {
    await gotoApp(page, "/runtime");
    await page.getByTestId("fault-install").click();
    await expect(page.getByTestId("fault-rules")).toContainText("firestore.commit");
    await api(request, "PATCH", `${DOCS}/f/one`, { fields: {} });
    const second = await request.fetch(`/ui/api/${DOCS}/f/two`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${controlToken()}` },
      data: { fields: {} },
    });
    expect(second.status()).toBe(409);
    await page.reload();
    await expect(page.getByText("firestore.commit #2")).toBeVisible();
    await page.getByTestId("fault-clear").click();
    await expect(page.getByText("No fault plan installed")).toBeVisible();
  });

  test("creates, selects, resets and deletes a session", async ({ page }) => {
    await gotoApp(page, "/runtime");
    await page.getByTestId("session-project").fill("demo-b");
    await page.getByTestId("session-create").click();
    const table = page.getByTestId("session-table");
    await expect(table).toContainText("demo-b");
    await page.getByTestId("session-reset-demo-b").click();
    await page.getByTestId("session-reset-demo-b-confirm").click();
    await page.getByTestId("session-delete-demo-b").click();
    await page.getByTestId("session-delete-demo-b-confirm").click();
    await expect(table).not.toContainText("demo-b");
  });

  test("reports what every service retains and asserts quiescence", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/retained/a`, { fields: { v: { integerValue: "1" } } });
    await gotoApp(page, "/runtime");
    const report = page.getByTestId("resources-report");
    await expect(report).toBeVisible();
    for (const service of ["snapshots", "firestore", "storage", "auth", "pubsub", "functions"]) {
      await expect(page.getByTestId(`resources-${service}`)).toBeVisible();
    }
    const firestore = page.getByTestId("resources-firestore");
    await expect(firestore).toContainText("history.session_bytes");
    await expect(firestore).toContainText("demo-app/(default)");
    await expect(firestore.locator("tr[data-outstanding='true']")).toHaveCount(0);

    // Nothing is outstanding on an idle daemon.
    await page.getByTestId("resources-assert").click();
    await expect(page.getByRole("status").filter({ hasText: "Quiescent" })).toBeVisible();

    // An allowance that excuses nothing is reported, never silently accepted.
    await page
      .getByTestId("resources-allowances")
      .fill("firestore transactions demo-app/(default) held by nobody");
    await page.getByTestId("resources-assert").click();
    const failure = page.getByTestId("quiescence-failure");
    await expect(failure).toContainText("Not quiescent");
    await expect(failure).toContainText("matched nothing");
    await expect(failure).toContainText("demo-app/(default)");
  });
});
