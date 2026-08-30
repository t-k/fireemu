import { expect, test } from "@playwright/test";
import { gotoApp } from "./helpers";

test.describe("Overview", () => {
  test("shows the project, services and the virtual clock", async ({ page }) => {
    await gotoApp(page, "/");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByText("demo-app").first()).toBeVisible();
    await expect(page.getByTestId("overview-clock")).toHaveText(/2026-08-29T12:0/);
    await expect(page.getByText("127.0.0.1:18080").first()).toBeVisible();
  });

  test("navigates between the panels", async ({ page }) => {
    await gotoApp(page, "/");
    await page.getByRole("link", { name: "Runtime" }).click();
    await expect(page.getByRole("heading", { name: "Runtime", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Rules" }).click();
    await expect(page.getByRole("heading", { name: "Rules", exact: true })).toBeVisible();
  });

  test("states the product scope honestly", async ({ page }) => {
    await gotoApp(page, "/");
    const scope = page.getByTestId("product-scope");
    await expect(scope.getByTestId("scope-rtdb")).toContainText("deferred");
    await expect(scope.getByTestId("scope-extensions")).toContainText("not planned");
    await expect(scope.getByTestId("scope-requests")).toContainText("supported");
    await expect(scope.getByTestId("scope-coverage")).toContainText("pending UI");
    await expect(scope.getByTestId("scope-alerts")).toContainText("pending UI");
    await expect(scope.getByTestId("scope-logging")).toContainText("substituted");
  });

  test("labels the deterministic controls as fireemu-only and groups them apart", async ({
    page,
  }) => {
    await gotoApp(page, "/runtime");
    await expect(page.getByTestId("runtime-fireemu-only")).toContainText("fireemu-only");
    await expect(page.getByText("fireemu runtime").first()).toBeVisible();
  });
});
