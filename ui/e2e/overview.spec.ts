import { expect, test } from "@playwright/test";
import { gotoApp } from "./helpers";
import { PORTS } from "./global-setup";

test.describe("Overview", () => {
  test("shows the project, services and the virtual clock", async ({ page }) => {
    await gotoApp(page, "/");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByText("demo-app").first()).toBeVisible();
    await expect(page.getByTestId("overview-clock")).toHaveText(/2026-08-29T12:0/);
    await expect(page.getByText(`127.0.0.1:${PORTS.firestore}`).first()).toBeVisible();
  });

  test("navigates between the panels", async ({ page }) => {
    await gotoApp(page, "/");
    await page.getByRole("link", { name: "Runtime" }).click();
    await expect(page.getByRole("heading", { name: "Runtime", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Rules" }).click();
    await expect(page.getByRole("heading", { name: "Rules", exact: true })).toBeVisible();
  });

  test("shows no product scope table and no compatibility label", async ({ page }) => {
    await gotoApp(page, "/");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByTestId("product-scope")).toHaveCount(0);
    await expect(page.locator("[data-testid^='scope-']")).toHaveCount(0);
    await expect(page.getByText("Product scope")).toHaveCount(0);
    await expect(page.getByText("not planned")).toHaveCount(0);
    await expect(page.getByTestId("env-dotenv")).toBeVisible();
  });

  test("labels the deterministic controls as fireemu-only and groups them apart", async ({
    page,
  }) => {
    await gotoApp(page, "/runtime");
    await expect(page.getByTestId("runtime-fireemu-only")).toContainText("fireemu-only");
    await expect(page.getByText("fireemu runtime").first()).toBeVisible();
  });
});
