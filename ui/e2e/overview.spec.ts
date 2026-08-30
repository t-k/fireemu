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
});
