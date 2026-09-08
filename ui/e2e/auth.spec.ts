import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";

test.describe("Authentication", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("shows second-factor enrollment in user rows", async ({ page, request }) => {
    const admin = "auth/identitytoolkit.googleapis.com/v1/projects/demo-app";
    const user = (await api(request, "POST", `${admin}/accounts`, {
      email: "mfa@example.com",
      password: "hunter22",
      emailVerified: true,
    })) as { localId: string };
    await api(request, "POST", `${admin}/accounts:update`, {
      localId: user.localId,
      mfa: { enrollments: [{ mfaEnrollmentId: "phone-factor", phoneInfo: "+15555550123" }] },
    });
    await gotoApp(page, "/auth");
    await expect(page.getByRole("columnheader", { name: "Second factors" })).toBeVisible();
    const row = page.getByTestId(`user-row-${user.localId}`);
    await expect(row.getByRole("cell", { name: "Phone", exact: true })).toBeVisible();
    await api(request, "POST", `${admin}/accounts:update`, {
      localId: user.localId,
      mfa: { enrollments: [] },
    });
    await page.getByTestId("user-refresh").click();
    await expect(row).toContainText("No second factors");
  });

  test("creates, edits, disables and deletes a user", async ({ page }) => {
    await gotoApp(page, "/auth");
    await expect(page.getByText("No users")).toBeVisible();
    await page.getByTestId("add-user").click();
    await page.getByTestId("new-user-email").fill("alice@example.com");
    await page.getByTestId("new-user-password").fill("hunter22");
    await page.getByTestId("new-user-name").fill("Alice");
    await page.getByTestId("new-user-save").click();
    const table = page.getByTestId("user-table");
    await expect(table).toContainText("alice@example.com");
    await expect(table).toContainText("Alice");

    await table
      .getByRole("button", { name: /^[A-Za-z0-9]{10,}$/ })
      .first()
      .click();
    await page.getByTestId("edit-name").fill("Alice Liddell");
    await page.getByTestId("edit-claims").fill('{"role": "admin"}');
    await page.getByTestId("edit-save").click();
    await expect(table).toContainText("Alice Liddell");
    await page.getByTestId("edit-toggle-disabled").click();
    await expect(table).toContainText("Disabled");

    const row = table.getByRole("row").filter({ hasText: "alice@example.com" });
    await row.getByRole("button", { name: "Delete" }).click();
    await row.getByRole("button", { name: "Confirm" }).click();
    await expect(page.getByText("No users")).toBeVisible();
  });

  test("lists pending email action codes", async ({ page, request }) => {
    const admin = "auth/identitytoolkit.googleapis.com/v1/projects/demo-app";
    await api(request, "POST", `${admin}/accounts`, {
      email: "bob@example.com",
      password: "hunter22",
    });
    await api(request, "POST", `${admin}/accounts:sendOobCode`, {
      requestType: "PASSWORD_RESET",
      email: "bob@example.com",
    });
    await gotoApp(page, "/auth");
    const codes = page.getByTestId("oob-table");
    await expect(codes).toContainText("bob@example.com");
    await expect(codes).toContainText("PASSWORD_RESET");
    await page.getByTestId("user-search").fill("bob@example.com");
    await page.getByTestId("user-search").press("Enter");
    await expect(page.getByTestId("user-table")).toContainText("bob@example.com");
    await page.getByTestId("user-search").fill("nobody@example.com");
    await page.getByTestId("user-search").press("Enter");
    await expect(page.getByText("No users")).toBeVisible();
  });
});
