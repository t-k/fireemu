import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";

// The console must never act on a target other than the one it shows: an editor belongs to
// one user, a draft is never lost silently, and names the API accepts stay reachable.
const ADMIN = "auth/identitytoolkit.googleapis.com/v1/projects/demo-app";
const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.describe("Console safety", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("the Auth editor belongs to one user: switching targets never carries a draft over", async ({
    page,
    request,
  }) => {
    await api(request, "POST", `${ADMIN}/accounts`, {
      localId: "user-a",
      email: "a@example.com",
      displayName: "Name-A",
    });
    await api(request, "POST", `${ADMIN}/accounts`, {
      localId: "user-b",
      email: "b@example.com",
      displayName: "Name-B",
    });
    await gotoApp(page, "/auth");
    const table = page.getByTestId("user-table");
    await table.getByRole("button", { name: "user-a" }).click();
    await expect(page.getByTestId("edit-uid")).toHaveValue("user-a");
    await page.getByTestId("edit-name").fill("Name-A edited");

    // Switching to B while A has an unsaved draft asks first; keeping stays on A.
    await table.getByRole("button", { name: "user-b" }).click();
    await expect(page.getByTestId("unsaved-prompt")).toContainText("user-a");
    await page.getByTestId("unsaved-keep").click();
    await expect(page.getByTestId("edit-uid")).toHaveValue("user-a");
    await expect(page.getByTestId("edit-name")).toHaveValue("Name-A edited");

    // Discarding opens B with B's own values, and a save reaches B only.
    await table.getByRole("button", { name: "user-b" }).click();
    await page.getByTestId("unsaved-discard").click();
    await expect(page.getByTestId("edit-uid")).toHaveValue("user-b");
    await expect(page.getByTestId("edit-name")).toHaveValue("Name-B");
    await page.getByTestId("edit-name").fill("Name-B saved");
    await page.getByTestId("edit-save").click();
    await expect(table.getByTestId("user-row-user-b")).toContainText("Name-B saved");
    await expect(table.getByTestId("user-row-user-a")).toContainText("Name-A");
    await expect(table.getByTestId("user-row-user-a")).not.toContainText("edited");
  });

  test("a Firestore document edit in progress is not lost by navigating away", async ({
    page,
    request,
  }) => {
    await api(request, "PATCH", `${DOCS}/cities/tokyo`, {
      fields: { name: { stringValue: "Tokyo" } },
    });
    await gotoApp(page, "/firestore/cities/tokyo");
    await page.getByTestId("document-edit").click();
    const view = page.getByTestId("document-view");
    await view.getByLabel("Value").first().fill("Edo");
    await page.getByRole("link", { name: "cities" }).click();
    await expect(page.getByTestId("unsaved-prompt")).toContainText("cities/tokyo");
    await page.getByTestId("unsaved-keep").click();
    await expect(view.getByLabel("Value").first()).toHaveValue("Edo");
    await page.getByRole("link", { name: "cities" }).click();
    await page.getByTestId("unsaved-discard").click();
    await expect(page.getByTestId("collection-view")).toBeVisible();
    const doc = (await api(request, "GET", `${DOCS}/cities/tokyo`)) as {
      fields: { name: { stringValue: string } };
    };
    expect(doc.fields.name.stringValue).toBe("Tokyo");
  });

  test("document IDs with # and ? open from the list and through the path box", async ({
    page,
    request,
  }) => {
    const id = "a#b?c%d";
    await api(request, "PATCH", `${DOCS}/odd/${encodeURIComponent(id)}`, {
      fields: { ok: { booleanValue: true } },
    });
    await gotoApp(page, "/firestore/odd");
    await page.getByTestId("document-list").getByRole("link", { name: id }).click();
    await expect(page.getByRole("heading", { name: id })).toBeVisible();
    await expect(page.getByTestId("document-fields")).toContainText("ok");
    await page.getByTestId("path-jump").fill("odd");
    await page.getByTestId("path-jump").press("Enter");
    await expect(page.getByTestId("collection-view")).toContainText(id);
  });

  test("the header names the selected session's project and the Overview follows it", async ({
    page,
    request,
  }) => {
    await api(request, "POST", "control/v1/sessions", { project: "demo-b", name: "demo-b" });
    await gotoApp(page, "/");
    await expect(page.getByTestId("header-project")).toHaveText("demo-app");
    await page.getByTestId("session-select").selectOption("demo-b");
    await expect(page.getByTestId("header-project")).toHaveText("demo-b");
    await expect(page.getByTestId("env-dotenv")).toContainText("GOOGLE_CLOUD_PROJECT=demo-b");
    await expect(page.getByTestId("connection-badge")).toHaveText("Connected");
    await api(request, "DELETE", "control/v1/sessions/demo-b");
  });

  test("a failed list read says so instead of showing an empty collection", async ({ page }) => {
    await gotoApp(page, "/firestore?db=no%20such%20db%2F%2F");
    await expect(page.getByTestId("fetch-error")).toBeVisible();
    await expect(page.getByText("No collections")).toHaveCount(0);
  });

  test("Function logs stop following once the reader scrolls up", async ({ page, request }) => {
    await gotoApp(page, "/functions");
    await expect(page.getByTestId("log-following")).toBeVisible();
    for (let i = 0; i < 40; i += 1) {
      await api(request, "PATCH", `${DOCS}/todos/t${i}`, {
        fields: { title: { stringValue: `line ${i}` } },
      });
    }
    await page.getByTestId("await-idle").click();
    const logs = page.getByTestId("function-logs");
    await expect(logs).toContainText("mirrorTodo");
    await expect.poll(() => logs.evaluate((el) => el.scrollHeight > el.clientHeight)).toBe(true);
    await logs.evaluate((el) => {
      el.scrollTop = 0;
    });
    await expect(page.getByTestId("log-jump")).toBeVisible();
    await api(request, "PATCH", `${DOCS}/todos/t-late`, {
      fields: { title: { stringValue: "late" } },
    });
    await page.getByTestId("await-idle").click();
    await expect(page.getByTestId("log-jump")).toContainText(/new lines/);
    await page.getByTestId("log-jump").click();
    await expect(page.getByTestId("log-following")).toBeVisible();
  });
});
