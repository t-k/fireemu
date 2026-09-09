import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";

const ADMIN = "auth/identitytoolkit.googleapis.com/v1/projects/demo-app";
const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";
test.beforeEach(async ({ request }) => {
  await resetSession(request);
});

test("field-name drafts require a decision before navigation", async ({ page, request }) => {
  await api(request, "PATCH", `${DOCS}/dogfood/note`, {
    fields: { title: { stringValue: "Original" } },
  });
  await gotoApp(page, "/firestore/dogfood/note");
  await page.getByTestId("document-edit").click();
  const field = page.getByTestId("document-view").getByLabel("Field", { exact: true }).first();
  await field.fill("renamed");
  await page.getByRole("link", { name: "Authentication", exact: true }).click();
  await expect(page.getByTestId("unsaved-prompt")).toBeVisible();
  await page.getByTestId("unsaved-keep").click();
  await expect(field).toHaveValue("renamed");
  await expect(field).toBeFocused();
  await page.getByRole("link", { name: "dogfood", exact: true }).click();
  await page.getByTestId("unsaved-discard").click();
  const doc = await api(request, "GET", `${DOCS}/dogfood/note`);
  expect(doc).toMatchObject({ fields: { title: { stringValue: "Original" } } });
});

test("Auth searches and refreshes retain an independent user draft", async ({ page, request }) => {
  await api(request, "POST", `${ADMIN}/accounts`, {
    localId: "alice",
    email: "alice@example.com",
    displayName: "Alice",
  });
  await gotoApp(page, "/auth");
  await page.getByRole("button", { name: "alice", exact: true }).click();
  await page.getByTestId("edit-name").fill("Alice-unsaved");
  await page.getByTestId("user-search").fill("nobody@example.com");
  await page.getByTestId("user-search").press("Enter");
  await expect(page.getByTestId("user-table")).toHaveCount(0);
  await expect(page.getByTestId("edit-name")).toHaveValue("Alice-unsaved");
  await page.getByTestId("user-refresh").click();
  await expect(page.getByTestId("edit-name")).toHaveValue("Alice-unsaved");
  await page.getByTestId("user-search").fill("alice@example.com");
  await page.getByTestId("user-search").press("Enter");
  await expect(page.getByTestId("user-table")).toContainText("Alice");
  await expect(page.getByTestId("edit-name")).toHaveValue("Alice-unsaved");
});

test("Auth scope switches clear old rows and armed confirmations", async ({ page, request }) => {
  await api(request, "POST", `${ADMIN}/accounts`, { localId: "alice", email: "alice@example.com" });
  await api(request, "POST", `${ADMIN}/accounts:sendOobCode`, {
    requestType: "PASSWORD_RESET",
    email: "alice@example.com",
  });
  await api(request, "POST", "control/v1/sessions", {
    name: "dogfood-scope",
    project: "demo-dogfood-scope",
  });
  try {
    await gotoApp(page, "/auth");
    await expect(page.getByTestId("oob-table")).toContainText("alice@example.com");
    await page.getByTestId("user-search").fill("alice@example.com");
    await page.getByTestId("user-search").press("Enter");
    await page.getByTestId("delete-all-users").click();
    await page.getByTestId("session-select").selectOption("dogfood-scope");
    await expect(page.getByTestId("header-project")).toHaveText("demo-dogfood-scope");
    await expect(page.getByTestId("user-row-alice")).toHaveCount(0);
    await expect(page.getByTestId("delete-all-users-confirm")).toHaveCount(0);
    await expect(page.getByTestId("oob-table")).toHaveCount(0);
    await expect(page.getByTestId("user-search")).toHaveValue("");
    await page.getByTestId("session-select").selectOption("default");
    await expect(page.getByTestId("user-row-alice")).toBeVisible();
    await page.getByRole("button", { name: "alice", exact: true }).click();
    await page.getByTestId("edit-name").fill("draft");
    await page.getByTestId("session-select").selectOption("dogfood-scope");
    await expect(page.getByTestId("unsaved-prompt")).toBeVisible();
    await expect(page.getByTestId("header-project")).toHaveText("demo-app");
    await page.getByTestId("unsaved-keep").click();
    await expect(page.getByTestId("edit-name")).toHaveValue("draft");
    await page.getByTestId("session-select").selectOption("dogfood-scope");
    await page.getByTestId("unsaved-discard").click();
    await expect(page.getByTestId("header-project")).toHaveText("demo-dogfood-scope");
    await expect(page.getByTestId("user-editor")).toHaveCount(0);
  } finally {
    await api(request, "DELETE", "control/v1/sessions/dogfood-scope");
  }
});

test("every smoke function has a trigger description after refresh", async ({ page }) => {
  await gotoApp(page, "/functions");
  const rows = page.locator('[data-testid^="function-row-"]');
  await expect(rows.first()).toBeVisible();
  for (let pass = 0; pass < 2; pass += 1) {
    for (const row of await rows.all()) {
      await expect(row.locator("td").nth(2)).not.toHaveText("");
    }
    if (pass === 0) await page.getByRole("button", { name: "Refresh", exact: true }).click();
  }
});

for (const width of [390, 768, 1280]) {
  test(`Auth actions fit a ${width}px viewport with long user identifiers`, async ({
    page,
    request,
  }) => {
    await api(request, "POST", `${ADMIN}/accounts`, {
      localId: "long-user-".repeat(12),
      email: `${"a".repeat(60)}@example.com`,
    });
    await page.setViewportSize({ width, height: 844 });
    await page.goto("/ui/auth");
    await expect(page.getByTestId("user-table")).toBeVisible();
    for (const id of ["user-search", "user-refresh", "add-user", "delete-all-users"]) {
      const box = await page.getByTestId(id).boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(width);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      width,
    );
    if (width === 390) {
      const toggle = page.getByRole("button", { name: "Navigation", exact: true });
      await toggle.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("navigation").first()).toBeVisible();
      await page.getByRole("link", { name: "Authentication", exact: true }).click();
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
    }
  });
}

test("late Auth reads cannot replace the newly selected project's rows", async ({
  page,
  request,
}) => {
  await api(request, "POST", `${ADMIN}/accounts`, { localId: "alice", email: "alice@example.com" });
  await api(request, "POST", "control/v1/sessions", {
    name: "dogfood-late",
    project: "demo-dogfood-late",
  });
  await api(
    request,
    "POST",
    "auth/identitytoolkit.googleapis.com/v1/projects/demo-dogfood-late/accounts",
    { localId: "bob", email: "bob@example.com" },
  );
  let release!: () => void;
  let received!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    received = resolve;
  });
  try {
    await gotoApp(page, "/auth");
    await expect(page.getByTestId("user-row-alice")).toBeVisible();
    // Delay a real daemon response; no fabricated API payloads.
    await page.route("**/projects/demo-app/accounts:batchGet**", async (route) => {
      const response = await route.fetch();
      received();
      await held;
      await route.fulfill({ response });
    });
    await page.getByTestId("user-refresh").click();
    await started;
    await page.getByTestId("session-select").selectOption("dogfood-late");
    await expect(page.getByTestId("user-row-bob")).toBeVisible();
    release();
    await page.unrouteAll({ behavior: "wait" });
    await expect(page.getByTestId("user-row-alice")).toHaveCount(0);
    await expect(page.getByTestId("user-row-bob")).toBeVisible();
  } finally {
    release();
    await api(request, "DELETE", "control/v1/sessions/dogfood-late");
  }
});

for (const change of ["add", "remove", "restore", "invalid"] as const) {
  test(`Firestore ${change} field edits have correct navigation protection`, async ({
    page,
    request,
  }) => {
    await api(request, "PATCH", `${DOCS}/dogfood/note`, {
      fields: { title: { stringValue: "Original" } },
    });
    await gotoApp(page, "/firestore/dogfood/note");
    await page.getByTestId("document-edit").click();
    const view = page.getByTestId("document-view");
    const name = view.getByLabel("Field", { exact: true }).first();
    if (change === "add") await view.getByTestId("add-field").click();
    if (change === "remove")
      await view.getByRole("button", { name: "Delete", exact: true }).first().click();
    if (change === "invalid") await name.fill("");
    if (change === "restore") {
      await name.fill("renamed");
      await name.fill("title");
    }
    await page.getByRole("link", { name: "Authentication", exact: true }).click();
    if (change === "restore") {
      await expect(
        page.getByRole("heading", { name: "Authentication", exact: true }),
      ).toBeVisible();
      await expect(page.getByTestId("unsaved-prompt")).toHaveCount(0);
    } else {
      await expect(page.getByTestId("unsaved-prompt")).toBeVisible();
      await page.getByTestId("unsaved-keep").click();
      await expect(view).toBeVisible();
    }
  });
}

test("a new Auth user draft survives a cancelled scope switch", async ({ page, request }) => {
  await api(request, "POST", "control/v1/sessions", {
    name: "dogfood-new",
    project: "demo-dogfood-new",
  });
  try {
    await gotoApp(page, "/auth");
    await page.getByTestId("add-user").click();
    await page.getByTestId("new-user-email").fill("unsaved@example.com");
    await page.getByTestId("session-select").selectOption("dogfood-new");
    await expect(page.getByTestId("unsaved-prompt")).toBeVisible();
    await page.getByTestId("unsaved-keep").click();
    await expect(page.getByTestId("session-select")).toHaveValue("default");
    await expect(page.getByTestId("new-user-email")).toHaveValue("unsaved@example.com");
    await page.getByTestId("session-select").selectOption("dogfood-new");
    await page.getByTestId("unsaved-discard").click();
    await expect(page.getByTestId("new-user")).toHaveCount(0);
    await expect(page.getByTestId("header-project")).toHaveText("demo-dogfood-new");
  } finally {
    await api(request, "DELETE", "control/v1/sessions/dogfood-new");
  }
});

test("an externally deleted Auth user keeps its draft and reports save failure", async ({
  page,
  request,
}) => {
  await api(request, "POST", `${ADMIN}/accounts`, {
    localId: "deleted-user",
    email: "deleted@example.com",
    displayName: "Original",
  });
  await gotoApp(page, "/auth");
  await page.getByRole("button", { name: "deleted-user", exact: true }).click();
  await page.getByTestId("edit-name").fill("unsaved");
  await api(request, "POST", `${ADMIN}/accounts:delete`, { localId: "deleted-user" });
  await page.getByTestId("user-refresh").click();
  await expect(page.getByTestId("user-table")).toHaveCount(0);
  await expect(page.getByTestId("edit-name")).toHaveValue("unsaved");
  await page.getByTestId("edit-save").click();
  await expect(page.getByTestId("user-editor").getByRole("alert")).toContainText("USER_NOT_FOUND");
  await expect(page.getByTestId("edit-name")).toHaveValue("unsaved");
});

test("saving a Firestore rename preserves the original numeric wire value", async ({
  page,
  request,
}) => {
  const value = { integerValue: "9223372036854775807" };
  await api(request, "PATCH", `${DOCS}/dogfood/numeric`, { fields: { before: value } });
  await gotoApp(page, "/firestore/dogfood/numeric");
  await page.getByTestId("document-edit").click();
  await page
    .getByTestId("document-view")
    .getByLabel("Field", { exact: true })
    .first()
    .fill("after");
  await page
    .getByTestId("document-view")
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(page.getByTestId("document-fields")).toContainText("after");
  const document = (await api(request, "GET", `${DOCS}/dogfood/numeric`)) as { fields: unknown };
  expect(document.fields).toEqual({ after: value });
});
