import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";

const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.describe("Firestore data browser", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("starts a collection, edits a document with typed fields and deletes it", async ({
    page,
  }) => {
    await gotoApp(page, "/firestore");
    await expect(page.getByText("No collections")).toBeVisible();
    await page.getByTestId("start-collection").click();
    await page.getByTestId("new-collection-id").fill("cities");
    await page.getByTestId("new-collection-doc-id").fill("tokyo");
    const form = page.getByTestId("new-collection");
    await form.getByLabel("Field").first().fill("name");
    await form.getByLabel("Value").first().fill("Tokyo");
    await form.getByTestId("add-field").click();
    await form.getByLabel("Field").nth(1).fill("population");
    await form.getByLabel("Type").nth(1).selectOption("number");
    await form.getByLabel("Value").nth(1).fill("14000000");
    await form.getByTestId("add-field").click();
    await form.getByLabel("Field").nth(2).fill("location");
    await form.getByLabel("Type").nth(2).selectOption("geopoint");
    await form.getByLabel("Value").nth(2).fill("35.68, 139.69");
    await page.getByTestId("new-collection-save").click();
    await expect(page).toHaveURL(/\/ui\/firestore\/cities\/tokyo/);
    const fields = page.getByTestId("document-fields");
    await expect(fields).toContainText("name");
    await expect(fields).toContainText('"Tokyo"');
    await expect(fields).toContainText("14000000");
    await expect(fields).toContainText("[35.68, 139.69]");

    // Edit: change the population, add a boolean.
    await page.getByTestId("document-edit").click();
    const editor = page.getByTestId("document-view");
    const rows = editor.getByLabel("Field");
    const count = await rows.count();
    await editor.getByTestId("add-field").click();
    await editor.getByLabel("Field").nth(count).fill("capital");
    await editor.getByLabel("Type").nth(count).selectOption("boolean");
    await editor.getByLabel("Value").nth(count).fill("true");
    await page.getByTestId("document-save").click();
    await expect(fields).toContainText("capital");
    await expect(fields).toContainText("true");

    // An invalid value is refused with the field named (fields come back sorted).
    await page.getByTestId("document-edit").click();
    const firstName = await editor.getByLabel("Field").first().inputValue();
    await editor.getByLabel("Type").first().selectOption("number");
    await editor.getByLabel("Value").first().fill("not a number");
    await page.getByTestId("document-save").click();
    await expect(page.getByRole("alert")).toContainText(`${firstName}: integer or decimal`);
    await page.getByRole("button", { name: "Cancel" }).click();

    // Delete the document, then the collection is empty.
    await page.getByTestId("document-delete").click();
    await page.getByTestId("document-delete-confirm").click();
    await expect(page).toHaveURL(/\/ui\/firestore\/cities/);
    await expect(page.getByText("No documents")).toBeVisible();
  });

  test("reflects commits made through the API live", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/live/one`, { fields: { v: { integerValue: "1" } } });
    await gotoApp(page, "/firestore/live");
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
    await expect(page.getByTestId("document-list")).toContainText("one");
    await api(request, "PATCH", `${DOCS}/live/two`, { fields: { v: { integerValue: "2" } } });
    await expect(page.getByTestId("document-list")).toContainText("two");
    await api(request, "DELETE", `${DOCS}/live/one`);
    await expect(page.getByTestId("document-list")).not.toContainText("one");
  });

  test("deletes a collection recursively", async ({ page, request }) => {
    for (let i = 0; i < 3; i += 1) {
      await api(request, "PATCH", `${DOCS}/bulk/d${i}`, {
        fields: { i: { integerValue: String(i) } },
      });
      await api(request, "PATCH", `${DOCS}/bulk/d${i}/sub/s`, { fields: {} });
    }
    await gotoApp(page, "/firestore/bulk");
    await page.getByTestId("collection-delete").click();
    await page.getByTestId("collection-delete-confirm").click();
    await expect(page).toHaveURL(/\/ui\/firestore\/?\?db=/);
    const ids = (await api(request, "POST", `${DOCS}:listCollectionIds`, {})) as {
      collectionIds?: string[];
    };
    expect(ids.collectionIds ?? []).not.toContain("bulk");
  });
});
