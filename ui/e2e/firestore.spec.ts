import { expect, test } from "@playwright/test";
import { api, controlToken, gotoApp, resetSession } from "./helpers";

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

  test("preserves wire values and safely masks literal field names", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/wire/one`, {
      fields: {
        local: { stringValue: "before" },
        maxInteger: { integerValue: "9223372036854775807" },
        wholeDouble: { doubleValue: 1 },
        negativeZero: { doubleValue: -0 },
        nan: { doubleValue: "NaN" },
        infinity: { doubleValue: "Infinity" },
        nested: {
          mapValue: {
            fields: { values: { arrayValue: { values: [{ doubleValue: "-Infinity" }] } } },
          },
        },
        constructor: { stringValue: "safe" },
        "dot.name": { stringValue: "literal" },
        "tick`slash\\": { stringValue: "remove safely" },
        removeMe: { booleanValue: true },
      },
    });
    const negativeZero = await request.fetch(
      `/ui/api/${DOCS}/wire/one?updateMask.fieldPaths=negativeZero`,
      {
        method: "PATCH",
        headers: {
          authorization: `Bearer ${controlToken()}`,
          "content-type": "application/json",
        },
        data: '{"fields":{"negativeZero":{"doubleValue":-0}}}',
      },
    );
    expect(negativeZero.ok(), await negativeZero.text()).toBe(true);
    await gotoApp(page, "/firestore/wire/one");
    await page.getByTestId("document-edit").click();
    const editor = page.getByTestId("document-view");
    const row = async (name: string) => {
      const index = await editor
        .getByLabel("Field")
        .evaluateAll(
          (inputs, target) =>
            inputs.findIndex((input) => (input as HTMLInputElement).value === target),
          name,
        );
      expect(index).toBeGreaterThanOrEqual(0);
      return editor.locator("tbody tr").nth(index);
    };
    await (await row("local")).getByLabel("Value").fill("after");
    await (await row("dot.name")).getByLabel("Value").fill("changed literal");
    await (await row("constructor")).getByRole("button", { name: "Delete" }).click();
    await (await row("tick`slash\\")).getByRole("button", { name: "Delete" }).click();
    await (await row("removeMe")).getByRole("button", { name: "Delete" }).click();
    await page.getByTestId("document-save").click();

    const saved = (await api(request, "GET", `${DOCS}/wire/one`)) as {
      fields: Record<string, unknown>;
      updateTime: string;
    };
    expect(saved.fields).toEqual({
      local: { stringValue: "after" },
      maxInteger: { integerValue: "9223372036854775807" },
      wholeDouble: { doubleValue: 1 },
      negativeZero: { doubleValue: -0 },
      nan: { doubleValue: "NaN" },
      infinity: { doubleValue: "Infinity" },
      nested: {
        mapValue: {
          fields: { values: { arrayValue: { values: [{ doubleValue: "-Infinity" }] } } },
        },
      },
      "dot.name": { stringValue: "changed literal" },
    });

    await page.getByTestId("document-edit").click();
    await page.getByTestId("document-save").click();
    const unchanged = (await api(request, "GET", `${DOCS}/wire/one`)) as { updateTime: string };
    expect(unchanged.updateTime).toBe(saved.updateTime);
  });

  test("keeps a draft on concurrent update or delete", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/conflicts/one`, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "before" } },
    });
    await gotoApp(page, "/firestore/conflicts/one");
    await page.getByTestId("document-edit").click();
    const editor = page.getByTestId("document-view");
    const valueFor = async (name: string) => {
      const index = await editor
        .getByLabel("Field")
        .evaluateAll(
          (inputs, target) =>
            inputs.findIndex((input) => (input as HTMLInputElement).value === target),
          name,
        );
      expect(index).toBeGreaterThanOrEqual(0);
      return editor.getByLabel("Value").nth(index);
    };
    await (await valueFor("local")).fill("draft");
    await api(request, "PATCH", `${DOCS}/conflicts/one`, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "external" } },
    });
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let saveStarted!: () => void;
    const saveRequestStarted = new Promise<void>((resolve) => {
      saveStarted = resolve;
    });
    let saveFinished!: () => void;
    const saveRequestFinished = new Promise<void>((resolve) => {
      saveFinished = resolve;
    });
    const savePattern = `**/${DOCS}/conflicts/one?*`;
    await page.route(savePattern, async (route) => {
      saveStarted();
      await saveGate;
      await route.continue();
      saveFinished();
    });
    await page.getByTestId("document-save").click();
    await saveRequestStarted;
    await expect(await valueFor("local")).toBeDisabled();
    releaseSave();
    await saveRequestFinished;
    await page.unroute(savePattern);
    await expect(page.getByRole("alert")).toContainText("changed after editing began");
    await expect(await valueFor("local")).toHaveValue("draft");

    await page.getByTestId("document-reload-draft").click();
    await page.getByTestId("document-save").click();
    const rebased = (await api(request, "GET", `${DOCS}/conflicts/one`)) as {
      fields: Record<string, unknown>;
    };
    expect(rebased.fields).toEqual({
      local: { stringValue: "draft" },
      remote: { stringValue: "external" },
    });

    await page.getByTestId("document-edit").click();
    await (await valueFor("local")).fill("deleted-draft");
    await api(request, "DELETE", `${DOCS}/conflicts/one`);
    await page.getByTestId("document-save").click();
    await expect(page.getByRole("alert")).toContainText("changed after editing began");
    await expect(await valueFor("local")).toHaveValue("deleted-draft");
    const absent = await request.get(`/ui/api/${DOCS}/conflicts/one`, {
      headers: { authorization: `Bearer ${controlToken()}` },
    });
    expect(absent.status()).toBe(404);
  });

  test("discards a stale conflict reload after navigation", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/scope/a`, {
      fields: { local: { stringValue: "before" } },
    });
    const alternateDocs = "firestore/v1/projects/demo-app/databases/scope-db/documents";
    await api(request, "PATCH", `${alternateDocs}/scope/a`, {
      fields: { identity: { stringValue: "alternate-database" } },
    });
    await gotoApp(page, "/firestore/scope/a");
    await page.getByTestId("document-edit").click();
    await page.getByLabel("Value").fill("draft-a");
    await api(request, "PATCH", `${DOCS}/scope/a`, {
      fields: { local: { stringValue: "external" } },
    });
    await page.getByTestId("document-save").click();
    await expect(page.getByTestId("document-reload-draft")).toBeVisible();

    let releaseReload!: () => void;
    const reloadGate = new Promise<void>((resolve) => {
      releaseReload = resolve;
    });
    let reloadStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      reloadStarted = resolve;
    });
    let reloadFinished!: () => void;
    const finished = new Promise<void>((resolve) => {
      reloadFinished = resolve;
    });
    await page.route(`**/${DOCS}/scope/a`, async (route) => {
      if (route.request().method() !== "GET") {
        await route.continue();
        return;
      }
      reloadStarted();
      const response = await route.fetch();
      await reloadGate;
      await route.fulfill({ response });
      reloadFinished();
    });
    await page.getByTestId("document-reload-draft").click();
    await started;
    await expect(page.getByRole("status")).toHaveText("Loading");
    await expect(page.getByTestId("document-save")).toHaveCount(0);
    await expect(page.getByLabel("Value")).toHaveCount(0);
    await page.getByTestId("database-input").fill("scope-db");
    await page.getByTestId("database-input").press("Tab");
    await expect(page).toHaveURL(/db=scope-db/);
    const staleResponse = page.waitForResponse(
      (response) =>
        response.request().method() === "GET" && response.url().includes(`/${DOCS}/scope/a`),
    );
    releaseReload();
    await staleResponse;
    await finished;
    await page.evaluate(
      () =>
        new Promise<void>((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
        ),
    );
    await expect(page.getByTestId("document-fields")).toContainText("alternate-database");
    await expect(page.getByTestId("document-reload-draft")).not.toBeVisible();
    await expect(page.getByLabel("Value")).toHaveCount(0);
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

  test("deletes every paginated subcollection before deleting its parent", async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);
    const resourceRoot = "projects/demo-app/databases/(default)/documents";
    const parentPath = "paged-delete/parent";
    const parent = resourceRoot + "/" + parentPath;
    const writes = Array.from({ length: 601 }, (_, index) => ({
      update: {
        name: parent + "/child-" + index + "/leaf",
        fields: {},
      },
    }));
    await api(request, "PATCH", DOCS + "/" + parentPath, { fields: {} });
    for (let offset = 0; offset < writes.length; offset += 250) {
      await api(request, "POST", DOCS + ":commit", {
        writes: writes.slice(offset, offset + 250),
      });
    }

    const first = (await api(request, "POST", DOCS + "/paged-delete/parent:listCollectionIds", {
      pageSize: 300,
    })) as { collectionIds?: string[]; nextPageToken?: string };
    expect(first.collectionIds ?? []).toHaveLength(300);
    expect(first.nextPageToken).toBeTruthy();
    const second = (await api(request, "POST", DOCS + "/paged-delete/parent:listCollectionIds", {
      pageSize: 300,
      pageToken: first.nextPageToken,
    })) as { collectionIds?: string[]; nextPageToken?: string };
    expect(second.collectionIds ?? []).toHaveLength(300);
    expect(second.nextPageToken).toBeTruthy();
    const third = (await api(request, "POST", DOCS + "/paged-delete/parent:listCollectionIds", {
      pageSize: 300,
      pageToken: second.nextPageToken,
    })) as { collectionIds?: string[]; nextPageToken?: string };
    expect(third.collectionIds ?? []).toHaveLength(1);
    expect(third.nextPageToken).toBeUndefined();

    await gotoApp(page, "/firestore/paged-delete");
    await page.getByTestId("collection-delete").click();
    await page.getByTestId("collection-delete-confirm").click();
    await expect(page).toHaveURL(/\/ui\/firestore\/?\?db=/);
    const ids = (await api(request, "POST", DOCS + ":listCollectionIds", {})) as {
      collectionIds?: string[];
    };
    expect(ids.collectionIds ?? []).not.toContain("paged-delete");
  });
});
