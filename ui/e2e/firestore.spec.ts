import { expect, test } from "@playwright/test";
import { api, controlToken, gotoApp, resetSession } from "./helpers";

const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.describe("Firestore data browser", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("keeps the focused document draft across two session polls", async ({ page, request }) => {
    await api(request, "PATCH", `${DOCS}/polling/draft`, {
      fields: { value: { stringValue: "original" } },
    });
    await gotoApp(page, "/firestore/polling/draft");
    await expect(page.getByTestId("document-fields")).toContainText("original");
    await page.getByTestId("document-edit").click();
    const input = page.getByLabel("Value");
    await input.fill("unsaved draft");
    // Await real polling responses, not an arbitrary delay shorter than the poll interval.
    for (let i = 0; i < 2; i += 1) {
      await page.waitForResponse((r) => r.url().endsWith("/control/v1/sessions") && r.ok());
      await expect(input).toHaveValue("unsaved draft");
      await expect(input).toBeFocused();
    }
    await page.getByTestId("document-save").click();
    await expect(page.getByTestId("document-fields")).toContainText("unsaved draft");
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
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
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
    // Keep the rendered resource stale while an explicit reload is superseded by a live GET.
    const reads: { release: () => void; finished: Promise<void>; updateTime?: string }[] = [];
    let readArrived!: () => void;
    const waitForRead = () =>
      new Promise<void>((resolve) => {
        readArrived = resolve;
      });
    const firstRead = waitForRead();
    await page.route(`**/${DOCS}/conflicts/one`, async (route) => {
      if (reads.length >= 3) {
        await route.continue();
        return;
      }
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let finished!: () => void;
      const done = new Promise<void>((resolve) => {
        finished = resolve;
      });
      const read: (typeof reads)[number] = { release, finished: done };
      reads.push(read);
      const response = await route.fetch();
      read.updateTime = ((await response.json()) as { updateTime: string }).updateTime;
      readArrived();
      await gate;
      await route.fulfill({ response });
      finished();
    });
    await api(request, "PATCH", `${DOCS}/conflicts/one`, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "external" } },
    });
    await firstRead;
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let saveStarted!: () => void;
    const saveRequestStarted = new Promise<void>((resolve) => {
      saveStarted = resolve;
    });
    const savePattern = `**/${DOCS}/conflicts/one?*`;
    await page.route(savePattern, async (route) => {
      saveStarted();
      await saveGate;
      await route.continue();
    });
    const staleSave = page.waitForRequest(savePattern);
    await page.getByTestId("document-save").click();
    await saveRequestStarted;
    await expect(await valueFor("local")).toBeDisabled();
    releaseSave();
    const staleResponse = await (await staleSave).response();
    expect(staleResponse).not.toBeNull();
    await staleResponse!.finished();
    expect((await staleResponse!.json()).error.status).toBe("FAILED_PRECONDITION");
    await page.unroute(savePattern);
    await expect(page.getByRole("alert")).toContainText("changed after editing began");
    await expect(await valueFor("local")).toHaveValue("draft");

    const reloadDraft = page.getByTestId("document-reload-draft");
    const reloadRead = waitForRead();
    await reloadDraft.click();
    await reloadRead;
    const supersedingRead = waitForRead();
    // Changing another document invalidates the view without changing our rebase precondition.
    await api(request, "PATCH", `${DOCS}/conflicts/other`, {
      fields: { value: { stringValue: "live invalidation" } },
    });
    await supersedingRead;
    expect(reads).toHaveLength(3);
    reads[1]!.release();
    await reads[1]!.finished;
    await expect(reloadDraft).not.toBeVisible();
    await expect(await valueFor("remote")).toHaveValue("external");
    await expect(editor.getByText(reads[1]!.updateTime!, { exact: true })).toBeVisible();
    await editor.getByRole("button", { name: "REST JSON", exact: true }).click();
    await expect(editor.locator("pre")).toHaveText(
      JSON.stringify(
        {
          local: { stringValue: "before" },
          remote: { stringValue: "external" },
        },
        null,
        2,
      ),
    );
    for (const read of reads) read.release();
    await Promise.all(reads.map((read) => read.finished));
    await page.unroute(`**/${DOCS}/conflicts/one`);
    const rebasedSave = page.waitForRequest(savePattern);
    await page.getByTestId("document-save").click();
    const rebasedRequest = await rebasedSave;
    expect(rebasedRequest.method()).toBe("PATCH");
    expect(new URL(rebasedRequest.url()).searchParams.get("currentDocument.updateTime")).toBe(
      reads[1]!.updateTime,
    );
    const rebasedResponse = await rebasedRequest.response();
    expect(rebasedResponse).not.toBeNull();
    expect(rebasedResponse!.ok(), await rebasedResponse!.text()).toBe(true);
    await expect(page.getByTestId("document-edit")).toBeVisible();
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
    await page.getByTestId("document-reload-draft").click();
    await expect(page.getByRole("alert")).toContainText("document was deleted");
    await expect(await valueFor("local")).toHaveValue("deleted-draft");
  });

  test("rebases onto a restored snapshot with a lower update time", async ({ page, request }) => {
    await page.clock.install();
    const documentPath = `${DOCS}/reload-restore/one`;
    const restored = (await api(request, "PATCH", documentPath, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "snapshot" } },
    })) as { updateTime: string };
    await api(request, "POST", "control/v1/sessions/default/snapshots", {
      name: "reload-basis",
      allowNonQuiescent: true,
    });
    await api(request, "POST", "control/v1/sessions/default/clock:advance", { seconds: 1 });
    const beforeRestore = (await api(request, "PATCH", documentPath, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "later" } },
    })) as { updateTime: string };
    expect(beforeRestore.updateTime > restored.updateTime).toBe(true);
    await gotoApp(page, "/firestore/reload-restore/one");
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
    const editor = page.getByTestId("document-view");
    await expect(editor.getByText(beforeRestore.updateTime, { exact: true })).toBeVisible();
    await page.getByTestId("document-edit").click();
    await editor.getByLabel("Value").first().fill("draft");
    // Hold the watch debounce so the explicit reload sees a restored server behind the view.
    await page.clock.pauseAt(new Date(Date.now() + 1000));
    await api(request, "POST", "control/v1/sessions/default/snapshots/reload-basis:restore", {});
    await expect(editor.getByText(beforeRestore.updateTime, { exact: true })).toBeVisible();
    await page.getByTestId("document-save").click();
    const reloadDraft = page.getByTestId("document-reload-draft");
    await expect(reloadDraft).toBeVisible();
    await reloadDraft.click();
    await expect(reloadDraft).not.toBeVisible();
    await expect(editor.getByLabel("Value").first()).toHaveValue("draft");
    await expect(editor.getByLabel("Value").nth(1)).toHaveValue("snapshot");
    await expect(editor.getByText(restored.updateTime, { exact: true }).last()).toBeVisible();
    const savedRequest = page.waitForRequest(`**/${documentPath}?*`);
    await page.getByTestId("document-save").click();
    const outgoing = await savedRequest;
    expect(new URL(outgoing.url()).searchParams.get("currentDocument.updateTime")).toBe(
      restored.updateTime,
    );
    const response = await outgoing.response();
    expect(response).not.toBeNull();
    expect(response!.ok(), await response!.text()).toBe(true);
    expect(((await api(request, "GET", documentPath)) as { fields: unknown }).fields).toEqual({
      local: { stringValue: "draft" },
      remote: { stringValue: "snapshot" },
    });
    await page.clock.resume();
  });

  test("rebases onto a newer live document that arrives before the manual reload", async ({
    page,
    request,
  }) => {
    const documentPath = `${DOCS}/reload-order/one`;
    await api(request, "PATCH", documentPath, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "initial" } },
    });
    await gotoApp(page, "/firestore/reload-order/one");
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
    await page.getByTestId("document-edit").click();
    const editor = page.getByTestId("document-view");
    await expect(editor.getByLabel("Field").first()).toHaveValue("local");
    await editor.getByLabel("Value").first().fill("draft");
    const first = (await api(request, "PATCH", documentPath, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "A" } },
    })) as { updateTime: string };
    await expect(editor.getByText(first.updateTime, { exact: true })).toBeVisible();
    await page.getByTestId("document-save").click();
    const reloadDraft = page.getByTestId("document-reload-draft");
    await expect(reloadDraft).toBeVisible();

    let releaseReload!: () => void;
    const reloadGate = new Promise<void>((resolve) => {
      releaseReload = resolve;
    });
    let reloadRead!: () => void;
    const reloadStarted = new Promise<void>((resolve) => {
      reloadRead = resolve;
    });
    await page.route(
      `**/${documentPath}`,
      async (route) => {
        const response = await route.fetch();
        expect(((await response.json()) as { updateTime: string }).updateTime).toBe(
          first.updateTime,
        );
        reloadRead();
        await reloadGate;
        await route.fulfill({ response });
      },
      { times: 1 },
    );
    await reloadDraft.click();
    await reloadStarted;
    const second = (await api(request, "PATCH", documentPath, {
      fields: { local: { stringValue: "before" }, remote: { stringValue: "B" } },
    })) as { updateTime: string };
    expect(second.updateTime).not.toBe(first.updateTime);
    await expect(editor.getByText(second.updateTime, { exact: true })).toBeVisible();
    await editor.getByRole("button", { name: "REST JSON", exact: true }).click();
    const expectedStored = JSON.stringify(
      {
        local: { stringValue: "before" },
        remote: { stringValue: "B" },
      },
      null,
      2,
    );
    await expect(editor.locator("pre")).toHaveText(expectedStored);

    releaseReload();
    await expect(reloadDraft).not.toBeVisible();
    await expect(editor.getByText(second.updateTime, { exact: true })).toBeVisible();
    await expect(editor.locator("pre")).toHaveText(expectedStored);
    await expect(editor.getByLabel("Value").first()).toHaveValue("draft");
    await expect(editor.getByLabel("Value").nth(1)).toHaveValue("B");
    const savedRequest = page.waitForRequest(`**/${documentPath}?*`);
    await page.getByTestId("document-save").click();
    const outgoing = await savedRequest;
    expect(new URL(outgoing.url()).searchParams.get("currentDocument.updateTime")).toBe(
      second.updateTime,
    );
    const response = await outgoing.response();
    expect(response).not.toBeNull();
    expect(response!.ok(), await response!.text()).toBe(true);
    const saved = (await api(request, "GET", documentPath)) as { fields: unknown };
    expect(saved.fields).toEqual({
      local: { stringValue: "draft" },
      remote: { stringValue: "B" },
    });
  });

  for (const olderFinishesFirst of [false, true]) {
    test(`supersedes an older pending live read ${olderFinishesFirst ? "before" : "after"} publishing a newer reload`, async ({
      page,
      request,
    }) => {
      await page.clock.install();
      const documentPath = `${DOCS}/pending-reload/one`;
      await api(request, "PATCH", documentPath, {
        fields: { value: { stringValue: "before" } },
      });
      await gotoApp(page, "/firestore/pending-reload/one");
      await expect(page.getByTestId("live-badge")).toHaveText("Live");
      await page.getByTestId("document-edit").click();
      await page.getByLabel("Value").fill("draft");
      const first = (await api(request, "PATCH", documentPath, {
        fields: { value: { stringValue: "A" } },
      })) as { updateTime: string };
      await expect(page.getByText(first.updateTime, { exact: true })).toBeVisible();
      await page.getByTestId("document-save").click();
      const reloadDraft = page.getByTestId("document-reload-draft");
      await expect(reloadDraft).toBeVisible();

      const gates = Array.from({ length: 3 }, () => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => {
          release = resolve;
        });
        let fetched!: () => void;
        const ready = new Promise<void>((resolve) => {
          fetched = resolve;
        });
        let finished!: () => void;
        const done = new Promise<void>((resolve) => {
          finished = resolve;
        });
        return { release, gate, fetched, ready, finished, done };
      });
      let reads = 0;
      const documentPattern = `**/${documentPath}`;
      await page.route(documentPattern, async (route) => {
        const index = reads++;
        if (index >= gates.length) {
          await route.continue();
          return;
        }
        const gate = gates[index]!;
        const response = await route.fetch();
        if (index === 0) {
          expect(((await response.json()) as { fields: unknown }).fields).toEqual({
            value: { stringValue: "older live" },
          });
        }
        gate.fetched();
        await gate.gate;
        await route.fulfill({ response });
        gate.finished();
      });
      const olderRequest = page.waitForRequest(documentPattern);
      const older = (await api(request, "PATCH", documentPath, {
        fields: { value: { stringValue: "older live" } },
      })) as { updateTime: string };
      await gates[0]!.ready;
      // Freeze the watch debounce after the old live read starts. The next commit still
      // reaches the real daemon; its timer cannot accidentally supersede that pending read.
      await page.clock.pauseAt(new Date(Date.now() + 1_000));
      const second = (await api(request, "PATCH", documentPath, {
        fields: { value: { stringValue: "B" } },
      })) as { updateTime: string };
      await reloadDraft.click();
      await gates[1]!.ready;
      if (olderFinishesFirst) {
        gates[0]!.release();
        await expect(page.getByText(older.updateTime, { exact: true })).toBeVisible();
      }
      gates[1]!.release();
      await expect(reloadDraft).not.toBeVisible();
      await expect.poll(() => reads).toBe(3);
      await gates[2]!.ready;
      await expect(page.getByText(second.updateTime, { exact: true })).toBeVisible();

      gates[0]!.release();
      const olderResponse = await (await olderRequest).response();
      expect(olderResponse).not.toBeNull();
      await olderResponse!.finished();
      await expect(page.getByText(second.updateTime, { exact: true })).toBeVisible();
      await page.getByRole("button", { name: "REST JSON", exact: true }).click();
      await expect(page.getByTestId("document-view").locator("pre")).toHaveText(
        JSON.stringify({ value: { stringValue: "B" } }, null, 2),
      );
      await expect(page.getByLabel("Value")).toHaveValue("draft");
      gates[2]!.release();
      await Promise.all(gates.map((gate) => gate.done));
      await page.unroute(documentPattern);
      await page.clock.resume();
      const savedRequest = page.waitForRequest(`**/${documentPath}?*`);
      await page.getByTestId("document-save").click();
      const outgoing = await savedRequest;
      expect(new URL(outgoing.url()).searchParams.get("currentDocument.updateTime")).toBe(
        second.updateTime,
      );
      const savedResponse = await outgoing.response();
      expect(savedResponse).not.toBeNull();
      expect(savedResponse!.ok(), await savedResponse!.text()).toBe(true);
    });
  }

  test("keeps the draft and reports an authorization failure when reloading a conflict", async ({
    page,
    request,
  }) => {
    await api(request, "PATCH", `${DOCS}/reload-errors/one`, {
      fields: { value: { stringValue: "before" } },
    });
    await gotoApp(page, "/firestore/reload-errors/one");
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
    await page.getByTestId("document-edit").click();
    await page.getByLabel("Value").fill("draft");
    const updated = (await api(request, "PATCH", `${DOCS}/reload-errors/one`, {
      fields: { value: { stringValue: "external" } },
    })) as { updateTime: string };
    await expect(page.getByText(updated.updateTime, { exact: true })).toBeVisible();
    await page.getByTestId("document-save").click();
    const reloadDraft = page.getByTestId("document-reload-draft");
    await expect(reloadDraft).toBeVisible();

    const documentPattern = `**/${DOCS}/reload-errors/one`;
    await page.route(documentPattern, async (route) => {
      await route.continue({
        headers: { ...route.request().headers(), authorization: "Bearer invalid-reload-token" },
      });
    });
    const reloadRequest = page.waitForRequest(documentPattern);
    await reloadDraft.click();
    const response = await (await reloadRequest).response();
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(403);
    const body = (await response!.json()) as { error: { message: string } };
    await expect(page.getByRole("alert")).toHaveText(body.error.message);
    await expect(page.getByLabel("Value")).toHaveValue("draft");
    await expect(reloadDraft).toBeEnabled();

    await page.unroute(documentPattern);
    await reloadDraft.click();
    await expect(reloadDraft).not.toBeVisible();
    await expect(page.getByLabel("Value")).toHaveValue("draft");
    const saveRequest = page.waitForRequest(`**/${DOCS}/reload-errors/one?*`);
    await page.getByTestId("document-save").click();
    const saved = await (await saveRequest).response();
    expect(saved).not.toBeNull();
    expect(saved!.ok(), await saved!.text()).toBe(true);
  });

  test("keeps the rebased document and draft visible when the convergence read fails", async ({
    page,
    request,
  }) => {
    const documentPath = `${DOCS}/convergence-error/one`;
    await api(request, "PATCH", documentPath, {
      fields: { value: { stringValue: "before" } },
    });
    await gotoApp(page, "/firestore/convergence-error/one");
    await expect(page.getByTestId("live-badge")).toHaveText("Live");
    await page.getByTestId("document-edit").click();
    const editor = page.getByTestId("document-view");
    await editor.getByLabel("Value").fill("draft");
    const updated = (await api(request, "PATCH", documentPath, {
      fields: { value: { stringValue: "external" } },
    })) as { updateTime: string };
    await expect(editor.getByText(updated.updateTime, { exact: true })).toBeVisible();
    await page.getByTestId("document-save").click();
    const reloadDraft = page.getByTestId("document-reload-draft");
    await expect(reloadDraft).toBeVisible();

    let reads = 0;
    const documentPattern = `**/${documentPath}`;
    await page.route(documentPattern, async (route) => {
      reads += 1;
      // The operation-owned reload succeeds; only the subsequent convergence GET fails.
      await route.continue(
        reads === 2
          ? {
              headers: {
                ...route.request().headers(),
                authorization: "Bearer invalid-convergence-token",
              },
            }
          : {},
      );
    });
    const failedRead = page.waitForResponse(
      (response) => response.url().endsWith(`/ui/api/${documentPath}`) && response.status() === 403,
    );
    await reloadDraft.click();
    const failed = await failedRead;
    const body = (await failed.json()) as { error: { message: string } };
    await expect(editor.getByLabel("Value")).toHaveValue("draft");
    await expect(editor.getByLabel("Value")).toBeEnabled();
    await expect(reloadDraft).not.toBeVisible();
    await expect(editor.getByText(updated.updateTime, { exact: true })).toBeVisible();
    await editor.getByRole("button", { name: "REST JSON", exact: true }).click();
    await expect(editor.locator("pre")).toHaveText(
      JSON.stringify({ value: { stringValue: "external" } }, null, 2),
    );
    const stale = page.getByTestId("fetch-stale");
    await expect(stale).toContainText(body.error.message);

    await page.unroute(documentPattern);
    await stale.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(stale).not.toBeVisible();
    await expect(editor.getByLabel("Value")).toHaveValue("draft");
    const savedRequest = page.waitForRequest(`**/${documentPath}?*`);
    await page.getByTestId("document-save").click();
    const response = await (await savedRequest).response();
    expect(response).not.toBeNull();
    expect(response!.ok(), await response!.text()).toBe(true);
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
    // While the reload runs the draft stays on screen but nothing can be submitted.
    await expect(page.getByTestId("document-save")).toBeDisabled();
    await expect(page.getByLabel("Value")).toBeDisabled();
    await page.getByTestId("database-input").fill("scope-db");
    await page.getByTestId("database-input").press("Tab");
    // Leaving the document with a draft asks first; the reader discards it.
    await page.getByTestId("unsaved-discard").click();
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
