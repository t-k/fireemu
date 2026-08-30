import { expect, test } from "@playwright/test";
import { controlToken, gotoApp, resetSession } from "./helpers";

test.describe("Storage", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("uploads, inspects, downloads and deletes an object", async ({ page }) => {
    await gotoApp(page, "/storage");
    await expect(page.getByTestId("bucket-select")).toHaveValue("demo-app.appspot.com");
    await expect(page.getByText("No objects under this prefix")).toBeVisible();
    await page.getByTestId("upload-input").setInputFiles({
      name: "hello.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("hello storage"),
    });
    await page.getByTestId("upload-button").click();
    const table = page.getByTestId("object-table");
    await expect(table).toContainText("hello.txt");
    await expect(table).toContainText("text/plain");
    await table.getByRole("button", { name: "hello.txt" }).click();
    const detail = page.getByTestId("object-detail");
    await expect(detail).toContainText("13 B");
    const download = page.waitForEvent("download");
    await page.getByTestId("object-download").click();
    expect((await download).suggestedFilename()).toBe("hello.txt");
    await page.getByTestId("object-delete").click();
    await page.getByTestId("object-delete-confirm").click();
    await expect(page.getByText("No objects under this prefix")).toBeVisible();
  });

  test("navigates folders", async ({ page, request }) => {
    const upload = async (name: string) => {
      const r = await request.post(
        `/ui/api/storage/upload/storage/v1/b/demo-app.appspot.com/o?uploadType=media&name=${encodeURIComponent(name)}`,
        {
          headers: { "content-type": "text/plain", authorization: `Bearer ${controlToken()}` },
          data: "x",
        },
      );
      expect(r.ok()).toBeTruthy();
    };
    await upload("images/a.txt");
    await upload("images/thumbs/b.txt");
    await upload("root.txt");
    await gotoApp(page, "/storage");
    const table = page.getByTestId("object-table");
    await expect(table).toContainText("images/");
    await expect(table).toContainText("root.txt");
    await expect(table).not.toContainText("a.txt");
    await table.getByRole("link", { name: "images/" }).click();
    await expect(table).toContainText("a.txt");
    await expect(table).toContainText("thumbs/");
    await table.getByRole("link", { name: "thumbs/" }).click();
    await expect(table).toContainText("b.txt");
  });
});
