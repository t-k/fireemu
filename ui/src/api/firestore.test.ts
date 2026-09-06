import { describe, expect, it } from "vitest";
import { buildUpdateDocumentRequest, quoteFieldPath } from "./firestore";

describe("Firestore update requests", () => {
  it("quotes special field paths and carries an update-time precondition", () => {
    expect(quoteFieldPath("plain_name2")).toBe("plain_name2");
    expect(quoteFieldPath("nested.name")).toBe("`nested.name`");
    expect(quoteFieldPath("tick`slash\\")).toBe("`tick\\`slash\\\\`");

    const request = buildUpdateDocumentRequest(
      "projects/demo-app/databases/(default)/documents",
      "items/one",
      { "nested.name": { integerValue: "2" } },
      ["nested.name", "removed"],
      "2026-09-05T01:02:03.000004Z",
    );
    expect(request.body).toEqual({ fields: { "nested.name": { integerValue: "2" } } });
    const parsed = new URL(`https://local/${request.path}`);
    expect(parsed.searchParams.getAll("updateMask.fieldPaths")).toEqual([
      "`nested.name`",
      "removed",
    ]);
    expect(parsed.searchParams.get("currentDocument.updateTime")).toBe(
      "2026-09-05T01:02:03.000004Z",
    );
  });
});
