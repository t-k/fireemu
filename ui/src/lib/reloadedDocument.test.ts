import { describe, expect, it } from "vitest";
import type { FsDocument } from "./firestoreValue";
import { selectReloadDocument } from "./reloadedDocument";

const document = (
  updateTime: string,
  name = "projects/p/databases/d/documents/c/a",
): FsDocument => ({
  name,
  updateTime,
});

describe("selectReloadDocument", () => {
  it.each([
    ["2026-09-14T12:00:00Z", "2026-09-15T12:00:00Z"],
    ["2026-09-15T12:00:00Z", "2026-09-14T12:00:00Z"],
    ["2026-09-14T12:00:00.001001001Z", "2026-09-14T12:00:00.001001002Z"],
  ])("orders reads independently of timestamp magnitude: %s / %s", (first, second) => {
    const a = { document: document(first), generation: 1 };
    const b = { document: document(second), generation: 2 };
    expect(selectReloadDocument(a, b)._unsafeUnwrap()).toBe(b.document);
    expect(selectReloadDocument(b, a)._unsafeUnwrap()).toBe(b.document);
  });

  it.each(["", ".000", ".000000", ".000000000"])(
    "preserves valid fractional precision %s",
    (fraction) => {
      const fetched = document(`2026-09-14T12:00:00${fraction}Z`);
      expect(selectReloadDocument({ document: fetched, generation: 1 }, null)._unsafeUnwrap()).toBe(
        fetched,
      );
    },
  );

  it("ignores a later read belonging to another document scope", () => {
    const fetched = document("2026-09-14T12:00:00Z");
    const other = document("2026-09-15T12:00:00Z", "projects/other/databases/d/documents/c/a");
    expect(
      selectReloadDocument(
        { document: fetched, generation: 1 },
        { document: other, generation: 2 },
      )._unsafeUnwrap(),
    ).toBe(fetched);
  });

  it.each([
    undefined,
    "not a timestamp",
    "2026-09-14T12:00:00+00:00",
    "2026-09-14T12:00:00.1Z",
    "2026-09-14T12:00:00.1234567890Z",
    "2026-02-30T12:00:00Z",
    "2026-09-14T25:00:00Z",
    "0000-01-01T00:00:00Z",
  ])("fails closed when the selected version is malformed: %s", (updateTime) => {
    const malformed: FsDocument = {
      name: document("").name,
      ...(updateTime === undefined ? {} : { updateTime }),
    };
    const valid = document("2026-09-14T12:00:00Z");
    expect(
      selectReloadDocument(
        { document: malformed, generation: 2 },
        { document: valid, generation: 1 },
      ).isErr(),
    ).toBe(true);
    expect(
      selectReloadDocument(
        { document: valid, generation: 1 },
        { document: malformed, generation: 2 },
      ).isErr(),
    ).toBe(true);
  });
});
