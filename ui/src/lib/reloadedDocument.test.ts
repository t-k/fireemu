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
    ["2026-09-14T12:00:00Z", "2026-09-14T12:00:00.001Z"],
    ["2026-09-14T12:00:00.001Z", "2026-09-14T12:00:00.001001Z"],
    ["2026-09-14T12:00:00.001001Z", "2026-09-14T12:00:00.001001001Z"],
    ["2026-09-14T12:00:00.001001001Z", "2026-09-14T12:00:00.001001002Z"],
    ["2026-09-14T12:00:00.999999999Z", "2026-09-14T12:00:01Z"],
    ["2026-09-14T23:59:59.999999999Z", "2026-09-15T00:00:00Z"],
  ])("orders complete timestamps %s and %s independently of response order", (earlier, later) => {
    const a = document(earlier);
    const b = document(later);
    expect(selectReloadDocument(a, b)._unsafeUnwrap()).toBe(b);
    expect(selectReloadDocument(b, a)._unsafeUnwrap()).toBe(b);
  });

  it.each(["", ".000", ".000000", ".000000000"])(
    "normalizes equivalent fractional precision %s",
    (fraction) => {
      const fetched = document(`2026-09-14T12:00:00${fraction}Z`);
      const observed = document("2026-09-14T12:00:00.000000000Z");
      expect(selectReloadDocument(fetched, observed)._unsafeUnwrap()).toBe(fetched);
    },
  );

  it("accepts a valid response when no document is displayed", () => {
    const fetched = document("2026-09-14T12:00:00Z");
    expect(selectReloadDocument(fetched, null)._unsafeUnwrap()).toBe(fetched);
  });

  it("does not compare versions belonging to another document scope", () => {
    const fetched = document("2026-09-14T12:00:00Z");
    const other = document("2026-09-15T12:00:00Z", "projects/other/databases/d/documents/c/a");
    expect(selectReloadDocument(fetched, other)._unsafeUnwrap()).toBe(fetched);
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
  ])("fails closed when either same-document version is malformed: %s", (updateTime) => {
    const malformed: FsDocument = {
      name: document("").name,
      ...(updateTime === undefined ? {} : { updateTime }),
    };
    const valid = document("2026-09-14T12:00:00Z");
    expect(selectReloadDocument(malformed, valid).isErr()).toBe(true);
    expect(selectReloadDocument(valid, malformed).isErr()).toBe(true);
  });
});
