import { describe, expect, it } from "vitest";
import { decodeSplat, firestoreHref, storageHref } from "./hrefs";

describe("in-app links encode names the URL would misread", () => {
  it("keeps # and ? inside a document ID as path data", () => {
    expect(firestoreHref("cities/a#b?c", "(default)")).toBe(
      "/firestore/cities/a%23b%3Fc?db=(default)",
    );
  });

  it("round-trips every segment through the router splat", () => {
    const names = ["tick`slash\\", "100%", "東京", "a b"];
    const href = firestoreHref(names.join("/"), "db-1");
    const splat = href.slice("/firestore/".length, href.indexOf("?"));
    expect(decodeSplat(splat)).toEqual(names);
  });

  it("links the root without a trailing slash", () => {
    expect(firestoreHref("", "(default)")).toBe("/firestore?db=(default)");
    expect(storageHref("", "demo.appspot.com")).toBe("/storage?bucket=demo.appspot.com");
  });

  it("drops the trailing slash of a storage prefix and encodes the bucket", () => {
    expect(storageHref("photos/2026#/", "my bucket")).toBe(
      "/storage/photos/2026%23?bucket=my%20bucket",
    );
  });

  it("leaves a segment that is not a valid escape as typed", () => {
    expect(decodeSplat("100%/ok")).toEqual(["100%", "ok"]);
    expect(decodeSplat(undefined)).toEqual([]);
  });
});
