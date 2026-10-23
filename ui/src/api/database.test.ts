import { afterEach, describe, expect, it, vi } from "vitest";
import { requestText } from "./client";
import { databaseTarget } from "./database";

afterEach(() => vi.unstubAllGlobals());

describe("raw database transport", () => {
  it("preserves source text and sends only the control credential", async () => {
    window.__FIREEMU__ = { controlToken: "private-control" };
    const fetcher = vi.fn().mockResolvedValue(new Response("-0", { headers: { etag: '"v1"' } }));
    vi.stubGlobal("fetch", fetcher);
    const response = await requestText("PUT", "database/data", " -0 ");
    expect(response.isOk()).toBe(true);
    expect(response._unsafeUnwrap()).toEqual({ status: 200, body: "-0", etag: '"v1"' });
    expect(fetcher).toHaveBeenCalledWith(
      "/ui/api/database/data",
      expect.objectContaining({
        body: " -0 ",
        headers: expect.objectContaining({ authorization: "Bearer private-control" }),
      }),
    );
  });
});

it("encodes spaces, plus signs, Unicode and literal percent exactly once", () => {
  for (const path of ["/white space", "/plus+", "/日😀", "/literal%2F", '/quote"']) {
    const target = databaseTarget(
      "data",
      { session: "default", project: "demo-a", namespace: "named" },
      path,
    );
    const raw = target.split("path=")[1]!;
    expect(decodeURIComponent(raw)).toBe(path);
    expect(raw).not.toContain("+");
  }
});
it("keeps denied probes distinct from transport failure and write success", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(new Response('{"error":"Permission denied"}', { status: 401 })),
      ),
  );
  expect((await requestText("GET", "database/data")).isErr()).toBe(true);
  const probe = await requestText("GET", "database/request", undefined, true);
  expect(probe._unsafeUnwrap().status).toBe(401);
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
  expect((await requestText("PUT", "database/data", "1"))._unsafeUnwrapErr().status).toBe(0);
});
