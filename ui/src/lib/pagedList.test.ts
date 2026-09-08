import { describe, expect, it } from "vitest";
import { errAsync, ResultAsync } from "neverthrow";
import { createRoot } from "solid-js";
import { createPagedList, type Page } from "./pagedList";
import type { ApiError } from "../api/client";

type Deferred = {
  resolve: (page: Page<string>) => void;
  reject: (e: ApiError) => void;
};

/** A fetcher whose answers the test releases by hand, in any order. */
const controlled = () => {
  const calls: { token: string | undefined; d: Deferred }[] = [];
  const fetchPage = (token: string | undefined): ResultAsync<Page<string>, ApiError> =>
    ResultAsync.fromPromise(
      new Promise<Page<string>>((resolve, reject) => {
        calls.push({ token, d: { resolve, reject: (e) => reject(e) } });
      }),
      (e) => e as ApiError,
    );
  return { calls, fetchPage };
};

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("createPagedList", () => {
  it("drops the answer of a target the reader has left", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const first = list.load(); // target A
      const second = list.load(); // target B
      expect(calls.length).toBe(2);
      calls[1]?.d.resolve({ items: ["b1"] });
      await second;
      calls[0]?.d.resolve({ items: ["a1"] });
      await first;
      await tick();
      expect(list.items()).toEqual(["b1"]);
      expect(list.loading()).toBe(false);
      dispose();
    });
  });

  it("re-reads every loaded page on refresh instead of snapping back to the first", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["1", "2"], nextToken: "p2" });
      await load;
      const more = list.more();
      calls[1]?.d.resolve({ items: ["3", "4"], nextToken: "p3" });
      await more;
      expect(list.items()).toEqual(["1", "2", "3", "4"]);
      const refresh = list.refresh();
      await tick();
      expect(calls[2]?.token).toBeUndefined();
      calls[2]?.d.resolve({ items: ["1", "2b"], nextToken: "p2" });
      await tick();
      expect(calls[3]?.token).toBe("p2");
      calls[3]?.d.resolve({ items: ["3", "4", "5"], nextToken: "p3" });
      await refresh;
      expect(list.items()).toEqual(["1", "2b", "3", "4", "5"]);
      expect(list.nextToken()).toBe("p3");
      // The old list stayed on screen while the refresh ran.
      expect(list.loading()).toBe(false);
      dispose();
    });
  });

  it("keeps the last good list when a refresh fails and reports it as stale", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["x"] });
      await load;
      const refresh = list.refresh();
      calls[1]?.d.reject({ status: 500, message: "boom" });
      await refresh;
      expect(list.items()).toEqual(["x"]);
      expect(list.stale()).toBe("boom");
      expect(list.error()).toBeNull();
      dispose();
    });
  });

  it("reports a failed first load as an error, not as an empty list", async () => {
    await createRoot(async (dispose) => {
      const list = createPagedList(() =>
        errAsync<Page<string>, ApiError>({ status: 0, message: "down" }),
      );
      await list.load();
      expect(list.error()).toBe("down");
      expect(list.items()).toEqual([]);
      expect(list.loading()).toBe(false);
      dispose();
    });
  });
});
