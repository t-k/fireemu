import { afterEach, describe, expect, it, vi } from "vitest";
import { errAsync, okAsync, ResultAsync } from "neverthrow";
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

describe("serialized membership refreshes", () => {
  afterEach(() => vi.useRealTimers());

  it.each([false, true])(
    "coalesces pending refreshes and applies the completed result (failure: %s)",
    async (fails) => {
      vi.useFakeTimers();
      await createRoot(async (dispose) => {
        const { calls, fetchPage } = controlled();
        const list = createPagedList(fetchPage);
        const initial = list.load();
        calls[0]!.d.resolve({ items: ["initial"] });
        await initial;
        const first = list.refresh();
        const second = list.refresh();
        const third = list.refresh();
        expect(list.loading()).toBe(false);
        expect(list.refreshing()).toBe(true);
        expect(calls).toHaveLength(2);
        if (fails) calls[1]!.d.reject({ status: 500, message: "refresh failed" });
        else calls[1]!.d.resolve({ items: ["first"] });
        await vi.advanceTimersByTimeAsync(0);
        expect(list.items()).toEqual([fails ? "initial" : "first"]);
        expect(list.stale()).toBe(fails ? "refresh failed" : null);
        expect(calls).toHaveLength(3);
        expect(list.refreshing()).toBe(true);
        calls[2]!.d.resolve({ items: ["follow-up"] });
        await Promise.all([first, second, third]);
        expect(list.items()).toEqual(["follow-up"]);
        expect(list.stale()).toBeNull();
        expect(list.refreshing()).toBe(false);
        expect(calls).toHaveLength(3);
        dispose();
      });
    },
  );

  it("queues one refresh behind a load without dropping the load result", async () => {
    vi.useFakeTimers();
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const initial = list.load();
      const refresh = list.refresh();
      const repeated = list.refresh();
      expect(calls).toHaveLength(1);
      calls[0]!.d.resolve({ items: ["initial"] });
      await vi.advanceTimersByTimeAsync(0);
      expect(list.items()).toEqual(["initial"]);
      expect(list.loading()).toBe(false);
      expect(list.refreshing()).toBe(true);
      expect(calls).toHaveLength(2);
      calls[1]!.d.resolve({ items: ["latest"] });
      await Promise.all([initial, refresh, repeated]);
      expect(list.items()).toEqual(["latest"]);
      expect(list.refreshing()).toBe(false);
      expect(calls).toHaveLength(2);
      dispose();
    });
  });

  it("discards the old target's pending follow-up without releasing the new target's refresh", async () => {
    vi.useFakeTimers();
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const initial = list.load();
      calls[0]!.d.resolve({ items: ["old"] });
      await initial;
      const oldRefresh = list.refresh();
      const oldPending = list.refresh();
      const next = list.load();
      calls[2]!.d.resolve({ items: ["new"] });
      await next;
      const newRefresh = list.refresh();
      calls[1]!.d.resolve({ items: ["obsolete"] });
      await Promise.all([oldRefresh, oldPending]);
      expect(list.items()).toEqual(["new"]);
      expect(list.refreshing()).toBe(true);
      expect(calls).toHaveLength(4);
      calls[3]!.d.resolve({ items: ["new refreshed"] });
      await newRefresh;
      expect(list.items()).toEqual(["new refreshed"]);
      expect(list.refreshing()).toBe(false);
      expect(calls).toHaveLength(4);
      dispose();
    });
  });
});

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

describe("createPagedList, transitions the first tests left open", () => {
  it("clears the old target and shows loading until the new one answers", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const first = list.load();
      calls[0]?.d.resolve({ items: ["a"], nextToken: "a2" });
      await first;
      const second = list.load();
      expect(list.items()).toEqual([]);
      expect(list.nextToken()).toBeUndefined();
      expect(list.loading()).toBe(true);
      calls[1]?.d.resolve({ items: ["b"] });
      await second;
      expect(list.loading()).toBe(false);
      dispose();
    });
  });

  it("a refresh stops once the pages held cover what was shown", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["1", "2"], nextToken: "p2" });
      await load;
      const refresh = list.refresh();
      await tick();
      calls[1]?.d.resolve({ items: ["1", "2"], nextToken: "p2-new" });
      await refresh;
      expect(calls.length).toBe(2);
      expect(list.nextToken()).toBe("p2-new");
      dispose();
    });
  });

  it("a refresh after a failed load is a fresh load", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.reject({ status: 500, message: "down" });
      await load;
      expect(list.error()).toBe("down");
      const refresh = list.refresh();
      expect(list.loading()).toBe(true);
      expect(list.error()).toBeNull();
      calls[1]?.d.resolve({ items: ["x"] });
      await refresh;
      expect(list.items()).toEqual(["x"]);
      expect(list.error()).toBeNull();
      expect(list.stale()).toBeNull();
      dispose();
    });
  });

  it("a successful refresh clears an earlier stale report and a load error", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["x"] });
      await load;
      const bad = list.refresh();
      calls[1]?.d.reject({ status: 500, message: "boom" });
      await bad;
      expect(list.stale()).toBe("boom");
      const good = list.refresh();
      calls[2]?.d.resolve({ items: ["y"] });
      await good;
      expect(list.stale()).toBeNull();
      expect(list.items()).toEqual(["y"]);
      dispose();
    });
  });

  it("drops a refresh answer once a new target has been loaded", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["a"] });
      await load;
      const refresh = list.refresh();
      const next = list.load();
      calls[2]?.d.resolve({ items: ["b"] });
      await next;
      calls[1]?.d.resolve({ items: ["a-stale"] });
      await refresh;
      await tick();
      expect(list.items()).toEqual(["b"]);
      dispose();
    });
  });

  it("more() is a no-op without a token, is dropped after a new load, and reports failure", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["a"] });
      await load;
      await list.more();
      expect(calls.length).toBe(1);

      const reload = list.load();
      calls[1]?.d.resolve({ items: ["b"], nextToken: "p2" });
      await reload;
      const more = list.more();
      const other = list.load();
      calls[3]?.d.resolve({ items: ["c"] });
      await other;
      calls[2]?.d.resolve({ items: ["b2"], nextToken: "p3" });
      await more;
      expect(list.items()).toEqual(["c"]);
      expect(list.nextToken()).toBeUndefined();

      const again = list.load();
      calls[4]?.d.resolve({ items: ["d"], nextToken: "p2" });
      await again;
      const failing = list.more();
      calls[5]?.d.reject({ status: 500, message: "page lost" });
      await failing;
      expect(list.items()).toEqual(["d"]);
      expect(list.nextToken()).toBe("p2");
      expect(list.stale()).toBe("page lost");
      dispose();
    });
  });
});

describe("createPagedList, survivors of the first mutation run", () => {
  it("starts empty and not loading", () => {
    createRoot((dispose) => {
      const list = createPagedList(() =>
        errAsync<Page<string>, ApiError>({ status: 0, message: "" }),
      );
      expect(list.items()).toEqual([]);
      expect(list.loading()).toBe(false);
      expect(list.error()).toBeNull();
      expect(list.stale()).toBeNull();
      dispose();
    });
  });

  it("a new load clears a stale report", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["x"] });
      await load;
      const bad = list.refresh();
      calls[1]?.d.reject({ status: 500, message: "boom" });
      await bad;
      const again = list.load();
      expect(list.stale()).toBeNull();
      calls[2]?.d.resolve({ items: ["y"] });
      await again;
      expect(list.stale()).toBeNull();
      dispose();
    });
  });

  it("refreshing an empty but successful list keeps it on screen without a loading state", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: [] });
      await load;
      const refresh = list.refresh();
      expect(list.loading()).toBe(false);
      expect(calls[1]?.token).toBeUndefined();
      calls[1]?.d.resolve({ items: ["new"] });
      await refresh;
      expect(list.items()).toEqual(["new"]);
      dispose();
    });
  });

  it("a late answer for an old target is dropped even after a refresh of the new one began", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const a = list.load();
      const b = list.load();
      calls[1]?.d.resolve({ items: ["b"] });
      await b;
      const refresh = list.refresh();
      calls[0]?.d.resolve({ items: ["a-late"] });
      await a;
      await tick();
      expect(list.items()).toEqual(["b"]);
      calls[2]?.d.resolve({ items: ["b2"] });
      await refresh;
      expect(list.items()).toEqual(["b2"]);
      dispose();
    });
  });

  it("more() advances the token it will use next", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage);
      const load = list.load();
      calls[0]?.d.resolve({ items: ["1"], nextToken: "p2" });
      await load;
      const more = list.more();
      calls[1]?.d.resolve({ items: ["2"], nextToken: "p3" });
      await more;
      expect(list.nextToken()).toBe("p3");
      const again = list.more();
      expect(calls[2]?.token).toBe("p3");
      calls[2]?.d.resolve({ items: ["3"] });
      await again;
      expect(list.items()).toEqual(["1", "2", "3"]);
      expect(list.nextToken()).toBeUndefined();
      dispose();
    });
  });
});

describe("createPagedList keyed rows", () => {
  it("keeps unchanged row objects while replacing only the updated key", async () => {
    await createRoot(async (dispose) => {
      const pages = [
        {
          items: [
            { name: "a", value: 1 },
            { name: "b", value: 1 },
          ],
        },
        {
          items: [
            { name: "a", value: 2 },
            { name: "b", value: 1 },
          ],
        },
      ];
      const list = createPagedList(
        () => okAsync(pages.shift()!),
        (item) => item.name,
      );
      await list.load();
      const unchanged = list.items()[1];
      await list.refresh();
      expect(list.items()[0]).not.toBe(unchanged);
      expect(list.items()[1]).toBe(unchanged);
      expect(list.items()[0]?.value).toBe(2);
      dispose();
    });
  });
});

describe("paged row update races", () => {
  it("keeps an incoming non-JSON value when no previous item exists", async () => {
    await createRoot(async (dispose) => {
      const item = () => 1;
      const list = createPagedList(
        () => okAsync({ items: [item] }),
        () => "key",
      );
      await list.load();
      expect(list.items()).toEqual([item]);
      expect(list.items()[0]).toBe(item);
      dispose();
    });
  });

  it("prunes an absent update on refresh before a concurrent page returns", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage, (item) => item.split(":")[0]!);
      const initial = list.load();
      calls[0]!.d.resolve({ items: ["a:1"], nextToken: "next" });
      await initial;
      const refresh = list.refresh();
      const more = list.more();
      expect(list.updateItem("b:2")).toBe(false);
      calls[1]!.d.resolve({ items: ["a:1"], nextToken: "next" });
      await refresh;
      calls[2]!.d.resolve({ items: ["b:1"] });
      await more;
      expect(list.items()).toEqual(["a:1", "b:1"]);
      dispose();
    });
  });

  it("retains a live update across a concurrent refresh and page request", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage, (item) => item.split(":")[0]!);
      const initial = list.load();
      calls[0]!.d.resolve({ items: ["a:1"], nextToken: "next" });
      await initial;
      const refresh = list.refresh();
      const more = list.more();
      expect(list.updateItem("b:2")).toBe(false);
      calls[1]!.d.resolve({ items: ["b:1"], nextToken: "next" });
      await refresh;
      calls[2]!.d.resolve({ items: ["b:1"] });
      await more;
      expect(list.items()).toEqual(["b:2", "b:2"]);
      dispose();
    });
  });

  it("returns false without a key function and reports errors for an empty list", async () => {
    await createRoot(async (dispose) => {
      const list = createPagedList(() => okAsync({ items: ["one"] }));
      list.reportStale("empty failure");
      expect(list.error()).toBe("empty failure");
      expect(list.stale()).toBeNull();
      await list.load();
      expect(list.updateItem("two")).toBe(false);
      expect(list.items()).toEqual(["one"]);
      list.reportStale("row failure");
      expect(list.error()).toBeNull();
      expect(list.stale()).toBe("row failure");
      dispose();
    });
  });

  it("accepts a newer page after an earlier row update and preserves unchanged rows", async () => {
    await createRoot(async (dispose) => {
      const pages = [
        {
          items: [
            { name: "a", value: 1 },
            { name: "b", value: 1 },
          ],
        },
        {
          items: [
            { name: "a", value: 3 },
            { name: "b", value: 1 },
            { name: "c", value: 1 },
          ],
        },
      ];
      const list = createPagedList(
        () => okAsync(pages.shift()!),
        (item) => item.name,
      );
      await list.load();
      const unchanged = list.items()[1];
      expect(list.updateItem({ name: "a", value: 2 })).toBe(true);
      expect(list.items()).toEqual([
        { name: "a", value: 2 },
        { name: "b", value: 1 },
      ]);
      await list.refresh();
      expect(list.items()).toEqual([
        { name: "a", value: 3 },
        { name: "b", value: 1 },
        { name: "c", value: 1 },
      ]);
      expect(list.items()[1]).toBe(unchanged);
      dispose();
    });
  });

  it("prunes an absent queued update before an older refresh returns", async () => {
    await createRoot(async (dispose) => {
      const { calls, fetchPage } = controlled();
      const list = createPagedList(fetchPage, (item) => item.split(":")[0]!);
      const initial = list.load();
      calls[0]!.d.resolve({ items: ["a:1"], nextToken: "next" });
      await initial;
      const refresh = list.refresh();
      expect(list.updateItem("b:2")).toBe(false);
      const more = list.more();
      calls[2]!.d.resolve({ items: ["c:1"] });
      await more;
      expect(list.items()).toEqual(["a:1", "c:1"]);
      calls[1]!.d.resolve({ items: ["b:1"] });
      await refresh;
      expect(list.items()).toEqual(["b:1"]);
      dispose();
    });
  });
  it("keeps an update that arrives while the initial page is loading", async () => {
    await createRoot(async (dispose) => {
      type Row = { name: string; value: number };
      const calls: { resolve: (page: Page<Row>) => void }[] = [];
      const fetchPage = () =>
        ResultAsync.fromPromise(
          new Promise<Page<Row>>((resolve) => calls.push({ resolve })),
          (e) => e as ApiError,
        );
      const list = createPagedList(fetchPage, (item) => item.name);
      const initial = list.load();
      expect(list.loading()).toBe(true);
      expect(list.updateItem({ name: "one", value: 2 })).toBe(false);
      calls[0]!.resolve({ items: [{ name: "one", value: 1 }] });
      await initial;
      expect(list.items()).toEqual([{ name: "one", value: 2 }]);
      dispose();
    });
  });

  it("keeps a row update that finishes while a stale refresh is still pending", async () => {
    await createRoot(async (dispose) => {
      type Row = { name: string; value: number };
      const calls: { resolve: (page: Page<Row>) => void }[] = [];
      const fetchPage = () =>
        ResultAsync.fromPromise(
          new Promise<Page<Row>>((resolve) => calls.push({ resolve })),
          (e) => e as ApiError,
        );
      const list = createPagedList(fetchPage, (item) => item.name);
      const initial = list.load();
      calls[0]!.resolve({ items: [{ name: "one", value: 1 }] });
      await initial;
      const staleRefresh = list.refresh();
      expect(list.updateItem({ name: "one", value: 2 })).toBe(true);
      calls[1]!.resolve({ items: [{ name: "one", value: 1 }] });
      await staleRefresh;
      expect(list.items()).toEqual([{ name: "one", value: 2 }]);
      dispose();
    });
  });

  it("applies a row update queued before its next page arrives", async () => {
    await createRoot(async (dispose) => {
      type Row = { name: string; value: number };
      const calls: { token: string | undefined; resolve: (page: Page<Row>) => void }[] = [];
      const fetchPage = (token: string | undefined) =>
        ResultAsync.fromPromise(
          new Promise<Page<Row>>((resolve) => calls.push({ token, resolve })),
          (e) => e as ApiError,
        );
      const list = createPagedList(fetchPage, (item) => item.name);
      const initial = list.load();
      calls[0]!.resolve({ items: [{ name: "one", value: 1 }], nextToken: "next" });
      await initial;
      const more = list.more();
      expect(calls[1]!.token).toBe("next");
      expect(list.updateItem({ name: "two", value: 2 })).toBe(false);
      calls[1]!.resolve({ items: [{ name: "two", value: 1 }] });
      await more;
      expect(list.items()).toEqual([
        { name: "one", value: 1 },
        { name: "two", value: 2 },
      ]);
      dispose();
    });
  });

  it("reports a row read failure as stale while keeping the last good rows", async () => {
    await createRoot(async (dispose) => {
      const list = createPagedList(() => okAsync({ items: ["one"] }));
      await list.load();
      list.reportStale("row read failed");
      expect(list.items()).toEqual(["one"]);
      expect(list.stale()).toBe("row read failed");
      dispose();
    });
  });
});
