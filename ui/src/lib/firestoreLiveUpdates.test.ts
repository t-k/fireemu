import { afterEach, describe, expect, it, vi } from "vitest";
import {
  affectedFirestoreViews,
  createLiveUpdateScheduler,
  createRowReadGuard,
  drainPendingRowUpdates,
  parseFirestoreWatchEvent,
} from "./firestoreLiveUpdates";

describe("Firestore live update event routing", () => {
  const root = "projects/p/databases/(default)/documents";

  it.each(["null", "42", '"text"', "{}", '{"changes":null}', '{"changes":{}}', "{"])(
    "treats malformed commit payload %s as an empty commit",
    (data) => {
      expect(parseFirestoreWatchEvent({ event: "commit", data })).toEqual({
        kind: "commit",
        changes: [],
      });
    },
  );

  it("filters malformed changes without discarding valid changes", () => {
    expect(
      parseFirestoreWatchEvent({
        event: "commit",
        data: JSON.stringify({
          changes: [
            null,
            1,
            "bad",
            {},
            { path: 1, kind: "created" },
            { path: "bad", kind: "unknown" },
            { path: "a", kind: "created" },
            { path: "b", kind: "updated" },
            { path: "c", kind: "deleted" },
          ],
        }),
      }),
    ).toEqual({
      kind: "commit",
      changes: [
        { path: "a", kind: "created" },
        { path: "b", kind: "updated" },
        { path: "c", kind: "deleted" },
      ],
    });
  });

  it("ignores primitive changes even when their prototype has change fields", () => {
    const prototype = Object.getPrototypeOf(1);
    Object.defineProperties(prototype, {
      path: { configurable: true, value: "unexpected" },
      kind: { configurable: true, value: "created" },
    });
    try {
      expect(parseFirestoreWatchEvent({ event: "commit", data: '{"changes":[1]}' })).toEqual({
        kind: "commit",
        changes: [],
      });
    } finally {
      Reflect.deleteProperty(prototype, "path");
      Reflect.deleteProperty(prototype, "kind");
    }
  });

  it("ignores non-commit events even when their data contains changes", () => {
    const event = parseFirestoreWatchEvent({ event: "heartbeat", data: '{"changes":[]}' });
    expect(event).toEqual({ kind: "other" });
    expect(affectedFirestoreViews(event, root, "users")).toEqual({
      full: false,
      collection: false,
      document: false,
      subcollections: false,
      updatedRows: [],
    });
  });

  it.each([
    ["users/alice", "updated", "users/alice", false, true, false, []],
    ["users/alice", "created", "users/alice", false, true, false, []],
    ["users/alice", "created", "users", true, false, false, []],
    ["users/alice", "deleted", "users", true, false, false, []],
    ["users/alice", "updated", "users", false, false, false, ["alice"]],
    ["users/alice/posts/one", "updated", "users/alice", false, false, true, []],
    ["users/alice/posts/one", "created", "users/alice", true, false, true, []],
    ["users/alice/posts/one", "deleted", "users/alice", true, false, true, []],
    ["users/alice", "created", "", true, false, false, []],
    ["users/alice", "deleted", "", true, false, false, []],
    ["users/alice", "updated", "", false, false, false, []],
    ["users", "created", "", false, false, false, []],
    ["users/bob/posts/one", "created", "users/alice", false, false, false, []],
    ["users/alice/posts/one", "updated", "users/alice/posts", false, false, false, ["one"]],
    ["users//alice/", "updated", "/users/", false, false, false, ["alice"]],
  ] as const)(
    "routes %s %s at %s",
    (path, kind, route, collection, document, subcollections, updatedRows) => {
      expect(
        affectedFirestoreViews(
          { kind: "commit", changes: [{ path: `${root}/${path}`, kind }] },
          root,
          route,
        ),
      ).toEqual({
        full: false,
        collection,
        document,
        subcollections,
        updatedRows,
      });
    },
  );

  it.each([`${root}Extra/users/alice`, "projects/p/databases/other/documents/users/alice"])(
    "ignores a path outside the documents root: %s",
    (path) => {
      expect(
        affectedFirestoreViews(
          { kind: "commit", changes: [{ path, kind: "updated" }] },
          root,
          "users",
        ),
      ).toEqual({
        full: false,
        collection: false,
        document: false,
        subcollections: false,
        updatedRows: [],
      });
    },
  );

  it("ignores a different root even when its suffix matches the open route", () => {
    expect(
      affectedFirestoreViews(
        {
          kind: "commit",
          changes: [{ path: `${"x".repeat(root.length)}/users/alice`, kind: "updated" }],
        },
        root,
        "users",
      ),
    ).toEqual({
      full: false,
      collection: false,
      document: false,
      subcollections: false,
      updatedRows: [],
    });
  });

  it("ignores an unrelated path and routes direct child update to its row", () => {
    const unrelated = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: `${root}/other/doc`, kind: "updated" }] }),
    });
    expect(affectedFirestoreViews(unrelated, root, "users")).toEqual({
      full: false,
      collection: false,
      document: false,
      subcollections: false,
      updatedRows: [],
    });
    const row = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: `${root}/users/alice`, kind: "updated" }] }),
    });
    expect(affectedFirestoreViews(row, root, "users").updatedRows).toEqual(["alice"]);
  });

  it.each(["created", "deleted"] as const)(
    "refreshes collection membership for child %s",
    (kind) => {
      const event = parseFirestoreWatchEvent({
        event: "commit",
        data: JSON.stringify({ changes: [{ path: `${root}/users/alice`, kind }] }),
      });
      expect(affectedFirestoreViews(event, root, "users").collection).toBe(true);
    },
  );

  it("refreshes the exact open document and its subcollection IDs", () => {
    const exact = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: `${root}/users/alice`, kind: "updated" }] }),
    });
    expect(affectedFirestoreViews(exact, root, "users/alice")).toMatchObject({
      document: true,
      subcollections: false,
    });
    const child = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({
        changes: [{ path: `${root}/users/alice/posts/one`, kind: "created" }],
      }),
    });
    expect(affectedFirestoreViews(child, root, "users/alice").subcollections).toBe(true);
  });

  it("refreshes root collection IDs for a create/delete and nested subcollections", () => {
    const rootCollection = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: `${root}/newCollection/one`, kind: "created" }] }),
    });
    expect(affectedFirestoreViews(rootCollection, root, "").collection).toBe(true);
    const nested = parseFirestoreWatchEvent({
      event: "commit",
      data: JSON.stringify({
        changes: [{ path: `${root}/users/alice/posts/thread/replies/one`, kind: "created" }],
      }),
    });
    expect(affectedFirestoreViews(nested, root, "users/alice").subcollections).toBe(true);
  });

  it.each(["created", "deleted"] as const)(
    "refreshes showMissing collection rows when a descendant is %s",
    (kind) => {
      const event = parseFirestoreWatchEvent({
        event: "commit",
        data: JSON.stringify({
          changes: [{ path: `${root}/users/missing/posts/one`, kind }],
        }),
      });
      expect(affectedFirestoreViews(event, root, "users").collection).toBe(true);
    },
  );

  it.each(["resync", "reset"])("requests a full refresh after %s", (eventName) => {
    const event = parseFirestoreWatchEvent({ event: eventName, data: "{}" });
    expect(affectedFirestoreViews(event, root, "users/alice")).toEqual({
      full: true,
      collection: true,
      document: true,
      subcollections: true,
      updatedRows: [],
    });
  });
});

describe("pending changed document rows", () => {
  it("does not drain loaded or missing rows while loading, then drains only loaded rows", () => {
    const pending = new Set(["loaded", "missing"]);
    expect(drainPendingRowUpdates(pending, new Set(["loaded"]), true, false)).toEqual([]);
    expect([...pending]).toEqual(["loaded", "missing"]);
    expect(drainPendingRowUpdates(pending, new Set(["loaded"]), false, true)).toEqual(["loaded"]);
    expect([...pending]).toEqual(["missing"]);
  });
  it("keeps rows queued during initial and later page loads until visible", () => {
    const pending = new Set(["alice"]);
    expect(drainPendingRowUpdates(pending, new Set(), true, true)).toEqual([]);
    expect(pending).toEqual(new Set(["alice"]));
    expect(drainPendingRowUpdates(pending, new Set(), false, true)).toEqual([]);
    expect(pending).toEqual(new Set(["alice"]));
    expect(drainPendingRowUpdates(pending, new Set(["alice"]), false, false)).toEqual(["alice"]);
    expect(pending).toEqual(new Set());
  });

  it("drops a changed row that is not visible and has no more pages", () => {
    const pending = new Set(["unloaded"]);
    expect(drainPendingRowUpdates(pending, new Set(), false, false)).toEqual([]);
    expect(pending).toEqual(new Set());
  });
});

describe("changed row read ordering", () => {
  it("increments sequences per key and epochs on invalidation", () => {
    const guard = createRowReadGuard();
    expect(guard.issue("a")).toEqual({ epoch: 0, sequence: 1 });
    const second = guard.issue("a");
    expect(second).toEqual({ epoch: 0, sequence: 2 });
    expect(guard.issue("b")).toEqual({ epoch: 0, sequence: 1 });
    guard.invalidate();
    expect(guard.isCurrent("a", second)).toBe(false);
    const next = guard.issue("a");
    expect(next).toEqual({ epoch: 1, sequence: 3 });
    expect(guard.isCurrent("a", next)).toBe(true);
    expect(guard.isCurrent("b", next)).toBe(false);
  });
  it("rejects an older read after a newer read and after a list refresh", () => {
    const guard = createRowReadGuard();
    const older = guard.issue("alice");
    const newer = guard.issue("alice");
    expect(guard.isCurrent("alice", newer)).toBe(true);
    expect(guard.isCurrent("alice", older)).toBe(false);
    guard.invalidate();
    expect(guard.isCurrent("alice", newer)).toBe(false);
  });
});

describe("leading and bounded trailing refresh", () => {
  afterEach(() => vi.useRealTimers());

  it("only refreshes a trailing window when it is dirty and ignores notifications after disposal", () => {
    vi.useFakeTimers();
    const refresh = vi.fn();
    const scheduler = createLiveUpdateScheduler(refresh, 100);
    scheduler.notify();
    expect(refresh).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(100);
    expect(refresh).toHaveBeenCalledTimes(1);
    scheduler.notify();
    scheduler.notify();
    vi.advanceTimersByTime(100);
    expect(refresh).toHaveBeenCalledTimes(3);
    scheduler.notify();
    vi.advanceTimersByTime(100);
    expect(refresh).toHaveBeenCalledTimes(4);
    scheduler.dispose();
    scheduler.notify();
    vi.runAllTimers();
    expect(refresh).toHaveBeenCalledTimes(4);
  });

  it("clears a pending timer on disposal", () => {
    vi.useFakeTimers();
    const scheduler = createLiveUpdateScheduler(vi.fn(), 100);
    scheduler.notify();
    scheduler.notify();
    expect(vi.getTimerCount()).toBe(1);
    scheduler.dispose();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not clear a timer when disposed before any notification", () => {
    vi.useFakeTimers();
    const clearTimeout = vi.spyOn(window, "clearTimeout");
    const scheduler = createLiveUpdateScheduler(vi.fn(), 100);
    scheduler.dispose();
    expect(clearTimeout).not.toHaveBeenCalled();
    clearTimeout.mockRestore();
  });

  it("refreshes immediately, then coalesces a burst at the window boundary", () => {
    vi.useFakeTimers();
    const refresh = vi.fn();
    const scheduler = createLiveUpdateScheduler(refresh, 150);
    scheduler.notify();
    expect(refresh).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(100);
    scheduler.notify();
    scheduler.notify();
    expect(refresh).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(49);
    expect(refresh).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    expect(refresh).toHaveBeenCalledTimes(2);
    scheduler.dispose();
  });

  it("cancels a pending trailing refresh on disposal", () => {
    vi.useFakeTimers();
    const refresh = vi.fn();
    const scheduler = createLiveUpdateScheduler(refresh, 150);
    scheduler.notify();
    scheduler.notify();
    scheduler.dispose();
    vi.runOnlyPendingTimers();
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
