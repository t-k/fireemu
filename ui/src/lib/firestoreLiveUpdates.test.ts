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
