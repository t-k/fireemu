import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@solidjs/testing-library";
import { createComponent } from "solid-js";
import { createMemoryHistory, MemoryRouter, Route } from "@solidjs/router";
import { okAsync, ResultAsync } from "neverthrow";
import Firestore from "../pages/Firestore";
import { appState } from "../state";
import { subscribe, type SseEvent } from "../api/client";
import { getDocument, listDocuments, type DocumentPage } from "../api/firestore";
import type { FsDocument } from "./firestoreValue";
import {
  affectedFirestoreViews,
  createLiveUpdateScheduler,
  createRowReadGuard,
  drainPendingRowUpdates,
  parseFirestoreWatchEvent,
} from "./firestoreLiveUpdates";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  subscribe: vi.fn(),
}));
vi.mock("../api/firestore", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/firestore")>()),
  listDocuments: vi.fn(),
  getDocument: vi.fn(),
}));

describe("Firestore live updates with delayed responses", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.resetAllMocks();
    vi.unstubAllGlobals();
  });

  it("re-reads alice after a trailing update arrives during her membership refresh", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        throw new Error("Unexpected network request");
      }),
    );
    appState.setSessions([{ name: "default", project: "p" }]);
    appState.setSession("default");
    const root = "projects/p/databases/(default)/documents";
    const alice = { name: `${root}/users/alice`, fields: { value: { stringValue: "value1" } } };
    let emit!: (event: SseEvent) => void;
    vi.mocked(subscribe).mockImplementation((_path, onEvent) => {
      emit = onEvent;
      return vi.fn();
    });
    let release!: (page: DocumentPage) => void;
    vi.mocked(listDocuments)
      .mockReturnValueOnce(okAsync({ documents: [] }))
      .mockImplementation(() =>
        ResultAsync.fromSafePromise(
          new Promise<DocumentPage>((resolve) => {
            release = resolve;
          }),
        ),
      );
    vi.mocked(getDocument).mockReturnValue(
      okAsync({
        ...alice,
        fields: { value: { stringValue: "value2" } },
      }),
    );
    const history = createMemoryHistory();
    history.set({ value: "/users" });
    const view = render(() =>
      createComponent(MemoryRouter, {
        history,
        get children() {
          return createComponent(Route, { path: "/:path", component: Firestore });
        },
      }),
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(listDocuments).toHaveBeenCalledTimes(1);
    emit({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: alice.name, kind: "created" }] }),
    });
    expect(listDocuments).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(100);
    emit({
      event: "commit",
      data: JSON.stringify({ changes: [{ path: alice.name, kind: "updated" }] }),
    });
    await vi.advanceTimersByTimeAsync(50);
    expect(getDocument).not.toHaveBeenCalled();
    release({ documents: [alice] });
    await vi.advanceTimersByTimeAsync(0);
    expect(getDocument).toHaveBeenCalledExactlyOnceWith(root, "users/alice");
    expect(view.getByTestId("document-list").textContent).toContain("value2");
    expect(view.getByTestId("document-list").textContent).not.toContain("value1");
  });

  it.each(["created", "updated"] as const)(
    "applies every completed response while %s events continue every 151 ms",
    async (kind) => {
      vi.useFakeTimers();
      vi.stubGlobal(
        "fetch",
        vi.fn(() => {
          throw new Error("Unexpected network request");
        }),
      );
      appState.setSessions([{ name: "default", project: "p" }]);
      appState.setSession("default");
      const root = "projects/p/databases/(default)/documents";
      let value = 0;
      const alice = { name: `${root}/users/alice`, fields: { value: { stringValue: "value0" } } };
      const bob = { name: `${root}/users/bob`, fields: { value: { stringValue: "unchanged" } } };
      let emit!: (event: SseEvent) => void;
      vi.mocked(subscribe).mockImplementation((_path, onEvent) => {
        emit = onEvent;
        return vi.fn();
      });
      let inFlight = 0;
      let maximumInFlight = 0;
      const completed: string[] = [];
      vi.mocked(listDocuments).mockReturnValue(okAsync({ documents: [alice, bob] }));
      const history = createMemoryHistory();
      history.set({ value: "/users" });
      const view = render(() =>
        createComponent(MemoryRouter, {
          history,
          get children() {
            return createComponent(Route, { path: "/:path", component: Firestore });
          },
        }),
      );
      await vi.advanceTimersByTimeAsync(0);
      const unchangedRow = view.getByText("bob").closest("tr");
      if (kind === "created") {
        vi.mocked(listDocuments).mockImplementation(() => {
          const snapshot = `value${value}`;
          inFlight += 1;
          maximumInFlight = Math.max(maximumInFlight, inFlight);
          return ResultAsync.fromSafePromise(
            new Promise<DocumentPage>((resolve) => {
              setTimeout(() => {
                inFlight -= 1;
                completed.push(snapshot);
                resolve({
                  documents: [
                    { ...alice, fields: { value: { stringValue: snapshot } } },
                    { ...bob },
                  ],
                });
              }, 300);
            }),
          );
        });
      } else {
        vi.mocked(getDocument).mockImplementation(() => {
          const snapshot = `value${value}`;
          return ResultAsync.fromSafePromise(
            new Promise<FsDocument>((resolve) => {
              setTimeout(() => {
                completed.push(snapshot);
                resolve({ ...alice, fields: { value: { stringValue: snapshot } } });
              }, 300);
            }),
          );
        });
      }
      value += 1;
      emit({ event: "commit", data: JSON.stringify({ changes: [{ path: alice.name, kind }] }) });
      const writes = setInterval(() => {
        value += 1;
        emit({ event: "commit", data: JSON.stringify({ changes: [{ path: alice.name, kind }] }) });
      }, 151);
      for (let response = 1; response <= 4; response += 1) {
        await vi.advanceTimersByTimeAsync(response === 1 || kind === "created" ? 300 : 151);
        expect(completed).toHaveLength(response);
        expect(view.getByTestId("document-list").textContent).toContain(completed.at(-1));
        expect(view.getByText("bob").closest("tr")).toBe(unchangedRow);
        if (kind === "created") expect(maximumInFlight).toBe(1);
        else expect(listDocuments).toHaveBeenCalledTimes(1);
      }
      clearInterval(writes);
      await vi.runAllTimersAsync();
    },
  );
});

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
  it("rejects an older read only after a newer result is applied or the target changes", () => {
    const guard = createRowReadGuard();
    const older = guard.issue("alice");
    const newer = guard.issue("alice");
    expect(guard.isCurrent("alice", older)).toBe(true);
    expect(guard.isCurrent("alice", newer)).toBe(true);
    guard.markApplied("alice", newer);
    expect(guard.isCurrent("alice", newer)).toBe(true);
    expect(guard.isCurrent("alice", older)).toBe(false);
    guard.invalidate();
    expect(guard.isCurrent("alice", newer)).toBe(false);
  });

  it("does not let a late older row response overwrite a newer applied response", async () => {
    const guard = createRowReadGuard();
    const older = guard.issue("alice");
    const newer = guard.issue("alice");
    let releaseOlder!: (value: string) => void;
    let releaseNewer!: (value: string) => void;
    let shown = "initial";
    const first = new Promise<string>((resolve) => {
      releaseOlder = resolve;
    }).then((value) => {
      if (guard.isCurrent("alice", older)) {
        shown = value;
        guard.markApplied("alice", older);
      }
    });
    const second = new Promise<string>((resolve) => {
      releaseNewer = resolve;
    }).then((value) => {
      if (guard.isCurrent("alice", newer)) {
        shown = value;
        guard.markApplied("alice", newer);
      }
    });
    releaseNewer("value2");
    await second;
    releaseOlder("value1");
    await first;
    expect(shown).toBe("value2");
    const other = guard.issue("bob");
    expect(guard.isCurrent("bob", other)).toBe(true);
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
