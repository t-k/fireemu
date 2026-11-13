import type { SseEvent } from "../api/client";

export type FirestoreWatchChange = { path: string; kind: "created" | "updated" | "deleted" };
export type FirestoreWatchEvent =
  | { kind: "commit"; changes: FirestoreWatchChange[] }
  | { kind: "resync" | "reset" }
  | { kind: "other" };

export type AffectedFirestoreViews = {
  full: boolean;
  collection: boolean;
  document: boolean;
  subcollections: boolean;
  updatedRows: string[];
};

export const createRowReadGuard = () => {
  let epoch = 0;
  const sequences = new Map<string, number>();
  const applied = new Map<string, number>();
  return {
    issue: (key: string) => {
      const sequence = (sequences.get(key) ?? 0) + 1;
      sequences.set(key, sequence);
      return { epoch, sequence };
    },
    isCurrent: (key: string, ticket: { epoch: number; sequence: number }) =>
      ticket.epoch === epoch &&
      ticket.sequence <= (sequences.get(key) ?? 0) &&
      ticket.sequence >= (applied.get(key) ?? 0),
    markApplied: (key: string, ticket: { epoch: number; sequence: number }) => {
      applied.set(key, ticket.sequence);
    },
    invalidate: () => {
      epoch += 1;
    },
  };
};

export const drainPendingRowUpdates = (
  pending: Set<string>,
  loadedRows: Set<string>,
  loading: boolean,
  hasMore: boolean,
): string[] => {
  if (loading) return [];
  const ready: string[] = [];
  for (const id of pending) {
    if (loadedRows.has(id)) {
      pending.delete(id);
      ready.push(id);
    } else if (!hasMore) {
      pending.delete(id);
    }
  }
  return ready;
};

export const parseFirestoreWatchEvent = (event: SseEvent): FirestoreWatchEvent => {
  if (event.event === "resync" || event.event === "reset") return { kind: event.event };
  if (event.event !== "commit") return { kind: "other" };
  try {
    const payload: unknown = JSON.parse(event.data);
    if (!payload || typeof payload !== "object" || !("changes" in payload))
      return { kind: "commit", changes: [] };
    const changes = (payload as { changes?: unknown }).changes;
    if (!Array.isArray(changes)) return { kind: "commit", changes: [] };
    return {
      kind: "commit",
      changes: changes.flatMap((change): FirestoreWatchChange[] => {
        if (!change || typeof change !== "object") return [];
        const item = change as { path?: unknown; kind?: unknown };
        if (
          typeof item.path !== "string" ||
          (item.kind !== "created" && item.kind !== "updated" && item.kind !== "deleted")
        )
          return [];
        return [{ path: item.path, kind: item.kind }];
      }),
    };
  } catch {
    return { kind: "commit", changes: [] };
  }
};

export const affectedFirestoreViews = (
  event: FirestoreWatchEvent,
  documentsRoot: string,
  routePath: string,
): AffectedFirestoreViews => {
  const none = {
    full: false,
    collection: false,
    document: false,
    subcollections: false,
    updatedRows: [] as string[],
  };
  if (event.kind === "resync" || event.kind === "reset") {
    return { ...none, full: true, collection: true, document: true, subcollections: true };
  }
  if (event.kind !== "commit") return none;
  const route = routePath.split("/").filter(Boolean);
  let collection = false;
  let document = false;
  let subcollections = false;
  const updatedRows = new Set<string>();
  for (const change of event.changes) {
    const prefix = `${documentsRoot}/`;
    if (!change.path.startsWith(prefix)) continue;
    const changedPath = change.path.slice(prefix.length).split("/").filter(Boolean);
    if (changedPath.join("/") === route.join("/")) document = true;
    const sharesRoute = route.every((segment, index) => segment === changedPath[index]);
    if (route.length > 0 && changedPath.length === route.length + 1 && sharesRoute) {
      if (change.kind === "updated") updatedRows.add(changedPath.at(-1)!);
      else collection = true;
    }
    if (
      route.length > 0 &&
      changedPath.length > route.length + 1 &&
      sharesRoute &&
      (change.kind === "created" || change.kind === "deleted")
    )
      collection = true;
    if (
      route.length === 0 &&
      changedPath.length >= 2 &&
      (change.kind === "created" || change.kind === "deleted")
    )
      collection = true;
    if (route.length > 0 && changedPath.length >= route.length + 2 && sharesRoute) {
      subcollections = true;
    }
  }
  return { full: false, collection, document, subcollections, updatedRows: [...updatedRows] };
};

/** Leading refresh, with at most one trailing refresh at the end of each fixed window. */
export const createLiveUpdateScheduler = (refresh: () => void, windowMs: number) => {
  let timer: number | undefined;
  let dirty = false;
  let disposed = false;
  const notify = () => {
    if (disposed) return;
    if (timer === undefined) {
      refresh();
      timer = window.setTimeout(() => {
        timer = undefined;
        if (dirty && !disposed) {
          dirty = false;
          refresh();
        }
      }, windowMs);
    } else {
      dirty = true;
    }
  };
  const dispose = () => {
    disposed = true;
    dirty = false;
    if (timer !== undefined) window.clearTimeout(timer);
    timer = undefined;
  };
  return { notify, dispose };
};
