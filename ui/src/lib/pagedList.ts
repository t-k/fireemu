import { batch, createSignal, type Accessor } from "solid-js";
import type { ResultAsync } from "neverthrow";
import type { ApiError } from "../api/client";

export type Page<T> = { items: T[]; nextToken?: string | undefined };

/**
 * A paged listing whose state never mixes targets. Every fetch carries a generation; a response for an older generation (a slow answer for a target the reader has left) is dropped instead of overwriting the list. Refreshes are serialized with one pending follow-up. A refresh re-reads as many pages as the reader had loaded, so live updates keep "Load more" progress rather than snapping the list back to its first page. A failed refresh keeps the last good list on screen and reports the failure separately (`stale`).
 */
export type PagedList<T> = {
  items: Accessor<T[]>;
  nextToken: Accessor<string | undefined>;
  /** True while nothing has been shown yet for the current target. */
  loading: Accessor<boolean>;
  /** True while a membership refresh is reading the loaded pages. */
  refreshing: Accessor<boolean>;
  /** The failure of the latest fetch, when it had nothing to show before. */
  error: Accessor<string | null>;
  /** The failure of the latest refresh, when the list shown is an older successful one. */
  stale: Accessor<string | null>;
  /** Shows a new target from its first page (the previous list is cleared). */
  load: () => Promise<void>;
  /** Re-reads the current target, keeping the number of pages already shown. */
  refresh: () => Promise<void>;
  /** Appends the next page. */
  more: () => Promise<void>;
  /** Replaces a loaded item with the same key; returns false when it is not loaded. */
  updateItem: (item: T) => boolean;
  reportStale: (message: string) => void;
};

export const createPagedList = <T>(
  fetchPage: (token: string | undefined) => ResultAsync<Page<T>, ApiError>,
  keyOf?: (item: T) => string,
): PagedList<T> => {
  const [items, setItems] = createSignal<T[]>([]);
  const [nextToken, setNextToken] = createSignal<string | undefined>(undefined);
  const [loading, setLoading] = createSignal(false);
  const [refreshing, setRefreshing] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [stale, setStale] = createSignal<string | null>(null);
  let generation = 0;
  let activeRead: Promise<void> | undefined;
  let refreshPending = false;
  let itemRevision = 0;
  const newerItems = new Map<string, { revision: number; item: T }>();
  const preserveUnchanged = (incoming: T[], revisionAtStart: number): T[] => {
    if (!keyOf) return incoming;
    const previous = new Map(items().map((item) => [keyOf(item), item]));
    return incoming.map((item) => {
      const key = keyOf(item);
      const update = newerItems.get(key);
      if (update && update.revision > revisionAtStart) return update.item;
      const old = previous.get(key);
      return old !== undefined && JSON.stringify(old) === JSON.stringify(item) ? old : item;
    });
  };
  const pruneUpdates = (liveItems: T[]): void => {
    if (!keyOf) return;
    const liveKeys = new Set(liveItems.map(keyOf));
    for (const key of newerItems.keys()) {
      if (!liveKeys.has(key)) newerItems.delete(key);
    }
  };

  /** Reads pages from the start until `minimum` items are held or the pages run out. */
  const readFrom = async (
    minimum: number,
  ): Promise<{ ok: true; page: Page<T> } | { ok: false; message: string }> => {
    const collected: T[] = [];
    let token: string | undefined;
    do {
      const r = await fetchPage(token);
      if (r.isErr()) {
        return { ok: false, message: r.error.message };
      }
      collected.push(...r.value.items);
      token = r.value.nextToken;
    } while (token && collected.length < minimum);
    return { ok: true, page: { items: collected, nextToken: token } };
  };

  const load = (): Promise<void> => {
    const revisionAtStart = itemRevision;
    const mine = ++generation;
    refreshPending = false;
    newerItems.clear();
    batch(() => {
      setItems([]);
      setNextToken(undefined);
      setError(null);
      setStale(null);
      setLoading(true);
      setRefreshing(false);
    });
    activeRead = (async () => {
      const r = await readFrom(1);
      if (mine !== generation) return;
      batch(() => {
        setLoading(false);
        if (r.ok) {
          setItems(preserveUnchanged(r.page.items, revisionAtStart));
          pruneUpdates(r.page.items);
          setNextToken(r.page.nextToken);
        } else {
          setError(r.message);
        }
      });
      activeRead = undefined;
      if (refreshPending) {
        refreshPending = false;
        await refresh();
      }
    })();
    return activeRead;
  };

  const refresh = (): Promise<void> => {
    if (activeRead) {
      refreshPending = true;
      return activeRead;
    }
    // A failed load left nothing good to keep (the list is empty whenever `error` is set):
    // behave as a fresh load.
    if (error() !== null) return load();
    activeRead = (async () => {
      do {
        refreshPending = false;
        const revisionAtStart = itemRevision;
        const mine = ++generation;
        setRefreshing(true);
        const r = await readFrom(Math.max(items().length, 1));
        if (mine !== generation) return;
        batch(() => {
          setLoading(false);
          if (r.ok) {
            const stableItems = preserveUnchanged(r.page.items, revisionAtStart);
            setItems(stableItems);
            pruneUpdates(stableItems);
            setNextToken(r.page.nextToken);
            setStale(null);
          } else {
            setStale(r.message);
          }
          setRefreshing(false);
        });
      } while (refreshPending);
      activeRead = undefined;
    })();
    return activeRead;
  };

  const more = async (): Promise<void> => {
    const token = nextToken();
    if (!token) return;
    const revisionAtStart = itemRevision;
    const mine = generation;
    const r = await fetchPage(token);
    if (mine !== generation) return;
    r.match(
      (page) => {
        batch(() => {
          const nextItems = preserveUnchanged([...items(), ...page.items], revisionAtStart);
          setItems(nextItems);
          pruneUpdates(nextItems);
          setNextToken(page.nextToken);
        });
      },
      (e) => setStale(e.message),
    );
  };

  const updateItem = (item: T): boolean => {
    if (!keyOf) return false;
    const key = keyOf(item);
    const revision = ++itemRevision;
    newerItems.set(key, { revision, item });
    let found = false;
    setItems((current) =>
      current.map((old) => {
        if (keyOf(old) !== key) return old;
        found = true;
        return item;
      }),
    );
    return found;
  };

  const reportStale = (message: string): void => {
    batch(() => {
      if (items().length > 0) setStale(message);
      else setError(message);
    });
  };

  return {
    items,
    nextToken,
    loading,
    refreshing,
    error,
    stale,
    load,
    refresh,
    more,
    updateItem,
    reportStale,
  };
};
