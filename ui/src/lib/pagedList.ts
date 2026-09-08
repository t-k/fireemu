import { batch, createSignal, type Accessor } from "solid-js";
import type { ResultAsync } from "neverthrow";
import type { ApiError } from "../api/client";

export type Page<T> = { items: T[]; nextToken?: string | undefined };

/**
 * A paged listing whose state never mixes targets. Every fetch carries a generation; a
 * response for an older generation (a slow answer for a target the reader has left, or a
 * refresh superseded by a newer one) is dropped instead of overwriting the list. A refresh
 * re-reads as many pages as the reader had loaded, so live updates keep "Load more" progress
 * rather than snapping the list back to its first page. A failed refresh keeps the last
 * good list on screen and reports the failure separately (`stale`).
 */
export type PagedList<T> = {
  items: Accessor<T[]>;
  nextToken: Accessor<string | undefined>;
  /** True while nothing has been shown yet for the current target. */
  loading: Accessor<boolean>;
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
};

export const createPagedList = <T>(
  fetchPage: (token: string | undefined) => ResultAsync<Page<T>, ApiError>,
): PagedList<T> => {
  const [items, setItems] = createSignal<T[]>([]);
  const [nextToken, setNextToken] = createSignal<string | undefined>(undefined);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [stale, setStale] = createSignal<string | null>(null);
  let generation = 0;

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

  const load = async (): Promise<void> => {
    const mine = ++generation;
    batch(() => {
      setItems([]);
      setNextToken(undefined);
      setError(null);
      setStale(null);
      setLoading(true);
    });
    const r = await readFrom(1);
    if (mine !== generation) return;
    batch(() => {
      setLoading(false);
      if (r.ok) {
        setItems(r.page.items);
        setNextToken(r.page.nextToken);
      } else {
        setError(r.message);
      }
    });
  };

  const refresh = async (): Promise<void> => {
    const mine = ++generation;
    const shown = items().length;
    if (shown === 0 && error() !== null) {
      // Nothing good to keep: behave as a fresh load.
      generation -= 1;
      return load();
    }
    const r = await readFrom(Math.max(shown, 1));
    if (mine !== generation) return;
    batch(() => {
      setLoading(false);
      if (r.ok) {
        setItems(r.page.items);
        setNextToken(r.page.nextToken);
        setError(null);
        setStale(null);
      } else {
        setStale(r.message);
      }
    });
  };

  const more = async (): Promise<void> => {
    const token = nextToken();
    if (!token) return;
    const mine = generation;
    const r = await fetchPage(token);
    if (mine !== generation) return;
    r.match(
      (page) => {
        batch(() => {
          setItems([...items(), ...page.items]);
          setNextToken(page.nextToken);
        });
      },
      (e) => setStale(e.message),
    );
  };

  return { items, nextToken, loading, error, stale, load, refresh, more };
};
