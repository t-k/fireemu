import {
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  untrack,
  type Accessor,
} from "solid-js";
import type { Result } from "neverthrow";
import type { ApiError } from "../api/client";

/** Retain only this scope's successful snapshot; an epoch owns every asynchronous read. */
export const createScopedFetch = <T>(
  scope: Accessor<string>,
  fetcher: (scope: string) => PromiseLike<Result<T, ApiError>>,
) => {
  const [state, setState] = createSignal<{
    scope: string;
    data: T | undefined;
    error: string | null;
    loading: boolean;
  }>({ scope: scope(), data: undefined, error: null, loading: true });
  let epoch = 0;
  let disposed = false;
  onCleanup(() => {
    disposed = true;
    epoch++;
  });
  const load = async (key: string, reset = false) => {
    const mine = ++epoch;
    setState((previous) => ({
      scope: key,
      data: !reset && previous.scope === key ? previous.data : undefined,
      error: null,
      loading: true,
    }));
    try {
      const result = await fetcher(key);
      if (disposed || mine !== epoch || scope() !== key) return;
      result.match(
        (data) => setState({ scope: key, data, error: null, loading: false }),
        (error) => setState((previous) => ({ ...previous, error: error.message, loading: false })),
      );
    } catch (error) {
      if (!disposed && mine === epoch && scope() === key)
        setState((previous) => ({ ...previous, error: String(error), loading: false }));
    }
  };
  createEffect(() => {
    const key = scope();
    untrack(() => void load(key, true));
  });
  return {
    data: createMemo(() => (state().scope === scope() ? state().data : undefined)),
    error: () => (state().scope === scope() ? state().error : null),
    loading: () => state().scope !== scope() || state().loading,
    refetch: () => load(scope()),
    replace: (data: T) => {
      epoch++;
      setState({ scope: scope(), data, error: null, loading: false });
    },
  };
};
