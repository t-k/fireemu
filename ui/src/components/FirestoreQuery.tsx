import { A } from "@solidjs/router";
import {
  createEffect,
  createMemo,
  createSignal,
  For,
  on,
  onCleanup,
  Show,
  type Component,
} from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import {
  loadMissingIndexes,
  runQuery,
  type MissingIndexReports,
  type QueryResults,
} from "../api/firestoreQuery";
import type { ApiError } from "../api/client";
import { t } from "../i18n";
import { appState } from "../state";
import {
  compileQuery,
  decodeSharedQuery,
  defaultQuery,
  encodeSharedQuery,
  QUERY_OPERATORS,
  QUERY_TYPES,
  type CompiledQuery,
  type QueryFilter,
  type QueryOperator,
  type QueryValueType,
} from "../lib/firestoreQuery";
import { relativePath } from "../lib/firestoreValue";
import { firestoreHref } from "../lib/hrefs";
import { ErrorBanner, Notice } from "./common";

type Execution = {
  scope: string;
  query: CompiledQuery;
  draft: string;
  loading: boolean;
  result?: QueryResults;
  error?: ApiError;
};
const failure = (error: ApiError): string =>
  `${error.status === 0 ? "" : `${error.status} `}${error.code ? `${error.code}: ` : ""}${error.message}`;
const valueLabel = (type: QueryValueType): string => {
  switch (type) {
    case "integer":
      return t("firestore.queryTypeInteger");
    case "double":
      return t("firestore.queryTypeDouble");
    case "string":
      return t("firestore.typeString");
    case "boolean":
      return t("firestore.typeBoolean");
    case "null":
      return t("firestore.typeNull");
    case "timestamp":
      return t("firestore.typeTimestamp");
    case "geopoint":
      return t("firestore.typeGeopoint");
    case "reference":
      return t("firestore.typeReference");
    case "array":
      return t("firestore.typeArray");
    case "map":
      return t("firestore.typeMap");
    case "bytes":
      return t("firestore.typeBytes");
  }
};

/** Query snapshots never follow live collection refreshes or relabel themselves after editing. */
const FirestoreQuery: Component<{ root: string; collection: string; db: string }> = (props) => {
  const [draft, setDraft] = createStore(defaultQuery());
  const [execution, setExecution] = createSignal<Execution | null>(null);
  const [shareError, setShareError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [reports, setReports] = createSignal<MissingIndexReports | null>(null);
  const [reportError, setReportError] = createSignal<string | null>(null);
  const [reportsLoading, setReportsLoading] = createSignal(false);
  let queryId = 0;
  let reportId = 0;
  let queryAbort: AbortController | undefined;
  let reportAbort: AbortController | undefined;
  let addFilterButton: HTMLButtonElement | undefined;
  let addOrderButton: HTMLButtonElement | undefined;
  const scopeKey = createMemo(() =>
    JSON.stringify([props.root, props.collection, appState.session()]),
  );
  const scopeLabel = () =>
    t("firestore.queryScope", {
      project: appState.project(),
      database: props.db,
      collection: props.collection,
      session: appState.session(),
    });
  const encodedDraft = createMemo(() => encodeSharedQuery(draft));
  const compiled = createMemo(() => compileQuery(props.root, props.collection, draft));
  const invalid = () => {
    const result = compiled();
    return result.isErr() ? t("firestore.queryInvalid", { message: result.error }) : null;
  };

  createEffect(
    on(scopeKey, () => {
      queryId++;
      reportId++;
      queryAbort?.abort();
      reportAbort?.abort();
      setExecution(null);
      setReports(null);
      setReportError(null);
      setReportsLoading(false);
      setNotice(null);
      setShareError(null);
      const text = new URL(window.location.href).searchParams.get("query");
      const shared = text === null ? null : decodeSharedQuery(text);
      if (shared?.isErr()) setShareError(t("firestore.querySharedInvalid"));
      setDraft(reconcile(shared?.isOk() ? shared.value : defaultQuery()));
    }),
  );
  onCleanup(() => {
    queryId++;
    reportId++;
    queryAbort?.abort();
    reportAbort?.abort();
  });

  const execute = async () => {
    const query = compiled();
    if (query.isErr()) return;
    queryAbort?.abort();
    queryAbort = new AbortController();
    const id = ++queryId;
    const key = scopeKey();
    const snapshot: Execution = {
      scope: scopeLabel(),
      query: query.value,
      draft: encodedDraft(),
      loading: true,
    };
    setExecution(snapshot);
    const result = await runQuery(query.value, queryAbort.signal);
    if (id !== queryId || key !== scopeKey()) return;
    setExecution(
      result.match(
        (value) => ({ ...snapshot, loading: false, result: value }),
        (error) => ({ ...snapshot, loading: false, error }),
      ),
    );
  };
  const readIndexes = async () => {
    reportAbort?.abort();
    reportAbort = new AbortController();
    const id = ++reportId;
    const key = scopeKey();
    setReportsLoading(true);
    setReportError(null);
    setReports(null);
    const result = await loadMissingIndexes(appState.session(), props.root, reportAbort.signal);
    if (id !== reportId || key !== scopeKey()) return;
    setReportsLoading(false);
    result.match(setReports, (error) =>
      setReportError(t("firestore.queryIndexUnavailable", { message: failure(error) })),
    );
  };
  const share = async () => {
    setNotice(null);
    setShareError(null);
    if (compiled().isErr()) return;
    const text = encodedDraft();
    if (decodeSharedQuery(text).isErr()) {
      setShareError(t("firestore.querySharedInvalid"));
      return;
    }
    const url = new URL(window.location.href);
    url.searchParams.delete("token");
    url.searchParams.set("query", text);
    try {
      await navigator.clipboard.writeText(url.toString());
      setNotice(t("firestore.queryCopied"));
    } catch {
      setShareError(t("firestore.queryCopyFailed"));
    }
  };
  const updateFilter = (index: number, patch: Partial<QueryFilter>) =>
    setDraft("filters", index, patch);

  return (
    <section
      class="my-5 border-y border-zinc-200 py-4 dark:border-zinc-700"
      data-testid="query-panel"
      aria-labelledby="firestore-query-heading"
    >
      <h3 id="firestore-query-heading" class="text-base font-semibold">
        {t("firestore.queryTitle")}
      </h3>
      <p class="mt-1 text-sm text-zinc-500">{t("firestore.queryHint")}</p>
      <p class="mono my-2 break-all text-xs">{scopeLabel()}</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void execute();
        }}
      >
        <label class="my-3 flex items-center gap-2 text-sm">
          <span>{t("firestore.queryGroup")}</span>
          <select
            class="input"
            value={draft.mode}
            onChange={(event) => setDraft("mode", event.currentTarget.value as "AND" | "OR")}
          >
            <option value="AND">{t("firestore.queryAnd")}</option>
            <option value="OR">{t("firestore.queryOr")}</option>
          </select>
        </label>
        <For each={draft.filters}>
          {(row, index) => (
            <fieldset
              class="mb-3 flex flex-wrap items-end gap-2 rounded border border-zinc-200 p-3 dark:border-zinc-700"
              data-testid={`query-filter-${index()}`}
            >
              <legend class="px-1 text-sm">
                {t("firestore.queryFilterRow", { row: index() + 1 })}
              </legend>
              <label class="grid gap-1 text-sm">
                <span>{t("firestore.queryField")}</span>
                <input
                  class="input mono"
                  value={row.field}
                  onInput={(event) => updateFilter(index(), { field: event.currentTarget.value })}
                />
              </label>
              <label class="grid gap-1 text-sm">
                <span>{t("firestore.queryOperator")}</span>
                <select
                  class="input"
                  value={row.op}
                  onChange={(event) =>
                    updateFilter(index(), { op: event.currentTarget.value as QueryOperator })
                  }
                >
                  <For each={QUERY_OPERATORS}>
                    {(operator) => <option value={operator}>{operator}</option>}
                  </For>
                </select>
              </label>
              <label class="grid gap-1 text-sm">
                <span>{t("firestore.queryValueType")}</span>
                <select
                  class="input"
                  value={row.type}
                  onChange={(event) =>
                    updateFilter(index(), { type: event.currentTarget.value as QueryValueType })
                  }
                >
                  <For each={QUERY_TYPES}>
                    {(type) => <option value={type}>{valueLabel(type)}</option>}
                  </For>
                </select>
              </label>
              <label class="grid min-w-48 flex-1 gap-1 text-sm">
                <span>{t("firestore.queryValue")}</span>
                <input
                  class="input mono"
                  disabled={row.type === "null"}
                  value={row.text}
                  onInput={(event) => updateFilter(index(), { text: event.currentTarget.value })}
                />
              </label>
              <button
                class="btn"
                type="button"
                aria-label={t("firestore.queryRemoveFilter", { row: index() + 1 })}
                onClick={() => {
                  setDraft("filters", (rows) => rows.filter((_, position) => position !== index()));
                  queueMicrotask(() => addFilterButton?.focus());
                }}
              >
                {t("app.delete")}
              </button>
            </fieldset>
          )}
        </For>
        <button
          ref={(element) => {
            addFilterButton = element;
          }}
          class="btn mb-3"
          type="button"
          disabled={draft.filters.length >= 20}
          onClick={() =>
            setDraft("filters", (rows) => [
              ...rows,
              { field: "", op: "EQUAL", type: "string", text: "" },
            ])
          }
        >
          {t("firestore.queryAddFilter")}
        </button>
        <p class="mb-3 text-xs text-zinc-500">{t("firestore.queryValueHint")}</p>
        <For each={draft.orders}>
          {(row, index) => (
            <fieldset
              class="mb-3 flex flex-wrap items-end gap-2 rounded border border-zinc-200 p-3 dark:border-zinc-700"
              data-testid={`query-order-${index()}`}
            >
              <legend class="px-1 text-sm">
                {t("firestore.queryOrderRow", { row: index() + 1 })}
              </legend>
              <label class="grid gap-1 text-sm">
                <span>{t("firestore.queryField")}</span>
                <input
                  class="input mono"
                  value={row.field}
                  onInput={(event) =>
                    setDraft("orders", index(), "field", event.currentTarget.value)
                  }
                />
              </label>
              <label class="grid gap-1 text-sm">
                <span>{t("firestore.queryDirection")}</span>
                <select
                  class="input"
                  value={row.direction}
                  onChange={(event) =>
                    setDraft(
                      "orders",
                      index(),
                      "direction",
                      event.currentTarget.value as "ASCENDING" | "DESCENDING",
                    )
                  }
                >
                  <option value="ASCENDING">{t("firestore.queryAscending")}</option>
                  <option value="DESCENDING">{t("firestore.queryDescending")}</option>
                </select>
              </label>
              <button
                class="btn"
                type="button"
                aria-label={t("firestore.queryRemoveOrder", { row: index() + 1 })}
                onClick={() => {
                  setDraft("orders", (rows) => rows.filter((_, position) => position !== index()));
                  queueMicrotask(() => addOrderButton?.focus());
                }}
              >
                {t("app.delete")}
              </button>
            </fieldset>
          )}
        </For>
        <button
          ref={(element) => {
            addOrderButton = element;
          }}
          class="btn mb-3"
          type="button"
          disabled={draft.orders.length >= 20}
          onClick={() =>
            setDraft("orders", (rows) => [...rows, { field: "", direction: "ASCENDING" }])
          }
        >
          {t("firestore.queryAddOrder")}
        </button>
        <div class="mb-3 flex flex-wrap items-end gap-2">
          <label class="grid gap-1 text-sm">
            <span>{t("firestore.queryLimit")}</span>
            <input
              class="input w-28"
              type="number"
              min="1"
              max="1000"
              step="1"
              value={draft.limit}
              onInput={(event) => setDraft("limit", event.currentTarget.value)}
            />
          </label>
          <button class="btn btn-primary" type="submit" disabled={compiled().isErr()}>
            {t("firestore.queryRun")}
          </button>
          <button
            class="btn"
            type="button"
            disabled={compiled().isErr()}
            onClick={() => void share()}
          >
            {t("firestore.queryShare")}
          </button>
        </div>
        <p class="mb-3 text-xs text-zinc-500">{t("firestore.queryBounded")}</p>
        <ErrorBanner message={invalid()} />
        <Show when={compiled().isOk()}>
          <details class="mb-3">
            <summary class="cursor-pointer text-sm">{t("firestore.queryPreview")}</summary>
            <pre class="mono max-h-64 overflow-auto rounded bg-zinc-100 p-3 text-xs dark:bg-zinc-900">
              {JSON.stringify(
                compiled().match(
                  (value) => value,
                  () => null,
                ),
                null,
                2,
              )}
            </pre>
          </details>
        </Show>
      </form>
      <ErrorBanner message={shareError()} />
      <Notice message={notice()} />
      <Show
        when={execution()}
        fallback={<p class="text-sm text-zinc-500">{t("firestore.queryNoResults")}</p>}
      >
        {(attempt) => (
          <>
            <Show when={attempt().draft !== encodedDraft()}>
              <p
                role="status"
                class="mb-2 text-sm text-amber-700 dark:text-amber-300"
                data-testid="query-stale"
              >
                {t("firestore.queryStale")}
              </p>
            </Show>
            <details class="mb-3" data-testid="query-executed">
              <summary class="cursor-pointer text-sm">{t("firestore.queryExecuted")}</summary>
              <p class="mono my-2 text-xs">{attempt().scope}</p>
              <pre class="mono max-h-64 overflow-auto text-xs">
                {JSON.stringify(attempt().query, null, 2)}
              </pre>
            </details>
            <Show when={attempt().loading}>
              <p role="status" data-testid="query-loading">
                {t("firestore.queryRunning")}
              </p>
            </Show>
            <Show when={attempt().error}>
              {(error) => (
                <div data-testid="query-error">
                  <ErrorBanner message={failure(error())} />
                </div>
              )}
            </Show>
            <Show when={attempt().result}>
              {(result) => (
                <section data-testid="query-results" aria-label={t("firestore.queryResult")}>
                  <h4 class="mb-2 font-semibold">{t("firestore.queryResult")}</h4>
                  <p role="status" class="mb-2 text-sm">
                    {t("firestore.queryCount", {
                      count: result().documents.length,
                      metadata: result().metadata.length,
                    })}
                  </p>
                  <Show when={result().documents.length === 0}>
                    <p class="my-2 text-sm">{t("firestore.queryEmpty")}</p>
                  </Show>
                  <ul class="mb-3 space-y-1">
                    <For each={result().documents}>
                      {(document) => (
                        <li>
                          <A
                            class="mono text-sm text-blue-700 underline dark:text-blue-300"
                            aria-label={t("firestore.queryOpenDocument", {
                              path: relativePath(document.name),
                            })}
                            href={firestoreHref(relativePath(document.name), props.db)}
                          >
                            {relativePath(document.name)}
                          </A>
                        </li>
                      )}
                    </For>
                  </ul>
                  <details open>
                    <summary class="cursor-pointer text-sm">{t("firestore.queryExact")}</summary>
                    <pre class="mono my-2 max-h-80 overflow-auto rounded bg-zinc-100 p-3 text-xs dark:bg-zinc-900">
                      {JSON.stringify(result().rows, null, 2)}
                    </pre>
                  </details>
                </section>
              )}
            </Show>
          </>
        )}
      </Show>
      <section
        class="mt-4 border-t border-zinc-200 pt-3 dark:border-zinc-700"
        data-testid="query-indexes"
        aria-label={t("firestore.queryIndexes")}
      >
        <h4 class="font-semibold">{t("firestore.queryIndexes")}</h4>
        <p class="my-2 text-xs text-zinc-500">{t("firestore.queryIndexHint")}</p>
        <button
          type="button"
          class="btn mb-2"
          disabled={reportsLoading()}
          onClick={() => void readIndexes()}
        >
          {t("firestore.queryLoadIndexes")}
        </button>
        <Show when={reportsLoading()}>
          <p role="status">{t("app.loading")}</p>
        </Show>
        <ErrorBanner message={reportError()} />
        <Show when={reports()}>
          {(value) => (
            <>
              <Show when={value().truncated}>
                <p role="status" class="my-2 text-sm">
                  {t("firestore.queryIndexTruncated", { count: value().dropped })}
                </p>
              </Show>
              <Show when={value().missingIndexes.length === 0}>
                <p>{t("firestore.queryIndexEmpty")}</p>
              </Show>
              <For each={value().missingIndexes}>
                {(entry) => (
                  <div class="my-2">
                    <p class="text-sm">{entry.message}</p>
                    <pre class="mono max-h-48 overflow-auto text-xs">
                      {JSON.stringify(entry.index, null, 2)}
                    </pre>
                  </div>
                )}
              </For>
            </>
          )}
        </Show>
      </section>
    </section>
  );
};

export default FirestoreQuery;
