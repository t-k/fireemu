import { createEffect, createSignal, For, Show, onCleanup, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import {
  AsyncButton,
  ConfirmButton,
  ErrorBanner,
  FetchState,
  Notice,
  Section,
} from "../components/common";
import {
  dropRules,
  getRules,
  putRules,
  ruleCoverage,
  rulesRequests,
  type RulesExprValue,
  type RulesRequest,
  type RuleCoverage,
} from "../api/control";
import { coverageRows, coverageSummary, sourceRange } from "../lib/coverage";
import { createLeaveGuard, LeavePrompt } from "../lib/unsaved";
import { settle } from "../api/client";
import { createScopedFetch } from "../lib/rules-state";

/** The editor is daemon-shared; scope remounts still discard session-owned drafts and callbacks. */
const RulesEditor: Component<{ which: "firestore" | "storage"; title: string; scope: string }> = (
  props,
) => {
  const info = createScopedFetch(
    () => props.scope,
    () => settle(getRules(props.which)),
  );
  const [draft, setDraft] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  let alive = true;
  let revision = 0;
  let mutation = 0;
  onCleanup(() => {
    alive = false;
    mutation++;
  });
  const source = () => draft() ?? info.data()?.source ?? "";
  const dirty = () => draft() !== null && draft() !== (info.data()?.source ?? "");
  const guard = createLeaveGuard(dirty);
  const save = async () => {
    const submitted = source();
    const atRevision = revision;
    const mine = ++mutation;
    setError(null);
    setNotice(null);
    const result = await putRules(props.which, submitted);
    if (!alive || mine !== mutation) return;
    result.match(
      () => {
        info.replace({ loaded: true, source: submitted });
        if (revision === atRevision) setDraft(null);
        setNotice(t("rules.saved"));
        void info.refetch();
      },
      (e) => setError(e.message),
    );
  };
  const drop = async () => {
    const atRevision = revision;
    const mine = ++mutation;
    setError(null);
    setNotice(null);
    const result = await dropRules(props.which);
    if (!alive || mine !== mutation) return;
    result.match(
      () => {
        info.replace({ loaded: false, source: "" });
        if (revision === atRevision) setDraft(null);
        void info.refetch();
      },
      (e) => setError(e.message),
    );
  };
  return (
    <Section
      title={props.title}
      actions={
        <>
          <Show when={info.data()}>
            <span class="badge">
              {info.data()?.loaded ? t("rules.loaded") : t("rules.notLoaded")}
            </span>
          </Show>
          <AsyncButton class="btn" onClick={info.refetch} testId={`rules-${props.which}-refresh`}>
            {t("rules.refresh")}
          </AsyncButton>
          <AsyncButton class="btn btn-primary" onClick={save} testId={`rules-${props.which}-save`}>
            {t("rules.replace")}
          </AsyncButton>
          <ConfirmButton
            label={t("rules.drop")}
            question={t("rules.dropConfirm", { which: props.which })}
            onConfirm={drop}
            testId={`rules-${props.which}-drop`}
          />
        </>
      }
    >
      <LeavePrompt guard={guard} subject={t("rules.editorSubject", { which: props.which })} />
      <p class="mb-2 text-sm">{t("rules.daemonShared")}</p>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <FetchState
        loading={info.loading() && info.data() === undefined}
        error={info.data() === undefined ? info.error() : null}
        stale={info.data() !== undefined ? info.error() : null}
        onRetry={info.refetch}
      >
        <Show when={info.loading()}>
          <p role="status">{t("rules.refreshing")}</p>
        </Show>
        <label class="label" for={`rules-${props.which}`}>
          {dirty() ? t("rules.draftSource") : t("rules.currentSource")}
        </label>
        <textarea
          id={`rules-${props.which}`}
          class="input mono h-72"
          spellcheck={false}
          value={source()}
          onInput={(e) => {
            revision++;
            setDraft(e.currentTarget.value);
          }}
        />
      </FetchState>
    </Section>
  );
};

/** Value outcomes are independent of the request's allow/deny outcome. */
const describe = (value: RulesExprValue): string => {
  switch (value.kind) {
    case "bool":
      return String(value.bool);
    case "int":
      return value.int ?? "";
    case "float":
      return String(value.float);
    case "string":
      return JSON.stringify(value.string ?? "");
    case "composite":
      return value.type ?? "value";
    case "undefined":
      return `${t("rules.evaluationError")}: undefined: ${value.cause?.message ?? ""}`;
    default:
      return "null";
  }
};

type Position = { currentOffset: number; endOffset: number };
const sameRange = (selected: Position | null, candidate: Position): boolean =>
  selected !== null &&
  selected.currentOffset === candidate.currentOffset &&
  selected.endOffset === candidate.endOffset;
/** A read-only pre preserves CRLF and UTF-16 exactly; no textarea newline normalization. */
const RecordedSource: Component<{
  source: string | null | undefined;
  position: Position | null;
  testId: string;
  identity: string;
  unavailable?: boolean;
}> = (props) => {
  let highlighted: HTMLElement | undefined;
  const range = () =>
    props.position && typeof props.source === "string" && !props.unavailable
      ? sourceRange(props.source, props.position.currentOffset, props.position.endOffset)
      : null;
  createEffect(() => {
    if (range())
      queueMicrotask(
        () => highlighted?.isConnected && highlighted.scrollIntoView?.({ block: "nearest" }),
      );
  });
  return (
    <div class="mt-3">
      <h3 class="font-semibold">{t("rules.recordedSource")}</h3>
      <p class="text-sm">{props.identity}</p>
      <Show
        when={typeof props.source === "string" && !props.unavailable}
        fallback={<p role="status">{t("rules.sourceUnavailable")}</p>}
      >
        <p class="text-sm">{t("rules.navigationHelp")}</p>
        <Show when={props.position && !range()}>
          <p role="status">{t("rules.rangeUnavailable")}</p>
        </Show>
        <pre
          class="mono max-h-80 overflow-auto whitespace-pre-wrap rounded border p-3"
          tabIndex={0}
          aria-label={t("rules.recordedSource")}
          data-testid={`${props.testId}-source`}
        >
          <Show when={range()} fallback={props.source}>
            {(r) => (
              <>
                {props.source!.slice(0, r().start)}
                <mark
                  class="bg-amber-200 text-black outline outline-2 outline-amber-700"
                  data-testid={`${props.testId}-highlight`}
                  ref={(node) => {
                    highlighted = node;
                  }}
                >
                  {props.source!.slice(r().start, r().end)}
                </mark>
                {props.source!.slice(r().end)}
              </>
            )}
          </Show>
        </pre>
      </Show>
    </div>
  );
};

/** Native buttons support Tab/Enter/Space; arrows/Home/End move and select expressions. */
const moveExpression = (event: KeyboardEvent) => {
  const button = event.currentTarget as HTMLButtonElement;
  const buttons = Array.from(
    button.closest("tbody")?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? [],
  );
  const index = buttons.indexOf(button);
  const next =
    event.key === "Home"
      ? 0
      : event.key === "End"
        ? buttons.length - 1
        : event.key === "ArrowDown"
          ? Math.min(index + 1, buttons.length - 1)
          : event.key === "ArrowUp"
            ? Math.max(index - 1, 0)
            : -1;
  if (next >= 0) {
    event.preventDefault();
    buttons[next]?.focus();
    buttons[next]?.click();
  }
};

const RulesRequestsPanel: Component<{ scope: string; session: string }> = (props) => {
  const list = createScopedFetch(
    () => props.scope,
    () => settle(rulesRequests(props.session)),
  );
  const [selected, setSelected] = createSignal<string | null>(null);
  const [position, setPosition] = createSignal<Position | null>(null);
  const requests = () => list.data()?.requests ?? [];
  const identity = (r: RulesRequest) =>
    JSON.stringify([props.scope, r.service, list.data()?.generation ?? null, r.sequence]);
  const current = () => requests().find((r) => identity(r) === selected());
  const sourceAvailable = () =>
    current()?.service === "firestore" &&
    typeof list.data()?.source === "string" &&
    typeof list.data()?.generation === "string" &&
    /^\d+$/.test(list.data()!.generation!);
  createEffect(() => {
    if (!current()) {
      setSelected(null);
      setPosition(null);
    }
  });
  return (
    <Section
      title={t("rules.requests")}
      actions={
        <AsyncButton class="btn" onClick={list.refetch} testId="rules-requests-refresh">
          {t("rules.refresh")}
        </AsyncButton>
      }
    >
      <FetchState
        loading={list.loading() && list.data() === undefined}
        error={list.data() === undefined ? list.error() : null}
        stale={list.data() !== undefined ? list.error() : null}
        onRetry={list.refetch}
      >
        <Show when={list.loading()}>
          <p role="status">{t("rules.refreshing")}</p>
        </Show>
        <Show when={list.data()?.loaded} fallback={<p>{t("rules.notLoaded")}</p>}>
          <Show when={requests().length > 0} fallback={<p>{t("rules.requestsNone")}</p>}>
            <table class="table" data-testid="rules-requests">
              <thead>
                <tr>
                  <th>{t("rules.method")}</th>
                  <th>{t("rules.path")}</th>
                  <th>{t("rules.uid")}</th>
                  <th>{t("rules.decision")}</th>
                  <th>{t("rules.trace")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={requests()}>
                  {(r) => (
                    <tr>
                      <td class="mono">
                        {r.method} ({r.service})
                      </td>
                      <td class="mono">{r.path}</td>
                      <td class="mono">{r.uid ?? "-"}</td>
                      <td>
                        <span class="badge">
                          {r.allowed ? t("rules.allowed") : t("rules.denied")}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          class="btn"
                          aria-expanded={selected() === identity(r)}
                          data-testid={`rules-request-trace-${r.sequence}`}
                          onClick={() => {
                            setSelected(selected() === identity(r) ? null : identity(r));
                            setPosition(null);
                          }}
                        >
                          {t("rules.trace")}
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            <Show when={current()}>
              {(r) => (
                <>
                  <p class="mt-3">
                    {t("rules.decision")}: {r().allowed ? t("rules.allowed") : t("rules.denied")} —{" "}
                    {r().reason || t("rules.noReason")}
                  </p>
                  <table class="table mt-3" data-testid="rules-request-expressions">
                    <thead>
                      <tr>
                        <th>{t("rules.position")}</th>
                        <th>{t("rules.values")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={r().expressions}>
                        {(e, index) => (
                          <tr>
                            <td>
                              <button
                                type="button"
                                class="btn mono"
                                disabled={
                                  !sourceAvailable() ||
                                  sourceRange(
                                    list.data()!.source!,
                                    e.currentOffset,
                                    e.endOffset,
                                  ) === null
                                }
                                aria-pressed={sameRange(position(), e)}
                                data-testid={`rules-request-expression-${index()}`}
                                onKeyDown={moveExpression}
                                onClick={() => setPosition(e)}
                              >
                                {e.line}:{e.column}
                              </button>
                              <Show
                                when={
                                  sourceAvailable() &&
                                  sourceRange(
                                    list.data()!.source!,
                                    e.currentOffset,
                                    e.endOffset,
                                  ) === null
                                }
                              >
                                <span class="text-sm">{t("rules.rangeUnavailable")}</span>
                              </Show>
                            </td>
                            <td class="mono">
                              {e.values.length
                                ? e.values.map((v) => `${describe(v.value)} ×${v.count}`).join(", ")
                                : t("rules.unreached")}
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                  <RecordedSource
                    source={list.data()?.source}
                    unavailable={!sourceAvailable()}
                    position={position()}
                    testId="rules-request"
                    identity={t("rules.traceIdentity", {
                      service: r().service,
                      generation: list.data()?.generation ?? "?",
                      sequence: r().sequence,
                    })}
                  />
                </>
              )}
            </Show>
          </Show>
        </Show>
      </FetchState>
    </Section>
  );
};

const RulesCoveragePanel: Component<{ scope: string; project: string }> = (props) => {
  const cov = createScopedFetch(
    () => props.scope,
    () => settle(ruleCoverage(props.project)),
  );
  const [selection, setSelection] = createSignal<{
    snapshot: RuleCoverage;
    position: Position;
  } | null>(null);
  // The range belongs to its complete coverage response, even before effects clear old selection.
  const position = () =>
    selection()?.snapshot === cov.data() ? (selection()?.position ?? null) : null;
  const setPosition = (position: Position | null) =>
    setSelection(position && cov.data() ? { snapshot: cov.data()!, position } : null);
  const rows = () => (cov.data() ? coverageRows(cov.data()!.report) : []);
  const summary = () => (cov.data() ? coverageSummary(cov.data()!) : { reached: 0, total: 0 });
  const file = () =>
    cov.data()?.rules.files.length === 1 ? cov.data()!.rules.files[0] : undefined;
  createEffect(() => {
    cov.data();
    setPosition(null);
  });
  return (
    <Section
      title={t("rules.coverage")}
      actions={
        <AsyncButton class="btn" onClick={cov.refetch} testId="rules-coverage-refresh">
          {t("rules.refresh")}
        </AsyncButton>
      }
    >
      <FetchState
        loading={cov.loading() && cov.data() === undefined}
        error={cov.data() === undefined ? cov.error() : null}
        stale={cov.data() !== undefined ? cov.error() : null}
        onRetry={cov.refetch}
      >
        <Show when={cov.loading()}>
          <p role="status">{t("rules.refreshing")}</p>
        </Show>
        <Show
          when={(cov.data()?.rules.files.length ?? 0) > 0}
          fallback={<p>{t("rules.coverageUnconfigured")}</p>}
        >
          <Show when={rows().length > 0} fallback={<p>{t("rules.coverageNone")}</p>}>
            <p class="mb-2" data-testid="rules-coverage-summary">
              {t("rules.coverageReached", summary())}
            </p>
            <table class="table" data-testid="rules-coverage">
              <thead>
                <tr>
                  <th>{t("rules.position")}</th>
                  <th>{t("rules.values")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={rows()}>
                  {(row, index) => (
                    <tr>
                      <td>
                        <button
                          type="button"
                          class="btn mono"
                          disabled={
                            !file() ||
                            sourceRange(file()!.content, row.currentOffset, row.endOffset) === null
                          }
                          aria-pressed={sameRange(position(), row)}
                          data-testid={`rules-coverage-expression-${index()}`}
                          onKeyDown={moveExpression}
                          onClick={() => setPosition(row)}
                        >
                          {row.line}:{row.column}
                        </button>
                        <Show
                          when={
                            file() &&
                            sourceRange(file()!.content, row.currentOffset, row.endOffset) === null
                          }
                        >
                          <span class="text-sm">{t("rules.rangeUnavailable")}</span>
                        </Show>
                      </td>
                      <td class="mono">{row.summary}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            <RecordedSource
              source={file()?.content}
              unavailable={!file()}
              position={position()}
              testId="rules-coverage"
              identity={t("rules.coverageIdentity", { file: file()?.name ?? "?" })}
            />
          </Show>
        </Show>
      </FetchState>
    </Section>
  );
};

const Rules: Component = () => {
  const scope = () => JSON.stringify([appState.session(), appState.project()]);
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("rules.title")}</h1>
      <Show when={!appState.config().rulesEnforced}>
        <div class="mb-4 rounded-md border border-amber-400 p-3 text-sm">
          {t("rules.enforcedOff")}
        </div>
      </Show>
      <Show when={scope()} keyed>
        {(key) => {
          const [session, project] = JSON.parse(key) as [string, string];
          return (
            <>
              <RulesEditor which="firestore" title={t("rules.firestore")} scope={key} />
              <RulesEditor which="storage" title={t("rules.storage")} scope={key} />
              <RulesRequestsPanel scope={key} session={session} />
              <RulesCoveragePanel scope={key} project={project} />
            </>
          );
        }}
      </Show>
    </div>
  );
};
export default Rules;
