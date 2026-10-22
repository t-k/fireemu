import { createMemo, createSignal, For, Show, type Component } from "solid-js";
import type {
  FunctionLog,
  FunctionsCausality,
  FunctionCodebase,
  InvocationInfo,
} from "../api/functions";
import { t } from "../i18n";
import { buildTimeline } from "../lib/functionsTimeline";
import { Section } from "./common";

export const FunctionsTimeline: Component<{
  project: string;
  session: string;
  causality?: FunctionsCausality | undefined;
  codebases: FunctionCodebase[];
  invocations: InvocationInfo[];
  logs: FunctionLog[];
  logGaps: boolean;
  stale: boolean;
}> = (props) => {
  const events = createMemo(() =>
    buildTimeline(
      props.project,
      props.causality?.events ?? [],
      props.invocations,
      props.logs,
      props.codebases,
    ),
  );
  const byKey = createMemo(() => new Map(events().map((event) => [event.key, event])));
  const [selection, setSelection] = createSignal("");
  const [source, setSource] = createSignal("");
  const [status, setStatus] = createSignal("");
  const [eventId, setEventId] = createSignal("");
  const [fn, setFn] = createSignal("");
  const [attempt, setAttempt] = createSignal("");
  const selected = () => byKey().get(selection());
  const sources = createMemo(() =>
    [...new Set(events().flatMap((e) => (e.causal ? [e.causal.source] : [])))].toSorted(),
  );
  const phases = createMemo(() =>
    [...new Set(events().flatMap((e) => e.causal?.phases.map((p) => p.phase) ?? []))].toSorted(),
  );
  const names = createMemo(() => [...new Set(events().map((e) => e.function))].toSorted());
  const visible = createMemo(() =>
    events()
      .filter(
        (e) =>
          (!source() || e.causal?.source === source()) &&
          (!status() || e.causal?.phases.at(-1)?.phase === status()) &&
          (!fn() || e.function === fn()) &&
          e.eventId.includes(eventId()),
      )
      .map((e) => e.key),
  );
  const attempts = createMemo(() =>
    [
      ...new Set([
        ...(selected()?.causal?.phases.map((p) => p.attempt) ?? []),
        ...(selected()?.outcomes.map((r) => r.attempt) ?? []),
      ]),
    ].toSorted((a, b) => a - b),
  );
  const selectedPhases = createMemo(
    () =>
      selected()?.causal?.phases.filter((p) => !attempt() || p.attempt === Number(attempt())) ?? [],
  );
  const outcomes = createMemo(
    () => selected()?.outcomes.filter((r) => !attempt() || r.attempt === Number(attempt())) ?? [],
  );
  const logs = createMemo(
    () =>
      selected()?.logs.filter(
        (r) => !attempt() || r.invocationId === `${selected()?.eventId}-${attempt()}`,
      ) ?? [],
  );
  const logOutput = createMemo(() =>
    logs()
      .map((r) => `[${r.codebase} / ${r.runner} / ${r.cursor}] ${r.line}`)
      .join("\n"),
  );
  const ungrouped = createMemo(
    () => props.logs.length - events().reduce((n, e) => n + e.logs.length, 0),
  );
  return (
    <Section title={t("functions.timeline")}>
      <p class="mb-2 text-sm" data-testid="timeline-owner">
        {t("functions.timelineOwner", { session: props.session, project: props.project })}
      </p>
      <Show when={props.stale}>
        <p role="status" class="mb-2 text-sm text-amber-800 dark:text-amber-200">
          {t("functions.timelineStale")}
        </p>
      </Show>
      <p class="mb-2 text-xs text-zinc-500" data-testid="timeline-retention">
        {t("functions.timelineGaps", {
          retained: props.causality?.retained ?? 0,
          retention: props.causality?.retention ?? 0,
          evicted: props.causality?.evicted ?? 0,
          resets: props.causality?.resetGaps ?? 0,
        })}
      </p>
      <Show when={props.causality?.truncated}>
        <p class="mb-2 text-sm">{t("functions.timelineProjection")}</p>
      </Show>
      <div class="mb-3 flex flex-wrap gap-2">
        <label class="text-sm">
          {t("functions.timelineEventFilter")}
          <input
            class="input block"
            value={eventId()}
            onInput={(e) => setEventId(e.currentTarget.value)}
          />
        </label>
        <label class="text-sm">
          {t("functions.filterFunction")}
          <select class="input block" value={fn()} onInput={(e) => setFn(e.currentTarget.value)}>
            <option value="">{t("functions.allFunctions")}</option>
            <For each={names()}>{(name) => <option value={name}>{name}</option>}</For>
          </select>
        </label>
        <label class="text-sm">
          {t("functions.timelineSourceFilter")}
          <select
            class="input block"
            value={source()}
            onInput={(e) => setSource(e.currentTarget.value)}
          >
            <option value="">{t("functions.timelineAllSources")}</option>
            <For each={sources()}>{(name) => <option value={name}>{name}</option>}</For>
          </select>
        </label>
        <label class="text-sm">
          {t("functions.timelineStatusFilter")}
          <select
            class="input block"
            value={status()}
            onInput={(e) => setStatus(e.currentTarget.value)}
          >
            <option value="">{t("functions.timelineAllStatuses")}</option>
            <For each={phases()}>{(name) => <option value={name}>{name}</option>}</For>
          </select>
        </label>
      </div>
      <Show
        when={events().length > 0}
        fallback={
          <p data-testid="timeline-empty" class="text-sm text-zinc-500">
            {t("functions.timelineEmpty")}
          </p>
        }
      >
        <Show
          when={visible().length > 0}
          fallback={<p class="text-sm">{t("functions.timelineNoMatch")}</p>}
        >
          <div class="max-h-64 overflow-auto">
            <table class="table" data-testid="event-timeline">
              <caption class="sr-only">{t("functions.timeline")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("functions.eventId")}</th>
                  <th scope="col">{t("functions.name")}</th>
                  <th scope="col">{t("functions.timelineSource")}</th>
                  <th scope="col">{t("functions.timelinePhase")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={visible()}>
                  {(key) => (
                    <tr>
                      <td>
                        <button
                          type="button"
                          class="btn mono text-xs focus-visible:outline-2 focus-visible:outline-offset-2"
                          aria-pressed={selection() === key}
                          aria-label={t("functions.timelineSelect", {
                            event: byKey().get(key)!.eventId,
                            function: byKey().get(key)!.function,
                          })}
                          onClick={() => {
                            setSelection(key);
                            setAttempt("");
                          }}
                        >
                          {byKey().get(key)!.eventId}
                        </button>
                      </td>
                      <td class="mono text-xs">{byKey().get(key)!.function}</td>
                      <td>{byKey().get(key)!.causal?.source ?? "—"}</td>
                      <td>{byKey().get(key)!.causal?.phases.at(-1)?.phase ?? "—"}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>
      <Show when={selection()}>
        <div
          class="mt-4 rounded-md border border-zinc-200 p-3 dark:border-zinc-700"
          data-testid="timeline-detail"
        >
          <button type="button" class="btn mb-2" onClick={() => setSelection("")}>
            {t("functions.timelineClearSelection")}
          </button>
          <Show
            when={selected()}
            fallback={<p role="status">{t("functions.timelineMissingSelection")}</p>}
          >
            <h3 class="mb-2 font-semibold">
              {t("functions.eventId")} {selected()?.eventId} / {selected()?.function}
            </h3>
            <Show when={selected()?.synthetic}>
              <p>{t("functions.timelineSynthetic")}</p>
            </Show>
            <Show
              when={selected()?.causal}
              fallback={
                <>
                  <p class="mb-2 text-sm">{t("functions.timelineUnavailable")}</p>
                  <p class="mb-2 text-xs text-zinc-500">{t("functions.timelineUnknownEpoch")}</p>
                </>
              }
            >
              <dl class="mb-3 grid grid-cols-2 gap-1 text-sm">
                <dt>{t("functions.timelineEventType")}</dt>
                <dd class="break-all mono">{selected()?.causal?.eventType}</dd>
                <dt>{t("functions.timelineParent")}</dt>
                <dd class="break-all mono">{selected()?.causal?.parent ?? "—"}</dd>
              </dl>
              <p class="mb-2 text-xs">
                {t("functions.timelineEpoch", { epoch: selected()?.causal?.epoch ?? 0 })}
              </p>
              <Show when={(selected()?.causal?.phasesDropped ?? 0) > 0}>
                <p class="mb-2 text-sm">
                  {t("functions.timelinePhaseGaps", {
                    count: selected()?.causal?.phasesDropped ?? 0,
                  })}
                </p>
              </Show>
              <Show when={selected()?.causal?.phases.at(-1)?.phase === "registered"}>
                <p class="mb-2 text-sm">{t("functions.timelinePending")}</p>
              </Show>
            </Show>
            <label class="mb-3 block text-sm">
              {t("functions.timelineAttemptFilter")}
              <select
                class="input ml-2"
                value={attempt()}
                onInput={(e) => setAttempt(e.currentTarget.value)}
              >
                <option value="">{t("functions.timelineAllAttempts")}</option>
                <For each={attempts()}>{(n) => <option value={n}>{n}</option>}</For>
              </select>
            </label>
            <h4 class="mb-1 text-sm font-semibold">{t("functions.timelinePhases")}</h4>
            <ol class="mb-3 list-inside list-decimal text-sm" data-testid="timeline-phases">
              <For each={selectedPhases()}>
                {(p) => (
                  <li>
                    <span class="mono">{p.phase}</span> · {t("functions.attempt")} {p.attempt} ·{" "}
                    {p.at ?? t("functions.timelineUnknownTime")}
                  </li>
                )}
              </For>
            </ol>
            <h4 class="mb-1 text-sm font-semibold">{t("functions.invocations")}</h4>
            <Show
              when={outcomes().length > 0}
              fallback={
                <p class="mb-3 text-sm" data-testid="timeline-no-outcomes">
                  {t("functions.timelineNoOutcomes")}
                </p>
              }
            >
              <ol class="mb-3 list-inside list-decimal text-sm" data-testid="timeline-outcomes">
                <For each={outcomes()}>
                  {(r) => (
                    <li>
                      {t("functions.attempt")} {r.attempt} · <span class="mono">{r.outcome}</span>
                    </li>
                  )}
                </For>
              </ol>
            </Show>
            <h4 class="mb-1 text-sm font-semibold">{t("functions.timelineRelatedLogs")}</h4>
            <p class="mb-1 text-xs text-zinc-500">{t("functions.timelineLogsPartial")}</p>
            <Show when={props.logGaps}>
              <p class="mb-1 text-sm" data-testid="timeline-log-gaps">
                {t("functions.timelineLogGaps")}
              </p>
            </Show>
            <pre
              class="mono max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-zinc-900 p-3 text-xs text-zinc-100"
              tabindex="0"
              aria-label={t("functions.timelineRelatedLogs")}
              data-testid="timeline-logs"
            >
              {logOutput() || t("functions.timelineNoRelatedLogs")}
            </pre>
          </Show>
        </div>
      </Show>
      <p class="mt-2 text-xs text-zinc-500">
        {t("functions.timelineUngroupedLogs", { count: ungrouped() })}
      </p>
    </Section>
  );
};
