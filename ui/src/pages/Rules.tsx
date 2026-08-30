import { createResource, createSignal, For, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import {
  AsyncButton,
  ConfirmButton,
  ErrorBanner,
  Notice,
  Section,
  Spinner,
} from "../components/common";
import { dropRules, getRules, putRules, rulesRequests, type RulesExprValue } from "../api/control";
import { settle } from "../api/client";

const RulesEditor: Component<{ which: "firestore" | "storage"; title: string }> = (props) => {
  const [info, { refetch }] = createResource(() => settle(getRules(props.which)));
  const [draft, setDraft] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const source = () =>
    draft() ??
    info()
      ?.map((i) => i.source)
      .unwrapOr("") ??
    "";
  const loaded = () =>
    info()
      ?.map((i) => i.loaded)
      .unwrapOr(false) ?? false;
  const save = async () => {
    setError(null);
    setNotice(null);
    const result = await putRules(props.which, source());
    result.match(
      () => {
        setNotice(t("rules.saved"));
        setDraft(null);
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  const drop = async () => {
    setError(null);
    const result = await dropRules(props.which);
    result.match(
      () => {
        setDraft(null);
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  return (
    <Section
      title={props.title}
      actions={
        <>
          <span
            class={`badge ${loaded() ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100" : "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"}`}
          >
            {loaded() ? t("rules.loaded") : t("rules.notLoaded")}
          </span>
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
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Show when={!info.loading} fallback={<Spinner />}>
        <label class="label" for={`rules-${props.which}`}>
          {t("rules.source")}
        </label>
        <textarea
          id={`rules-${props.which}`}
          class="input mono h-72"
          spellcheck={false}
          value={source()}
          onInput={(e) => setDraft(e.currentTarget.value)}
        />
      </Show>
    </Section>
  );
};

/** How one recorded value reads in a row: short, and never a whole document. */
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
      return `undefined: ${value.cause?.message ?? ""}`;
    default:
      return "null";
  }
};

/**
 * The requests Security Rules decided, newest first, with what every expression evaluated to.
 * The route is fireemu's own (`GET /v1/sessions/{s}/rules/requests`); it carries no token and
 * no claim other than the subject the rule saw.
 */
const RulesRequestsPanel: Component = () => {
  const session = appState.session;
  const [list, { refetch }] = createResource(session, (s) => settle(rulesRequests(s)));
  const [selected, setSelected] = createSignal<number | null>(null);
  const current = () => list()?.unwrapOr(null) ?? null;
  const requests = () => current()?.requests ?? [];
  const expressions = () => requests().find((r) => r.sequence === selected())?.expressions ?? [];
  return (
    <Section
      title={t("rules.requests")}
      actions={
        <AsyncButton
          class="btn"
          onClick={async () => {
            await refetch();
          }}
          testId="rules-requests-refresh"
        >
          {t("rules.refresh")}
        </AsyncButton>
      }
    >
      <Show when={!list.loading} fallback={<Spinner />}>
        <Show
          when={requests().length > 0}
          fallback={<p class="text-sm text-zinc-500">{t("rules.requestsNone")}</p>}
        >
          <table class="table" data-testid="rules-requests">
            <thead>
              <tr>
                <th>{t("rules.method")}</th>
                <th>{t("rules.path")}</th>
                <th>{t("rules.uid")}</th>
                <th>{t("rules.decision")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={requests()}>
                {(r) => (
                  <tr>
                    <td class="mono">{r.method}</td>
                    <td class="mono">{r.path}</td>
                    <td class="mono">{r.uid ?? "-"}</td>
                    <td>
                      <span
                        class={`badge ${r.allowed ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100" : "bg-rose-100 text-rose-800 dark:bg-rose-900 dark:text-rose-100"}`}
                      >
                        {r.allowed ? t("rules.allowed") : t("rules.denied")}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        class="btn"
                        data-testid={`rules-request-trace-${r.sequence}`}
                        onClick={() => setSelected(selected() === r.sequence ? null : r.sequence)}
                      >
                        {t("rules.trace")}
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
          <Show when={selected() !== null}>
            <table class="table mt-3" data-testid="rules-request-expressions">
              <thead>
                <tr>
                  <th>{t("rules.position")}</th>
                  <th>{t("rules.values")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={expressions()}>
                  {(e) => (
                    <tr>
                      <td class="mono">
                        {e.line}:{e.column}
                      </td>
                      <td class="mono">
                        {e.values.map((v) => `${describe(v.value)} x${v.count}`).join(", ")}
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        </Show>
      </Show>
    </Section>
  );
};

const Rules: Component = () => (
  <div>
    <h1 class="mb-4 text-xl font-bold">{t("rules.title")}</h1>
    <Show when={!appState.config().rulesEnforced}>
      <div class="mb-4 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm dark:bg-amber-900/30">
        {t("rules.enforcedOff")}
      </div>
    </Show>
    <RulesEditor which="firestore" title={t("rules.firestore")} />
    <RulesEditor which="storage" title={t("rules.storage")} />
    <RulesRequestsPanel />
  </div>
);

export default Rules;
