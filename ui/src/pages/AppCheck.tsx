import { createResource, createSignal, For, onCleanup, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import {
  AsyncButton,
  ConfirmButton,
  CopyField,
  ErrorBanner,
  Field,
  Section,
  Spinner,
} from "../components/common";
import { errorOf, settle } from "../api/client";
import {
  appCheckObservations,
  appCheckSummary,
  createDebugToken,
  deleteDebugToken,
  listDebugTokens,
  type AppCheckApp,
} from "../api/appcheck";
import { canonicalDebugSecret, counterTotals } from "../lib/appCheck";

const modeBadge = (mode: string): string => {
  if (mode === "enforced") {
    return "badge bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100";
  }
  if (mode === "unenforced") {
    return "badge bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100";
  }
  return "badge bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
};

const outcomeBadge = (admitted: boolean): string =>
  admitted
    ? "badge bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100"
    : "badge bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200";

/**
 * The App Check page: what this runtime enforces, which apps it knows, the debug tokens
 * registered against them and what it observed.
 *
 * The raw debug secret of a creation lives in one signal, is rendered once, and is dropped
 * when the page is left or the reader dismisses it. It is never written to storage, never
 * put in the URL and never sent anywhere else: the daemon keeps only its digest and cannot
 * show it again.
 */
const AppCheck: Component = () => {
  const [summary, { refetch: refetchSummary }] = createResource(
    () => appState.project(),
    (project) => settle(appCheckSummary(project)),
  );
  const value = () => summary()?.unwrapOr(null) ?? null;
  const enabled = () => value()?.enabled ?? appState.config().appCheckEnabled;
  const apps = (): AppCheckApp[] => value()?.apps ?? [];

  const [picked, setPicked] = createSignal<string>("");
  const selected = (): AppCheckApp | null =>
    apps().find((a) => a.appId === picked()) ?? apps()[0] ?? null;

  const [tokens, { refetch: refetchTokens }] = createResource(
    () => {
      const app = selected();
      return app ? { project: app.projectId, appId: app.appId } : null;
    },
    (key) => settle(listDebugTokens(key.project, key.appId)),
  );

  const [observed, { refetch: refetchObservations }] = createResource(
    () => appState.session(),
    (session) => settle(appCheckObservations(session)),
  );

  const [displayName, setDisplayName] = createSignal("");
  const [generate, setGenerate] = createSignal(true);
  const [draft, setDraft] = createSignal("");
  const [secret, setSecret] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  // The secret exists in this page and nowhere else; leaving the page ends it.
  onCleanup(() => setSecret(null));

  const create = async () => {
    setError(null);
    const app = selected();
    if (!app) {
      return;
    }
    let supplied: string | null = null;
    if (!generate()) {
      const parsed = canonicalDebugSecret(draft());
      if (parsed.isErr()) {
        setError(t("appCheck.secretInvalid"));
        return;
      }
      supplied = parsed.value;
    }
    const result = await createDebugToken(
      app.projectId,
      app.appId,
      displayName().trim() || t("appCheck.manage"),
      supplied,
    );
    result.match(
      (created) => {
        setSecret(created.debugToken);
        setDraft("");
        setDisplayName("");
        void refetchTokens();
        void refetchSummary();
      },
      (e) => setError(e.message),
    );
  };

  const remove = async (tokenId: string) => {
    setError(null);
    const app = selected();
    if (!app) {
      return;
    }
    const result = await deleteDebugToken(app.projectId, app.appId, tokenId);
    result.match(
      () => {
        void refetchTokens();
        void refetchSummary();
      },
      (e) => setError(e.message),
    );
  };

  const counters = () => observed()?.unwrapOr(null)?.counters ?? [];
  // Newest first: the ring the daemon keeps is oldest first.
  const observations = () => (observed()?.unwrapOr(null)?.observations ?? []).toReversed();

  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("appCheck.title")}</h1>
      <ErrorBanner message={error() ?? errorOf(summary())} />
      <Show
        when={enabled()}
        fallback={
          <div
            class="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm dark:bg-amber-900/30"
            data-testid="appcheck-disabled"
          >
            {t("appCheck.disabled")}
          </div>
        }
      >
        <Section
          title={t("appCheck.configuration")}
          actions={
            <AsyncButton
              onClick={async () => {
                await refetchSummary();
              }}
              testId="appcheck-refresh-config"
            >
              {t("app.refresh")}
            </AsyncButton>
          }
        >
          <Show when={!summary.loading} fallback={<Spinner />}>
            <div class="mb-3 grid gap-3 sm:grid-cols-2">
              <Field label={t("appCheck.kid")} mono>
                <span data-testid="appcheck-kid">{value()?.kid ?? t("app.none")}</span>
              </Field>
              <Field label={t("appCheck.tokenTtl")}>
                {value()?.tokenTtlSeconds ?? 0} {t("appCheck.seconds")}
              </Field>
            </div>
            <div class="label mb-1">{t("appCheck.modes")}</div>
            <table class="table mb-2" data-testid="appcheck-mode-table">
              <thead>
                <tr>
                  <th>{t("appCheck.service")}</th>
                  <th>{t("appCheck.mode")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={value()?.modes ?? []}>
                  {(row) => (
                    <tr>
                      <td>{row.service}</td>
                      <td>
                        <span class={modeBadge(row.mode)}>{row.mode}</span>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            <p class="text-xs text-zinc-500">{t("appCheck.functionsNote")}</p>
          </Show>
        </Section>

        <Section title={t("appCheck.apps")}>
          <Show when={apps().length > 0} fallback={<p class="text-sm">{t("appCheck.noApps")}</p>}>
            <table class="table" data-testid="appcheck-app-table">
              <thead>
                <tr>
                  <th>{t("appCheck.appId")}</th>
                  <th>{t("appCheck.projectNumber")}</th>
                  <th>{t("appCheck.appEnabled")}</th>
                  <th>{t("appCheck.staticDigests")}</th>
                  <th>{t("appCheck.dynamicTokens")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={apps()}>
                  {(app) => (
                    <tr>
                      <td class="mono">{app.appId}</td>
                      <td class="mono">{app.projectNumber}</td>
                      <td>{app.enabled ? t("app.yes") : t("app.no")}</td>
                      <td>{app.staticDigestCount}</td>
                      <td>{app.dynamicTokenCount}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        </Section>

        <Show when={selected()}>
          {(app) => (
            <Section
              title={t("appCheck.manage")}
              actions={
                <AsyncButton
                  onClick={async () => {
                    await refetchTokens();
                  }}
                  testId="appcheck-refresh-tokens"
                >
                  {t("app.refresh")}
                </AsyncButton>
              }
            >
              <label class="label" for="appcheck-app">
                {t("appCheck.selectedApp")}
              </label>
              <select
                id="appcheck-app"
                class="input mb-3"
                value={app().appId}
                onChange={(e) => setPicked(e.currentTarget.value)}
              >
                <For each={apps()}>{(a) => <option value={a.appId}>{a.appId}</option>}</For>
              </select>

              <Show when={secret()}>
                {(shown) => (
                  <div
                    class="mb-3 rounded-md border border-amber-400 bg-amber-50 p-3 dark:bg-amber-900/30"
                    role="alert"
                  >
                    <div class="mb-1 text-sm font-semibold">{t("appCheck.secretOnce")}</div>
                    <p class="mb-2 text-xs">{t("appCheck.secretWarning")}</p>
                    <CopyField
                      label={t("appCheck.secretInput")}
                      value={shown()}
                      testId="appcheck-secret"
                    />
                    <button
                      type="button"
                      class="btn"
                      data-testid="appcheck-secret-dismiss"
                      onClick={() => setSecret(null)}
                    >
                      {t("appCheck.secretDismiss")}
                    </button>
                  </div>
                )}
              </Show>

              <div class="mb-3 grid items-end gap-2 sm:grid-cols-3">
                <div>
                  <label class="label" for="appcheck-token-name">
                    {t("appCheck.displayName")}
                  </label>
                  <input
                    id="appcheck-token-name"
                    class="input"
                    value={displayName()}
                    onInput={(e) => setDisplayName(e.currentTarget.value)}
                  />
                </div>
                <div>
                  <label class="label" for="appcheck-secret-input">
                    {t("appCheck.secretInput")}
                  </label>
                  <input
                    id="appcheck-secret-input"
                    class="input mono"
                    autocomplete="off"
                    spellcheck={false}
                    disabled={generate()}
                    value={draft()}
                    onInput={(e) => setDraft(e.currentTarget.value)}
                  />
                </div>
                <div class="flex items-center gap-2">
                  <label class="flex items-center gap-1 text-sm">
                    <input
                      id="appcheck-generate"
                      type="checkbox"
                      checked={generate()}
                      onChange={(e) => setGenerate(e.currentTarget.checked)}
                    />
                    {t("appCheck.generate")}
                  </label>
                  <AsyncButton class="btn btn-primary" onClick={create} testId="appcheck-create">
                    {t("appCheck.createToken")}
                  </AsyncButton>
                </div>
              </div>

              <Show when={!tokens.loading} fallback={<Spinner />}>
                <Show
                  when={(tokens()?.unwrapOr(null)?.debugTokens ?? []).length > 0}
                  fallback={<p class="text-sm">{t("appCheck.noDebugTokens")}</p>}
                >
                  <table class="table" data-testid="appcheck-token-table">
                    <thead>
                      <tr>
                        <th>{t("appCheck.tokenId")}</th>
                        <th>{t("appCheck.displayName")}</th>
                        <th>{t("appCheck.created")}</th>
                        <th>{t("appCheck.digestPrefix")}</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      <For each={tokens()?.unwrapOr(null)?.debugTokens ?? []}>
                        {(record) => (
                          <tr>
                            <td class="mono">{record.tokenId}</td>
                            <td>{record.displayName}</td>
                            <td class="mono">{record.createdAt}</td>
                            <td class="mono">{record.digestPrefix}</td>
                            <td>
                              <ConfirmButton
                                label={t("appCheck.deleteToken")}
                                question={t("appCheck.deleteTokenConfirm", {
                                  name: record.displayName,
                                })}
                                onConfirm={() => remove(record.tokenId)}
                                testId={`appcheck-delete-${record.tokenId}`}
                              />
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </Show>
              </Show>
            </Section>
          )}
        </Show>

        <Section
          title={t("appCheck.observations")}
          actions={
            <AsyncButton
              onClick={async () => {
                await refetchObservations();
              }}
              testId="appcheck-refresh-observations"
            >
              {t("app.refresh")}
            </AsyncButton>
          }
        >
          <ErrorBanner message={errorOf(observed())} />
          <div class="mb-3 flex gap-4 text-sm">
            <span>
              {t("appCheck.admitted")}:{" "}
              <span data-testid="appcheck-admitted">{counterTotals(counters()).admitted}</span>
            </span>
            <span>
              {t("appCheck.denied")}:{" "}
              <span data-testid="appcheck-denied">{counterTotals(counters()).denied}</span>
            </span>
          </div>
          <div class="label mb-1">{t("appCheck.counters")}</div>
          <Show
            when={counters().length > 0}
            fallback={<p class="mb-3 text-sm">{t("appCheck.noCounters")}</p>}
          >
            <table class="table mb-4" data-testid="appcheck-counter-table">
              <thead>
                <tr>
                  <th>{t("appCheck.service")}</th>
                  <th>{t("appCheck.appId")}</th>
                  <th>{t("appCheck.function")}</th>
                  <th>{t("appCheck.category")}</th>
                  <th>{t("appCheck.outcome")}</th>
                  <th>{t("appCheck.count")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={counters()}>
                  {(row) => (
                    <tr>
                      <td>{row.service}</td>
                      <td class="mono">{row.appId}</td>
                      <td class="mono">{row.function ?? ""}</td>
                      <td>{row.category}</td>
                      <td>
                        <span class={outcomeBadge(row.outcome === "admitted")}>{row.outcome}</span>
                      </td>
                      <td>{row.count}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
          <div class="label mb-1">{t("appCheck.recent")}</div>
          <Show
            when={observations().length > 0}
            fallback={<p class="text-sm">{t("appCheck.noObservations")}</p>}
          >
            <div class="max-h-96 overflow-y-auto">
              <table class="table" data-testid="appcheck-observation-table">
                <thead>
                  <tr>
                    <th>{t("appCheck.at")}</th>
                    <th>{t("appCheck.service")}</th>
                    <th>{t("appCheck.transport")}</th>
                    <th>{t("appCheck.operation")}</th>
                    <th>{t("appCheck.mode")}</th>
                    <th>{t("appCheck.category")}</th>
                    <th>{t("appCheck.appId")}</th>
                    <th>{t("appCheck.reason")}</th>
                    <th>{t("appCheck.outcome")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={observations()}>
                    {(row) => (
                      <tr>
                        <td class="mono">{row.at}</td>
                        <td>{row.service}</td>
                        <td>{row.transport}</td>
                        <td class="mono">{row.operation}</td>
                        <td>
                          <span class={modeBadge(row.mode)}>{row.mode}</span>
                        </td>
                        <td>{row.category}</td>
                        <td class="mono">{row.appId}</td>
                        <td class="mono">{row.reason ?? ""}</td>
                        <td>
                          <span class={outcomeBadge(row.admitted)}>
                            {row.admitted ? t("appCheck.admitted") : t("appCheck.denied")}
                          </span>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
          <p class="mt-2 text-xs text-zinc-500">{t("appCheck.ringNote")}</p>
        </Section>
      </Show>
    </div>
  );
};

export default AppCheck;
