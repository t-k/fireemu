import { createResource, For, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import { Field, Section, Spinner } from "../components/common";
import { getRules } from "../api/control";
import { settle } from "../api/client";
import { productScope, statusLabelKey, type ProductStatus } from "../lib/products";

/** Tailwind classes for a product-scope status badge. */
const statusClass = (status: ProductStatus): string => {
  switch (status) {
    case "supported":
      return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100";
    case "deferred":
      return "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-100";
    case "pendingBackend":
      return "bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-100";
    case "substituted":
      return "bg-violet-100 text-violet-800 dark:bg-violet-900 dark:text-violet-100";
    case "notPlanned":
      return "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  }
};

const Overview: Component = () => {
  const config = appState.config;
  const [firestoreRules] = createResource(() => settle(getRules("firestore")));
  const [storageRules] = createResource(() => settle(getRules("storage")));
  const env = () =>
    [
      `FIRESTORE_EMULATOR_HOST=${config().firestoreAddr}`,
      `FIREBASE_AUTH_EMULATOR_HOST=${config().httpAddr}`,
      `FIREBASE_STORAGE_EMULATOR_HOST=${config().storageAddr}`,
      `STORAGE_EMULATOR_HOST=http://${config().storageAddr}`,
      `GOOGLE_CLOUD_PROJECT=${config().project}`,
      `FIREEMU_CONTROL_URL=http://${config().httpAddr}/v1/`,
      ...(config().functionsAddr ? [`FIREEMU_FUNCTIONS_HOST=${config().functionsAddr}`] : []),
    ].join("\n");
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("overview.title")}</h1>
      <Show when={!config().uiBundled}>
        <div class="mb-4 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm dark:bg-amber-900/30">
          {t("app.notBundled")}
        </div>
      </Show>
      <div class="grid gap-4 md:grid-cols-2">
        <Section title={t("overview.project")}>
          <Field label={t("overview.project")} mono>
            {config().project}
          </Field>
          <Field label={t("overview.edition")}>{config().edition}</Field>
          <Field label={t("overview.version")} mono>
            {config().version}
          </Field>
          <Field label={t("overview.clock")} mono>
            <span data-testid="overview-clock">{appState.clock()}</span>{" "}
            <span class="text-zinc-500">
              ({config().clockPinned ? t("overview.clockPinned") : t("overview.clockWall")})
            </span>
          </Field>
        </Section>
        <Section title={t("overview.services")}>
          <Field label={t("overview.firestore")} mono>
            {config().firestoreAddr}
          </Field>
          <Field label={t("overview.auth")} mono>
            {config().httpAddr}
          </Field>
          <Field label={t("overview.storage")} mono>
            {config().storageAddr}
          </Field>
          <Field label={t("overview.functions")} mono>
            <Show when={config().functionsAddr} fallback={t("overview.functionsNone")}>
              {config().functionsAddr} ({config().functionsSource})
            </Show>
          </Field>
          <Field label={t("overview.control")} mono>
            http://{config().httpAddr}/v1/
          </Field>
          <Field label={t("overview.ui")} mono>
            http://{config().uiAddr}/ui
          </Field>
        </Section>
        <Section title={t("overview.rules")}>
          <Field label={t("overview.rules")}>
            {config().rulesEnforced ? t("overview.rulesEnforced") : t("overview.rulesDisabled")}
          </Field>
          <Field label={t("overview.rulesFirestore")}>
            <Show when={!firestoreRules.loading} fallback={<Spinner />}>
              {firestoreRules()?.unwrapOr(null)?.loaded ? t("app.yes") : t("app.no")}
            </Show>
          </Field>
          <Field label={t("overview.rulesStorage")}>
            <Show when={!storageRules.loading} fallback={<Spinner />}>
              {storageRules()?.unwrapOr(null)?.loaded ? t("app.yes") : t("app.no")}
            </Show>
          </Field>
        </Section>
        <Section title={t("overview.sessions")}>
          <table class="table">
            <thead>
              <tr>
                <th>{t("overview.session")}</th>
                <th>{t("overview.project")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={appState.sessions()}>
                {(s) => (
                  <tr>
                    <td class="mono">{s.name}</td>
                    <td class="mono">{s.project}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Section>
      </div>
      <Section title={t("scope.title")}>
        <p class="mb-3 text-sm text-zinc-500">{t("scope.intro")}</p>
        <table class="table" data-testid="product-scope">
          <thead>
            <tr>
              <th>{t("scope.product")}</th>
              <th>{t("scope.status")}</th>
              <th>{t("scope.note")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={productScope()}>
              {(row) => (
                <tr data-testid={`scope-${row.id}`}>
                  <td>{t(row.nameKey)}</td>
                  <td>
                    <span class={`badge ${statusClass(row.status)}`} data-status={row.status}>
                      {t(statusLabelKey(row.status))}
                    </span>
                  </td>
                  <td class="text-xs text-zinc-500">{t(row.noteKey)}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Section>
      <Section title={t("overview.envVars")}>
        <pre class="mono whitespace-pre-wrap rounded-md bg-zinc-100 p-3 dark:bg-zinc-800">
          {env()}
        </pre>
      </Section>
    </div>
  );
};

export default Overview;
