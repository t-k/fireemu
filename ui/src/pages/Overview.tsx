import { createSignal, For, Show, type Component } from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import { AsyncButton, Field, Section, FetchState } from "../components/common";
import { getRules } from "../api/control";
import { settle } from "../api/client";
import { createScopedFetch } from "../lib/rules-state";

/** A block of text with a copy button (clipboard, or select-all when denied). */
const CopyBlock: Component<{ text: string; testId: string }> = (props) => {
  const [copied, setCopied] = createSignal(false);
  const [copyStatus, setCopyStatus] = createSignal("");
  const [manualCopy, setManualCopy] = createSignal(false);
  let manualInput: HTMLTextAreaElement | undefined;
  const copy = async () => {
    setManualCopy(false);
    setCopied(false);
    setCopyStatus("");
    try {
      await navigator.clipboard.writeText(props.text);
      setCopied(true);
      setCopyStatus(t("app.copied"));
    } catch {
      setCopyStatus(t("app.copyManually"));
      setManualCopy(true);
      queueMicrotask(() => {
        manualInput?.focus();
        manualInput?.select();
      });
    }
  };
  return (
    <div class="relative">
      <pre
        class="mono whitespace-pre-wrap rounded-md bg-zinc-100 p-3 pr-20 text-xs dark:bg-zinc-800"
        data-testid={props.testId}
      >
        {props.text}
      </pre>
      <AsyncButton
        class="btn absolute top-2 right-2"
        onClick={copy}
        testId={`${props.testId}-copy`}
      >
        {copied() ? t("app.copied") : t("app.copy")}
      </AsyncButton>
      <p role="status" class="mt-1 text-sm" data-testid={`${props.testId}-copy-status`}>
        {copyStatus()}
      </p>
      <Show when={manualCopy()}>
        <textarea
          ref={(element) => {
            manualInput = element;
          }}
          class="input mono mt-2 w-full"
          readonly
          value={props.text}
          aria-label={t("app.copyManually")}
        />
      </Show>
    </div>
  );
};

const RulesStatus: Component<{ which: "firestore" | "storage" }> = (props) => {
  const info = createScopedFetch(
    () => JSON.stringify([appState.session(), appState.project()]),
    () => settle(getRules(props.which)),
  );
  return (
    <FetchState
      loading={info.loading() && info.data() === undefined}
      error={info.data() === undefined ? info.error() : null}
      stale={info.data() !== undefined ? info.error() : null}
      onRetry={info.refetch}
    >
      <Show when={info.loading()}>
        <span role="status">{t("rules.refreshing")}</span>
      </Show>
      <Show when={info.data()}>
        {(data) => <span>{data().loaded ? t("rules.loaded") : t("rules.notLoaded")}</span>}
      </Show>
      <AsyncButton class="btn" onClick={info.refetch} testId={`overview-${props.which}-refresh`}>
        {t("rules.refresh")}
      </AsyncButton>
    </FetchState>
  );
};

const Overview: Component = () => {
  const config = appState.config;
  // The environment for the selected session's project: what the header shows is what
  // an SDK pointed here talks to. The daemon's own default project is shown separately.
  const hosts = () =>
    [
      `FIRESTORE_EMULATOR_HOST=${config().firestoreAddr}`,
      `FIREBASE_AUTH_EMULATOR_HOST=${config().httpAddr}`,
      `FIREBASE_STORAGE_EMULATOR_HOST=${config().storageAddr}`,
      `STORAGE_EMULATOR_HOST=http://${config().storageAddr}`,
      ...(config().functionsAddr ? [`FIREEMU_FUNCTIONS_HOST=${config().functionsAddr}`] : []),
    ].join("\n");
  const env = () =>
    [
      hosts(),
      `GOOGLE_CLOUD_PROJECT=${appState.project()}`,
      `FIREEMU_CONTROL_URL=http://${config().httpAddr}/v1/`,
    ].join("\n");
  const envExport = () =>
    env()
      .split("\n")
      .map((line) => `export ${line}`)
      .join("\n");
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
          <Field label={t("overview.selectedSession")} mono>
            {appState.session()}
          </Field>
          <Field label={t("overview.project")} mono>
            {appState.project()}
          </Field>
          <Show when={appState.project() !== config().project}>
            <Field label={t("overview.daemonProject")} mono>
              {config().project}
            </Field>
          </Show>
          <Field label={t("overview.edition")}>{config().edition}</Field>
          <Field label={t("overview.version")} mono>
            {config().version}
          </Field>
          <Field label={t("overview.clock")} mono>
            <span data-testid="overview-clock">{appState.clock()}</span>{" "}
            <span class="text-zinc-500" data-testid="overview-clock-mode">
              {config().clockMode === "frozen"
                ? t("overview.clockFrozen")
                : t("overview.clockRealtime")}
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
        <Section title={t("overview.hostNames")}>
          <div data-testid="host-names">
            <p class="mb-2 text-sm text-zinc-500">{t("overview.hostNamesHint")}</p>
            <Field label={t("overview.hostNamesAlways")}>
              <span class="mono">
                {[...config().hosts.defaultNames, ...config().hosts.defaultSuffixes].join(", ")}
              </span>
              {", "}
              {t("overview.hostNamesAnyIp")}
            </Field>
            <Field label={t("overview.hostNamesAdded")}>
              <Show
                when={config().hosts.allowed.length > 0}
                fallback={<p data-testid="host-names-none">{t("overview.hostNamesNone")}</p>}
              >
                <span class="mono">{config().hosts.allowed.join(", ")}</span>
              </Show>
            </Field>
            <Field label={t("overview.hostNamesSingleLabel")}>
              <span data-testid="host-names-single-label">
                {config().hosts.allowNonLoopbackHosts ? t("app.yes") : t("app.no")}
              </span>
            </Field>
            <Show when={config().hosts.allowed.includes("*")}>
              <div
                data-testid="host-names-open"
                class="mt-2 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm dark:bg-amber-900/30"
              >
                {t("overview.hostNamesOpen")}
              </div>
            </Show>
          </div>
        </Section>
        <Section title={t("overview.rules")}>
          <Field label={t("overview.rules")}>
            {config().rulesEnforced ? t("overview.rulesEnforced") : t("overview.rulesDisabled")}
          </Field>
          <Field label={t("overview.rulesFirestore")}>
            <RulesStatus which="firestore" />
          </Field>
          <Field label={t("overview.rulesStorage")}>
            <RulesStatus which="storage" />
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
      <Section title={t("overview.envVars")}>
        <p class="mb-2 text-sm text-zinc-500">
          {t("overview.envVarsFor", { session: appState.session(), project: appState.project() })}
        </p>
        <div class="grid gap-3 lg:grid-cols-2">
          <div>
            <div class="label mb-1">{t("overview.envDotenv")}</div>
            <CopyBlock text={env()} testId="env-dotenv" />
          </div>
          <div>
            <div class="label mb-1">{t("overview.envShell")}</div>
            <CopyBlock text={envExport()} testId="env-shell" />
          </div>
        </div>
      </Section>
    </div>
  );
};

export default Overview;
