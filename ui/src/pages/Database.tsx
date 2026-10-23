import { createEffect, createSignal, For, onCleanup, Show, type Component } from "solid-js";
import { useParams } from "@solidjs/router";
import { appState } from "../state";
import { t } from "../i18n";
import {
  AsyncButton,
  ConfirmButton,
  ErrorBanner,
  FetchState,
  Notice,
  Section,
} from "../components/common";
import { createLeaveGuard, LeavePrompt, requestScopeChange } from "../lib/unsaved";
import { createScopedFetch } from "../lib/rules-state";
import { settle, type TextReply } from "../api/client";
import {
  databaseInstances,
  databaseRead,
  databaseWrite,
  databaseRules,
  databaseSaveRules,
  databaseProbe,
  type DataMethod,
  type DatabaseScope,
} from "../api/database";

const Editor: Component<{ scope: DatabaseScope; path: string }> = (props) => {
  const key = () => JSON.stringify([props.scope, props.path]);
  const data = createScopedFetch(key, () => settle(databaseRead(props.scope, props.path)));
  const rules = createScopedFetch(key, () => settle(databaseRules(props.scope)));
  const [draft, setDraft] = createSignal<string | null>(null);
  const [rulesDraft, setRulesDraft] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [pending, setPending] = createSignal(false);
  const [method, setMethod] = createSignal<DataMethod>("GET");
  const [query, setQuery] = createSignal("");
  const [probeSource, setProbeSource] = createSignal("null");
  const [probe, setProbe] = createSignal<TextReply>();
  let revision = 0;
  let rulesRevision = 0;
  let alive = true;
  onCleanup(() => {
    alive = false;
  });
  const dirty = () =>
    (draft() !== null && draft() !== data.data()?.body) ||
    (rulesDraft() !== null && rulesDraft() !== rules.data()?.body);
  const guard = createLeaveGuard(dirty);
  const source = () => draft() ?? data.data()?.body ?? "null";
  const rulesSource = () => rulesDraft() ?? rules.data()?.body ?? "{}";
  const mutate = async (which: "data" | "rules", operation: DataMethod) => {
    if (pending()) return;
    const submitted = which === "rules" ? rulesSource() : source();
    const atRevision = which === "rules" ? rulesRevision : revision;
    setError(null);
    setNotice(null);
    if (operation !== "DELETE") {
      try {
        JSON.parse(submitted);
      } catch {
        setError(t("database.invalidJson"));
        return;
      }
    }
    setPending(true);
    const result = await (which === "rules"
      ? databaseSaveRules(props.scope, submitted)
      : databaseWrite(
          props.scope,
          props.path,
          operation,
          operation === "DELETE" ? undefined : submitted,
        ));
    if (!alive) return;
    setPending(false);
    result.match(
      (reply) => {
        if (which === "rules") {
          rules.replace({ ...reply, body: submitted });
          if (atRevision === rulesRevision) setRulesDraft(null);
          void rules.refetch();
        } else {
          if (operation !== "PATCH") {
            data.replace(reply);
            if (atRevision === revision) setDraft(null);
            void data.refetch();
          } else {
            void data.refetch().then(() => {
              if (alive && !data.error() && atRevision === revision) setDraft(null);
            });
          }
        }
        setNotice(t(which === "rules" ? "database.rulesSaved" : "database.saved"));
      },
      (failure) => setError(failure.status === 0 ? t("database.unknownOutcome") : failure.message),
    );
  };
  const run = async () => {
    const response = await databaseProbe(
      props.scope,
      props.path,
      method(),
      query(),
      method() === "PUT" || method() === "PATCH" ? probeSource() : undefined,
    );
    if (!alive) return;
    response.match(setProbe, (failure) => {
      setProbe(undefined);
      setError(failure.message);
    });
  };
  return (
    <>
      <LeavePrompt guard={guard} subject={t("database.draft")} />
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Section title={t("database.data")}>
        <p class="mb-2 text-sm">{t("database.adminHint")}</p>
        <FetchState
          loading={data.loading() && data.data() === undefined}
          error={data.data() === undefined ? data.error() : null}
          stale={data.data() !== undefined ? data.error() : null}
          onRetry={data.refetch}
        >
          <Show when={data.loading()}>
            <p role="status">{t("database.refreshing")}</p>
          </Show>
          <label class="label" for="database-source">
            {t("database.json")}
          </label>
          <textarea
            id="database-source"
            class="input mono h-56"
            spellcheck={false}
            value={source()}
            onInput={(event) => {
              revision++;
              setDraft(event.currentTarget.value);
            }}
          />
          <div class="mt-2 flex flex-wrap gap-2">
            <AsyncButton disabled={pending()} onClick={data.refetch} testId="database-data-refresh">
              {t("app.refresh")}
            </AsyncButton>
            <AsyncButton
              disabled={pending()}
              onClick={() => mutate("data", "PUT")}
              testId="database-save"
            >
              {t("database.replace")}
            </AsyncButton>
            <AsyncButton
              disabled={pending()}
              onClick={() => mutate("data", "PATCH")}
              testId="database-patch"
            >
              {t("database.patch")}
            </AsyncButton>
            <ConfirmButton
              label={t("app.delete")}
              question={t("database.deleteConfirm")}
              onConfirm={() => mutate("data", "DELETE")}
              testId="database-delete"
            />
          </div>
        </FetchState>
      </Section>
      <Section title={t("database.rules")}>
        <FetchState
          loading={rules.loading() && rules.data() === undefined}
          error={rules.data() === undefined ? rules.error() : null}
          stale={rules.data() !== undefined ? rules.error() : null}
          onRetry={rules.refetch}
        >
          <label class="label" for="database-rules">
            {t("database.rulesSource")}
          </label>
          <textarea
            id="database-rules"
            class="input mono h-48"
            spellcheck={false}
            value={rulesSource()}
            onInput={(event) => {
              rulesRevision++;
              setRulesDraft(event.currentTarget.value);
            }}
          />
          <div class="mt-2 flex gap-2">
            <AsyncButton
              disabled={pending()}
              onClick={rules.refetch}
              testId="database-rules-refresh"
            >
              {t("app.refresh")}
            </AsyncButton>
            <AsyncButton
              disabled={pending()}
              onClick={() => mutate("rules", "PUT")}
              testId="database-rules-save"
            >
              {t("database.replaceRules")}
            </AsyncButton>
          </div>
        </FetchState>
      </Section>
      <Section title={t("database.requests")}>
        <p>{t("database.anonymousHint")}</p>
        <label class="label" for="database-method">
          {t("database.method")}
        </label>
        <select
          id="database-method"
          class="input"
          value={method()}
          onChange={(event) => setMethod(event.currentTarget.value as DataMethod)}
        >
          <For each={["GET", "PUT", "PATCH", "DELETE"] as const}>
            {(value) => <option>{value}</option>}
          </For>
        </select>
        <label class="label" for="database-query">
          {t("database.query")}
        </label>
        <input
          id="database-query"
          class="input mono"
          value={query()}
          onInput={(event) => setQuery(event.currentTarget.value)}
        />
        <label class="label" for="database-request-source">
          {t("database.requestBody")}
        </label>
        <textarea
          id="database-request-source"
          class="input mono h-24"
          value={probeSource()}
          onInput={(event) => setProbeSource(event.currentTarget.value)}
        />
        <AsyncButton onClick={run} testId="database-request-run">
          {t("database.run")}
        </AsyncButton>
        <Show when={probe()}>
          {(response) => (
            <div data-testid="database-response">
              <p role="status">HTTP {response().status}</p>
              <Show when={response().etag}>
                <p>ETag: {response().etag}</p>
              </Show>
              <pre class="mono whitespace-pre-wrap">{response().body}</pre>
            </div>
          )}
        </Show>
      </Section>
    </>
  );
};

const Scope: Component<{ session: string; project: string; initialPath: string }> = (props) => {
  const instances = createScopedFetch(
    () => JSON.stringify([props.session, props.project]),
    () => settle(databaseInstances(props.session, props.project)),
  );
  const [namespace, setNamespace] = createSignal("");
  const [path, setPath] = createSignal(props.initialPath || "/");
  const [pathDraft, setPathDraft] = createSignal(path());
  createEffect(() => {
    const names = instances.data()?.instances ?? [];
    if (!names.some((item) => item.name === namespace())) setNamespace(names[0]?.name ?? "");
  });
  return (
    <FetchState
      loading={instances.loading() && instances.data() === undefined}
      error={instances.error()}
      onRetry={instances.refetch}
      empty={instances.data()?.instances.length === 0}
      emptyMessage={t("database.noInstances")}
    >
      <label class="label" for="database-instance">
        {t("database.instance")}
      </label>
      <select
        id="database-instance"
        class="input"
        value={namespace()}
        onChange={(event) => {
          const next = event.currentTarget.value;
          event.currentTarget.value = namespace();
          requestScopeChange(() => setNamespace(next));
        }}
      >
        <For each={instances.data()?.instances ?? []}>
          {(instance) => <option value={instance.name}>{instance.name}</option>}
        </For>
      </select>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          requestScopeChange(() => setPath(pathDraft()));
        }}
      >
        <label class="label" for="database-path">
          {t("database.path")}
        </label>
        <input
          id="database-path"
          class="input mono"
          value={pathDraft()}
          onInput={(event) => setPathDraft(event.currentTarget.value)}
        />
        <button type="submit" class="btn">
          {t("database.open")}
        </button>
      </form>
      <Show when={namespace() && JSON.stringify([namespace(), path()])} keyed>
        {(target) => {
          const [selected, location] = JSON.parse(target) as [string, string];
          return (
            <Editor
              scope={{ session: props.session, project: props.project, namespace: selected }}
              path={location}
            />
          );
        }}
      </Show>
    </FetchState>
  );
};
const Database: Component = () => {
  const params = useParams();
  const current = () =>
    appState
      .sessions()
      .find(
        (session) => session.name === appState.session() && session.project === appState.project(),
      );
  const scope = () =>
    current() && JSON.stringify([appState.session(), appState.project(), params.path ?? ""]);
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("database.title")}</h1>
      <Show when={scope()} keyed fallback={<p role="alert">{t("database.sessionMissing")}</p>}>
        {(key) => {
          const [session, project, initialPath] = JSON.parse(key) as [string, string, string];
          return <Scope session={session} project={project} initialPath={initialPath} />;
        }}
      </Show>
    </div>
  );
};
export default Database;
