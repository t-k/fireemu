import {
  createResource,
  createSignal,
  For,
  onCleanup,
  onMount,
  Show,
  type Component,
} from "solid-js";
import { t } from "../i18n";
import { appState } from "../state";
import { AsyncButton, ErrorBanner, Notice, Section, Spinner } from "../components/common";
import { awaitIdle, functionsStatus, publishMessage, runSchedule } from "../api/control";
import { settle } from "../api/client";
import {
  functionsOverview,
  subscribeLogs,
  type FunctionInfo,
  type InvocationInfo,
  type TriggerInfo,
} from "../api/functions";

const MAX_LINES = 2000;

const describeTrigger = (trigger: TriggerInfo): string => {
  switch (trigger.kind) {
    case "http":
      return t("functions.triggerHttp", {
        kind: trigger.callable
          ? t("functions.triggerHttpCallable")
          : t("functions.triggerHttpRequest"),
      });
    case "firestore":
      return `${t("functions.triggerFirestore", { event: trigger.event.split(".").at(-1) ?? trigger.event, document: trigger.document })}${trigger.withAuthContext ? ` (${t("functions.withAuthContext")})` : ""}`;
    case "pubsub":
      return t("functions.triggerPubsub", { topic: trigger.topic });
    case "auth":
      return t("functions.triggerAuth", {
        event: trigger.event.split(".").at(-1) ?? trigger.event,
      });
    case "storage":
      return t("functions.triggerStorage", {
        event: trigger.event.split(".").at(-1) ?? trigger.event,
        bucket: trigger.bucket ?? t("functions.defaultBucket"),
      });
    case "schedule":
      return t("functions.triggerSchedule", {
        schedule: trigger.schedule,
        timeZone: trigger.timeZone ?? t("functions.utc"),
      });
  }
};

const PublishForm: Component<{ topic: string; onDone: (count: number) => void }> = (props) => {
  const [message, setMessage] = createSignal('{"hello": "world"}');
  const [attributes, setAttributes] = createSignal("{}");
  const [error, setError] = createSignal<string | null>(null);
  const publish = async () => {
    setError(null);
    let attrs: unknown;
    try {
      attrs = JSON.parse(attributes() || "{}");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    let json: unknown;
    let data: string | undefined;
    try {
      json = JSON.parse(message());
    } catch {
      data = btoa(unescape(encodeURIComponent(message())));
    }
    const body =
      data !== undefined
        ? { data, attributes: attrs as Record<string, string> }
        : { json, attributes: attrs as Record<string, string> };
    const r = await publishMessage(appState.session(), props.topic, body);
    r.match(
      (res) => props.onDone(res.messageIds.length),
      (e) => setError(e.message),
    );
  };
  return (
    <div
      class="mt-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
      data-testid={`publish-${props.topic}`}
    >
      <ErrorBanner message={error()} />
      <label class="block text-sm">
        <span class="label">{t("functions.message")}</span>
        <textarea
          class="input mono h-16"
          value={message()}
          onInput={(e) => setMessage(e.currentTarget.value)}
        />
      </label>
      <label class="mt-1 block text-sm">
        <span class="label">{t("functions.attributes")}</span>
        <input
          class="input mono"
          value={attributes()}
          onInput={(e) => setAttributes(e.currentTarget.value)}
        />
      </label>
      <AsyncButton
        class="btn btn-primary mt-2"
        onClick={publish}
        testId={`publish-${props.topic}-send`}
      >
        {t("functions.publish")}
      </AsyncButton>
    </div>
  );
};

const FunctionRow: Component<{
  f: FunctionInfo;
  project: string;
  onNotice: (m: string) => void;
  onError: (m: string) => void;
}> = (props) => {
  const [publishing, setPublishing] = createSignal(false);
  const trigger = () => props.f.trigger;
  return (
    <tr data-testid={`function-row-${props.f.name}`}>
      <td class="mono">{props.f.name}</td>
      <td class="mono text-xs">{props.f.region}</td>
      <td class="text-xs">
        {describeTrigger(trigger())}
        <Show when={trigger().kind === "http" && appState.config().functionsAddr}>
          <div class="mono text-zinc-500">
            http://{appState.config().functionsAddr}/{props.project}/{props.f.region}/{props.f.name}
          </div>
        </Show>
        <Show when={publishing() && trigger().kind === "pubsub"}>
          <PublishForm
            topic={(trigger() as { topic: string }).topic}
            onDone={(count) => {
              setPublishing(false);
              props.onNotice(t("functions.published", { count }));
            }}
          />
        </Show>
      </td>
      <td class="text-xs">{props.f.timeoutSeconds}s</td>
      <td class="text-xs">{props.f.retry ? t("app.yes") : t("app.no")}</td>
      <td class="text-xs">{props.f.concurrency}</td>
      <td class="text-right">
        <Show when={trigger().kind === "schedule"}>
          <AsyncButton
            class="btn"
            testId={`run-${props.f.name}`}
            onClick={async () => {
              const r = await runSchedule(appState.session(), props.f.name);
              r.match(
                () => props.onNotice(`${t("functions.runNow")}: ${props.f.name}`),
                (e) => props.onError(e.message),
              );
            }}
          >
            {t("functions.runNow")}
          </AsyncButton>
        </Show>
        <Show when={trigger().kind === "pubsub"}>
          <button
            type="button"
            class="btn"
            data-testid={`publish-${props.f.name}`}
            onClick={() => setPublishing(!publishing())}
          >
            {t("functions.publish")}
          </button>
        </Show>
      </td>
    </tr>
  );
};

const Functions: Component = () => {
  const [overview, { refetch }] = createResource(() => settle(functionsOverview()));
  const [status, { refetch: refetchStatus }] = createResource(() =>
    settle(functionsStatus(appState.session())),
  );
  const [lines, setLines] = createSignal<string[]>([]);
  const [invocations, setInvocations] = createSignal<InvocationInfo[]>([]);
  const [connected, setConnected] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const configured = () => overview()?.unwrapOr(null)?.configured ?? false;
  const [logBox, setLogBox] = createSignal<HTMLPreElement>();

  onMount(() => {
    const stop = subscribeLogs(
      (e) => {
        if (e.kind === "snapshot") {
          setLines(e.logs.slice(-MAX_LINES));
          setInvocations(e.invocations);
        } else if (e.kind === "log") {
          setLines((l) => [...l, e.line].slice(-MAX_LINES));
        } else {
          setInvocations((i) => [...i, e.record]);
          void refetchStatus();
        }
        setConnected(true);
        const box = logBox();
        if (box) box.scrollTop = box.scrollHeight;
      },
      () => setConnected(false),
    );
    const timer = window.setInterval(() => void refetchStatus(), 3000);
    onCleanup(() => {
      stop();
      window.clearInterval(timer);
    });
  });

  const s = () => status()?.unwrapOr(null) ?? null;
  const o = () => overview()?.unwrapOr(null) ?? null;
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("functions.title")}</h1>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <Show when={!overview.loading} fallback={<Spinner />}>
        <Show
          when={configured()}
          fallback={<p class="card text-sm text-zinc-500">{t("functions.notConfigured")}</p>}
        >
          <Section
            title={t("functions.registered")}
            actions={
              <>
                <span class="mono text-xs text-zinc-500">{o()?.source ?? ""}</span>
                <AsyncButton
                  class="btn"
                  onClick={async () => {
                    await refetch();
                  }}
                >
                  {t("app.refresh")}
                </AsyncButton>
              </>
            }
          >
            <table class="table" data-testid="function-table">
              <thead>
                <tr>
                  <th>{t("functions.name")}</th>
                  <th>{t("functions.region")}</th>
                  <th>{t("functions.trigger")}</th>
                  <th>{t("functions.timeout")}</th>
                  <th>{t("functions.retry")}</th>
                  <th>{t("functions.concurrency")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                <For each={o()?.functions ?? []}>
                  {(f) => (
                    <FunctionRow
                      f={f}
                      project={o()?.project ?? appState.project()}
                      onNotice={setNotice}
                      onError={setError}
                    />
                  )}
                </For>
              </tbody>
            </table>
          </Section>
          <div class="grid gap-4 xl:grid-cols-2">
            <Section
              title={t("functions.status")}
              actions={
                <AsyncButton
                  class="btn"
                  testId="await-idle"
                  onClick={async () => {
                    const r = await awaitIdle(appState.session(), 30);
                    r.match(
                      (res) => setNotice(res.idle ? t("functions.idle") : t("functions.notIdle")),
                      (e) => setError(e.message),
                    );
                    void refetchStatus();
                  }}
                >
                  {t("functions.awaitIdle")}
                </AsyncButton>
              }
            >
              <Show when={s()} fallback={<Spinner />}>
                {(st) => (
                  <dl
                    class="grid grid-cols-2 gap-x-4 gap-y-1 text-sm"
                    data-testid="function-status"
                  >
                    <dt class="label">{t("functions.pending")}</dt>
                    <dd>{st().pending}</dd>
                    <dt class="label">{t("functions.running")}</dt>
                    <dd>{st().running}</dd>
                    <dt class="label">{t("functions.retryWaiting")}</dt>
                    <dd>{st().retryWaiting}</dd>
                    <dt class="label">{t("functions.succeeded")}</dt>
                    <dd data-testid="succeeded-count">{st().succeeded}</dd>
                    <dt class="label">{t("functions.deadLettered")}</dt>
                    <dd>{st().deadLettered}</dd>
                    <dt class="label">{t("functions.runnerAlive")}</dt>
                    <dd>{st().runnerAlive ? t("app.yes") : t("app.no")}</dd>
                  </dl>
                )}
              </Show>
            </Section>
            <Section title={t("functions.invocations")}>
              <Show
                when={invocations().length > 0}
                fallback={<p class="text-sm text-zinc-500">{t("functions.noInvocations")}</p>}
              >
                <div class="max-h-64 overflow-auto">
                  <table class="table" data-testid="invocation-table">
                    <thead>
                      <tr>
                        <th>{t("functions.eventId")}</th>
                        <th>{t("functions.name")}</th>
                        <th>{t("functions.attempt")}</th>
                        <th>{t("functions.outcome")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={invocations().toReversed()}>
                        {(r) => (
                          <tr>
                            <td class="mono text-xs">{r.eventId}</td>
                            <td class="mono">{r.function}</td>
                            <td>{r.attempt}</td>
                            <td class="mono text-xs">{r.outcome}</td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </Section>
          </div>
          <Section
            title={t("functions.logs")}
            actions={
              <>
                <span
                  class={`badge ${connected() ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100" : "bg-zinc-200 dark:bg-zinc-800"}`}
                >
                  {connected() ? t("firestore.live") : t("firestore.liveOff")}
                </span>
                <button type="button" class="btn" onClick={() => setLines([])}>
                  {t("functions.clearLogs")}
                </button>
              </>
            }
          >
            <pre
              ref={setLogBox}
              class="mono h-72 overflow-auto whitespace-pre-wrap rounded-md bg-zinc-900 p-3 text-zinc-100"
              data-testid="function-logs"
            >
              <Show when={lines().length > 0} fallback={t("functions.noLogs")}>
                {lines().join("\n")}
              </Show>
            </pre>
          </Section>
        </Show>
      </Show>
    </div>
  );
};

export default Functions;
