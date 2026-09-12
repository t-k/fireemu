import {
  createEffect,
  createMemo,
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
import { AsyncButton, ErrorBanner, FetchState, Notice, Section } from "../components/common";
import { awaitIdle, functionsStatus, publishMessage, runSchedule, setClock } from "../api/control";
import { errorOf, settle } from "../api/client";
import {
  enqueueTask,
  functionsOverview,
  invokeFunction,
  subscribeLogs,
  type FunctionInfo,
  type InvocationInfo,
  type InvokeResponse,
  type TriggerInfo,
} from "../api/functions";
import { buildCallableInvoke, buildEnqueue, buildRequestInvoke } from "../lib/invoke";
import { matchesLog, type LevelFilter } from "../lib/logFilter";

const LEVEL_OPTIONS: { value: LevelFilter; key: Parameters<typeof t>[0] }[] = [
  { value: "all", key: "functions.levelAll" },
  { value: "debug", key: "functions.levelDebug" },
  { value: "info", key: "functions.levelInfo" },
  { value: "warn", key: "functions.levelWarn" },
  { value: "error", key: "functions.levelError" },
  { value: "other", key: "functions.levelOther" },
];

const MAX_LINES = 2000;
/**
 * Invocation rows kept in the browser. The server retains a bounded window too, so a
 * long-running session cannot grow either collection without limit.
 */
const MAX_INVOCATIONS = 500;

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
    case "tasks":
      return t("functions.triggerTasks", {
        attempts: trigger.maxAttempts,
        concurrency: trigger.maxConcurrentDispatches,
      });
    case "eventarc":
      return t("functions.triggerEventarc", {
        event: trigger.event,
        channel: trigger.channel ?? t("functions.defaultChannel"),
        filters: JSON.stringify(trigger.filters),
      });
    case "blockingAuth":
      return t("functions.triggerBlockingAuth", { event: trigger.event });
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
    default:
      return t("functions.triggerUnknown", { kind: (trigger as { kind: string }).kind });
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

/** Renders the response of a forwarded invocation: the status line, headers and body. */
const InvokeResult: Component<{ response: InvokeResponse }> = (props) => (
  <div class="mt-2 text-sm" data-testid="invoke-result">
    <div class="label">
      {t("functions.invokeStatus", {
        status: props.response.status,
        ms: props.response.durationMs,
      })}
    </div>
    <Show when={props.response.truncated}>
      <p class="text-xs text-amber-700 dark:text-amber-300">
        {t("functions.invokeTruncated", { bytes: props.response.bodyLength })}
      </p>
    </Show>
    <Show when={props.response.headers.length > 0}>
      <pre class="mono mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all text-xs text-zinc-500">
        {props.response.headers.map(([name, value]) => `${name}: ${value}`).join("\n")}
      </pre>
    </Show>
    <pre
      class="mono mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-zinc-900 p-2 text-xs text-zinc-100"
      data-testid="invoke-response-body"
    >
      {props.response.bodyEncoding === "base64"
        ? `(base64) ${props.response.body ?? ""}`
        : (props.response.body ?? "")}
    </pre>
  </div>
);

/** Invokes an HTTP or callable function, showing the response the port returns. */
const InvokeForm: Component<{ f: FunctionInfo; onError: (m: string) => void }> = (props) => {
  const callable = () => props.f.trigger.kind === "http" && props.f.trigger.callable;
  const [data, setData] = createSignal('{"a": 1, "b": 2}');
  const [authToken, setAuthToken] = createSignal("");
  const [appCheckToken, setAppCheckToken] = createSignal("");
  const [method, setMethod] = createSignal("POST");
  const [path, setPath] = createSignal("");
  const [query, setQuery] = createSignal("");
  const [headers, setHeaders] = createSignal("");
  const [body, setBody] = createSignal("");
  const [response, setResponse] = createSignal<InvokeResponse | null>(null);

  const send = async () => {
    const built = callable()
      ? buildCallableInvoke({
          data: data(),
          authToken: authToken(),
          appCheckToken: appCheckToken(),
        })
      : buildRequestInvoke({
          method: method(),
          path: path(),
          query: query(),
          headers: headers(),
          body: body(),
        });
    if (built.isErr()) {
      props.onError(built.error);
      return;
    }
    const r = await invokeFunction(props.f.name, built.value);
    r.match(
      (res) => setResponse(res),
      (e) => props.onError(e.message),
    );
  };

  return (
    <div
      class="mt-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
      data-testid={`invoke-${props.f.name}`}
    >
      <Show
        when={callable()}
        fallback={
          <>
            <label class="block text-sm">
              <span class="label">{t("functions.invokeMethod")}</span>
              <select
                class="input"
                data-testid={`invoke-${props.f.name}-method`}
                value={method()}
                onInput={(e) => setMethod(e.currentTarget.value)}
              >
                <For each={["GET", "POST", "PUT", "PATCH", "DELETE"]}>
                  {(m) => <option value={m}>{m}</option>}
                </For>
              </select>
            </label>
            <label class="mt-1 block text-sm">
              <span class="label">{t("functions.invokePath")}</span>
              <input
                class="input mono"
                value={path()}
                onInput={(e) => setPath(e.currentTarget.value)}
              />
            </label>
            <label class="mt-1 block text-sm">
              <span class="label">{t("functions.invokeQuery")}</span>
              <input
                class="input mono"
                value={query()}
                onInput={(e) => setQuery(e.currentTarget.value)}
              />
            </label>
            <label class="mt-1 block text-sm">
              <span class="label">{t("functions.invokeHeaders")}</span>
              <textarea
                class="input mono h-16"
                value={headers()}
                onInput={(e) => setHeaders(e.currentTarget.value)}
              />
            </label>
            <label class="mt-1 block text-sm">
              <span class="label">{t("functions.invokeBody")}</span>
              <textarea
                class="input mono h-16"
                value={body()}
                onInput={(e) => setBody(e.currentTarget.value)}
              />
            </label>
          </>
        }
      >
        <label class="block text-sm">
          <span class="label">{t("functions.invokeData")}</span>
          <textarea
            class="input mono h-16"
            data-testid={`invoke-${props.f.name}-data`}
            value={data()}
            onInput={(e) => setData(e.currentTarget.value)}
          />
        </label>
        <label class="mt-1 block text-sm">
          <span class="label">{t("functions.invokeAuthToken")}</span>
          <input
            class="input mono"
            value={authToken()}
            onInput={(e) => setAuthToken(e.currentTarget.value)}
          />
        </label>
        <label class="mt-1 block text-sm">
          <span class="label">{t("functions.invokeAppCheckToken")}</span>
          <input
            class="input mono"
            value={appCheckToken()}
            onInput={(e) => setAppCheckToken(e.currentTarget.value)}
          />
        </label>
      </Show>
      <AsyncButton
        class="btn btn-primary mt-2"
        onClick={send}
        testId={`invoke-${props.f.name}-send`}
      >
        {t("functions.invokeSend")}
      </AsyncButton>
      <Show when={response()}>{(res) => <InvokeResult response={res()} />}</Show>
    </div>
  );
};

/** Enqueues a Cloud Task onto an onTaskDispatched queue. */
const EnqueueForm: Component<{
  f: FunctionInfo;
  onDone: () => void;
  onError: (m: string) => void;
}> = (props) => {
  const [data, setData] = createSignal('{"id": "1", "n": 1}');
  const [id, setId] = createSignal("");
  const enqueue = async () => {
    const built = buildEnqueue({ data: data(), id: id() });
    if (built.isErr()) {
      props.onError(built.error);
      return;
    }
    const r = await enqueueTask(props.f.name, built.value);
    r.match(
      () => props.onDone(),
      (e) => props.onError(e.message),
    );
  };
  return (
    <div
      class="mt-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
      data-testid={`enqueue-${props.f.name}`}
    >
      <label class="block text-sm">
        <span class="label">{t("functions.enqueueData")}</span>
        <textarea
          class="input mono h-16"
          data-testid={`enqueue-${props.f.name}-data`}
          value={data()}
          onInput={(e) => setData(e.currentTarget.value)}
        />
      </label>
      <label class="mt-1 block text-sm">
        <span class="label">{t("functions.enqueueId")}</span>
        <input class="input mono" value={id()} onInput={(e) => setId(e.currentTarget.value)} />
      </label>
      <AsyncButton
        class="btn btn-primary mt-2"
        onClick={enqueue}
        testId={`enqueue-${props.f.name}-send`}
      >
        {t("functions.enqueueSend")}
      </AsyncButton>
    </div>
  );
};

const FunctionRow: Component<{
  f: FunctionInfo;
  project: string;
  functionsAddr: string | null;
  /** Whether the selected session is the one the functions belong to; actions are disabled otherwise. */
  active: boolean;
  onNotice: (m: string) => void;
  onError: (m: string) => void;
  onRefresh: () => Promise<void>;
}> = (props) => {
  const [publishing, setPublishing] = createSignal(false);
  const [invoking, setInvoking] = createSignal(false);
  const [enqueuing, setEnqueuing] = createSignal(false);
  const trigger = () => props.f.trigger;
  return (
    <tr data-testid={`function-row-${props.f.name}`}>
      <td class="mono">{props.f.name}</td>
      <td class="mono text-xs">{props.f.region}</td>
      <td class="text-xs">
        {describeTrigger(trigger())}
        <Show
          when={
            ![
              "http",
              "firestore",
              "pubsub",
              "auth",
              "storage",
              "schedule",
              "tasks",
              "eventarc",
              "blockingAuth",
            ].includes(trigger().kind)
          }
        >
          <details>
            <summary>{t("functions.triggerDetails")}</summary>
            <pre class="whitespace-pre-wrap break-all">{JSON.stringify(trigger(), null, 2)}</pre>
          </details>
        </Show>
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
        <Show when={invoking() && trigger().kind === "http"}>
          <InvokeForm f={props.f} onError={props.onError} />
        </Show>
        <Show when={enqueuing() && trigger().kind === "tasks"}>
          <EnqueueForm
            f={props.f}
            onDone={() => {
              setEnqueuing(false);
              props.onNotice(t("functions.enqueued", { name: props.f.name }));
            }}
            onError={props.onError}
          />
        </Show>
        <Show when={trigger().kind === "schedule" && props.f.nextRun}>
          {(nextRun) => (
            <div class="mono text-xs text-zinc-500" data-testid={`next-run-${props.f.name}`}>
              {t("functions.nextRun")}: {nextRun()}
            </div>
          )}
        </Show>
      </td>
      <td class="text-xs">{props.f.timeoutSeconds}s</td>
      <td class="text-xs">{props.f.retry ? t("app.yes") : t("app.no")}</td>
      <td class="text-xs">{props.f.concurrency}</td>
      <td class="text-right">
        <Show when={trigger().kind === "schedule"}>
          <AsyncButton
            class="btn"
            disabled={!props.active}
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
          <Show when={props.f.nextRun}>
            {(nextRun) => (
              <AsyncButton
                class="btn"
                disabled={!props.active}
                testId={`advance-to-next-${props.f.name}`}
                onClick={async () => {
                  const r = await setClock(appState.session(), nextRun(), false);
                  await r.match(
                    async (c) => {
                      appState.setClock(c.clock);
                      props.onNotice(t("functions.advancedToNextRun", { instant: nextRun() }));
                      await props.onRefresh();
                    },
                    async (e) => props.onError(e.message),
                  );
                }}
              >
                {t("functions.advanceToNextRun")}
              </AsyncButton>
            )}
          </Show>
        </Show>
        <Show when={trigger().kind === "pubsub"}>
          <button
            type="button"
            class="btn"
            disabled={!props.active}
            data-testid={`publish-${props.f.name}`}
            onClick={() => setPublishing(!publishing())}
          >
            {t("functions.publish")}
          </button>
        </Show>
        <Show when={trigger().kind === "http"}>
          <Show
            when={props.functionsAddr}
            fallback={
              <span class="text-xs text-zinc-500" title={t("functions.invokeUnavailable")}>
                {t("functions.invokeUnavailable")}
              </span>
            }
          >
            <button
              type="button"
              class="btn"
              disabled={!props.active}
              data-testid={`invoke-${props.f.name}-toggle`}
              onClick={() => setInvoking(!invoking())}
            >
              {t("functions.invoke")}
            </button>
          </Show>
        </Show>
        <Show when={trigger().kind === "tasks"}>
          <button
            type="button"
            class="btn"
            disabled={!props.active}
            data-testid={`enqueue-${props.f.name}-toggle`}
            onClick={() => setEnqueuing(!enqueuing())}
          >
            {t("functions.enqueue")}
          </button>
        </Show>
      </td>
    </tr>
  );
};

export const FunctionRows: Component<{
  functions: FunctionInfo[];
  project: string;
  functionsAddr?: string | null;
  /** Whether the selected session owns the functions; actions are disabled otherwise. */
  active?: boolean;
  onNotice: (m: string) => void;
  onError: (m: string) => void;
  onRefresh?: () => Promise<void>;
}> = (props) => {
  // Refreshed objects describe the same target. Keep its form mounted until that target changes.
  // `nextRun` is deliberately excluded so advancing the clock updates a row without discarding
  // an open invoke or enqueue form.
  const byTarget = createMemo(
    () =>
      new Map(
        props.functions.map((f) => [
          JSON.stringify([appState.session(), props.project, f.region, f.name, f.trigger]),
          f,
        ]),
      ),
  );
  return (
    <For each={[...byTarget().keys()]}>
      {(key) => (
        <FunctionRow
          f={byTarget().get(key)!}
          project={props.project}
          functionsAddr={props.functionsAddr ?? null}
          active={props.active ?? true}
          onNotice={props.onNotice}
          onError={props.onError}
          onRefresh={props.onRefresh ?? (async () => {})}
        />
      )}
    </For>
  );
};

const Functions: Component = () => {
  const [overview, { refetch }] = createResource(() => settle(functionsOverview()));
  const [status, { refetch: refetchStatus }] = createResource(() =>
    settle(functionsStatus(appState.session())),
  );
  const [lines, setLines] = createSignal<string[]>([]);
  const [invocations, setInvocations] = createSignal<InvocationInfo[]>([]);
  const [truncated, setTruncated] = createSignal(false);
  const [connected, setConnected] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const configured = () => overview()?.unwrapOr(null)?.configured ?? false;
  const [logBox, setLogBox] = createSignal<HTMLPreElement>();
  // Follow the tail only while the reader is at the tail; otherwise count what arrived.
  const [following, setFollowing] = createSignal(true);
  const [unseen, setUnseen] = createSignal(0);
  const atBottom = (box: HTMLPreElement) => box.scrollHeight - box.scrollTop - box.clientHeight < 8;
  const jumpToEnd = () => {
    const box = logBox();
    if (box) box.scrollTop = box.scrollHeight;
    setFollowing(true);
    setUnseen(0);
  };
  const [logLevel, setLogLevel] = createSignal<LevelFilter>("all");
  const [logText, setLogText] = createSignal("");
  const [fnFilter, setFnFilter] = createSignal("");

  const filteredLines = (): string[] =>
    lines().filter((line) => matchesLog(line, { level: logLevel(), text: logText() }));
  const filteredInvocations = (): InvocationInfo[] => {
    const name = fnFilter();
    return name === "" ? invocations() : invocations().filter((r) => r.function === name);
  };
  /** Function names to offer in the filter: the registered ones plus any seen in invocations. */
  const functionNames = (): string[] => {
    const names = new Set<string>((o()?.functions ?? []).map((f) => f.name));
    for (const r of invocations()) {
      names.add(r.function);
    }
    return [...names].toSorted();
  };

  const keepRecent = (records: InvocationInfo[]): InvocationInfo[] => {
    setTruncated(records.length > MAX_INVOCATIONS);
    return records.slice(-MAX_INVOCATIONS);
  };

  // Keep the tail in view after every render that changes the lines (or mounts the box).
  createEffect(() => {
    const box = logBox();
    void filteredLines();
    if (box && following()) box.scrollTop = box.scrollHeight;
  });

  onMount(() => {
    const stop = subscribeLogs(
      (e) => {
        if (e.kind === "snapshot") {
          setLines(e.logs.slice(-MAX_LINES));
          setInvocations(keepRecent(e.invocations));
        } else if (e.kind === "log") {
          setLines((l) => [...l, e.line].slice(-MAX_LINES));
          if (!following()) setUnseen((n) => n + 1);
        } else if (e.kind === "resync") {
          // The server could not answer this connection's cursor (a reset, or records that
          // fell out of its retention window): replace the list rather than append a gap.
          setInvocations(keepRecent(e.invocations));
          void refetchStatus();
        } else {
          setInvocations((i) => keepRecent([...i, e.record]));
          void refetchStatus();
        }
        setConnected(true);
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
  // The functions belong to one project's session. Actions are enabled only when the selected
  // session still exists and its project is the functions' project. Matching the real selected
  // session (not `appState.project()`, which falls back to the default project when the
  // selection has been deleted) keeps actions disabled after that session is removed elsewhere,
  // rather than silently re-enabling them against the default project.
  const active = () => {
    const owner = o();
    if (!owner?.configured || owner.project === undefined) {
      return false;
    }
    const selected = appState.sessions().find((sess) => sess.name === appState.session());
    return selected !== undefined && selected.project === owner.project;
  };
  return (
    <div>
      <h1 class="mb-4 text-xl font-bold">{t("functions.title")}</h1>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <FetchState
        loading={overview.loading && !overview()}
        error={errorOf(overview())}
        onRetry={async () => {
          await refetch();
        }}
      >
        <Show
          when={configured()}
          fallback={<p class="card text-sm text-zinc-500">{t("functions.notConfigured")}</p>}
        >
          <Show when={!active()}>
            <div
              role="status"
              data-testid="functions-session-mismatch"
              class="mb-4 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100"
            >
              {t("functions.sessionMismatch", {
                session: o()?.session ?? "",
                project: o()?.project ?? "",
              })}
            </div>
          </Show>
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
                <FunctionRows
                  functions={o()?.functions ?? []}
                  project={o()?.project ?? appState.project()}
                  functionsAddr={o()?.functionsAddr ?? null}
                  active={active()}
                  onNotice={setNotice}
                  onError={setError}
                  onRefresh={async () => {
                    await refetch();
                  }}
                />
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
              <FetchState
                loading={status.loading && !status()}
                error={errorOf(status())}
                onRetry={async () => {
                  await refetchStatus();
                }}
              >
                <Show when={s()}>
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
              </FetchState>
            </Section>
            <Section
              title={t("functions.invocations")}
              actions={
                <label class="text-sm">
                  <span class="sr-only">{t("functions.filterFunction")}</span>
                  <select
                    class="input"
                    data-testid="invocation-function-filter"
                    value={fnFilter()}
                    onInput={(e) => setFnFilter(e.currentTarget.value)}
                  >
                    <option value="">{t("functions.allFunctions")}</option>
                    <For each={functionNames()}>
                      {(name) => <option value={name}>{name}</option>}
                    </For>
                  </select>
                </label>
              }
            >
              <Show
                when={invocations().length > 0}
                fallback={<p class="text-sm text-zinc-500">{t("functions.noInvocations")}</p>}
              >
                <Show when={truncated()}>
                  <p class="mb-1 text-xs text-zinc-500" data-testid="invocations-truncated">
                    {t("functions.invocationsTruncated", { count: MAX_INVOCATIONS })}
                  </p>
                </Show>
                <Show
                  when={filteredInvocations().length > 0}
                  fallback={
                    <p class="text-sm text-zinc-500" data-testid="invocations-no-match">
                      {t("functions.noMatchingInvocations")}
                    </p>
                  }
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
                        <For each={filteredInvocations().toReversed()}>
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
              </Show>
            </Section>
          </div>
          <Section
            title={t("functions.logs")}
            actions={
              <>
                <label class="text-sm">
                  <span class="sr-only">{t("functions.filterLevel")}</span>
                  <select
                    class="input"
                    data-testid="log-level-filter"
                    value={logLevel()}
                    onInput={(e) => setLogLevel(e.currentTarget.value as LevelFilter)}
                  >
                    <For each={LEVEL_OPTIONS}>
                      {(opt) => <option value={opt.value}>{t(opt.key)}</option>}
                    </For>
                  </select>
                </label>
                <label class="text-sm">
                  <span class="sr-only">{t("functions.filterText")}</span>
                  <input
                    class="input w-40"
                    data-testid="log-text-filter"
                    placeholder={t("functions.filterTextPlaceholder")}
                    value={logText()}
                    onInput={(e) => setLogText(e.currentTarget.value)}
                  />
                </label>
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
            <div class="mb-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
              <span data-testid="log-count">
                {t("functions.logsFilteredCount", {
                  shown: filteredLines().length,
                  total: lines().length,
                })}
              </span>
              <Show
                when={following()}
                fallback={
                  <button type="button" class="btn" data-testid="log-jump" onClick={jumpToEnd}>
                    {unseen() > 0
                      ? t("functions.logsNewLines", { count: unseen() })
                      : t("functions.logsJumpToEnd")}
                  </button>
                }
              >
                <span data-testid="log-following">{t("functions.logsFollowing")}</span>
              </Show>
            </div>
            <pre
              ref={setLogBox}
              class="mono h-72 overflow-auto whitespace-pre-wrap rounded-md bg-zinc-900 p-3 text-xs text-zinc-100"
              data-testid="function-logs"
              onScroll={(e) => {
                const box = e.currentTarget;
                if (atBottom(box)) {
                  setFollowing(true);
                  setUnseen(0);
                } else {
                  setFollowing(false);
                }
              }}
            >
              <Show
                when={filteredLines().length > 0}
                fallback={
                  lines().length > 0 ? t("functions.noMatchingLogs") : t("functions.noLogs")
                }
              >
                {filteredLines().join("\n")}
              </Show>
            </pre>
          </Section>
        </Show>
      </FetchState>
    </div>
  );
};

export default Functions;
