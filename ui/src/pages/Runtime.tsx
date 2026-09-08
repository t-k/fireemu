import { createResource, createSignal, For, Show, type Component } from "solid-js";
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
  advanceClock,
  assertQuiescent,
  captureSnapshot,
  clearFaultPlan,
  createSession,
  deleteSession,
  deleteSnapshot,
  getFaultPlan,
  installFaultPlan,
  listSnapshots,
  resetSession,
  restoreSnapshot,
  sessionResources,
  setClock,
} from "../api/control";
import { errorOf, settle } from "../api/client";
import {
  formatQuantity,
  parseAllowances,
  saturation,
  type QuiescenceResult,
  type ServiceResources,
} from "../lib/resources";

const ClockPanel: Component = () => {
  const [seconds, setSeconds] = createSignal("60");
  const [instant, setInstant] = createSignal("");
  const [backwards, setBackwards] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const session = appState.session;
  const advance = async () => {
    setError(null);
    const n = Number(seconds());
    if (!Number.isFinite(n)) {
      setError(
        t("firestore.invalidValue", {
          field: t("runtime.seconds"),
          message: t("firestore.hintNumber"),
        }),
      );
      return;
    }
    const r = await advanceClock(session(), Math.trunc(n));
    r.match(
      (c) => appState.setClock(c.clock),
      (e) => setError(e.message),
    );
  };
  const set = async () => {
    setError(null);
    const r = await setClock(session(), instant(), backwards());
    r.match(
      (c) => appState.setClock(c.clock),
      (e) => setError(e.message),
    );
  };
  return (
    <Section title={t("runtime.clock")}>
      <ErrorBanner message={error()} />
      <div class="mb-3">
        <span class="label">{t("runtime.clockNow")}</span>
        <span class="mono" data-testid="runtime-clock">
          {appState.clock()}
        </span>
      </div>
      <div class="mb-3 flex flex-wrap items-end gap-2">
        <label class="text-sm">
          <span class="label">{t("runtime.advanceBy")}</span>
          <input
            class="input w-32"
            data-testid="advance-seconds"
            value={seconds()}
            onInput={(e) => setSeconds(e.currentTarget.value)}
          />
        </label>
        <span class="pb-1 text-sm">{t("runtime.seconds")}</span>
        <AsyncButton class="btn btn-primary" onClick={advance} testId="advance-clock">
          {t("runtime.advance")}
        </AsyncButton>
      </div>
      <div class="flex flex-wrap items-end gap-2">
        <label class="text-sm">
          <span class="label">{t("runtime.setTo")}</span>
          <input
            class="input w-64"
            placeholder="2026-01-02T03:04:05Z"
            value={instant()}
            onInput={(e) => setInstant(e.currentTarget.value)}
          />
        </label>
        <label class="flex items-center gap-1 pb-1 text-sm">
          <input
            type="checkbox"
            checked={backwards()}
            onChange={(e) => setBackwards(e.currentTarget.checked)}
          />
          {t("runtime.allowBackwards")}
        </label>
        <AsyncButton class="btn" onClick={set}>
          {t("runtime.set")}
        </AsyncButton>
      </div>
    </Section>
  );
};

const SnapshotsPanel: Component = () => {
  const session = appState.session;
  const [list, { refetch }] = createResource(session, (s) => settle(listSnapshots(s)));
  const [name, setName] = createSignal("");
  const [allow, setAllow] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const capture = async () => {
    setError(null);
    setNotice(null);
    const r = await captureSnapshot(session(), name(), allow());
    r.match(
      () => {
        setName("");
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  return (
    <Section title={t("runtime.snapshots")}>
      <ErrorBanner message={error()} />
      <Notice message={notice()} />
      <div class="mb-3 flex flex-wrap items-end gap-2">
        <label class="text-sm">
          <span class="label">{t("runtime.snapshotName")}</span>
          <input
            class="input w-48"
            data-testid="snapshot-name"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </label>
        <label class="flex items-center gap-1 pb-1 text-sm">
          <input
            type="checkbox"
            checked={allow()}
            onChange={(e) => setAllow(e.currentTarget.checked)}
          />
          {t("runtime.allowNonQuiescent")}
        </label>
        <AsyncButton class="btn btn-primary" onClick={capture} testId="snapshot-capture">
          {t("runtime.capture")}
        </AsyncButton>
      </div>
      <FetchState
        loading={list.loading && !list()}
        error={errorOf(list())}
        onRetry={async () => {
          await refetch();
        }}
      >
        <Show
          when={(list()?.unwrapOr({ snapshots: [] }).snapshots.length ?? 0) > 0}
          fallback={<p class="text-sm text-zinc-500">{t("runtime.noSnapshots")}</p>}
        >
          <table class="table" data-testid="snapshot-table">
            <thead>
              <tr>
                <th>{t("runtime.snapshotName")}</th>
                <th>{t("overview.clock")}</th>
                <th>{t("runtime.parts")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={list()?.unwrapOr({ snapshots: [] }).snapshots ?? []}>
                {(s) => (
                  <tr>
                    <td class="mono">{s.name}</td>
                    <td class="mono">{s.clock}</td>
                    <td>{s.parts}</td>
                    <td class="space-x-2 text-right">
                      <ConfirmButton
                        class="btn"
                        label={t("runtime.restore")}
                        question={t("runtime.restoreConfirm", { name: s.name })}
                        details={t("runtime.restoreDetails", {
                          session: session(),
                          clock: s.clock,
                        })}
                        testId={`snapshot-restore-${s.name}`}
                        onConfirm={async () => {
                          const r = await restoreSnapshot(session(), s.name);
                          r.match(
                            () => {
                              setNotice(`${t("runtime.restore")}: ${s.name}`);
                              void appState.refreshClock();
                            },
                            (e) => setError(e.message),
                          );
                        }}
                      />
                      <ConfirmButton
                        label={t("app.delete")}
                        question={t("runtime.deleteSnapshotConfirm", { name: s.name })}
                        onConfirm={async () => {
                          const r = await deleteSnapshot(session(), s.name);
                          r.match(
                            () => void refetch(),
                            (e) => setError(e.message),
                          );
                        }}
                      />
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </FetchState>
    </Section>
  );
};

const EXAMPLE_PLAN = JSON.stringify(
  {
    seed: 1,
    rules: [
      {
        match: { operation: "firestore.commit", nth: 2 },
        action: { type: "returnError", code: "ABORTED" },
      },
    ],
  },
  null,
  2,
);

const FaultPlanPanel: Component = () => {
  const session = appState.session;
  const [plan, { refetch }] = createResource(session, (s) => settle(getFaultPlan(s)));
  const [draft, setDraft] = createSignal(EXAMPLE_PLAN);
  const [error, setError] = createSignal<string | null>(null);
  const install = async () => {
    setError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(draft());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    const r = await installFaultPlan(session(), parsed);
    r.match(
      () => void refetch(),
      (e) => setError(e.message),
    );
  };
  const clear = async () => {
    setError(null);
    const r = await clearFaultPlan(session());
    r.match(
      () => void refetch(),
      (e) => setError(e.message),
    );
  };
  const current = () => plan()?.unwrapOr(null) ?? null;
  return (
    <Section
      title={t("runtime.faultPlan")}
      actions={
        <>
          <AsyncButton class="btn btn-primary" onClick={install} testId="fault-install">
            {t("runtime.install")}
          </AsyncButton>
          <AsyncButton class="btn" onClick={clear} testId="fault-clear">
            {t("runtime.clear")}
          </AsyncButton>
        </>
      }
    >
      <ErrorBanner message={error()} />
      <label class="label" for="fault-plan">
        {t("runtime.faultPlanJson")}
      </label>
      <textarea
        id="fault-plan"
        class="input mono h-40"
        spellcheck={false}
        value={draft()}
        onInput={(e) => setDraft(e.currentTarget.value)}
      />
      <FetchState
        loading={plan.loading && !plan()}
        error={errorOf(plan())}
        onRetry={async () => {
          await refetch();
        }}
      >
        <Show
          when={current()?.plan}
          fallback={<p class="mt-3 text-sm text-zinc-500">{t("runtime.faultPlanNone")}</p>}
        >
          {(p) => (
            <table class="table mt-3" data-testid="fault-rules">
              <thead>
                <tr>
                  <th>{t("runtime.operation")}</th>
                  <th>{t("runtime.nth")}</th>
                  <th>{t("runtime.function")}</th>
                  <th>{t("runtime.action")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={p().rules}>
                  {(r) => (
                    <tr>
                      <td class="mono">{r.match.operation}</td>
                      <td>{r.match.nth ?? ""}</td>
                      <td class="mono">{r.match.function ?? ""}</td>
                      <td class="mono">{JSON.stringify(r.action)}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          )}
        </Show>
        <div class="mt-3">
          <div class="label">{t("runtime.fired")}</div>
          <Show
            when={(current()?.fired.length ?? 0) > 0}
            fallback={<p class="text-sm text-zinc-500">{t("runtime.noneFired")}</p>}
          >
            <ul class="mono">
              <For each={current()?.fired ?? []}>
                {(f) => (
                  <li>
                    {f.operation} #{f.occurrence} {f.function ?? ""} {f.action}
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </div>
      </FetchState>
    </Section>
  );
};

const SessionsPanel: Component = () => {
  const [project, setProject] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const create = async () => {
    setError(null);
    const r = await createSession(project());
    r.match(
      () => {
        setProject("");
        void appState.refreshClock();
      },
      (e) => setError(e.message),
    );
  };
  return (
    <Section title={t("runtime.sessions")}>
      <ErrorBanner message={error()} />
      <div class="mb-3 flex flex-wrap items-end gap-2">
        <label class="text-sm">
          <span class="label">{t("runtime.sessionProject")}</span>
          <input
            class="input w-48"
            data-testid="session-project"
            placeholder="demo-b"
            value={project()}
            onInput={(e) => setProject(e.currentTarget.value)}
          />
        </label>
        <AsyncButton class="btn btn-primary" onClick={create} testId="session-create">
          {t("runtime.newSession")}
        </AsyncButton>
      </div>
      <table class="table" data-testid="session-table">
        <thead>
          <tr>
            <th>{t("runtime.sessionName")}</th>
            <th>{t("runtime.sessionProject")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <For each={appState.sessions()}>
            {(s) => (
              <tr>
                <td class="mono">
                  <label class="flex items-center gap-2">
                    <input
                      type="radio"
                      name="session"
                      checked={appState.session() === s.name}
                      onChange={() => appState.setSession(s.name)}
                    />
                    {s.name}
                  </label>
                </td>
                <td class="mono">{s.project}</td>
                <td class="space-x-2 text-right">
                  <ConfirmButton
                    class="btn"
                    label={t("runtime.reset")}
                    question={t("runtime.resetConfirm", { name: s.name, project: s.project })}
                    details={t("runtime.resetDetails")}
                    testId={`session-reset-${s.name}`}
                    onConfirm={async () => {
                      const r = await resetSession(s.name);
                      r.match(
                        () => void appState.refreshClock(),
                        (e) => setError(e.message),
                      );
                    }}
                  />
                  <Show when={s.name !== "default"}>
                    <ConfirmButton
                      label={t("app.delete")}
                      question={t("runtime.deleteSessionConfirm", { name: s.name })}
                      testId={`session-delete-${s.name}`}
                      onConfirm={async () => {
                        const r = await deleteSession(s.name);
                        r.match(
                          () => {
                            if (appState.session() === s.name) {
                              appState.setSession("default");
                            }
                            void appState.refreshClock();
                          },
                          (e) => setError(e.message),
                        );
                      }}
                    />
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </Section>
  );
};

const ServiceResourcesView: Component<{ service: ServiceResources }> = (props) => (
  <div class="mb-4" data-testid={`resources-${props.service.service}`}>
    <h3 class="mb-1 font-semibold">
      {props.service.service}
      <Show when={props.service.roots.truncated}>
        <span class="ml-2 text-xs font-normal text-amber-700 dark:text-amber-300">
          {t("runtime.resourcesTruncated", {
            shown: String(props.service.roots.items.length),
            total: String(props.service.roots.total),
          })}
        </span>
      </Show>
    </h3>
    <table class="table">
      <thead>
        <tr>
          <th>{t("runtime.gauge")}</th>
          <th>{t("runtime.measure")}</th>
          <th class="text-right">{t("runtime.current")}</th>
          <th class="text-right">{t("runtime.limit")}</th>
          <th class="text-right">{t("runtime.reclaimable")}</th>
        </tr>
      </thead>
      <tbody>
        <For each={props.service.gauges}>
          {(gauge) => (
            <tr>
              <td class="mono">{gauge.id}</td>
              <td>{gauge.measure}</td>
              <td class="mono text-right">{formatQuantity(gauge.current, gauge.unit)}</td>
              <td class="mono text-right">
                {gauge.limit === null ? "" : formatQuantity(gauge.limit, gauge.unit)}
                <Show when={saturation(gauge) !== null}>
                  <span class="ml-1 text-xs text-zinc-500">({saturation(gauge)}%)</span>
                </Show>
              </td>
              <td class="mono text-right">
                {gauge.reclaimable > 0 ? formatQuantity(gauge.reclaimable, gauge.unit) : ""}
              </td>
            </tr>
          )}
        </For>
      </tbody>
    </table>
    <Show when={props.service.refusals.some((r) => r.count > 0)}>
      <div class="mt-2 text-sm">
        <span class="label">{t("runtime.refusals")}</span>
        <ul class="mono">
          <For each={props.service.refusals.filter((r) => r.count > 0)}>
            {(refusal) => (
              <li>
                {refusal.reason}: {refusal.count}
              </li>
            )}
          </For>
        </ul>
      </div>
    </Show>
    <div class="mt-2 text-sm">
      <span class="label">{t("runtime.roots")}</span>
      <Show
        when={props.service.roots.items.length > 0}
        fallback={<p class="text-sm text-zinc-500">{t("runtime.noRoots")}</p>}
      >
        <table class="table">
          <thead>
            <tr>
              <th>{t("runtime.rootKind")}</th>
              <th>{t("runtime.rootId")}</th>
              <th class="text-right">{t("runtime.rootCount")}</th>
              <th class="text-right">{t("runtime.rootBytes")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.service.roots.items}>
              {(root) => (
                <tr data-outstanding={root.outstanding ? "true" : "false"}>
                  <td class="mono">
                    {root.kind}
                    <Show when={root.outstanding}>
                      <span class="ml-1 rounded bg-amber-100 px-1 text-xs text-amber-900 dark:bg-amber-900 dark:text-amber-100">
                        {t("runtime.outstanding")}
                      </span>
                    </Show>
                  </td>
                  <td class="mono break-all">{root.id}</td>
                  <td class="mono text-right">{root.count}</td>
                  <td class="mono text-right">{formatQuantity(root.bytes, "bytes")}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </div>
  </div>
);

const QuiescenceView: Component<{ result: QuiescenceResult }> = (props) => (
  <Show
    when={!props.result.quiescent && props.result}
    fallback={
      <Notice
        message={t("runtime.quiescent", {
          allowed: String(props.result.quiescent ? props.result.allowed : 0),
        })}
      />
    }
  >
    {(failure) => (
      <div
        class="mb-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100"
        role="status"
        data-testid="quiescence-failure"
      >
        <div class="font-semibold">{t("runtime.notQuiescent")}</div>
        <Show when={failure().leaks.length > 0}>
          <div class="mt-1">{t("runtime.leaks")}</div>
          <ul class="mono">
            <For each={failure().leaks}>
              {(leak) => (
                <li>
                  {leak.service} {leak.kind} {leak.id} ({leak.count},{" "}
                  {formatQuantity(leak.bytes, "bytes")})
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={failure().staleAllowances.length > 0}>
          <div class="mt-1">{t("runtime.staleAllowances")}</div>
          <ul class="mono">
            <For each={failure().staleAllowances}>
              {(stale) => (
                <li>
                  {stale.service} {stale.kind} {stale.id}
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={failure().truncatedServices.length > 0}>
          <div class="mt-1">
            {t("runtime.truncatedServices")}: {failure().truncatedServices.join(", ")}
          </div>
        </Show>
      </div>
    )}
  </Show>
);

const ResourcesPanel: Component = () => {
  const session = appState.session;
  const [report, { refetch }] = createResource(session, (s) => settle(sessionResources(s)));
  const [allowances, setAllowances] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [quiescence, setQuiescence] = createSignal<QuiescenceResult | null>(null);
  const assert = async () => {
    setError(null);
    setQuiescence(null);
    const parsed = parseAllowances(allowances());
    if (!parsed.ok) {
      setError(t("runtime.allowancesBadLine", { line: String(parsed.line) }));
      return;
    }
    const r = await assertQuiescent(session(), parsed.allow);
    r.match(
      (result) => {
        setQuiescence(result);
        void refetch();
      },
      (e) => setError(e.message),
    );
  };
  const current = () => report()?.unwrapOr(null) ?? null;
  return (
    <Section
      title={t("runtime.resources")}
      actions={
        <>
          <AsyncButton
            class="btn"
            onClick={async () => {
              await refetch();
            }}
            testId="resources-refresh"
          >
            {t("runtime.resourcesRefresh")}
          </AsyncButton>
          <AsyncButton class="btn btn-primary" onClick={assert} testId="resources-assert">
            {t("runtime.assertQuiescent")}
          </AsyncButton>
        </>
      }
    >
      <p class="mb-3 text-sm text-zinc-600 dark:text-zinc-300">{t("runtime.resourcesIntro")}</p>
      <ErrorBanner message={error()} />
      <Show when={quiescence()}>{(result) => <QuiescenceView result={result()} />}</Show>
      <label class="text-sm">
        <span class="label">{t("runtime.allowances")}</span>
        <textarea
          class="input mono h-20 w-full"
          data-testid="resources-allowances"
          spellcheck={false}
          value={allowances()}
          onInput={(e) => setAllowances(e.currentTarget.value)}
        />
      </label>
      <FetchState
        loading={report.loading && !current()}
        error={errorOf(report())}
        onRetry={async () => {
          await refetch();
        }}
      >
        <Show when={current()}>
          {(r) => (
            <div class="mt-3" data-testid="resources-report">
              <Show when={!r().complete}>
                <ErrorBanner
                  message={t("runtime.resourcesIncomplete", {
                    services: r()
                      .errors.map((e) => `${e.service}: ${e.message}`)
                      .join("; "),
                  })}
                />
              </Show>
              <For each={r().services}>
                {(service) => <ServiceResourcesView service={service} />}
              </For>
            </div>
          )}
        </Show>
      </FetchState>
    </Section>
  );
};

const Runtime: Component = () => (
  <div>
    <h1 class="mb-4 text-xl font-bold">{t("runtime.title")}</h1>
    <div
      class="mb-4 rounded-md border border-sky-300 bg-sky-50 p-3 text-sm text-sky-900 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-100"
      role="note"
      data-testid="runtime-fireemu-only"
    >
      {t("runtime.fireemuOnly")}
    </div>
    <div class="grid gap-4 xl:grid-cols-2">
      <div>
        <ClockPanel />
        <SessionsPanel />
      </div>
      <div>
        <SnapshotsPanel />
        <FaultPlanPanel />
      </div>
    </div>
    <ResourcesPanel />
  </div>
);

export default Runtime;
