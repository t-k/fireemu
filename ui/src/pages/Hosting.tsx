import { createResource, For, Show, type Component, type JSX } from "solid-js";
import { hostingInfo, type HostingRule } from "../api/hosting";
import { errorOf, settle } from "../api/client";
import { AsyncButton, FetchState, Field, Section } from "../components/common";
import { t, type MessageKey } from "../i18n";
import {
  redirectTarget,
  rewriteTarget,
  ruleHeaders,
  ruleMatcher,
  type RewriteTarget,
} from "../lib/hosting";

const rewriteText = (target: RewriteTarget): string => {
  switch (target.kind) {
    case "file":
      return target.destination;
    case "none":
      return "-";
    default: {
      const label = target.kind === "function" ? t("hosting.function") : t("hosting.cloudRun");
      return `${label} ${target.id}${target.region === null ? "" : ` (${target.region})`}`;
    }
  }
};

/** The `#`, matcher kind and pattern cells every rule row starts with. */
const MatcherCells: Component<{ index: number; rule: HostingRule }> = (props) => {
  const matcher = () => ruleMatcher(props.rule);
  return (
    <>
      <td>{props.index + 1}</td>
      <td>{matcher().kind === "none" ? "-" : matcher().kind}</td>
      <td class="mono">
        {(() => {
          const m = matcher();
          return m.kind === "none" ? "-" : m.pattern;
        })()}
      </td>
    </>
  );
};

/** One rule list as a table, or the sentence saying there is none. */
const RuleTable: Component<{
  kind: "rewrites" | "redirects" | "headers";
  title: MessageKey;
  none: MessageKey;
  rules: HostingRule[] | undefined;
  columns: MessageKey[];
  ordered?: boolean;
  cells: (rule: HostingRule) => JSX.Element;
}> = (props) => (
  <Section title={t(props.title)}>
    <Show when={props.ordered}>
      <p class="mb-2 text-sm text-zinc-500">{t("hosting.orderHint")}</p>
    </Show>
    <Show
      when={(props.rules?.length ?? 0) > 0}
      fallback={<p data-testid={`hosting-${props.kind}-none`}>{t(props.none)}</p>}
    >
      <table class="table" data-testid={`hosting-${props.kind}`}>
        <thead>
          <tr>
            <th>#</th>
            <th>{t("hosting.matcher")}</th>
            <th>{t("hosting.pattern")}</th>
            <For each={props.columns}>{(column) => <th>{t(column)}</th>}</For>
          </tr>
        </thead>
        <tbody>
          <For each={props.rules}>
            {(rule, index) => (
              <tr>
                <MatcherCells index={index()} rule={rule} />
                {props.cells(rule)}
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </Show>
  </Section>
);

const slashText = (trailingSlash: boolean | undefined): string => {
  if (trailingSlash === undefined) return t("hosting.slashUnchanged");
  return trailingSlash ? t("hosting.slashAdded") : t("hosting.slashRemoved");
};

const Hosting: Component = () => {
  const [info, { refetch }] = createResource(() => settle(hostingInfo()));
  const refresh = async () => {
    await refetch();
  };
  // The last successful read, so a failed refresh keeps showing it (with the error).
  const current = () => info.latest?.unwrapOr(undefined);
  const site = () => {
    const value = current();
    return value?.served ? value : undefined;
  };
  return (
    <div>
      <div class="mb-4 flex items-center justify-between">
        <h1 class="text-xl font-bold">{t("hosting.title")}</h1>
        <AsyncButton testId="hosting-refresh" onClick={refresh}>
          {t("app.refresh")}
        </AsyncButton>
      </div>
      <FetchState
        loading={info.loading && current() === undefined}
        error={current() === undefined ? errorOf(info()) : null}
        stale={current() === undefined ? null : errorOf(info())}
        onRetry={refresh}
      >
        <Show when={current()?.served === false}>
          <p class="card" data-testid="hosting-not-served">
            {t("hosting.notServed")}
          </p>
        </Show>
        <Show when={site()}>
          {(served) => (
            <>
              <Section title={t("hosting.site")}>
                <Field label={t("hosting.url")}>
                  <a
                    data-testid="hosting-url"
                    href={served().url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {served().url}
                  </a>
                </Field>
                <Field label={t("hosting.public")}>
                  <span class="mono" data-testid="hosting-public">
                    {served().site.public}
                  </span>
                </Field>
                <Field label={t("hosting.publicRoot")}>
                  <span class="mono" data-testid="hosting-public-root">
                    {served().publicRoot}
                  </span>
                </Field>
                <Show when={!served().publicExists}>
                  <p class="mb-2 text-sm text-amber-700" data-testid="hosting-public-missing">
                    {t("hosting.publicMissing")}
                  </p>
                </Show>
                <Field label={t("hosting.cleanUrls")}>
                  <span data-testid="hosting-clean-urls">
                    {served().site.cleanUrls ? t("app.yes") : t("app.no")}
                  </span>
                </Field>
                <Field label={t("hosting.trailingSlash")}>
                  <span data-testid="hosting-trailing-slash">
                    {slashText(served().site.trailingSlash)}
                  </span>
                </Field>
                <Show when={served().site.i18n?.root}>
                  {(root) => (
                    <Field label={t("hosting.i18nRoot")}>
                      <span class="mono" data-testid="hosting-i18n-root">
                        {root()}
                      </span>
                    </Field>
                  )}
                </Show>
                <Show when={served().site.appAssociation}>
                  {(association) => (
                    <Field label={t("hosting.appAssociation")}>
                      <span data-testid="hosting-app-association">{association()}</span>
                    </Field>
                  )}
                </Show>
                <Show when={(served().site.ignore?.length ?? 0) > 0}>
                  <Field label={t("hosting.ignore")}>
                    <ul data-testid="hosting-ignore">
                      <For each={served().site.ignore}>
                        {(glob) => <li class="mono">{glob}</li>}
                      </For>
                    </ul>
                  </Field>
                </Show>
              </Section>
              <RuleTable
                kind="rewrites"
                title="hosting.rewrites"
                none="hosting.rewritesNone"
                rules={served().site.rewrites}
                columns={["hosting.target"]}
                ordered
                cells={(rule) => <td>{rewriteText(rewriteTarget(rule))}</td>}
              />
              <RuleTable
                kind="redirects"
                title="hosting.redirects"
                none="hosting.redirectsNone"
                rules={served().site.redirects}
                columns={["hosting.destination", "hosting.status"]}
                ordered
                cells={(rule) => (
                  <>
                    <td>{redirectTarget(rule).destination}</td>
                    <td>{redirectTarget(rule).status}</td>
                  </>
                )}
              />
              <RuleTable
                kind="headers"
                title="hosting.headers"
                none="hosting.headersNone"
                rules={served().site.headers}
                columns={["hosting.headers"]}
                cells={(rule) => (
                  <td>
                    <For each={ruleHeaders(rule)}>
                      {(header) => (
                        <div>
                          {header.key}: {header.value}
                        </div>
                      )}
                    </For>
                  </td>
                )}
              />
            </>
          )}
        </Show>
      </FetchState>
    </div>
  );
};

export default Hosting;
