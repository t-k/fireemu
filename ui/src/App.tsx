import { A, type RouteSectionProps } from "@solidjs/router";
import { For, Show, onCleanup, onMount, type Component } from "solid-js";
import { t, type MessageKey } from "./i18n";
import { appState } from "./state";

type NavItem = { href: string; key: MessageKey };

// The official Emulator Suite products, then the fireemu-only deterministic runtime controls,
// kept in a visually and semantically separate group so the two are never conflated.
const OFFICIAL_NAV: NavItem[] = [
  { href: "/", key: "nav.overview" },
  { href: "/firestore", key: "nav.firestore" },
  { href: "/auth", key: "nav.auth" },
  { href: "/storage", key: "nav.storage" },
  { href: "/functions", key: "nav.functions" },
  { href: "/alerts", key: "nav.alerts" },
  { href: "/rules", key: "nav.rules" },
  { href: "/appcheck", key: "nav.appCheck" },
];
const RUNTIME_NAV: NavItem[] = [{ href: "/runtime", key: "nav.runtime" }];

/** The frame: sidebar navigation, a status bar with the clock, the routed page. */
export const App: Component<RouteSectionProps> = (props) => {
  onMount(() => {
    void appState.refreshClock();
    const timer = window.setInterval(() => void appState.refreshClock(), 5000);
    onCleanup(() => window.clearInterval(timer));
  });
  const connectionClass = () => {
    switch (appState.connected()) {
      case true:
        return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100";
      case false:
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100";
      default:
        return "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
    }
  };
  const connectionLabel = () => {
    switch (appState.connected()) {
      case true:
        return t("header.connected");
      case false:
        return t("header.disconnected");
      default:
        return t("header.connecting");
    }
  };
  return (
    <div class="flex min-h-screen">
      <aside class="w-44 shrink-0 border-r border-zinc-200 bg-zinc-100 p-3 lg:w-56 dark:border-zinc-800 dark:bg-zinc-900">
        <div class="mb-4 px-3">
          <div class="text-lg font-bold">{t("app.title")}</div>
          <div class="text-xs text-zinc-500">{t("app.subtitle")}</div>
        </div>
        <nav class="space-y-0.5" aria-label={t("nav.sectionOfficial")}>
          <For each={OFFICIAL_NAV}>
            {(item) => (
              <A href={item.href} class="nav-link" end={item.href === "/"}>
                {t(item.key)}
              </A>
            )}
          </For>
        </nav>
        <div class="mt-5 mb-1 px-3 text-xs font-semibold tracking-wide text-zinc-400 uppercase">
          {t("nav.sectionRuntime")}
        </div>
        <nav class="space-y-0.5" aria-label={t("nav.sectionRuntime")}>
          <For each={RUNTIME_NAV}>
            {(item) => (
              <A href={item.href} class="nav-link" end={false}>
                {t(item.key)}
              </A>
            )}
          </For>
        </nav>
      </aside>
      <div class="flex min-w-0 flex-1 flex-col">
        {/* Where every action lands: the target the pages act on, and whether the daemon answers. */}
        <header
          class="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-zinc-200 bg-white px-4 py-2 text-xs dark:border-zinc-800 dark:bg-zinc-900"
          data-testid="context-bar"
        >
          <span class="font-semibold text-zinc-600 dark:text-zinc-300">{t("header.local")}</span>
          <label class="flex items-center gap-1">
            <span class="label">{t("overview.session")}</span>
            <select
              class="input mono w-auto py-0.5"
              data-testid="session-select"
              value={appState.session()}
              onChange={(e) => {
                appState.setSession(e.currentTarget.value);
                void appState.refreshClock();
              }}
            >
              <For each={appState.sessions()}>
                {(s) => <option value={s.name}>{s.name}</option>}
              </For>
            </select>
          </label>
          <span class="flex items-center gap-1">
            <span class="label">{t("overview.project")}</span>
            <span class="mono break-all" data-testid="header-project">
              {appState.project()}
            </span>
          </span>
          <span class="flex items-center gap-1">
            <span class="label">{t("overview.clock")}</span>
            <span class="mono" data-testid="clock">
              {appState.clock()}
            </span>
            <span class="text-zinc-500">
              ({appState.config().clockPinned ? t("overview.clockPinned") : t("overview.clockWall")}
              )
            </span>
          </span>
          <span class={`badge ${connectionClass()}`} data-testid="connection-badge">
            {connectionLabel()}
          </span>
        </header>
        <main class="min-w-0 flex-1 p-4 lg:p-6">
          <Show when={!appState.config().controlToken}>
            <div class="mb-4 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-900/30 dark:text-amber-100">
              {t("app.tokenMissing")}
            </div>
          </Show>
          {props.children}
        </main>
      </div>
    </div>
  );
};
