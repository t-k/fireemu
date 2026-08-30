import { A, type RouteSectionProps } from "@solidjs/router";
import { For, Show, onCleanup, onMount, type Component } from "solid-js";
import { t, type MessageKey } from "./i18n";
import { appState } from "./state";

const NAV: { href: string; key: MessageKey }[] = [
  { href: "/", key: "nav.overview" },
  { href: "/firestore", key: "nav.firestore" },
  { href: "/auth", key: "nav.auth" },
  { href: "/storage", key: "nav.storage" },
  { href: "/functions", key: "nav.functions" },
  { href: "/rules", key: "nav.rules" },
  { href: "/appcheck", key: "nav.appCheck" },
  { href: "/runtime", key: "nav.runtime" },
];

/** The frame: sidebar navigation, a status bar with the clock, the routed page. */
export const App: Component<RouteSectionProps> = (props) => {
  onMount(() => {
    void appState.refreshClock();
    const timer = window.setInterval(() => void appState.refreshClock(), 5000);
    onCleanup(() => window.clearInterval(timer));
  });
  return (
    <div class="flex min-h-screen">
      <aside class="w-56 shrink-0 border-r border-zinc-200 bg-zinc-100 p-3 dark:border-zinc-800 dark:bg-zinc-900">
        <div class="mb-4 px-3">
          <div class="text-lg font-bold">{t("app.title")}</div>
          <div class="text-xs text-zinc-500">{t("app.subtitle")}</div>
        </div>
        <nav class="space-y-0.5" aria-label={t("app.subtitle")}>
          <For each={NAV}>
            {(item) => (
              <A href={item.href} class="nav-link" end={item.href === "/"}>
                {t(item.key)}
              </A>
            )}
          </For>
        </nav>
        <div class="mt-6 px-3 text-xs text-zinc-500">
          <div class="label">{t("overview.project")}</div>
          <div class="mono break-all">{appState.project()}</div>
          <div class="label mt-2">{t("overview.clock")}</div>
          <div class="mono" data-testid="clock">
            {appState.clock()}
          </div>
        </div>
      </aside>
      <main class="min-w-0 flex-1 p-6">
        <Show when={!appState.config().controlToken}>
          <div class="mb-4 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-900/30 dark:text-amber-100">
            {t("app.tokenMissing")}
          </div>
        </Show>
        {props.children}
      </main>
    </div>
  );
};
