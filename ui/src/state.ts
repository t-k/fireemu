import { createMemo, createRoot, createSignal } from "solid-js";
import { initialConfig, type RuntimeConfig, type Session } from "./config";
import { sessionInfo, listSessions } from "./api/control";

/** App-wide reactive state: the runtime configuration, the clock, the sessions. */
const store = createRoot(() => {
  const [config, setConfig] = createSignal<RuntimeConfig>(initialConfig());
  const [clock, setClock] = createSignal<string>("");
  const [sessions, setSessionSnapshot] = createSignal<Session[]>(initialConfig().sessions);
  // Keep row-local forms for unchanged targets, but discard them for a replacement project.
  const setSessions = (snapshot: Session[]) =>
    setSessionSnapshot((previous) =>
      snapshot.map(
        (next) =>
          previous.find((old) => old.name === next.name && old.project === next.project) ?? next,
      ),
    );
  const [session, setSession] = createSignal<string>("default");
  /** Whether the last poll of the daemon answered (null until the first one). */
  const [connected, setConnected] = createSignal<boolean | null>(null);

  /** The project of the selected session. */
  // Polling must not invalidate consumers when the selected project is unchanged.
  const project = createMemo(
    () => sessions().find((s) => s.name === session())?.project ?? config().project,
  );

  /** Re-reads the clock (and the session list) from the daemon. */
  const refreshClock = async (): Promise<void> => {
    const info = await sessionInfo(session());
    info.map((i) => setClock(i.clock.clock));
    const list = await listSessions();
    list.map((l) => setSessions(l.sessions));
    setConnected(info.isOk() && list.isOk());
  };

  return {
    config,
    setConfig,
    clock,
    setClock,
    sessions,
    setSessions,
    session,
    setSession,
    project,
    connected,
    refreshClock,
  };
});

export const appState = store;
