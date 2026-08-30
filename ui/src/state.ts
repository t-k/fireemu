import { createRoot, createSignal } from "solid-js";
import { initialConfig, type RuntimeConfig, type Session } from "./config";
import { sessionInfo, listSessions } from "./api/control";

/** App-wide reactive state: the runtime configuration, the clock, the sessions. */
const store = createRoot(() => {
  const [config, setConfig] = createSignal<RuntimeConfig>(initialConfig());
  const [clock, setClock] = createSignal<string>("");
  const [sessions, setSessions] = createSignal<Session[]>(initialConfig().sessions);
  const [session, setSession] = createSignal<string>("default");

  /** The project of the selected session. */
  const project = (): string =>
    sessions().find((s) => s.name === session())?.project ?? config().project;

  /** Re-reads the clock (and the session list) from the daemon. */
  const refreshClock = async (): Promise<void> => {
    const info = await sessionInfo(session());
    info.map((i) => setClock(i.clock.clock));
    const list = await listSessions();
    list.map((l) => setSessions(l.sessions));
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
    refreshClock,
  };
});

export const appState = store;
