import { createMemo, createRoot, createSignal } from "solid-js";
import { initialConfig, type RuntimeConfig, type Session } from "./config";
import { sessionInfo, listSessions } from "./api/control";

/** App-wide reactive state: the runtime configuration, the clock, the sessions. */
const store = createRoot(() => {
  const [config, setConfig] = createSignal<RuntimeConfig>(initialConfig());
  const [clock, setClock] = createSignal<string>("");
  const [sessions, setSessionSnapshot] = createSignal<Session[]>(initialConfig().sessions);
  // Keep row-local forms for unchanged targets, but discard them for a replacement project.
  const setSessions = (snapshot: Session[]) => {
    const before = project();
    setSessionSnapshot((previous) =>
      snapshot.map(
        (next) =>
          previous.find((old) => old.name === next.name && old.project === next.project) ?? next,
      ),
    );
    if (before !== project()) resetPoll();
  };
  const [session, setSelectedSession] = createSignal<string>("default");
  let pollEpoch = 0;
  let completedEpoch = 0;
  const [lastConnectedAt, setLastConnectedAt] = createSignal<string | null>(null);
  const setSession = (name: string) => {
    if (name === session()) return;
    setSelectedSession(name);
    resetPoll();
  };
  const resetPoll = () => {
    completedEpoch = ++pollEpoch;
    setConnected(null);
    setLastConnectedAt(null);
    setClock("");
  };
  /** Whether the last poll of the daemon answered (null until the first one). */
  const [connected, setConnected] = createSignal<boolean | null>(null);

  /** The project of the selected session. */
  // Polling must not invalidate consumers when the selected project is unchanged.
  const project = createMemo(
    () => sessions().find((s) => s.name === session())?.project ?? config().project,
  );

  /** Re-reads the clock (and the session list) from the daemon. */
  const refreshClock = async (): Promise<void> => {
    const mine = ++pollEpoch;
    const selected = session();
    const selectedProject = project();
    const [info, list] = await Promise.all([sessionInfo(selected), listSessions()]);
    if (mine <= completedEpoch || selected !== session() || selectedProject !== project()) return;
    list.map((l) => setSessions(l.sessions));
    if (mine <= completedEpoch) return;
    completedEpoch = mine;
    info.map((i) => setClock(i.clock.clock));
    const answered = info.isOk() && list.isOk();
    if (answered) setLastConnectedAt(new Date().toISOString());
    setConnected(answered);
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
    lastConnectedAt,
    refreshClock,
  };
});

export const appState = store;
