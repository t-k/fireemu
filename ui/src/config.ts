// The runtime configuration the daemon injects into index.html (`window.__FIREEMU__`). During
// `vite` development nothing is injected; the token then comes from `?token=` in the page
// URL and is kept in memory only (never in storage another script could read later).

export type Session = { name: string; project: string };

export type RuntimeConfig = {
  version: string;
  project: string;
  edition: string;
  firestoreAddr: string;
  httpAddr: string;
  storageAddr: string;
  functionsAddr: string | null;
  functionsSource: string | null;
  uiAddr: string;
  rulesEnforced: boolean;
  clockPinned: boolean;
  functionsConfigured: boolean;
  appCheckEnabled: boolean;
  uiBundled: boolean;
  sessions: Session[];
  controlToken: string;
};

declare global {
  interface Window {
    __FIREEMU__?: Partial<RuntimeConfig>;
  }
}

let developmentToken: string | null = null;

const tokenFromLocation = (): string | null => {
  if (developmentToken !== null) {
    return developmentToken;
  }
  try {
    const url = new URL(window.location.href);
    const token = url.searchParams.get("token");
    if (token) {
      developmentToken = token;
      // Leave the URL without the token so it does not stay in the history.
      url.searchParams.delete("token");
      window.history.replaceState(null, "", url.toString());
      return token;
    }
    return null;
  } catch {
    return null;
  }
};

const injected = (): Partial<RuntimeConfig> => window.__FIREEMU__ ?? {};

/** The control token every API request presents (empty when unknown). */
export const controlToken = (): string => injected().controlToken ?? tokenFromLocation() ?? "";

/** The injected configuration with safe defaults for a development page. */
export const initialConfig = (): RuntimeConfig => {
  const c = injected();
  return {
    version: c.version ?? "",
    project: c.project ?? "",
    edition: c.edition ?? "standard",
    firestoreAddr: c.firestoreAddr ?? "",
    httpAddr: c.httpAddr ?? "",
    storageAddr: c.storageAddr ?? "",
    functionsAddr: c.functionsAddr ?? null,
    functionsSource: c.functionsSource ?? null,
    uiAddr: c.uiAddr ?? "",
    rulesEnforced: c.rulesEnforced ?? true,
    clockPinned: c.clockPinned ?? false,
    functionsConfigured: c.functionsConfigured ?? false,
    appCheckEnabled: c.appCheckEnabled ?? false,
    uiBundled: c.uiBundled ?? true,
    sessions: c.sessions ?? [],
    controlToken: controlToken(),
  };
};
