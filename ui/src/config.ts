// The runtime configuration the daemon injects into index.html (`window.__FTD__`). During
// `vite` development nothing is injected; the token then comes from `?token=` or storage.

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
  uiBundled: boolean;
  sessions: Session[];
  controlToken: string;
};

declare global {
  interface Window {
    __FTD__?: Partial<RuntimeConfig>;
  }
}

const STORAGE_KEY = "ftd.controlToken";

const tokenFromLocation = (): string | null => {
  try {
    const url = new URL(window.location.href);
    const token = url.searchParams.get("token");
    if (token) {
      window.localStorage.setItem(STORAGE_KEY, token);
      return token;
    }
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};

const injected = (): Partial<RuntimeConfig> => window.__FTD__ ?? {};

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
    uiBundled: c.uiBundled ?? true,
    sessions: c.sessions ?? [],
    controlToken: controlToken(),
  };
};
