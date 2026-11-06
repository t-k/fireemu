import { adminClient } from "../../../tools/sdk-smoke-database/cv11-genuine-auth.mjs";

export function createAuth({
  fetchImpl = fetch,
  adminFetch = fetchImpl,
  headers = {},
  projectId,
  apiKey,
  email,
  password,
  log,
  stop = {},
  secrets = [],
}) {
  let uid,
    idToken,
    state = "baseline",
    unknown = false,
    signedIn = false;
  const safeSecrets = [...secrets, apiKey, email, password];
  const admin = adminClient({
    fetchImpl: adminFetch,
    headers,
    log: (row) => log({ ...row, body: row.body === undefined ? undefined : "***" }),
    stop,
    secrets: safeSecrets,
  });
  const signInClient = adminClient({
    fetchImpl,
    headers: {},
    log: (row) =>
      log({
        ...row,
        url: row.url.replace(/([?&]key=)[^&]*/g, "$1***"),
        body: row.body === undefined ? undefined : "***",
      }),
    stop,
    secrets: safeSecrets,
  });
  const base = `https://identitytoolkit.googleapis.com/v1/projects/${encodeURIComponent(projectId)}`;
  return {
    get uid() {
      return uid;
    },
    get idToken() {
      return idToken;
    },
    get state() {
      return state;
    },
    async create() {
      if (unknown || state !== "baseline") throw Error("create unavailable");
      const r = await admin.call("user-create", "POST", `${base}/accounts`, { email, password });
      if (r.outcome === "ok" && typeof r.value?.localId === "string" && r.value.localId) {
        uid = r.value.localId;
        state = "live";
      } else if (r.outcome === "unknown" || r.outcome === "ok") {
        unknown = true;
        state = "unknown";
      } else state = "create-refused";
      return { outcome: state === "unknown" ? "unknown" : r.outcome, status: r.status };
    },
    async signIn() {
      if (unknown || state !== "live" || signedIn) throw Error("sign in unavailable");
      signedIn = true;
      const r = await signInClient.call(
        "user-sign-in",
        "POST",
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
        { email, password, returnSecureToken: true },
      );
      if (
        r.outcome === "ok" &&
        r.value?.localId === uid &&
        typeof r.value?.idToken === "string" &&
        r.value.idToken
      )
        idToken = r.value.idToken;
      return {
        outcome: idToken ? "ok" : r.outcome === "refused" ? "refused" : "unknown",
        status: r.status,
      };
    },
    async delete() {
      admin.cleanup();
      if (unknown || state !== "live") return "skipped";
      const r = await admin.call("user-delete", "POST", `${base}/accounts:delete`, {
        localId: uid,
      });
      if (r.outcome === "ok") state = "deleted";
      else if (r.outcome === "unknown") {
        unknown = true;
        state = "unknown";
      } else state = "delete-refused";
      return r.outcome;
    },
    async confirmGone() {
      if (state !== "deleted") return false;
      const r = await admin.call("user-gone", "POST", `${base}/accounts:lookup`, {
        localId: [uid],
      });
      if (r.outcome === "unknown") {
        unknown = true;
        state = "unknown";
      }
      if (r.outcome === "ok" && r.value && (!r.value.users || r.value.users.length === 0)) {
        state = "gone";
        return true;
      }
      return false;
    },
  };
}
