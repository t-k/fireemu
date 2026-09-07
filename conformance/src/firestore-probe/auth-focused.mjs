// Focused ID-token audience observation. Firestore requests are GET-only; no database reset.
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { withAnonymousUser } from "./credentials.mjs";

const PROJECT_ID = /^[a-z][a-z0-9-]{4,61}[a-z0-9]$/;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const CODES = new Set([
  "OK",
  "CANCELLED",
  "UNKNOWN",
  "INVALID_ARGUMENT",
  "DEADLINE_EXCEEDED",
  "NOT_FOUND",
  "ALREADY_EXISTS",
  "PERMISSION_DENIED",
  "RESOURCE_EXHAUSTED",
  "FAILED_PRECONDITION",
  "ABORTED",
  "OUT_OF_RANGE",
  "UNIMPLEMENTED",
  "INTERNAL",
  "UNAVAILABLE",
  "DATA_LOSS",
  "UNAUTHENTICATED",
]);

export function readProbeConfig(env) {
  const target = env.FIRESTORE_AUTH_PROBE_TARGET;
  if (!["local", "production"].includes(target))
    throw new Error("A local or production target is required");
  const project = env.FIRESTORE_AUTH_PROBE_PROJECT;
  const foreignProject = env.FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT;
  if (!PROJECT_ID.test(project ?? "")) throw new Error("A valid own project ID is required");
  if (
    foreignProject !== undefined &&
    (!PROJECT_ID.test(foreignProject) || foreignProject === project)
  ) {
    throw new Error("The foreign project must be a different valid project ID");
  }
  const firestoreBase =
    env.FIRESTORE_AUTH_PROBE_FIRESTORE_BASE ??
    (target === "production" ? "https://firestore.googleapis.com" : "");
  const authBase =
    env.FIRESTORE_AUTH_PROBE_AUTH_BASE ??
    (target === "production" ? "https://identitytoolkit.googleapis.com" : "");
  for (const [base, productionHost] of [
    [firestoreBase, "firestore.googleapis.com"],
    [authBase, "identitytoolkit.googleapis.com"],
  ]) {
    let endpoint;
    try {
      endpoint = new URL(base);
    } catch {
      throw new Error("A valid probe endpoint is required");
    }
    if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
      throw new Error("Probe endpoints cannot include credentials, queries or fragments");
    }
    if (target === "production") {
      if (
        endpoint.protocol !== "https:" ||
        endpoint.host !== productionHost ||
        endpoint.pathname !== "/"
      ) {
        throw new Error("Production probes require the official HTTPS endpoints");
      }
    } else if (endpoint.protocol !== "http:" || !LOCAL_HOSTS.has(endpoint.hostname)) {
      throw new Error("Local probes require loopback HTTP endpoints");
    }
  }
  return {
    target,
    project,
    foreignProject,
    foreignProjectActive: env.FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT_ACTIVE === "1",
    firestoreBase: firestoreBase.replace(/\/$/, ""),
    authBase: authBase.replace(/\/$/, ""),
  };
}

// Decode only to verify the API key selected the intended project. Token validation
// and signature verification remain the responsibility of the actual Firestore server.
export function requireOwnAudience(token, project) {
  let claims;
  try {
    claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("Identity Toolkit returned an unreadable ID token");
  }
  if (claims.aud !== project)
    throw new Error("Identity Toolkit token does not belong to the own project");
}

export function sanitizedObservation(status, body) {
  const error = body?.error;
  const code =
    status >= 200 && status < 300
      ? "OK"
      : CODES.has(error?.status)
        ? error.status
        : "unknown-response";
  const disabled = /has not been used|it is disabled|SERVICE_DISABLED|API_DISABLED/i.test(
    JSON.stringify(error ?? {}),
  );
  return { status, code, servicePrecondition: disabled ? "api-unavailable" : "not-observed" };
}

export function buildReport(config, observations) {
  const foreign = observations.foreignProject;
  const decisive = Boolean(
    config.foreignProject &&
    config.foreignProjectActive &&
    foreign &&
    foreign.servicePrecondition === "not-observed" &&
    foreign.code !== "unknown-response",
  );
  return {
    target: config.target,
    credential: {
      kind: "user",
      provider: "anonymous",
      issuance: "identity-toolkit",
      ownAudienceChecked: true,
    },
    observations,
    crossProject: {
      status: decisive ? "observed" : "unverified",
      reason: !config.foreignProject
        ? "No second active project was supplied"
        : !config.foreignProjectActive
          ? "Second-project API activation was not independently confirmed"
          : foreign?.servicePrecondition === "api-unavailable"
            ? "Google API activation rejected the request before audience verification"
            : !decisive
              ? "No interpretable cross-project response was obtained"
              : "An ID-token observation was recorded; compare separately with the other target",
    },
  };
}

async function observe(base, project, token) {
  // A fixed missing-document path avoids listing or recording application data.
  const response = await fetch(
    `${base}/v1/projects/${encodeURIComponent(project)}/databases/(default)/documents/fireemu_auth_scope_probe/missing`,
    {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    },
  );
  let body;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return sanitizedObservation(response.status, body);
}

export async function runFocusedProbe(env = process.env) {
  const config = readProbeConfig(env);
  const apiKey =
    env.FIRESTORE_AUTH_PROBE_API_KEY ??
    (env.FIRESTORE_AUTH_PROBE_API_KEY_FILE
      ? (await readFile(env.FIRESTORE_AUTH_PROBE_API_KEY_FILE, "utf8")).trim()
      : undefined);
  return withAnonymousUser({ base: config.authBase, apiKey }, async (token) => {
    requireOwnAudience(token, config.project);
    const observations = { ownProject: await observe(config.firestoreBase, config.project, token) };
    if (config.foreignProject) {
      observations.foreignProject = await observe(
        config.firestoreBase,
        config.foreignProject,
        token,
      );
    }
    return buildReport(config, observations);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.stdout.write(`${JSON.stringify(await runFocusedProbe(), null, 2)}\n`);
  } catch {
    // Network/API errors may contain URLs or credentials. Keep CLI output sanitized.
    process.stderr.write(
      "Focused Auth probe failed; no verified report was produced. Check endpoint, API key, anonymous sign-up and exact-user cleanup availability.\n",
    );
    process.exitCode = 1;
  }
}
