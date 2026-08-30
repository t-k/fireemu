import type { ResultAsync } from "neverthrow";
import { request, type ApiError, type Json } from "./client";

// The App Check surface of the UI API (specification sections 9 and 15). Nothing here ever
// carries a raw debug secret except the one creation response, which returns it exactly once.

/** One app of the static `appCheck.apps` registration. */
export type AppCheckApp = {
  appId: string;
  projectId: string;
  projectNumber: string;
  enabled: boolean;
  /** Digests that came from configuration. */
  staticDigestCount: number;
  /** Debug tokens registered through the management routes since the daemon started. */
  dynamicTokenCount: number;
};

/** The effective baseline mode of one service (`off`, `unenforced`, `enforced`). */
export type ServiceMode = { service: string; mode: string };

/** The read-only configuration summary: no digest, no secret, no epoch. */
export type AppCheckSummary = {
  enabled: boolean;
  kid: string | null;
  modes: ServiceMode[];
  tokenTtlSeconds?: number;
  apps: AppCheckApp[];
};

/** One dynamic debug-token registration, as a list shows it. */
export type DebugTokenRecord = {
  tokenId: string;
  displayName: string;
  createdAt: string;
  /** The leading bytes of the SHA-256 digest, enough to recognise an entry. */
  digestPrefix: string;
};

/** The creation response: the only place the raw secret ever appears. */
export type CreatedDebugToken = DebugTokenRecord & { debugToken: string };

/**
 * One counter of the selected session's project. The daemon keeps one ring and one set of
 * counters per project, so nothing here depends on what another project's traffic did, and
 * the counts include observations the ring has already dropped.
 */
export type AppCheckCounter = {
  service: string;
  appId: string;
  /** The callable name, for the `functions` service alone. */
  function: string | null;
  category: string;
  outcome: string;
  count: number;
};

export type AppCheckObservation = {
  service: string;
  transport: string;
  operation: string;
  mode: string;
  category: string;
  reason: string | null;
  appId: string;
  at: string;
  policyGeneration: number;
  admitted: boolean;
};

export type AppCheckObservations = {
  session: string;
  project: string;
  policyGeneration: number;
  counters: AppCheckCounter[];
  observations: AppCheckObservation[];
};

export const appCheckSummary = (project: string): ResultAsync<AppCheckSummary, ApiError> =>
  request<AppCheckSummary>("GET", `appcheck/config?project=${encodeURIComponent(project)}`);

const tokensPath = (project: string, appId: string): string =>
  `appcheck/projects/${encodeURIComponent(project)}/apps/${encodeURIComponent(appId)}/debugTokens`;

export const listDebugTokens = (
  project: string,
  appId: string,
): ResultAsync<{ debugTokens: DebugTokenRecord[] }, ApiError> =>
  request("GET", tokensPath(project, appId));

/**
 * Registers a debug token. `secret` is a canonical UUIDv4 the caller supplies; `null` asks
 * the daemon to draw one from the operating system CSPRNG. Either way the response carries
 * the raw secret exactly once and the registry keeps only its digest.
 */
export const createDebugToken = (
  project: string,
  appId: string,
  displayName: string,
  secret: string | null,
): ResultAsync<CreatedDebugToken, ApiError> =>
  request<CreatedDebugToken>(
    "POST",
    tokensPath(project, appId),
    secret === null ? { displayName, generate: true } : { displayName, debugToken: secret },
  );

export const deleteDebugToken = (
  project: string,
  appId: string,
  tokenId: string,
): ResultAsync<Json, ApiError> =>
  request("DELETE", `${tokensPath(project, appId)}/${encodeURIComponent(tokenId)}`);

export const appCheckObservations = (
  session: string,
): ResultAsync<AppCheckObservations, ApiError> =>
  request<AppCheckObservations>(
    "GET",
    `control/v1/sessions/${encodeURIComponent(session)}/appCheck/observations`,
  );
