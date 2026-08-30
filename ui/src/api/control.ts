import type { ResultAsync } from "neverthrow";
import { request, type ApiError, type Json } from "./client";
import type { Session } from "../config";

export type ClockInfo = { clock: string; backwardsSets: number };
export type SessionInfo = {
  session: string;
  edition: string;
  requireDemoPrefix: boolean;
  clock: ClockInfo;
};
export type SnapshotInfo = { name: string; clock: string; parts: number };
export type FaultRule = {
  match: {
    operation: string;
    nth?: number | null;
    function?: string | null;
    eventType?: string | null;
  };
  action: { type: string; code?: string; seconds?: number; count?: number };
};
export type FaultPlanInfo = {
  session: string;
  plan: { seed: number; rules: FaultRule[] } | null;
  fired: { operation: string; occurrence: number; function: string | null; action: string }[];
  counters: Record<string, number>;
};
export type RulesInfo = { loaded: boolean; source: string };
export type FunctionsStatus = {
  pending: number;
  running: number;
  retryWaiting: number;
  succeeded: number;
  deadLettered: number;
  catchUpPending: boolean;
  overlapRejected: number;
  runnerAlive: boolean;
  epoch: number;
  functions: string[];
};

const base = (session: string): string => `control/v1/sessions/${encodeURIComponent(session)}`;

export const sessionInfo = (session: string): ResultAsync<SessionInfo, ApiError> =>
  request<SessionInfo>("GET", base(session));

export const listSessions = (): ResultAsync<{ sessions: Session[] }, ApiError> =>
  request("GET", "control/v1/sessions");

export const createSession = (project: string, name?: string): ResultAsync<Json, ApiError> =>
  request("POST", "control/v1/sessions", name ? { project, name } : { project });

export const resetSession = (session: string): ResultAsync<Json, ApiError> =>
  request("POST", `${base(session)}/reset`, {});

export const deleteSession = (session: string): ResultAsync<Json, ApiError> =>
  request("DELETE", base(session));

export const advanceClock = (session: string, seconds: number): ResultAsync<ClockInfo, ApiError> =>
  request<ClockInfo>("POST", `${base(session)}/clock:advance`, { seconds });

export const setClock = (
  session: string,
  instant: string,
  allowBackwards: boolean,
): ResultAsync<ClockInfo, ApiError> =>
  request<ClockInfo>("POST", `${base(session)}/clock:set`, { instant, allowBackwards });

export const listSnapshots = (
  session: string,
): ResultAsync<{ snapshots: SnapshotInfo[] }, ApiError> =>
  request("GET", `${base(session)}/snapshots`);

export const captureSnapshot = (
  session: string,
  name: string,
  allowNonQuiescent: boolean,
): ResultAsync<Json, ApiError> =>
  request("POST", `${base(session)}/snapshots`, { name, allowNonQuiescent });

export const restoreSnapshot = (session: string, name: string): ResultAsync<Json, ApiError> =>
  request("POST", `${base(session)}/snapshots/${encodeURIComponent(name)}:restore`, {});

export const deleteSnapshot = (session: string, name: string): ResultAsync<Json, ApiError> =>
  request("DELETE", `${base(session)}/snapshots/${encodeURIComponent(name)}`);

export const getFaultPlan = (session: string): ResultAsync<FaultPlanInfo, ApiError> =>
  request<FaultPlanInfo>("GET", `${base(session)}/faultPlan`);

export const installFaultPlan = (session: string, plan: unknown): ResultAsync<Json, ApiError> =>
  request("PUT", `${base(session)}/faultPlan`, plan);

export const clearFaultPlan = (session: string): ResultAsync<Json, ApiError> =>
  request("DELETE", `${base(session)}/faultPlan`);

const rulesPath = (which: "firestore" | "storage"): string =>
  which === "firestore" ? "control/v1/rules" : "control/v1/storage/rules";

export const getRules = (which: "firestore" | "storage"): ResultAsync<RulesInfo, ApiError> =>
  request<RulesInfo>("GET", rulesPath(which));

export const putRules = (
  which: "firestore" | "storage",
  source: string,
): ResultAsync<Json, ApiError> => request("PUT", rulesPath(which), { source });

export const dropRules = (which: "firestore" | "storage"): ResultAsync<Json, ApiError> =>
  request("DELETE", rulesPath(which));

export const functionsStatus = (session: string): ResultAsync<FunctionsStatus, ApiError> =>
  request<FunctionsStatus>("GET", `${base(session)}/functions`);

export const runSchedule = (session: string, name: string): ResultAsync<Json, ApiError> =>
  request("POST", `${base(session)}/functions/${encodeURIComponent(name)}:run`, {});

export const publishMessage = (
  session: string,
  topic: string,
  message: { data?: string; json?: unknown; attributes?: Record<string, string> },
): ResultAsync<{ messageIds: string[] }, ApiError> =>
  request("POST", `${base(session)}/pubsub/topics/${encodeURIComponent(topic)}:publish`, {
    messages: [message],
  });

export const awaitIdle = (
  session: string,
  timeoutSeconds: number,
): ResultAsync<{ idle: boolean }, ApiError> =>
  request("POST", `${base(session)}:awaitIdle`, { timeoutSeconds });

export const capabilities = (): ResultAsync<Json, ApiError> =>
  request("GET", "control/v1/capabilities");
