import type { ResultAsync } from "neverthrow";
import { request, type ApiError, type Json } from "./client";
import type { Session } from "../config";
import type { Allowance, QuiescenceResult, ResourceReport } from "../lib/resources";

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

/** The session's resource diagnostics (privileged: the page sends the control token). */
export const sessionResources = (session: string): ResultAsync<ResourceReport, ApiError> =>
  request<ResourceReport>("GET", `${base(session)}/resources`);

/**
 * Asserts that nothing beyond the exact allow-list is outstanding. A 409 is a valid answer
 * (the leaks), so it is mapped to a result rather than an error.
 */
export const assertQuiescent = (
  session: string,
  allow: Allowance[],
): ResultAsync<QuiescenceResult, ApiError> =>
  request<QuiescenceResult>(
    "POST",
    `${base(session)}/resources:assertQuiescent`,
    { allow },
    {
      accept: [200, 409],
    },
  );

export const capabilities = (): ResultAsync<Json, ApiError> =>
  request("GET", "control/v1/capabilities");

/**
 * Publishes a Firebase alert through the official Eventarc `/google/publishEvents` mechanism
 * (the UI front reaches it in process), firing every registered `onAlertPublished` handler for
 * the alerttype. Returns how many handlers it reached.
 */
export const publishAlert = (
  alertType: string,
  payload: unknown,
  appId?: string,
): ResultAsync<{ delivered: number; alertType: string }, ApiError> =>
  request(
    "POST",
    "functions/alerts",
    appId ? { alertType, payload, appId } : { alertType, payload },
  );

/** One value an expression took while a request was decided. */
export type RulesExprValue = {
  kind: "null" | "bool" | "int" | "float" | "string" | "composite" | "undefined";
  bool?: boolean;
  int?: string;
  float?: number;
  string?: string;
  type?: string;
  cause?: {
    line: number;
    column: number;
    currentOffset: number;
    endOffset: number;
    message: string;
  };
};

/** One expression of the ruleset, with what it evaluated to. */
export type RulesExpression = {
  line: number;
  column: number;
  currentOffset: number;
  endOffset: number;
  values: { value: RulesExprValue; count: number }[];
};

/** One request Security Rules decided, newest first in the list. */
export type RulesRequest = {
  sequence: number;
  service: string;
  method: string;
  path: string;
  allowed: boolean;
  reason: string;
  uid: string | null;
  expressions: RulesExpression[];
};

export type RulesRequests = { capacity: number; loaded: boolean; requests: RulesRequest[] };

export const rulesRequests = (session: string): ResultAsync<RulesRequests, ApiError> =>
  request<RulesRequests>("GET", `${base(session)}/rules/requests`);

/** One value a coverage expression took, in the official :ruleCoverage encoding. */
export type CoverageValue = {
  boolValue?: boolean;
  intValue?: string;
  floatValue?: number;
  stringValue?: string;
  typeValue?: string;
  nullValue?: null;
  undefined?: { causeMessage: string };
};

/** A node of the coverage report tree: a source position and what it evaluated to. */
export type CoverageNode = {
  sourcePosition: { line: number; column: number; currentOffset: number; endOffset: number };
  values?: { value: CoverageValue; count: number }[];
  children?: CoverageNode[];
};

/** The official :ruleCoverage report: the rules source and the evaluated-expression tree. */
export type RuleCoverage = {
  rules: { files: { name: string; content: string }[] };
  report: CoverageNode[];
};

/**
 * The per-expression coverage of the Firestore ruleset, keyed by source position, exactly as
 * the official emulator's `GET /emulator/v1/projects/{project}:ruleCoverage` serves it. Reached
 * through the same privileged Firestore-REST front the data browser uses.
 */
export const ruleCoverage = (project: string): ResultAsync<RuleCoverage, ApiError> =>
  request<RuleCoverage>(
    "GET",
    `firestore/emulator/v1/projects/${encodeURIComponent(project)}:ruleCoverage`,
  );
