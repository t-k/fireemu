import type { ResultAsync } from "neverthrow";
import { request, subscribe, type ApiError, type SseEvent } from "./client";
import type { FunctionsStatus } from "./control";

export type TriggerInfo =
  | { kind: "http"; callable: boolean }
  | {
      kind: "firestore";
      event: string;
      database: string;
      document: string;
      withAuthContext: boolean;
    }
  | { kind: "tasks"; maxAttempts: number; maxConcurrentDispatches: number }
  | { kind: "eventarc"; event: string; channel: string | null; filters: Record<string, string> }
  | {
      kind: "blockingAuth";
      event: string;
      tokenPolicy: { accessToken: boolean; idToken: boolean; refreshToken: boolean };
    }
  | { kind: "pubsub"; topic: string }
  | { kind: "auth"; event: string }
  | { kind: "storage"; event: string; bucket: string | null }
  | { kind: "schedule"; schedule: string; timeZone: string | null };

export type FunctionInfo = {
  name: string;
  region: string;
  entryPoint: string;
  trigger: TriggerInfo;
  timeoutSeconds: number;
  retry: boolean;
  concurrency: number;
};

export type InvocationInfo = {
  eventId: string;
  function: string;
  attempt: number;
  outcome: string;
  /** Position in the runtime's diagnostic stream; absent on the overview payload. */
  sequence?: number;
};

export type FunctionsOverview = {
  configured: boolean;
  project?: string;
  source?: string | null;
  functions: FunctionInfo[];
  status?: FunctionsStatus;
  history: InvocationInfo[];
  deadLetters: InvocationInfo[];
  logs?: string[];
};

export const functionsOverview = (): ResultAsync<FunctionsOverview, ApiError> =>
  request<FunctionsOverview>("GET", "functions");

/**
 * The stream sends the retained window once, then one `invocation` per new record. A `resync`
 * replaces the list: the runtime reset (a new generation) or the records this client was
 * missing fell out of the server's retention window, so a delta would leave a gap.
 */
export type LogEvent =
  | { kind: "snapshot"; generation: number; logs: string[]; invocations: InvocationInfo[] }
  | { kind: "log"; line: string }
  | { kind: "invocation"; record: InvocationInfo }
  | { kind: "resync"; generation: number; invocations: InvocationInfo[] };

const parse = (event: SseEvent): LogEvent | null => {
  try {
    const data = JSON.parse(event.data) as Record<string, unknown>;
    if (event.event === "snapshot") {
      return {
        kind: "snapshot",
        generation: Number(data.generation ?? 0),
        logs: (data.logs as string[]) ?? [],
        invocations: (data.invocations as InvocationInfo[]) ?? [],
      };
    }
    if (event.event === "log") {
      return { kind: "log", line: String(data.line ?? "") };
    }
    if (event.event === "invocation") {
      return { kind: "invocation", record: data as unknown as InvocationInfo };
    }
    if (event.event === "resync") {
      return {
        kind: "resync",
        generation: Number(data.generation ?? 0),
        invocations: (data.invocations as InvocationInfo[]) ?? [],
      };
    }
    return null;
  } catch {
    return null;
  }
};

/** Subscribes to the log stream; returns the unsubscribe function. */
export const subscribeLogs = (
  onEvent: (e: LogEvent) => void,
  onClose: (error?: string) => void,
): (() => void) =>
  subscribe(
    "functions/logs",
    (event) => {
      const parsed = parse(event);
      if (parsed) {
        onEvent(parsed);
      }
    },
    onClose,
  );
