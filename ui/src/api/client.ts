import { err, ok, ResultAsync, type Result } from "neverthrow";
import { controlToken } from "../config";

/**
 * A `ResultAsync` as a plain promise of its `Result`, for `createResource` fetchers (Solid
 * resolves thenables, so the resource then holds the `Result` itself).
 */
export const settle = <T, E>(r: ResultAsync<T, E>): Promise<Result<T, E>> =>
  r.match(
    (v) => ok<T, E>(v),
    (e) => err<T, E>(e),
  );

/** An API failure: the HTTP status and the daemon's message. */
export type ApiError = { status: number; code?: string; message: string };

/** The message of a failed result (for banners), `null` otherwise. */
export const errorOf = <T>(r: Result<T, ApiError> | undefined): string | null =>
  r?.match(
    () => null,
    (e) => e.message,
  ) ?? null;

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const BASE = "/ui/api";

const authHeaders = (): Record<string, string> => {
  const token = controlToken();
  return token ? { authorization: `Bearer ${token}` } : {};
};

const messageOf = (status: number, body: unknown): string => {
  if (body && typeof body === "object" && "error" in body) {
    const error = (body as { error?: unknown }).error;
    if (error && typeof error === "object" && "message" in error) {
      const message = (error as { message?: unknown }).message;
      if (typeof message === "string") {
        return message;
      }
    }
    if (typeof error === "string") {
      return error;
    }
  }
  return `HTTP ${status}`;
};

/** Preserves the optional Google RPC status used by callers for typed recovery. */
export const parseApiError = (status: number, body: unknown): ApiError => {
  let code: string | undefined;
  if (body && typeof body === "object" && "error" in body) {
    const error = (body as { error?: unknown }).error;
    if (error && typeof error === "object" && "status" in error) {
      const value = (error as { status?: unknown }).status;
      if (typeof value === "string") code = value;
    }
  }
  return code === undefined
    ? { status, message: messageOf(status, body) }
    : { status, code, message: messageOf(status, body) };
};

const parseBody = async (response: Response): Promise<unknown> => {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
};

/**
 * One JSON request to the UI API. `path` is relative to `/ui/api` (for example
 * `firestore/v1/projects/p/databases/(default)/documents`).
 */
export const request = <T = Json>(
  method: string,
  path: string,
  body?: unknown,
  init?: { headers?: Record<string, string>; raw?: BodyInit },
): ResultAsync<T, ApiError> =>
  ResultAsync.fromPromise(
    (async (): Promise<Result<T, ApiError>> => {
      const headers: Record<string, string> = { ...authHeaders(), ...init?.headers };
      let payload: BodyInit | undefined = init?.raw;
      if (body !== undefined) {
        headers["content-type"] = "application/json";
        payload = JSON.stringify(body);
      }
      const response = await fetch(`${BASE}/${path}`, {
        method,
        headers,
        body: payload ?? null,
      });
      const parsed = await parseBody(response);
      if (!response.ok) {
        return err(parseApiError(response.status, parsed));
      }
      return ok(parsed as T);
    })(),
    (e): ApiError => ({ status: 0, message: e instanceof Error ? e.message : String(e) }),
  ).andThen((r) => r);

/** A request whose response body is bytes (downloads). */
export const requestBytes = (
  path: string,
): ResultAsync<{ blob: Blob; contentType: string }, ApiError> =>
  ResultAsync.fromPromise(
    (async (): Promise<Result<{ blob: Blob; contentType: string }, ApiError>> => {
      const response = await fetch(`${BASE}/${path}`, { headers: authHeaders() });
      if (!response.ok) {
        const parsed = await parseBody(response);
        return err({ status: response.status, message: messageOf(response.status, parsed) });
      }
      return ok({
        blob: await response.blob(),
        contentType: response.headers.get("content-type") ?? "application/octet-stream",
      });
    })(),
    (e): ApiError => ({ status: 0, message: e instanceof Error ? e.message : String(e) }),
  ).andThen((r) => r);

export type SseEvent = { event: string; data: string };

/**
 * Parses server-sent events from a text chunk stream. Returns complete events and the
 * unconsumed remainder (pure, so it is unit-tested).
 */
export const parseSse = (buffer: string): { events: SseEvent[]; rest: string } => {
  const events: SseEvent[] = [];
  let rest = buffer;
  for (;;) {
    const end = rest.indexOf("\n\n");
    if (end < 0) {
      break;
    }
    const block = rest.slice(0, end);
    rest = rest.slice(end + 2);
    let event = "message";
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) {
        continue;
      }
      const colon = line.indexOf(":");
      const field = colon < 0 ? line : line.slice(0, colon);
      const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") {
        event = value;
      } else if (field === "data") {
        data.push(value);
      }
    }
    if (data.length > 0) {
      events.push({ event, data: data.join("\n") });
    }
  }
  return { events, rest };
};

/**
 * Subscribes to an event stream of the UI API through `fetch` (so the control token
 * travels as a header). `onEvent` receives each event; `onClose` fires when the stream
 * ends for any reason. The returned function aborts the subscription.
 */
export const subscribe = (
  path: string,
  onEvent: (event: SseEvent) => void,
  onClose: (error?: string) => void,
): (() => void) => {
  const controller = new AbortController();
  (async () => {
    try {
      const response = await fetch(`${BASE}/${path}`, {
        headers: { ...authHeaders(), accept: "text/event-stream" },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        const parsed = await parseBody(response);
        onClose(messageOf(response.status, parsed));
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        const parsed = parseSse(buffer);
        buffer = parsed.rest;
        for (const event of parsed.events) {
          onEvent(event);
        }
      }
      onClose();
    } catch (e) {
      if (!controller.signal.aborted) {
        onClose(e instanceof Error ? e.message : String(e));
      }
    }
  })();
  return () => controller.abort();
};
