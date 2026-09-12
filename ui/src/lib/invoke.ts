import { err, ok, type Result } from "neverthrow";

// Pure request builders for the Functions console actions: shaping an invoke request for an
// HTTP or callable function and a task enqueue from what the user typed. The daemon validates
// again at the boundary; these keep the forms honest and are unit-tested in isolation.

/** The invoke request body the UI API accepts (see functions_actions::build_invoke). */
export type InvokeRequest = {
  method?: string;
  path?: string;
  query?: string;
  headers?: Record<string, string>;
  body?: string;
};

/** The enqueue request body the UI API accepts (see api::enqueue_task). */
export type EnqueueRequest = {
  data: unknown;
  id?: string;
  headers?: Record<string, string>;
};

/**
 * Parses `Name: value` lines into a header map. Blank lines are ignored; a line without a
 * colon, an empty name, or a duplicate name is an error, so a typo never silently drops a
 * header the user meant to send.
 */
export const parseHeaderLines = (text: string): Result<Record<string, string>, string> => {
  const headers: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") {
      continue;
    }
    const colon = line.indexOf(":");
    if (colon < 0) {
      return err(`Header line without a colon: ${line}`);
    }
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name === "") {
      return err(`Header line with an empty name: ${line}`);
    }
    if (name in headers) {
      return err(`Duplicate header: ${name}`);
    }
    headers[name] = value;
  }
  return ok(headers);
};

/** Parses text as JSON, reporting the parser's message with a label for the field. */
const parseJson = (label: string, text: string): Result<unknown, string> => {
  try {
    return ok(JSON.parse(text) as unknown);
  } catch (e) {
    return err(`${label} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
};

/**
 * Builds the invoke request for a callable (`onCall`): the data is wrapped as `{"data": ...}`
 * (the callable envelope), and an ID token or App Check token, when given, travel as the
 * `Authorization` and `X-Firebase-AppCheck` headers a client sends.
 */
export const buildCallableInvoke = (input: {
  data: string;
  authToken: string;
  appCheckToken: string;
}): Result<InvokeRequest, string> =>
  parseJson("The callable data", input.data).map((data) => {
    const headers: Record<string, string> = {};
    const auth = input.authToken.trim();
    if (auth !== "") {
      headers.authorization = auth.startsWith("Bearer ") ? auth : `Bearer ${auth}`;
    }
    const appCheck = input.appCheckToken.trim();
    if (appCheck !== "") {
      headers["x-firebase-appcheck"] = appCheck;
    }
    const request: InvokeRequest = { method: "POST", body: JSON.stringify({ data }) };
    if (Object.keys(headers).length > 0) {
      request.headers = headers;
    }
    return request;
  });

/**
 * Builds the invoke request for an HTTP function (`onRequest`): the method, an optional path
 * and query, freeform headers, and a raw body sent as typed.
 */
export const buildRequestInvoke = (input: {
  method: string;
  path: string;
  query: string;
  headers: string;
  body: string;
}): Result<InvokeRequest, string> =>
  parseHeaderLines(input.headers).map((headers) => {
    const path = input.path.trim();
    const query = input.query.trim().replace(/^\?/, "");
    const request: InvokeRequest = { method: input.method };
    if (path !== "") {
      request.path = path;
    }
    if (query !== "") {
      request.query = query;
    }
    if (Object.keys(headers).length > 0) {
      request.headers = headers;
    }
    if (input.body !== "") {
      request.body = input.body;
    }
    return request;
  });

/**
 * Builds the enqueue request: the task data (parsed as JSON) and, when given, a task id.
 */
export const buildEnqueue = (input: { data: string; id: string }): Result<EnqueueRequest, string> =>
  parseJson("The task data", input.data).map((data) => {
    const id = input.id.trim();
    const request: EnqueueRequest = { data };
    if (id !== "") {
      request.id = id;
    }
    return request;
  });
