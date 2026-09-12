import { expect, it } from "vitest";
import { buildCallableInvoke, buildEnqueue, buildRequestInvoke, parseHeaderLines } from "./invoke";

it("parses header lines and rejects malformed ones", () => {
  expect(parseHeaderLines("X-A: 1\n\nX-B: two words ")._unsafeUnwrap()).toEqual({
    "X-A": "1",
    "X-B": "two words",
  });
  expect(parseHeaderLines("")._unsafeUnwrap()).toEqual({});
  // A whitespace-only line is skipped, not treated as a colon-less line.
  expect(parseHeaderLines("   \nX-A: 1")._unsafeUnwrap()).toEqual({ "X-A": "1" });
  // The name and value are each trimmed of surrounding whitespace.
  expect(parseHeaderLines("  X-A  :  1  ")._unsafeUnwrap()).toEqual({ "X-A": "1" });
  expect(parseHeaderLines("no-colon")._unsafeUnwrapErr()).toContain("without a colon");
  // A colon at the very start is an empty name, distinct from a missing colon.
  expect(parseHeaderLines(": value")._unsafeUnwrapErr()).toContain("empty name");
  expect(parseHeaderLines("X: 1\nX: 2")._unsafeUnwrapErr()).toContain("Duplicate");
});

it("wraps callable data in the envelope and carries the tokens as headers", () => {
  const r = buildCallableInvoke({
    data: '{"a":1}',
    authToken: "id-token",
    appCheckToken: "ac-token",
  })._unsafeUnwrap();
  expect(r.method).toBe("POST");
  expect(r.body).toBe('{"data":{"a":1}}');
  expect(r.headers).toEqual({
    authorization: "Bearer id-token",
    "x-firebase-appcheck": "ac-token",
  });
});

it("keeps an Authorization value that already carries the Bearer scheme", () => {
  const r = buildCallableInvoke({
    data: "{}",
    authToken: "Bearer keep-me",
    appCheckToken: "",
  })._unsafeUnwrap();
  expect(r.headers).toEqual({ authorization: "Bearer keep-me" });
});

it("omits the headers object when a callable has only blank tokens", () => {
  // Whitespace-only tokens count as absent for both the auth and App Check headers.
  const r = buildCallableInvoke({
    data: "{}",
    authToken: "  ",
    appCheckToken: " \t ",
  })._unsafeUnwrap();
  expect(r.headers).toBeUndefined();
  expect(r.body).toBe('{"data":{}}');
});

it("reports invalid callable data as a JSON error naming the field", () => {
  const r = buildCallableInvoke({ data: "{not json", authToken: "", appCheckToken: "" });
  expect(r.isErr()).toBe(true);
  expect(r._unsafeUnwrapErr()).toContain("callable data");
  expect(r._unsafeUnwrapErr()).toContain("not valid JSON");
});

it("builds an onRequest invocation from method, path, query, headers and body", () => {
  const r = buildRequestInvoke({
    method: "GET",
    path: " /users ",
    query: "  ?limit=5  ",
    headers: "X-Smoke: hi",
    body: "",
  })._unsafeUnwrap();
  expect(r).toEqual({
    method: "GET",
    path: "/users",
    // Surrounding whitespace is trimmed and a single leading "?" is dropped.
    query: "limit=5",
    headers: { "X-Smoke": "hi" },
  });
});

it("omits empty path, query, headers and body on an onRequest invocation", () => {
  const r = buildRequestInvoke({
    method: "POST",
    path: "  ",
    query: "",
    headers: "\n\n",
    body: "",
  })._unsafeUnwrap();
  expect(r).toEqual({ method: "POST" });
});

it("keeps a non-empty body and only strips a leading question mark from the query", () => {
  const r = buildRequestInvoke({
    method: "POST",
    path: "",
    // A "?" that is not at the start belongs to the query and must be kept.
    query: "a=1?b=2",
    headers: "",
    body: "raw body",
  })._unsafeUnwrap();
  expect(r.query).toBe("a=1?b=2");
  expect(r.body).toBe("raw body");
});

it("propagates a header parse error from an onRequest invocation", () => {
  const r = buildRequestInvoke({
    method: "POST",
    path: "",
    query: "",
    headers: "broken",
    body: "",
  });
  expect(r.isErr()).toBe(true);
});

it("builds an enqueue request with and without an id", () => {
  expect(buildEnqueue({ data: '{"n":1}', id: " job-1 " })._unsafeUnwrap()).toEqual({
    data: { n: 1 },
    id: "job-1",
  });
  expect(buildEnqueue({ data: "{}", id: "" })._unsafeUnwrap()).toEqual({ data: {} });
});

it("reports invalid task data as a JSON error naming the field", () => {
  const r = buildEnqueue({ data: "oops", id: "" });
  expect(r.isErr()).toBe(true);
  expect(r._unsafeUnwrapErr()).toContain("task data");
  expect(r._unsafeUnwrapErr()).toContain("not valid JSON");
});
