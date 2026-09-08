import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { errorOf, request, requestBytes, setApiBase, settle, subscribe } from "./client";
import { startTestServer } from "./testServer";
import { errAsync, okAsync } from "neverthrow";

// The client against a real HTTP server: what it sends (token, content type, body) and how it
// reads every kind of answer (JSON, text, empty, error shapes, bytes, event streams).
let server: Awaited<ReturnType<typeof startTestServer>>;

beforeAll(async () => {
  server = await startTestServer();
  setApiBase(server.base);
});
afterAll(async () => {
  await server.close();
});
beforeEach(() => {
  server.seen.length = 0;
  server.script.clear();
  window.__FIREEMU__ = { controlToken: "tok-1" };
});

const JSON_HEADERS = { "content-type": "application/json" };

describe("request", () => {
  it("sends the control token, a JSON body and reads a JSON answer", async () => {
    server.script.set("POST /ui/api/things", { headers: JSON_HEADERS, body: '{"id":"t1"}' });
    const r = await request("POST", "things", { name: "x" });
    expect(r._unsafeUnwrap()).toEqual({ id: "t1" });
    const seen = server.seen[0]!;
    expect(seen.method).toBe("POST");
    expect(seen.url).toBe("/ui/api/things");
    expect(seen.headers.authorization).toBe("Bearer tok-1");
    expect(seen.headers["content-type"]).toBe("application/json");
    expect(seen.body).toBe('{"name":"x"}');
  });

  it("sends no authorization header without a token and no body for a GET", async () => {
    window.__FIREEMU__ = {};
    server.script.set("GET /ui/api/plain", { body: "" });
    const r = await request("GET", "plain");
    expect(r._unsafeUnwrap()).toBeNull();
    const seen = server.seen[0]!;
    expect(seen.headers.authorization).toBeUndefined();
    expect(seen.headers["content-type"]).toBeUndefined();
    expect(seen.body).toBe("");
  });

  it("merges extra headers and sends a raw body as given", async () => {
    server.script.set("PUT /ui/api/raw", { body: "ok" });
    const r = await request("PUT", "raw", undefined, {
      headers: { "content-type": "text/plain", "x-extra": "1" },
      raw: "raw text",
    });
    expect(r._unsafeUnwrap()).toBe("ok");
    const seen = server.seen[0]!;
    expect(seen.headers["content-type"]).toBe("text/plain");
    expect(seen.headers["x-extra"]).toBe("1");
    expect(seen.headers.authorization).toBe("Bearer tok-1");
    expect(seen.body).toBe("raw text");
  });

  it("keeps a non-JSON body as text", async () => {
    server.script.set("GET /ui/api/text", { body: "not json" });
    expect((await request("GET", "text"))._unsafeUnwrap()).toBe("not json");
  });

  it.each([
    [
      { error: { code: 400, status: "INVALID_ARGUMENT", message: "bad" } },
      "bad",
      "INVALID_ARGUMENT",
    ],
    [{ error: { message: "plain message" } }, "plain message", undefined],
    [{ error: "string error" }, "string error", undefined],
    [{ error: { detail: 1 } }, "HTTP 400", undefined],
    [{ error: { status: 5, message: "numeric status" } }, "numeric status", undefined],
    [{ error: { status: "X", message: 7 } }, "HTTP 400", "X"],
    [{ other: 1 }, "HTTP 400", undefined],
    ["text", "HTTP 400", undefined],
    ["", "HTTP 400", undefined],
  ])("reads a 400 whose body is %j", async (body, message, code) => {
    server.script.set("GET /ui/api/fail", {
      status: 400,
      headers: JSON_HEADERS,
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    const e = (await request("GET", "fail"))._unsafeUnwrapErr();
    expect(e.status).toBe(400);
    expect(e.message).toBe(message);
    expect(e.code).toBe(code);
    expect("code" in e).toBe(code !== undefined);
  });

  it("treats an accepted non-2xx status as an answer", async () => {
    server.script.set("POST /ui/api/assert", { status: 409, body: '{"leaks":1}' });
    const r = await request("POST", "assert", {}, { accept: [409] });
    expect(r._unsafeUnwrap()).toEqual({ leaks: 1 });
    const other = await request("POST", "assert", {}, { accept: [418] });
    expect(other._unsafeUnwrapErr().status).toBe(409);
  });

  it("reports a network failure as status 0 with the cause", async () => {
    setApiBase("http://127.0.0.1:1/ui/api");
    try {
      const e = (await request("GET", "x"))._unsafeUnwrapErr();
      expect(e.status).toBe(0);
      expect(e.message.length).toBeGreaterThan(0);
    } finally {
      setApiBase(server.base);
    }
  });

  it("reports a dropped connection as status 0", async () => {
    server.script.set("GET /ui/api/drop", { drop: true });
    const e = (await request("GET", "drop"))._unsafeUnwrapErr();
    expect(e.status).toBe(0);
    expect(e.message).toBe("fetch failed");
  });
});

describe("requestBytes", () => {
  it("returns the body and its content type", async () => {
    server.script.set("GET /ui/api/blob", {
      headers: { "content-type": "image/png" },
      body: Buffer.from([1, 2, 3]),
    });
    const r = (await requestBytes("blob"))._unsafeUnwrap();
    expect(r.contentType).toBe("image/png");
    expect(new Uint8Array(await r.blob.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(server.seen[0]!.headers.authorization).toBe("Bearer tok-1");
  });

  it("defaults the content type and reads an error body", async () => {
    server.script.set("GET /ui/api/typeless", { body: "x" });
    expect((await requestBytes("typeless"))._unsafeUnwrap().contentType).toBe(
      "application/octet-stream",
    );
    server.script.set("GET /ui/api/missing", {
      status: 404,
      headers: JSON_HEADERS,
      body: '{"error":{"message":"no such object"}}',
    });
    expect((await requestBytes("missing"))._unsafeUnwrapErr()).toEqual({
      status: 404,
      message: "no such object",
    });
    server.script.set("GET /ui/api/gone", { drop: true });
    expect((await requestBytes("gone"))._unsafeUnwrapErr().status).toBe(0);
  });
});

const collect = (path: string) => {
  const events: { event: string; data: string }[] = [];
  const closes: (string | undefined)[] = [];
  const done = new Promise<void>((resolve) => {
    const stop = subscribe(
      path,
      (e) => events.push(e),
      (error) => {
        closes.push(error);
        resolve();
      },
    );
    void stop;
  });
  return { events, closes, done };
};

describe("subscribe", () => {
  it("delivers events split across chunks in order and closes cleanly at the end", async () => {
    server.script.set("GET /ui/api/firestore/watch", {
      headers: { "content-type": "text/event-stream" },
      chunks: [
        "event: ready\ndata: {}\n\nevent: com",
        "mit\ndata: 1\ndata: 2\n\n: ping\n\n",
        "data: tail\n\n",
      ],
    });
    const s = collect("firestore/watch");
    await s.done;
    expect(s.events).toEqual([
      { event: "ready", data: "{}" },
      { event: "commit", data: "1\n2" },
      { event: "message", data: "tail" },
    ]);
    expect(s.closes).toEqual([undefined]);
    expect(server.seen[0]!.headers.accept).toBe("text/event-stream");
    expect(server.seen[0]!.headers.authorization).toBe("Bearer tok-1");
  });

  it("closes with the daemon's message on a non-ok answer", async () => {
    server.script.set("GET /ui/api/denied", {
      status: 401,
      headers: JSON_HEADERS,
      body: '{"error":{"message":"bad token"}}',
    });
    const s = collect("denied");
    await s.done;
    expect(s.events).toEqual([]);
    expect(s.closes).toEqual(["bad token"]);
  });

  it("closes with the cause when the connection fails", async () => {
    server.script.set("GET /ui/api/cut", { drop: true });
    const s = collect("cut");
    await s.done;
    expect(s.closes).toEqual(["fetch failed"]);
  });

  it("stays silent after the subscriber aborts", async () => {
    server.script.set("GET /ui/api/slow", {
      headers: { "content-type": "text/event-stream" },
      chunks: ["data: a\n\n", "data: b\n\n", "data: c\n\n"],
    });
    const events: string[] = [];
    let closed = 0;
    const stop = subscribe(
      "slow",
      (e) => {
        events.push(e.data);
        if (e.data === "a") stop();
      },
      () => {
        closed += 1;
      },
    );
    await new Promise((r) => setTimeout(r, 80));
    expect(events).toEqual(["a"]);
    expect(closed).toBe(0);
  });
});

describe("Result helpers", () => {
  it("settle keeps both sides and errorOf reads the message", async () => {
    expect((await settle(okAsync<number, string>(1))).isOk()).toBe(true);
    expect((await settle(errAsync<number, string>("e")))._unsafeUnwrapErr()).toBe("e");
    expect(errorOf(undefined)).toBeNull();
    expect(errorOf((await request("GET", "nothing-scripted")).map(() => 1))).toBe(
      "no script for GET /ui/api/nothing-scripted",
    );
    server.script.set("GET /ui/api/ok", { body: "1" });
    expect(errorOf(await request("GET", "ok"))).toBeNull();
  });
});

describe("survivors of the first mutation run", () => {
  it("reports the status of a refused request even when init has no accept list", async () => {
    server.script.set("GET /ui/api/nope", { status: 403, body: "" });
    const e = (
      await request("GET", "nope", undefined, { headers: { "x-a": "1" } })
    )._unsafeUnwrapErr();
    expect(e).toEqual({ status: 403, message: "HTTP 403" });
  });

  it("decodes a multi-byte character split across two chunks", async () => {
    const bytes = Buffer.from("data: café\n\n", "utf8");
    const cut = bytes.indexOf(Buffer.from("é", "utf8")) + 1;
    server.script.set("GET /ui/api/utf8", {
      headers: { "content-type": "text/event-stream" },
      chunks: [bytes.subarray(0, cut), bytes.subarray(cut)],
    });
    const s = collect("utf8");
    await s.done;
    expect(s.events).toEqual([{ event: "message", data: "café" }]);
  });
});
