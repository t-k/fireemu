// Bytes are test fixtures, not production observations. Exercise the actual bounded reader.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { boundedText } from "../network.mjs";

const invalidSequences = [
  ["isolated-continuation", [0x80]],
  ["invalid-leading-byte", [0xff]],
  ["overlong-null", [0xc0, 0x80]],
  ["overlong-slash", [0xe0, 0x80, 0xaf]],
  ["encoded-surrogate", [0xed, 0xa0, 0x80]],
  ["above-unicode-maximum", [0xf4, 0x90, 0x80, 0x80]],
  ["truncated-two-byte", [0xc3]],
  ["truncated-three-byte", [0xe2, 0x82]],
  ["truncated-four-byte", [0xf0, 0x9f, 0x92]],
];
const responseFor = (chunks) =>
  new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(Uint8Array.from(chunk));
        controller.close();
      },
    }),
  );
for (const [label, bytes] of invalidSequences) {
  for (const split of [false, true]) {
    test(`invalid UTF-8 is refused: ${label}, split=${split}`, async () => {
      const raw = Buffer.concat([
        Buffer.from('{"message":"'),
        Buffer.from(bytes),
        Buffer.from('"}'),
      ]);
      const chunks = split ? [...raw].map((byte) => [byte]) : [raw];
      const response = responseFor(chunks);
      await assert.rejects(boundedText(response), { message: "response-invalid-utf8" });
      assert.equal(response.body.locked, false);
    });
  }
}
for (const text of ["", "ASCII", "日本語", "😀", "e\u0301", "\ufffd", "a\ufeffb", "\ufeff{}"])
  test(`valid text round-trips without replacement or normalization: ${JSON.stringify(text)}`, async () => {
    const raw = Buffer.from(text);
    const response = responseFor([...raw].map((byte) => [byte]));
    const decoded = await boundedText(response);
    assert.equal(decoded, text);
    assert.deepEqual(Buffer.from(decoded), raw, "raw-body hash inputs must retain their bytes");
    assert.equal(response.body.locked, false);
  });

test("a leading BOM remains visible to JSON parsing, as before this repair", async () => {
  const text = await boundedText(new Response(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])));
  assert.equal(text.charCodeAt(0), 0xfeff);
  assert.throws(() => JSON.parse(text), SyntaxError);
});

test("size ceiling counts UTF-8 bytes rather than UTF-16 characters", async () => {
  assert.equal(await boundedText(new Response("😀"), 4), "😀");
  const oversized = new Response("😀");
  await assert.rejects(boundedText(oversized, 3), { message: "response-too-large" });
  assert.equal(oversized.body.locked, false);
});

test("no-body response is still empty", async () => {
  assert.equal(await boundedText(new Response(null, { status: 204 })), "");
});

test("stream failure does not become a decoded prefix", async () => {
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(Buffer.from("{}"));
        controller.error(new Error("stream-broken"));
      },
    }),
  );
  await assert.rejects(boundedText(response), { message: "stream-broken" });
  assert.equal(response.body.locked, false);
});

async function withServer(handler, fn) {
  const server = createServer(handler);
  server.on("clientError", (_error, socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

for (const valid of [false, true])
  test(`real HTTP distinguishes invalid bytes from a legitimate replacement character: ${valid}`, async () => {
    const raw = Buffer.concat([
      Buffer.from('{"message":"'),
      valid ? Buffer.from("\ufffd") : Buffer.from([0x80]),
      Buffer.from('"}'),
    ]);
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json", "content-length": raw.length });
        res.end(raw);
      },
      async (origin) => {
        const response = await fetch(origin, { signal: AbortSignal.timeout(2000) });
        if (valid) assert.deepEqual(JSON.parse(await boundedText(response)), { message: "\ufffd" });
        else await assert.rejects(boundedText(response), { message: "response-invalid-utf8" });
      },
    );
  });

test("real HTTP truncated content-length remains a transport failure even for a complete JSON prefix", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "content-length": 64 });
      res.write("{}");
      const timer = setTimeout(() => res.destroy(), 25);
      res.once("close", () => clearTimeout(timer));
    },
    async (origin) => {
      const response = await fetch(origin, { signal: AbortSignal.timeout(2000) });
      await assert.rejects(boundedText(response));
      assert.equal(response.body.locked, false);
    },
  );
});

test("an already-aborted signal is rejected without locking the response body", async () => {
  const controller = new AbortController();
  const reason = new Error("already-stopped");
  controller.abort(reason);
  const response = new Response("{}");
  await assert.rejects(boundedText(response, undefined, controller.signal), (e) => e === reason);
  assert.equal(response.body.locked, false);
});

for (const cancellation of ["resolve", "reject", "never-resolve"])
  test(`reader abort releases its lock without waiting for source cancellation: ${cancellation}`, async () => {
    const { getEventListeners } = await import("node:events");
    const controller = new AbortController();
    const reason = new Error("cancelled-reader");
    let cancellations = 0;
    const response = new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(Buffer.from("{"));
        },
        cancel() {
          cancellations++;
          if (cancellation === "reject") return Promise.reject(new Error("source-cancel-failed"));
          if (cancellation === "never-resolve") return new Promise(() => {});
        },
      }),
    );
    const pending = boundedText(response, undefined, controller.signal);
    assert.equal(getEventListeners(controller.signal, "abort").length, 1);
    const timer = setTimeout(() => controller.abort(reason), 30);
    const ceiling = setTimeout(() => {
      throw new Error("test-reader-did-not-stop");
    }, 1500);
    try {
      await assert.rejects(pending, (e) => e === reason);
      assert.equal(cancellations, 1);
      assert.equal(response.body.locked, false);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      clearTimeout(timer);
      clearTimeout(ceiling);
    }
  });

test("size failure does not wait for an uncooperative source cancel promise", async () => {
  let cancellations = 0;
  const response = new Response(
    new ReadableStream({
      start(c) {
        c.enqueue(Buffer.from("oversized"));
      },
      cancel() {
        cancellations++;
        return new Promise(() => {});
      },
    }),
  );
  const ceiling = setTimeout(() => {
    throw new Error("test-size-rejection-did-not-stop");
  }, 1500);
  try {
    await assert.rejects(boundedText(response, 3), { message: "response-too-large" });
    assert.equal(cancellations, 1);
    assert.equal(response.body.locked, false);
  } finally {
    clearTimeout(ceiling);
  }
});

test("success removes the signal listener and a later abort changes nothing", async () => {
  const { getEventListeners } = await import("node:events");
  const controller = new AbortController();
  const response = new Response("日本語");
  assert.equal(await boundedText(response, undefined, controller.signal), "日本語");
  assert.equal(response.body.locked, false);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  controller.abort();
});
