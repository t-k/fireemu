import assert from "node:assert/strict";

import { initializeApp } from "firebase/app";
import { connectFunctionsEmulator, getFunctions, httpsCallable } from "firebase/functions";

const functionsHost = process.env.FIREEMU_FUNCTIONS_HOST;
const project = process.env.GOOGLE_CLOUD_PROJECT;
assert.ok(functionsHost, "FIREEMU_FUNCTIONS_HOST is required");
assert.ok(project, "GOOGLE_CLOUD_PROJECT is required");

const [host, portText] = functionsHost.split(":");
const app = initializeApp({ apiKey: "fake-api-key", appId: "streaming-e2e", projectId: project });
const functions = getFunctions(app, "us-central1");
connectFunctionsEmulator(functions, host, Number(portText));

const streamSequence = httpsCallable(functions, "streamSequence");
const releaseStream = httpsCallable(functions, "releaseStream");
const streamStatus = httpsCallable(functions, "streamStatus");
const nonStreamingChunk = httpsCallable(functions, "nonStreamingChunk");
const streamError = httpsCallable(functions, "streamError");
const waitForDisconnect = httpsCallable(functions, "waitForDisconnect");
const genkitStream = httpsCallable(functions, "genkitStream");

const bounded = async (promise, label, milliseconds = 2_000) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const waitUntilFirstSent = async (nonce) => {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if ((await streamStatus({ nonce })).data.firstSent) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`fixture did not send the first chunk for ${nonce}`);
};

const assertProgressiveSequence = async (callable, nonce, expectedFinal) => {
  const pendingStream = callable.stream({ nonce });
  await waitUntilFirstSent(nonce);
  let result;
  try {
    result = await bounded(pendingStream, `${nonce} response headers`);
  } catch (error) {
    await releaseStream({ nonce });
    await pendingStream.catch(() => undefined);
    throw error;
  }
  const iterator = result.stream[Symbol.asyncIterator]();
  assert.deepEqual(await bounded(iterator.next(), `${nonce} first chunk`), {
    done: false,
    value: expectedFinal === "genkit" ? { mode: "stream", step: 1 } : { nonce, step: 1 },
  });
  let finalSettled = false;
  result.data.finally(() => {
    finalSettled = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(finalSettled, false, "the final result must remain pending before release");
  await releaseStream({ nonce });
  assert.deepEqual(await bounded(iterator.next(), `${nonce} second chunk`), {
    done: false,
    value: expectedFinal === "genkit" ? { mode: "stream", step: 2 } : { nonce, step: 2 },
  });
  assert.deepEqual(await bounded(result.data, `${nonce} final result`),
    expectedFinal === "genkit"
      ? { input: { nonce }, mode: "output" }
      : { acceptsStreaming: true, firstWrote: true, nonce, secondWrote: true },
  );
  assert.equal((await iterator.next()).done, true);
};

await assertProgressiveSequence(streamSequence, "ordinary", "ordinary");
await assertProgressiveSequence(genkitStream, "genkit", "genkit");

assert.deepEqual((await nonStreamingChunk({})).data, {
  acceptsStreaming: false,
  wrote: false,
});
assert.deepEqual((await genkitStream({ nonce: "non-streaming" })).data, {
  input: { nonce: "non-streaming" },
  mode: "run",
});

const failed = await streamError.stream({});
const failedIterator = failed.stream[Symbol.asyncIterator]();
assert.deepEqual(await failedIterator.next(), { done: false, value: { step: 1 } });
await assert.rejects(failedIterator.next(), (error) => {
  assert.equal(error.code, "functions/failed-precondition");
  assert.equal(error.message, "stream stopped");
  assert.deepEqual(error.details, { phase: "after-first" });
  return true;
});
await assert.rejects(failed.data, { code: "functions/failed-precondition" });

const nonce = "disconnect";
const abort = new AbortController();
const disconnectedPromise = waitForDisconnect.stream({ nonce }, { signal: abort.signal });
await waitUntilFirstSent(nonce);
const disconnected = await bounded(disconnectedPromise, "disconnect response headers");
const disconnectedIterator = disconnected.stream[Symbol.asyncIterator]();
assert.deepEqual(await disconnectedIterator.next(), { done: false, value: { step: 1 } });
abort.abort();
await assert.rejects(disconnected.data, { code: "functions/cancelled" });
for (let attempt = 0; attempt < 80; attempt += 1) {
  if ((await streamStatus({ nonce })).data.aborted) process.exit(0);
  await new Promise((resolve) => setTimeout(resolve, 25));
}
throw new Error("the callable response signal was not aborted after the client disconnected");
