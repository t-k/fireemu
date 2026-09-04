const { HttpsError, onCall, onCallGenkit } = require("firebase-functions/v2/https");

const states = new Map();

function stateFor(nonce) {
  let state = states.get(nonce);
  if (!state) {
    let release;
    state = {
      aborted: false,
      firstSent: false,
      release: new Promise((resolve) => {
        release = resolve;
      }),
      resolve: release,
    };
    states.set(nonce, state);
  }
  return state;
}

exports.streamSequence = onCall({ heartbeatSeconds: null }, async (request, response) => {
  const nonce = request.data.nonce;
  const state = stateFor(nonce);
  const firstWrote = await response.sendChunk({ nonce, step: 1 });
  state.firstSent = true;
  await state.release;
  const secondWrote = await response.sendChunk({ nonce, step: 2 });
  states.delete(nonce);
  return { acceptsStreaming: request.acceptsStreaming, firstWrote, secondWrote, nonce };
});

exports.releaseStream = onCall((request) => {
  const state = stateFor(request.data.nonce);
  state.resolve();
  return { released: true };
});

exports.streamStatus = onCall((request) => {
  const state = states.get(request.data.nonce);
  return { aborted: state?.aborted ?? false, firstSent: state?.firstSent ?? false };
});

exports.nonStreamingChunk = onCall(async (request, response) => ({
  acceptsStreaming: request.acceptsStreaming,
  wrote: await response.sendChunk({ hidden: true }),
}));

exports.streamError = onCall({ heartbeatSeconds: null }, async (_request, response) => {
  await response.sendChunk({ step: 1 });
  throw new HttpsError("failed-precondition", "stream stopped", { phase: "after-first" });
});

exports.waitForDisconnect = onCall({ heartbeatSeconds: null }, async (request, response) => {
  const state = stateFor(request.data.nonce);
  await response.sendChunk({ step: 1 });
  state.firstSent = true;
  await new Promise((resolve) => {
    response.signal.addEventListener(
      "abort",
      () => {
        state.aborted = true;
        resolve();
      },
      { once: true },
    );
  });
  return { aborted: true };
});

const fakeGenkitAction = {
  __action: { name: "fakeGenkitStream" },
  async run(input) {
    return { result: { input, mode: "run" } };
  },
  stream(input) {
    const state = stateFor(input.nonce);
    return {
      stream: (async function* () {
        yield { mode: "stream", step: 1 };
        state.firstSent = true;
        await state.release;
        yield { mode: "stream", step: 2 };
      })(),
      output: state.release.then(() => {
        states.delete(input.nonce);
        return { input, mode: "output" };
      }),
    };
  },
};

exports.genkitStream = onCallGenkit({ heartbeatSeconds: null }, fakeGenkitAction);
