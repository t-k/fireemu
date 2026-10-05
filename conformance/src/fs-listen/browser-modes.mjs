// The two WebChannel transports of the browser recording. Forced long polling closes every
// backchannel response at once (`CI=1`); streaming turns the buffering-proxy detection off so the
// backchannel stays open and chunked (`CI=0`). This file imports nothing: the page loads it too.

export const MODES = ["long-polling", "streaming"];

export const MODE_SETTINGS = {
  "long-polling": { experimentalForceLongPolling: true },
  streaming: { experimentalForceLongPolling: false, experimentalAutoDetectLongPolling: false },
};

/** The `CI` value of a Listen channel request in each mode (what the wire evidence must show). */
export const EXPECTED_CI = { "long-polling": "1", streaming: "0" };

/** A short suffix per mode: the run id of a mode is the run id plus this. */
export const MODE_SUFFIX = { "long-polling": "l", streaming: "s" };

/** The run id of one mode of a recording. */
export const modeRun = (run, mode) => {
  const suffix = MODE_SUFFIX[mode];
  if (!suffix) throw new Error(`unknown browser transport mode: ${mode}`);
  return `${run}${suffix}`;
};
