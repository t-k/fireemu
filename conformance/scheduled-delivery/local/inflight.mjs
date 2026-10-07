// The scenario behind `cadence.in-flight-skip`: the recorded fixture's `every 1 minutes` job whose handler lasts 100
// seconds, run under a pinned logical clock with the handler lasting 100 *logical* seconds (the real 100 s sleep would
// stall nothing and the 100 ms stand-in of the other scenarios would never overlap an occurrence), and one manual run
// of the job while a natural run is in flight (production's forced run did the same).

/** The statement of the recorded fixture's slow handler that waits 100 real seconds. */
export const SLEEP = "await new Promise((resolve) => setTimeout(resolve, 100_000));";

/**
 * Rewrites the copied fixture so that the slow handler waits until the clock file (the logical epoch seconds the local
 * child writes before each advance) is 100 seconds past what it read when the handler began.
 */
export function logicalSlowHandler(source, { clockFile } = {}) {
  if (!source.includes(SLEEP))
    throw new Error("the fixture no longer holds the slow handler's sleep");
  if (!clockFile) throw new Error("the slow handler needs the clock file of the local run");
  const read = `Number(require("node:fs").readFileSync(${JSON.stringify(clockFile)}, "utf8"))`;
  return source.replace(
    SLEEP,
    `await new Promise((resolve) => {
      const begun = ${read};
      const timer = setInterval(() => {
        if (${read} - begun >= 100) {
          clearInterval(timer);
          resolve();
        }
      }, 5);
    });`,
  );
}

/** The options of the run (the rest, binary and profile, come from the caller). */
export const INFLIGHT_RUN = {
  seconds: 700,
  awaitIdle: false,
  pauseMs: 60,
  clockFile: true,
  manualAt: [{ name: "schedSlowV2", afterSeconds: 200 }],
};
