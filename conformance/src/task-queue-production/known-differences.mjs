// The known differences between fireemu's strict profile (under productionExact) and the two production recordings. Each cites
// the coordinator ruling that puts the behaviour outside the claim (docs.local/runs/task-queue-parent/coordinator-rulings.md,
// stated here by number) and says what differs. A difference that is not here is a mismatch.
//
// Ruling 3 (2026-11-11): scope is Node.js v2 `onTaskDispatched` in us-central1; the queue management API beyond setup and read-back,
// the value and verification of the OIDC token, the function URL and Cloud Run's platform are excluded.
// Ruling 6 (2026-11-11): the strict profile follows the recordings; what makes local tests worse is a development default that
// `productionExact` restores.
export const KNOWN_DIFFERENCES = Object.freeze([
  {
    id: "KD-LOCAL-URL",
    part: "admission",
    cases: "*",
    paths: [/^\/body\/httpRequest\/url$/],
    ruling: 3,
    what: "The task's httpRequest.url in an answer is the function's own URL: a Cloud Run URL in production, the daemon's route here. The daemon refuses a task that names another URL, so this is the one address it can echo.",
  },
  {
    id: "KD-QUEUE-READS",
    part: "admission",
    cases: [
      "get-dup-sched",
      "get-dup-first",
      "queue-tqdef",
      "queue-tqretry",
      "queue-tqlimit",
      "queue-tqwindow",
      "queue-tqconc1",
      "queue-tqconc2",
      "queue-tqrate",
      "queue-tqdead",
      "queue-absent",
    ],
    paths: [/.*/],
    ruling: 3,
    what: "getTask and getQueue are the Cloud Tasks management API, which neither fireemu nor the official emulator serves (405 here); the recordings are read-back evidence of the queue settings and of the task states, not a claim.",
  },
  {
    id: "KD-PLATFORM-HEADERS",
    part: "deliveries",
    cases: "*",
    paths: [],
    ruling: 3,
    what: "Cloud Run's front end adds forwarded, host, traceparent, x-cloud-trace-context, x-forwarded-for, x-forwarded-proto and accept-encoding to every delivery, and the daemon's own HTTP/1.1 hop adds connection; none has a counterpart on the other side (the platform is outside the claim).",
    hide(delivery) {
      const platform = [
        "connection",
        "forwarded",
        "host",
        "traceparent",
        "x-cloud-trace-context",
        "x-forwarded-for",
        "x-forwarded-proto",
        "accept-encoding",
      ];
      const headers = delivery.request.headers;
      const names = headers.names.filter((name) => !platform.includes(name));
      let changed = names.length !== headers.names.length;
      headers.names = names;
      for (const name of ["accept-encoding", "x-forwarded-proto"])
        if (headers.fixed[name] !== undefined) {
          delete headers.fixed[name];
          changed = true;
        }
      return changed;
    },
  },
  {
    id: "KD-OBSERVATION-WINDOW",
    part: "deliveries",
    cases: ["window-six"],
    paths: [],
    window: { minAttempts: 18 },
    ruling: 16,
    what: "A queue that retries a hundred times is observed for as long as the run lasts (45 and 44 attempts in the two recordings, about 24 locally), so the deliveries of the two sides are compared up to the shorter side, which must hold at least 18 attempts: the first eleven gaps follow the declared schedule and the gaps from the twelfth on are 4, 8 and 10 s in production and in strict under productionExact. Which gaps follow after the last one observed, and how the growth depends on the declared maxBackoff, are not recorded.",
  },
  {
    id: "KD-LOCAL-PATH",
    part: "deliveries",
    cases: "*",
    paths: [/^\[\]\/request\/path$/],
    ruling: 3,
    what: "A delivery's path is `/` in production; the daemon's runner routes on the function's public path, `/<project>/<region>/<function>`.",
  },
]);

/** Cases whose timing is not a claim: the delay is the property under test, or depends on the observation window. */
export const NO_TIMING_CLAIM = Object.freeze(
  new Set([
    ...["a", "b", "c", "d"].map((n) => "conc1-" + n),
    ...["a", "b", "c", "d", "e"].map((n) => "conc2-" + n),
    ...["a", "b", "c", "d", "e", "f", "g", "h"].map((n) => "rate-" + n),
  ]),
);
