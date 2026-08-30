// The execution context every scenario receives.
//
// A scenario never learns which side it is running on for the purpose of *behaving*
// differently: `ctx.side` exists only for the two setup differences the two products cannot
// share (Security Rules are loaded from firebase.json by the official suite and through the
// control API by firebase-testd, and only firebase-testd can mint an App Check token).

import { APP_CHECK, BUCKET, PROJECT, REGION } from "../config.mjs";
import { normalize, normalizeError } from "../normalize.mjs";

/** Hosts the runner was handed by whichever supervisor started it. */
export function hostsFromEnv() {
  const required = (name) => {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is not set; the runner must be started by a supervisor`);
    return value;
  };
  return {
    firestore: required("FIRESTORE_EMULATOR_HOST"),
    auth: required("FIREBASE_AUTH_EMULATOR_HOST"),
    storage: required("FIREBASE_STORAGE_EMULATOR_HOST"),
    functions: required("CONFORMANCE_FUNCTIONS_HOST"),
    appCheck: process.env.FTD_APP_CHECK_EMULATOR_HOST ?? null,
  };
}

/**
 * Builds a per-scenario recorder. Steps are appended in call order, which is the order the
 * fixture stores and the order `check` compares.
 */
export function createContext({ side, variant, hosts, shared }) {
  const steps = [];
  // Values a scenario has declared nondeterministic: each is replaced by its placeholder in
  // every string of every later recorded value, including inside an error message. This is the
  // one normalization a scenario can add, and it is narrow on purpose -- the harness replaces a
  // literal it was handed, never a pattern it guessed.
  const redactions = new Map();
  const redact = (value) => {
    if (typeof value === "string") {
      let out = value;
      for (const [literal, placeholder] of redactions) out = out.replaceAll(literal, placeholder);
      return out;
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v)]));
    }
    return value;
  };

  const ctx = {
    side,
    variant,
    hosts,
    project: PROJECT,
    bucket: BUCKET,
    region: REGION,
    appCheck: APP_CHECK,
    shared,

    /**
     * Declares one server-generated literal nondeterministic. The two sides generate uids and
     * upload session ids in different shapes and neither repeats them between runs, so a row
     * that would otherwise embed one records the placeholder instead. Record the *shape* of
     * such a value (its length, its prefix) in a separate step if the shape is the point.
     */
    redact(literal, placeholder) {
      if (typeof literal === "string" && literal.length >= 8) redactions.set(literal, placeholder);
      return literal;
    },

    /** Records the normalized result of `fn`, or the normalized error it threw. */
    async step(id, fn) {
      if (steps.some((s) => s.id === id)) throw new Error(`duplicate step id ${id}`);
      let value;
      try {
        value = normalize(await fn());
      } catch (error) {
        value = normalizeError(error);
      }
      value = redact(value);
      steps.push({ id, value });
      return value;
    },

    /**
     * Records a row no local oracle can answer. `reason` becomes the fixture's explanation;
     * `production` describes, in prose, what the row would observe against a real project.
     * Nothing here is ever presented as an observed result.
     */
    pending(id, reason, production) {
      if (steps.some((s) => s.id === id)) throw new Error(`duplicate step id ${id}`);
      steps.push({ id, pending: true, reason, production });
    },

    /** The callable / onRequest URL both emulators serve. */
    functionUrl(name) {
      return `http://${hosts.functions}/${PROJECT}/${REGION}/${name}`;
    },
  };
  return { ctx, steps };
}

/** Deterministic per-scenario email addresses: derived from the scenario id, never a clock. */
export function emailFor(scenarioId, label) {
  const slug = `${scenarioId}-${label}`.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
  return `conf-${slug}@example.com`;
}
