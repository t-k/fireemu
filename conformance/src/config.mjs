// Shared constants for both sides of the differential suite.
//
// Ports live in the 32xxx range so a conformance run never collides with the default
// emulator ports (8080 / 9099 / 9199 / 5001) or with the `tools/sdk-smoke` scripts.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CONFORMANCE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_ROOT = resolve(CONFORMANCE_DIR, "..");
export const FIXTURES_DIR = resolve(CONFORMANCE_DIR, "fixtures");
export const RUNS_DIR = resolve(CONFORMANCE_DIR, ".runs");

/** Both sides run against the same demo project; `demo-` keeps the official CLI offline. */
export const PROJECT = "demo-conformance";
export const BUCKET = `${PROJECT}.appspot.com`;
export const REGION = "us-central1";

/** The app the App Check rows use; only firebase-testd can actually issue tokens for it. */
export const APP_CHECK = Object.freeze({
  appId: "1:1234567890:web:conformance",
  projectNumber: "1234567890",
  // A clearly fake local debug secret; its SHA-256 digest is what the firebase-testd
  // configs register. Never reuse a production App Check debug token.
  debugSecret: "deadbeef-0000-4000-8000-000000000001",
});

/** Ports the official Local Emulator Suite binds (mirrors `firebase.json`). */
export const OFFICIAL_PORTS = Object.freeze({
  firestore: 32080,
  auth: 32099,
  storage: 32199,
  functions: 32001,
  hub: 32400,
  logging: 32500,
});

/** Ports firebase-testd binds; distinct so a stray daemon cannot answer for the oracle. */
export const TESTD_PORTS = Object.freeze({
  firestore: 32180,
  http: 32198,
  storage: 32197,
  functions: 32196,
});

/**
 * Corpus variants. A variant is a daemon configuration, not a scenario grouping: every
 * scenario declares the one variant it runs under, and each variant is one process launch
 * per side.
 */
export const VARIANTS = Object.freeze({
  /** App Check present but every service `unenforced`, which is what the official suite does. */
  baseline: "baseline",
  /** firebase-testd with Firestore, Storage and Auth `enforced`; the official suite cannot do this. */
  appCheckEnforced: "appCheckEnforced",
});

/** Fixture and comparison statuses. */
export const STATUS = Object.freeze({
  /** firebase-testd and the oracle agree; drift here fails `check`. */
  parity: "parity",
  /** They differ on purpose and the difference is documented; drift from the recorded
   *  firebase-testd value still fails `check`. */
  documentedDivergence: "documented-divergence",
  /** They differ and the difference is not documented yet; listed in DEBT.md, never a gate. */
  debt: "debt",
  /** No local oracle can answer this row; recorded with a reason, never compared. */
  pending: "pending",
});
