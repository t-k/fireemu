// Firestore matrix divergences are registered beside the fixture-based conformance rows so
// every accepted difference has one authority record. This module deliberately exports only
// the executable expectation and reason consumed by the probe; authority metadata remains in
// the canonical JSON register and is validated before classification.

import { readValidatedDivergenceRegister } from "../divergence-authority.mjs";

const register = readValidatedDivergenceRegister();

export const DIVERGENCES = Object.fromEntries(
  Object.entries(register.firestoreMatrixDivergences ?? {}).map(([key, entry]) => [
    key,
    { fireemu: entry.fireemu, reason: entry.reason },
  ]),
);
