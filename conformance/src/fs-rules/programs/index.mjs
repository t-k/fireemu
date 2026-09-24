// The FS-RULES corpus: every area's rules fragment and its programs, in recording order.
//
// Order matters. The run starts without a release (the no-release program), publishes `main`
// for the matrix, switches to `alt` and back inside the publication program, and ends with the
// expiry program, which waits for a token issued at session start to pass its exp.

import { PRINCIPALS } from "./common.mjs";
import * as limits from "./limits.mjs";
import * as principals from "./principals.mjs";
import * as query from "./query.mjs";
import * as states from "./states.mjs";
import * as writes from "./writes.mjs";

export { PRINCIPALS };

export const FRAGMENTS = [
  ...principals.FRAGMENTS,
  ...writes.FRAGMENTS,
  ...query.FRAGMENTS,
  ...limits.FRAGMENTS,
  ...states.FRAGMENTS,
];

const byId = (programs, id) => {
  const program = programs.find((p) => p.id === id);
  if (!program) throw new Error(`no program ${id}`);
  return program;
};

const statePrograms = states.PROGRAMS;

export const PROGRAMS = [
  byId(statePrograms, "fs-rules/publication/no-release"),
  byId(limits.PROGRAMS, "fs-rules/compile/acceptance"),
  ...principals.PROGRAMS,
  ...writes.PROGRAMS,
  ...query.PROGRAMS,
  byId(limits.PROGRAMS, "fs-rules/runtime-limits/evaluation"),
  byId(statePrograms, "fs-rules/refusals/credentials"),
  byId(statePrograms, "fs-rules/token-states/after-account-change"),
  byId(statePrograms, "fs-rules/publication/switch"),
  byId(statePrograms, "fs-rules/named-database/releases"),
  byId(statePrograms, "fs-rules/expiry/around-exp"),
];

if (
  PROGRAMS.length !==
  new Set([
    ...principals.PROGRAMS,
    ...writes.PROGRAMS,
    ...query.PROGRAMS,
    ...limits.PROGRAMS,
    ...statePrograms,
  ]).size
) {
  throw new Error("a program is missing from the recording order");
}
