// What a saved FS-CONFIG-LIFECYCLE row depends on besides the harness (run.mjs binds rows to it).
import { createHash } from "node:crypto";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/**
 * The program itself and the committed bytes of every capture it uploads that another
 * recording wrote (a changed capture makes its rows stale). A capture the program writes itself
 * comes from the same recording as its rows, which it cannot disagree with.
 */
export const programDigest = (program, captures = {}) => {
  const own = new Set(
    program.steps.filter((s) => s.capture).map((s) => `${program.id}:${s.capture.as}`),
  );
  const used = program.steps
    .filter((s) => s.upload && !own.has(s.upload.from))
    .map((s) => sha256(JSON.stringify(captures[s.upload.from] ?? null)));
  return sha256(JSON.stringify(program) + used.join(""));
};
