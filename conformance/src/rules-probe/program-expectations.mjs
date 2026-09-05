// What `check-programs` gates a recorded Rules program on.
//
// `conformance/rules-programs.json` is a recording, not an authority. A `divergence` field in
// it would pin fireemu to an answer other than the oracle's, which is exactly the promotion
// the canonical register (`conformance/divergences.json`) exists to control. The register has
// no section for Rules programs, so any recorded program divergence is refused rather than
// trusted; adding one means adding a `rulesProgramDivergences` section validated by both the
// Node validator and the Rust gate (CC-10) first.

import { err, ok } from "neverthrow";

/**
 * @param row one entry of `rules-programs.json#programs`
 * @returns `ok({expected, diverged})` or `err(message)` when the row carries a divergence the
 *   canonical register does not authorize.
 */
export function programExpectation(row) {
  if (row.divergence !== undefined) {
    return err(
      `${row.id}: rules-programs.json records a divergence, but no canonical divergence ` +
        "authority exists for Rules programs; remove it or register it in " +
        "conformance/divergences.json under a validated section",
    );
  }
  return ok({ expected: row.oracle, diverged: false });
}
