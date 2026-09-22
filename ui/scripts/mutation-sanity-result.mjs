import { err, ok } from "neverthrow";

// Timeouts and infrastructure errors must not count as successful detection here.
export const assessSanity = (mutants) => {
  if (mutants.length === 0) return err("No mutants executed; a dry run is insufficient.");
  const unexpected = mutants.filter((mutant) => mutant.status !== "Killed");
  if (unexpected.length > 0) {
    return err(
      `Sanity mutants were not killed: ${unexpected.map((mutant) => mutant.status).join(", ")}`,
    );
  }
  return ok(mutants.length);
};
