// Corpus rules learned from production that do not change how a row is sent or recorded, kept
// out of harness.mjs so that adding one does not invalidate the recorded fixture's harness
// digest. run.mjs applies them together with validateActionCorpus.

/**
 * Production limits verification links per address: a second one within minutes answers
 * TOO_MANY_ATTEMPTS_TRY_LATER (recording 2026-09-24), so each address named by value gets at
 * most one in the whole corpus.
 */
export function validateVerificationLinks(programs) {
  const verified = new Set();
  for (const program of programs) {
    for (const step of program.steps) {
      if (step.body?.requestType !== "VERIFY_EMAIL" || typeof step.body?.email !== "string")
        continue;
      const address = step.body.email.replace(/^EMAILMIXED\(/, "EMAIL(");
      if (verified.has(address))
        throw new Error(`${program.id}#${step.id}: a second verification link for ${address}`);
      verified.add(address);
    }
  }
}
