// Narrow sequencing seam; the production adapter and its evidence checks require separate review.
import { stageContextCases, stageContextSeed } from './stage-context-corpus.mjs';

export async function runStageContextRounds(io) {
  const cases = stageContextCases();
  if (cases.length !== 11) throw new Error('unexpected stage-context corpus');
  let observations = 0;
  let support = 0;
  async function call(op, detail) {
    if (op === 'observe') observations++; else support++;
    let result;
    try { result = await io(op, detail); } catch { throw new Error(`unknown ${op}; retain claims`); }
    if (!result || result.known !== true) throw new Error(`unknown ${op}; retain claims`);
    if (op !== 'observe' && result.ok !== true) throw new Error(`failed ${op}; retain claims`);
    return result;
  }
  for (let round = 1; round <= 2; round++) {
    await call('baseline', { round });
    await call('seed', { round, documents: stageContextSeed() });
    for (const step of cases) await call('observe', { round, step });
    await call('verify', { round, documents: stageContextSeed() });
    await call('delete-owned', { round, paths: stageContextSeed().map(([path]) => path) });
    await call('verify-absence', { round, paths: stageContextSeed().map(([path]) => path) });
  }
  return { observations, support };
}
