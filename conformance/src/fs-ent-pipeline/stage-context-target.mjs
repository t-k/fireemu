import { createContext } from './harness.mjs';

// The reviewed packet supplies the only database authorized for this run.
export function createStageContext({ database, approvedDatabase, ...options }) {
  if (typeof approvedDatabase !== 'string' || !/^entpipe2-[0-9]{8}$/.test(approvedDatabase) || database !== approvedDatabase) {
    throw new Error('unexpected stage-context database');
  }
  return { ...createContext(options), database };
}
