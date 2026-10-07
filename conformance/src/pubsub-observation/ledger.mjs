// The observation family validates normalized replies without changing legacy recorder contracts.
import {
  createLedger as legacyCreate,
  readLedger as legacyRead,
  kindOf as legacyKind,
} from "../pubsub-production/ledger.mjs";
import { normalizeOutcome, unknownOutcome } from "../pubsub-production/outcome.mjs";
export const kindOf = (reply) => legacyKind(normalizeOutcome(reply));
export function guardLedger(ledger) {
  return {
    ...ledger,
    withJournal: (journal) => guardLedger(ledger.withJournal(journal)),
    observeRead: (name, reply) => !unknownOutcome(reply) && ledger.observeRead(name, reply),
    observeOperation: (name, reply) =>
      !unknownOutcome(reply) && ledger.observeOperation(name, reply),
    settleAbsent: (name, reply, options) =>
      !unknownOutcome(reply) && ledger.settleAbsent(name, reply, options),
  };
}
export const createLedger = (options) => guardLedger(legacyCreate(options));
export const readLedger = (path) => guardLedger(legacyRead(path));
