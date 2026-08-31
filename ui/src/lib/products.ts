// The honest product-scope inventory shown on the Overview. Every product and diagnostic a
// user of the official Emulator Suite UI might look for appears here with an explicit status,
// so a deferred or not-planned product is labelled rather than represented by an empty or
// misleading tab. This is a pure description (no runtime state), so it is unit-tested.

import type { MessageKey } from "../i18n";

export type ProductStatus =
  | "supported" // a parity view exists in this UI
  | "deferred" // planned, not implemented yet
  | "notPlanned" // out of scope for fireemu
  | "pendingBackend" // the UI workflow is designed but the daemon does not serve it yet
  | "pendingUi" // the daemon serves it; the parity UI view is not built yet
  | "substituted"; // fireemu offers a different, documented mechanism for the same need

export type ProductScopeRow = {
  id: string;
  nameKey: MessageKey;
  status: ProductStatus;
  noteKey: MessageKey;
};

/**
 * The fixed inventory, in the order the Overview lists it: the four active parity products and
 * their companions first, then the products fireemu defers or does not plan, then the
 * diagnostics whose daemon surface is still being built, and finally the official Logging
 * emulator, for which fireemu's SSE log stream is the documented substitute.
 */
export const productScope = (): readonly ProductScopeRow[] => [
  { id: "auth", nameKey: "scope.auth", status: "supported", noteKey: "scope.authNote" },
  {
    id: "firestore",
    nameKey: "scope.firestore",
    status: "supported",
    noteKey: "scope.firestoreNote",
  },
  {
    id: "functions",
    nameKey: "scope.functions",
    status: "supported",
    noteKey: "scope.functionsNote",
  },
  { id: "storage", nameKey: "scope.storage", status: "supported", noteKey: "scope.storageNote" },
  { id: "rules", nameKey: "scope.rules", status: "supported", noteKey: "scope.rulesNote" },
  { id: "appCheck", nameKey: "scope.appCheck", status: "supported", noteKey: "scope.appCheckNote" },
  { id: "rtdb", nameKey: "scope.rtdb", status: "deferred", noteKey: "scope.rtdbNote" },
  {
    id: "extensions",
    nameKey: "scope.extensions",
    status: "notPlanned",
    noteKey: "scope.extensionsNote",
  },
  {
    id: "requests",
    nameKey: "scope.requests",
    status: "supported",
    noteKey: "scope.requestsNote",
  },
  { id: "coverage", nameKey: "scope.coverage", status: "supported", noteKey: "scope.coverageNote" },
  { id: "alerts", nameKey: "scope.alerts", status: "supported", noteKey: "scope.alertsNote" },
  { id: "logging", nameKey: "scope.logging", status: "substituted", noteKey: "scope.loggingNote" },
];

/** The i18n key of a status's short label. */
export const statusLabelKey = (status: ProductStatus): MessageKey => `scope.status.${status}`;
