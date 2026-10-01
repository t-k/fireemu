import { createHash } from "node:crypto";
import { validateCorpus } from "./corpus.mjs";

/** Fix the finite object and Firestore requests before any sender can resolve credentials. */
export function buildDeclaredRequestManifest(corpus, closure) {
  const checked = validateCorpus(corpus, closure);
  const rows = [];
  const ids = new Set();
  const counts = { storage: 0, firestore: 0 };

  function add(family, programId, stage, step) {
    const request = step.request ?? step;
    const service = request.service ?? "storage";
    if (!Object.hasOwn(counts, service)) throw new Error(`unexpected request service: ${service}`);
    const id = `${family}/${programId}/${stage}/${step.id}`;
    if (ids.has(id)) throw new Error(`duplicate manifest request ID: ${id}`);
    ids.add(id);
    rows.push({
      id,
      family,
      programId,
      stage,
      service,
      request: structuredClone(request),
      ...(step.request ? { requiredState: step.requiredState, when: step.when } : {}),
    });
    counts[service]++;
  }

  for (const entry of corpus.cases) {
    for (const step of entry.baseline) add("case", entry.id, "baseline", step);
    for (const step of entry.setup) add("case", entry.id, "setup", step);
    for (const step of entry.before) add("case", entry.id, "before", step);
    add("case", entry.id, "subject", entry.subject);
    if (entry.comparison) add("case", entry.id, "comparison", entry.comparison);
    for (const step of entry.after) add("case", entry.id, "after", step);
    for (const step of entry.cleanup) add("case", entry.id, "cleanup", step);
  }
  for (const program of corpus.firestorePrograms) {
    for (const step of program.steps) add("firestore-program", program.id, "step", step);
    for (const step of program.cleanup) add("firestore-program", program.id, "cleanup", step);
  }
  if (
    counts.storage !== checked.declaredObjectRequestsPerRecording ||
    counts.firestore !== checked.declaredFirestoreRequestsPerRecording
  ) {
    throw new Error("manifest count differs from validated corpus declaration");
  }
  const manifest = {
    status: "LOCAL_PARTIAL_NO_SEND",
    sendAuthorized: false,
    binding: structuredClone(corpus.binding),
    counts,
    rows,
  };
  return {
    ...manifest,
    sha256: createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
  };
}
