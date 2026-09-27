import { validateDeliveryEvidence } from "./evidence.mjs";
import { verifyNativeFirestoreV2Frame } from "./native_firestore.mjs";

/** Check every declared Firestore v2 event frame after the case-level evidence contract. */
export function validateNativeFirestoreV2Evidence(corpus, closure, binding, record) {
  try {
    const base = validateDeliveryEvidence(corpus, closure, binding, record);
    const row = corpus.cases.find((item) => item.id === record.caseId);
    if (row.source !== "firestore" || row.generation !== 2)
      throw new Error("unsupported native source");
    const operations = new Map(record.operations.map((operation) => [operation.id, operation]));
    let nativeFramesVerified = 0;
    for (const frame of record.capture.frames) {
      if (frame.kind === "barrier") continue;
      const operation = operations.get(frame.operationId);
      if (!operation) throw new Error("unowned frame");
      verifyNativeFirestoreV2Frame(frame, operation, row);
      nativeFramesVerified++;
    }
    if (nativeFramesVerified === 0) throw new Error("missing native frame");
    return Object.freeze({
      status: "native-firestore-v2-evidence-consistent",
      caseId: base.caseId,
      nativeFramesVerified,
      nativeFrameConsistencyVerified: true,
      semanticAdaptersVerified: false,
      captureProvenanceVerified: false,
      compatibilityEstablished: false,
      absenceEstablished: false,
      sendAuthorized: false,
    });
  } catch {
    throw new Error("native Firestore v2 evidence rejected");
  }
}
