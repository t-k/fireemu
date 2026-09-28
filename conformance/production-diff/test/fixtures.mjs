// Small, explicitly derived test fixtures, NOT a new production receipt.
// Program: programs.mjs @ 2526c61e, lines 887-923.
// Response projection: firestore-production-matrix.json @ a0fd4396, lines 21690-21816.
import { CASE } from "../registry.mjs";
export function programFixture() {
  const docs = "/v1/projects/PROJECT/databases/(default)/documents";
  const names = "projects/PROJECT/databases/(default)/documents";
  const int = (n) => ({ integerValue: String(n) });
  const update = (path, fields, extra = {}) => ({
    update: { name: `${names}/${path}`, fields },
    ...extra,
  });
  return {
    id: "writes/batch-write",
    area: "writes",
    seed: [{ path: `${docs}/bw/existing`, fields: { a: int(1) } }],
    steps: [
      {
        id: "non-atomic-batch",
        method: "POST",
        path: `${docs}:batchWrite`,
        body: {
          writes: [
            update("bw/one", { a: int(1) }),
            update("bw/none", { a: int(1) }, { currentDocument: { exists: true } }),
            update("bw/existing", { a: int(2) }, { currentDocument: { exists: false } }),
            { delete: `${names}/bw/existing` },
            {
              transform: {
                document: `${names}/bw/one`,
                fieldTransforms: [{ fieldPath: "n", increment: int(5) }],
              },
            },
          ],
        },
      },
      { id: "one-was-written", method: "GET", path: `${docs}/bw/one` },
      { id: "existing-was-deleted", method: "GET", path: `${docs}/bw/existing` },
      { id: "empty-batch", method: "POST", path: `${docs}:batchWrite`, body: { writes: [] } },
      {
        id: "batch-with-transaction-is-refused",
        method: "POST",
        path: `${docs}:batchWrite`,
        body: {
          writes: [update("bw/two", { a: int(1) })],
          transaction: "AA==",
        },
      },
    ],
  };
}
export function productionRows() {
  return {
    "non-atomic-batch": {
      status: 400,
      code: "INVALID_ARGUMENT",
      message: "the same document cannot be written more than once in a single request",
    },
    "one-was-written": {
      status: 404,
      code: "NOT_FOUND",
      message:
        'Document "projects/demo-firestore-probe/databases/(default)/documents/bw/one" not found.',
    },
    "existing-was-deleted": {
      status: 200,
      code: "OK",
      body: {
        name: "projects/demo-firestore-probe/databases/(default)/documents/bw/existing",
        fields: { a: { integerValue: "1" } },
        createTime: "<now>",
        updateTime: "<now>",
      },
    },
    "empty-batch": { status: 200, code: "OK", body: {} },
    "batch-with-transaction-is-refused": {
      status: 400,
      code: "INVALID_ARGUMENT",
      message: 'Invalid JSON payload received. Unknown name "transaction": Cannot find field.',
    },
  };
}
export const actualFixture = () => ({ [CASE.programId]: { steps: productionRows() } });
export function matrixFixture() {
  return {
    version: 1,
    evidence: {
      verified: true,
      validation: [],
      observations: {
        production: {
          source: { gitSha: CASE.observedSource, trackedTreeClean: true },
          observation: {
            side: "production",
            mode: "live",
            database: {
              type: "FIRESTORE_NATIVE",
              databaseEdition: "STANDARD",
            },
          },
          inputs: { corpusDigest: CASE.corpusDigest },
        },
      },
    },
    programs: [
      {
        id: CASE.programId,
        area: "writes",
        steps: Object.fromEntries(
          Object.entries(productionRows()).map(([id, row]) => [
            id,
            {
              production: row,
              // Deliberately conflicting auxiliary values; the new path must ignore them.
              emulator: { status: 500, code: "INTERNAL" },
              fireemu: { missing: true },
              status: "debt",
            },
          ]),
        ),
      },
    ],
  };
}
