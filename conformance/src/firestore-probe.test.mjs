import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildProductionPrograms } from "./firestore-probe/run.mjs";

describe("Firestore production recorder", () => {
  it("uses the live fireemu step even when the stored divergence disagrees", () => {
    const result = buildProductionPrograms({
      production: {
        sample: {
          steps: {
            read: { status: "OK", code: "OK", body: { value: "production" } },
          },
        },
      },
      fireemu: {
        sample: {
          steps: {
            read: { status: "OK", code: "OK", body: { value: "live" } },
          },
        },
      },
      matrix: {
        programs: [
          {
            id: "sample",
            steps: {
              read: {
                oracle: { status: "OK", code: "OK", body: { value: "official" } },
                divergence: {
                  fireemu: { status: "OK", code: "OK", body: { value: "production" } },
                },
              },
            },
          },
        ],
      },
      programDefinitions: [{ id: "sample", area: "production", steps: [{ id: "read" }] }],
      evidenceValid: true,
    });

    const row = result.programs[0].steps.read;
    assert.deepEqual(row.fireemu, { status: "OK", code: "OK", body: { value: "live" } });
    assert.equal(row.status, "three-way-difference");
  });

  it("records a missing live step instead of falling back to a stored expectation", () => {
    const result = buildProductionPrograms({
      production: {
        sample: {
          steps: {
            read: { status: "OK", code: "OK", body: { value: "production" } },
          },
        },
      },
      fireemu: {},
      matrix: {
        programs: [
          {
            id: "sample",
            steps: {
              read: {
                oracle: { status: "OK", code: "OK", body: { value: "official" } },
                divergence: {
                  fireemu: { status: "OK", code: "OK", body: { value: "stored" } },
                },
              },
            },
          },
        ],
      },
      programDefinitions: [{ id: "sample", area: "production", steps: [{ id: "read" }] }],
      evidenceValid: true,
    });

    const row = result.programs[0].steps.read;
    assert.deepEqual(row.fireemu, { missing: true });
    assert.equal(row.status, "unverified");
  });

  it("marks missing production and live observations as unverified", () => {
    const result = buildProductionPrograms({
      production: {},
      fireemu: {},
      matrix: {
        programs: [
          {
            id: "sample",
            steps: {
              read: {
                oracle: { status: "OK", code: "OK", body: { value: "official" } },
              },
            },
          },
        ],
      },
      programDefinitions: [{ id: "sample", area: "production", steps: [{ id: "read" }] }],
      evidenceValid: true,
    });

    const row = result.programs[0].steps.read;
    assert.deepEqual(row.production, { missing: true });
    assert.deepEqual(row.fireemu, { missing: true });
    assert.equal(row.status, "unverified");
  });
});
