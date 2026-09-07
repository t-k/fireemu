import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildReport,
  readProbeConfig,
  requireOwnAudience,
  sanitizedObservation,
} from "./firestore-probe/auth-focused.mjs";

describe("Focused Firestore Auth probe", () => {
  const env = {
    FIRESTORE_AUTH_PROBE_TARGET: "production",
    FIRESTORE_AUTH_PROBE_PROJECT: "demo-own",
  };
  it("uses official production endpoints and rejects redirected credential destinations", () => {
    assert.equal(readProbeConfig(env).authBase, "https://identitytoolkit.googleapis.com");
    assert.throws(() =>
      readProbeConfig({ ...env, FIRESTORE_AUTH_PROBE_AUTH_BASE: "https://example.com" }),
    );
    assert.throws(() =>
      readProbeConfig({
        ...env,
        FIRESTORE_AUTH_PROBE_AUTH_BASE: "https://secret@identitytoolkit.googleapis.com",
      }),
    );
  });
  it("requires loopback endpoints locally and a distinct foreign project", () => {
    assert.throws(() => readProbeConfig({ ...env, FIRESTORE_AUTH_PROBE_TARGET: "local" }));
    assert.throws(() =>
      readProbeConfig({ ...env, FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT: "demo-own" }),
    );
    assert.equal(
      readProbeConfig({
        ...env,
        FIRESTORE_AUTH_PROBE_TARGET: "local",
        FIRESTORE_AUTH_PROBE_AUTH_BASE: "http://127.0.0.1:9099/identitytoolkit.googleapis.com",
        FIRESTORE_AUTH_PROBE_FIRESTORE_BASE: "http://127.0.0.1:8080",
      }).target,
      "local",
    );
  });
  it("checks the minted token audience without returning claims", () => {
    const token = `x.${Buffer.from(JSON.stringify({ aud: "demo-own", sub: "private" })).toString("base64url")}.x`;
    assert.equal(requireOwnAudience(token, "demo-own"), undefined);
    assert.throws(() => requireOwnAudience(token, "demo-foreign"), /own project/);
    assert.throws(() => requireOwnAudience("garbage", "demo-own"), /unreadable/);
  });
  it("never records document data, principal IDs or server messages", () => {
    assert.deepEqual(sanitizedObservation(200, { fields: { secret: "private" } }), {
      status: 200,
      code: "OK",
      servicePrecondition: "not-observed",
    });
    assert.deepEqual(
      sanitizedObservation(403, {
        error: {
          status: "PERMISSION_DENIED",
          message: "API has not been used in project private",
        },
      }),
      { status: 403, code: "PERMISSION_DENIED", servicePrecondition: "api-unavailable" },
    );
  });
  it("does not promote an absent second project or service-activation 403 to conformance", () => {
    const ownProject = sanitizedObservation(404, { error: { status: "NOT_FOUND" } });
    assert.equal(
      buildReport(readProbeConfig(env), { ownProject }).crossProject.status,
      "unverified",
    );
    const config = readProbeConfig({
      ...env,
      FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT: "demo-foreign",
    });
    const foreignProject = sanitizedObservation(401, { error: { status: "UNAUTHENTICATED" } });
    assert.equal(
      buildReport(config, { ownProject, foreignProject }).crossProject.status,
      "unverified",
    );
    const active = { ...config, foreignProjectActive: true };
    assert.equal(
      buildReport(active, { ownProject, foreignProject }).crossProject.status,
      "observed",
    );
    assert.equal(
      buildReport(active, {
        ownProject,
        foreignProject: {
          status: 403,
          code: "PERMISSION_DENIED",
          servicePrecondition: "api-unavailable",
        },
      }).crossProject.status,
      "unverified",
    );
  });
});
