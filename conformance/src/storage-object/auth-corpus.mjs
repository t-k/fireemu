import { buildSymbolicStorageAuthPlan } from "./auth-plan.mjs";

const SEED_BYTES = "b3duZXItc2VlZA==";
const SUBJECT_BYTES = "YXV0aC1zdWJqZWN0";

/** Declare the two authentication recipes without resolving credentials or sending requests. */
export function buildAuthCorpus({ projectId, bucket, runId } = {}) {
  const plan = buildSymbolicStorageAuthPlan({ projectId, bucket, runId });
  const gcsObjectPath = (name) => `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
  const firebaseObjectPath = (name) => `/v0/b/${bucket}/o/${encodeURIComponent(name)}`;

  function gcsReads(name, phase) {
    return [
      {
        id: `${phase}-metadata`,
        service: "gcs-json",
        method: "GET",
        bucket,
        objectName: name,
        path: gcsObjectPath(name),
        query: {},
        credential: "owner",
      },
      {
        id: `${phase}-media`,
        service: "gcs-json",
        method: "GET",
        bucket,
        objectName: name,
        path: gcsObjectPath(name),
        query: { alt: "media" },
        credential: "owner",
      },
      {
        id: `${phase}-prefix`,
        service: "gcs-json",
        method: "GET",
        bucket,
        objectName: name,
        path: `/storage/v1/b/${bucket}/o`,
        query: { prefix: name, maxResults: "1000" },
        requireExhaustedSinglePage: true,
        credential: "owner",
      },
    ];
  }

  function accountSteps(program, kind, account) {
    return [
      {
        id: `${kind}-email-absence`,
        service: "identitytoolkit",
        method: "POST",
        path: "/v1/accounts:lookup",
        credential: "owner",
        body: { email: [account.email], targetProjectId: projectId },
        requireEmptyUsers: true,
      },
      {
        id: `${kind}-signup`,
        service: "identitytoolkit",
        method: "POST",
        path: "/v1/accounts:signUp",
        query: { key: { kind: "private-api-key" } },
        credential: "none",
        body: {
          email: account.email,
          password: { kind: "private-password", accountRef: account.ref },
          returnSecureToken: true,
        },
        accountRef: account.ref,
        requireUidAndToken: true,
      },
      {
        id: `${kind}-token-lookup`,
        service: "identitytoolkit",
        method: "POST",
        path: "/v1/accounts:lookup",
        query: { key: { kind: "private-api-key" } },
        credential: "none",
        body: { idToken: { kind: "signup-id-token", accountRef: account.ref } },
        requireSameUidAndEmail: true,
      },
    ];
  }

  function accountCleanup(kind, account) {
    return [
      {
        id: `${kind}-delete`,
        service: "identitytoolkit",
        method: "POST",
        path: "/v1/accounts:delete",
        credential: "owner",
        body: {
          localId: { kind: "owned-uid", accountRef: account.ref },
          targetProjectId: projectId,
        },
        onlyOwnedUid: true,
      },
      {
        id: `${kind}-absence`,
        service: "identitytoolkit",
        method: "POST",
        path: "/v1/accounts:lookup",
        credential: "owner",
        body: { email: [account.email], targetProjectId: projectId },
        requireEmptyUsers: true,
      },
    ];
  }

  const recipes = plan.programs.map((program) => {
    const accounts = {
      valid: { ref: program.validAccountRef, email: "storage-object@example.com" },
      competitor: {
        ref: program.competitorAccountRef,
        email: `storage-object-control-${runId}-${program.id}@example.com`,
      },
    };
    const accountSetup = [
      ...accountSteps(program, "valid", accounts.valid),
      ...accountSteps(program, "competitor", accounts.competitor),
    ];
    const probes = plan.probes
      .filter((probe) => probe.programId === program.id)
      .map((probe) => {
        const name = probe.objectName;
        const credentialRef =
          probe.credentialRef === "valid" || probe.credentialRef === "competitor"
            ? { kind: probe.credentialRef, accountRef: accounts[probe.credentialRef].ref }
            : { kind: probe.credentialRef };
        return {
          id: probe.id,
          action: probe.action,
          credential: probe.credentialRef,
          objectName: name,
          initial: gcsReads(name, "initial"),
          seed:
            probe.action === "read"
              ? {
                  id: "owner-seed",
                  service: "gcs-json",
                  method: "POST",
                  bucket,
                  objectName: name,
                  path: `/upload/storage/v1/b/${bucket}/o`,
                  query: { uploadType: "media", name, ifGenerationMatch: "0" },
                  credential: "owner",
                  body: { base64: SEED_BYTES },
                }
              : null,
          before: gcsReads(name, "before"),
          subject: {
            id: "subject",
            service: "firebase-storage",
            method: probe.action === "read" ? "GET" : "POST",
            bucket,
            objectName: name,
            path: probe.action === "read" ? firebaseObjectPath(name) : `/v0/b/${bucket}/o`,
            query: probe.action === "read" ? { alt: "media" } : { name },
            credentialRef,
            ...(probe.action === "write" ? { body: { base64: SUBJECT_BYTES } } : {}),
          },
          after: gcsReads(name, "after"),
          cleanup: [
            {
              id: "owned-delete",
              service: "gcs-json",
              method: "DELETE",
              bucket,
              objectName: name,
              path: gcsObjectPath(name),
              query: { ifGenerationMatch: { kind: "owned-generation", name } },
              onlyAfterOwnedGeneration: true,
              credential: "owner",
            },
            ...gcsReads(name, "cleanup"),
          ],
          outcome: "UNOBSERVED",
        };
      });
    return {
      id: program.recipeId,
      accountLifecycle: program.accountLifecycle,
      accounts,
      accountSetup,
      probes,
      accountCleanup: [
        ...accountCleanup("competitor", accounts.competitor),
        ...accountCleanup("valid", accounts.valid),
      ],
    };
  });
  const subjectEntries = recipes.reduce(
    (sum, recipe) =>
      sum +
      recipe.accountSetup.length +
      recipe.probes.reduce(
        (probeSum, probe) =>
          probeSum + probe.initial.length + (probe.seed ? 1 : 0) + probe.before.length + 1 + probe.after.length,
        0,
      ),
    0,
  );
  const cleanupEntries = recipes.reduce(
    (sum, recipe) =>
      sum + recipe.accountCleanup.length + recipe.probes.reduce((probeSum, probe) => probeSum + probe.cleanup.length, 0),
    0,
  );
  return {
    status: "DECLARED_NO_SEND",
    recipeIds: recipes.map((recipe) => recipe.id),
    recipes,
    subjectEntries,
    cleanupEntries,
    requestsPerRecording: subjectEntries + cleanupEntries,
    sendAuthorized: false,
  };
}
