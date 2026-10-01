import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus, validateCorpus } from "./storage-rules/corpus.mjs";

const closure = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)),
);
const input = {
  bucket: "synthetic-rules-bucket",
  prefix: "STORAGE-RULES/local-run/",
  uidA: "local-user-a",
  uidB: "local-user-b",
};
const build = () => buildCorpus(input);
const rows = (corpus, suffix) =>
  corpus.cases.filter((c) => c.recipeId === `storage-rules/${suffix}`);

test("partial declaration preserves every frozen behavior recipe without claiming verification", () => {
  const corpus = build();
  const result = validateCorpus(corpus, closure);
  assert.equal(result.cases, 331);
  assert.equal(result.declaredRecipes, 22);
  assert.equal(result.pendingRecipes, 0);
  assert.equal(result.firestorePrograms, 5);
  assert.equal(result.managementPrograms, 3);
  assert.equal(result.declaredObjectRequestsPerRecording, 3739);
  assert.equal(result.declaredFirestoreRequestsPerRecording, 60);
  assert.equal(corpus.productionRecordingsRequired, 2);
  assert.equal(corpus.sendAuthorized, false);
  assert.equal(corpus.compatibilityEstablished, false);
  const ids = closure.conditions
    .flatMap((c) => c.recipeIds)
    .filter((id) => !["storage-rules/final-artifact", "storage-rules/closure-review"].includes(id));
  assert.deepEqual(new Set([...corpus.declaredRecipes, ...corpus.pendingRecipes]), new Set(ids));
  assert.deepEqual(build(), corpus);
});

test("Storage compile declaration retains every distinct Rules source and the invalid control", () => {
  const corpus = build();
  const program = corpus.managementPrograms.find((entry) => entry.id === "storage-service-compile");
  const switched = corpus.managementPrograms.find((entry) => entry.id === "release-switch");
  assert.equal(program.recipeId, "storage-rules/storage-service-compile");
  assert.equal(program.sendAuthorized, false);
  assert.equal(program.observationStatus, "PENDING_PRODUCTION");
  assert.equal(
    program.releaseName,
    `projects/fireemu-oracle-query/releases/firebase.storage/${input.bucket}`,
  );
  const referenced = [
    ...[...corpus.cases, ...corpus.firestorePrograms].map((entry) => entry.rulesSource),
    switched.sourceA,
    switched.sourceB,
  ];
  assert.equal(program.validSources.length, referenced.length);
  assert.deepEqual(
    new Set(program.validSources.map((entry) => entry.content)),
    new Set(referenced),
  );
  assert.equal(new Set(program.validSources.map((entry) => entry.sha256)).size, referenced.length);
  assert.ok(
    program.validSources.every((entry) => entry.content.includes("service firebase.storage")),
  );
  assert.ok(program.invalidSource.content.includes("allow get: if ;"));
  assert.ok(!referenced.includes(program.invalidSource.content));
  assert.deepEqual(
    program.validSequence.map((step) => step.id),
    ["release-before", "test-valid-source"],
  );
  assert.ok(program.validSequence.every((step) => step.service === "firebase-rules"));
  assert.equal(program.validSequence[0].repeatFor, undefined);
  assert.equal(program.validSequence[1].method, "POST");
  assert.equal(program.validSequence[1].path, "/v1/projects/fireemu-oracle-query:test");
  assert.equal(program.validSequence[1].repeatFor, "validSources");
  assert.deepEqual(program.validSequence[1].body, {
    source: { files: [{ name: "storage.rules", contentRef: "validSources[].content" }] },
  });
  assert.deepEqual(
    program.invalidSequence.map((step) => step.id),
    ["test-invalid-source", "release-after-invalid"],
  );
  assert.equal(program.invalidSequence.at(-1).id, "release-after-invalid");
  assert.equal(program.invalidSequence[0].method, "POST");
  assert.equal(program.invalidSequence[0].path, "/v1/projects/fireemu-oracle-query:test");
  assert.deepEqual(program.invalidSequence[0].body, {
    source: { files: [{ name: "storage.rules", contentRef: "invalidSource.content" }] },
  });
  assert.ok(!JSON.stringify(program).includes("rulesets"));
  assert.equal(Object.hasOwn(program, "expectedStatus"), false);
});

test("release switch declares two opposite decisions and verified absence restoration", () => {
  const program = build().managementPrograms.find((entry) => entry.id === "release-switch");
  assert.equal(program.recipeId, "storage-rules/release-switch");
  assert.equal(program.expectedBaseline, "bucket-specific-and-bucketless-release-absent");
  assert.ok(program.objectA.startsWith(input.prefix));
  assert.ok(program.objectB.startsWith(input.prefix));
  assert.notEqual(program.objectA, program.objectB);
  assert.match(program.sourceA, /service firebase\.storage/);
  assert.match(program.sourceB, /service firebase\.storage/);
  assert.ok(program.sourceA.includes(program.objectA));
  assert.ok(program.sourceB.includes(program.objectB));
  assert.ok(!program.sourceA.includes(program.objectB));
  assert.ok(!program.sourceB.includes(program.objectA));
  assert.deepEqual(program.decisionOrder, [
    { release: "A", object: "A", role: "old-allow" },
    { release: "A", object: "B", role: "new-not-yet-allow" },
    { release: "B", object: "A", role: "old-no-longer-allow" },
    { release: "B", object: "B", role: "new-allow" },
  ]);
  assert.deepEqual(program.restore, [
    "delete-owned-release",
    "confirm-release-absent",
    "confirm-bucketless-absent",
    "delete-unreferenced-rulesets",
    "confirm-rulesets-absent",
    "owned-object-cleanup",
  ]);
  assert.equal(program.sendAuthorized, false);
  assert.equal(Object.hasOwn(program, "expectedStatus"), false);
});

test("no-release declaration pairs Firebase refusal with Admin readback and owned cleanup", () => {
  const program = build().managementPrograms.find((entry) => entry.id === "no-release");
  assert.equal(program.recipeId, "storage-rules/no-release");
  assert.equal(program.expectedBaseline, "bucket-specific-and-bucketless-release-absent");
  assert.ok(program.objectName.startsWith(input.prefix));
  assert.deepEqual(program.stepOrder, [
    "confirm-releases-absent",
    "confirm-object-absent",
    "admin-seed",
    "admin-read-before",
    "firebase-get-without-release",
    "admin-read-after",
    "owned-admin-delete",
    "confirm-object-absent-after",
    "confirm-releases-still-absent",
  ]);
  assert.equal(program.sendAuthorized, false);
  assert.equal(Object.hasOwn(program, "expectedStatus"), false);
});

test("management declarations reject missing sources or changed restoration claims", () => {
  const mutations = [
    (corpus) => corpus.managementPrograms[0].validSources.pop(),
    (corpus) => (corpus.managementPrograms[0].invalidSource.content = "allow get: if true;"),
    (corpus) =>
      (corpus.managementPrograms[0].validSequence[1].path =
        "/v1/projects/fireemu-oracle-query/rulesets"),
    (corpus) => (corpus.managementPrograms[0].validSequence[1].body.testSuite = { testCases: [] }),
    (corpus) => (corpus.managementPrograms[1].restore[1] = "skip-readback"),
    (corpus) => (corpus.managementPrograms[2].stepOrder[4] = "admin-get"),
  ];
  for (const mutate of mutations) {
    const corpus = build();
    mutate(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("Firestore cross-service programs cover document transitions and distinct access budgets", () => {
  const corpus = build();
  const programs = corpus.firestorePrograms;
  assert.equal(programs.length, 5);
  assert.deepEqual(
    new Set(programs.map((p) => p.id)),
    new Set([
      "firestore-get-transition",
      "firestore-exists-transition",
      "firestore-budget-two",
      "firestore-budget-three",
      "firestore-budget-repeat",
    ]),
  );
  assert.deepEqual(
    new Set(programs.map((p) => p.recipeId)),
    new Set([
      "storage-rules/firestore-get",
      "storage-rules/firestore-exists",
      "storage-rules/firestore-access-budget",
    ]),
  );
  for (const program of programs) {
    assert.equal(program.projectId, "fireemu-oracle-query");
    assert.equal(program.databaseId, "(default)");
    assert.equal(program.collectionId, "STORAGE-RULES");
    assert.equal(program.sendAuthorized, false);
    assert.equal(program.observationStatus, "PENDING_PRODUCTION");
    assert.equal(Object.hasOwn(program, "expectedStatus"), false);
    assert.ok(
      program.firestoreDocumentNames.every((name) =>
        name.startsWith(
          "projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/local-run-",
        ),
      ),
    );
    assert.ok(program.storageObjectNames.every((name) => name.startsWith(input.prefix)));
    assert.match(program.rulesSource, /service firebase\.storage/);
    assert.ok(program.steps.every((step) => step.request.capture.body === "raw-bytes"));
    assert.ok(program.cleanup.every((step) => step.request.capture.body === "raw-bytes"));
    const steps = [...program.steps, ...program.cleanup];
    assert.equal(new Set(steps.map((s) => s.id)).size, steps.length);
    assert.ok(
      program.steps
        .filter((s) => s.id.startsWith("baseline-"))
        .every((s) => s.requiredState === "absent"),
    );
    const seen = new Map();
    for (const value of steps) {
      const request = value.request;
      assert.ok(request.path.startsWith("/") && !request.path.includes("://"));
      assert.deepEqual(
        request.headers,
        request.operation === "upload" ? { "content-type": "text/plain" } : {},
      );
      if (request.service === "firestore") {
        assert.ok(program.firestoreDocumentNames.includes(request.documentName));
        assert.ok(
          request.path.startsWith(
            "/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES",
          ),
        );
        assert.equal(request.credential, "admin");
        const ref = request.query["currentDocument.updateTime"];
        if (ref) {
          assert.equal(ref.kind, "firestore-update-time");
          assert.equal(ref.documentName, request.documentName);
          assert.ok(seen.has(ref.fromStep));
          if (ref.ownerWriteSteps) {
            assert.equal(value.when, "owned-update-time-matches-run-write");
            for (const ownerStep of ref.ownerWriteSteps) {
              assert.ok(seen.has(ownerStep));
              assert.equal(seen.get(ownerStep).documentName, request.documentName);
              assert.ok(["POST", "PATCH"].includes(seen.get(ownerStep).method));
            }
          }
        }
      } else {
        assert.equal(request.service, "storage");
        assert.ok(program.storageObjectNames.includes(request.objectName));
        const ref = request.query.ifGenerationMatch;
        if (typeof ref === "object") {
          assert.equal(ref.kind, "gcs-object-generation");
          assert.equal(ref.objectName, request.objectName);
          assert.ok(seen.has(ref.fromStep));
          assert.equal(value.when, "owned-generation-matches-receipt");
          assert.ok(seen.has(ref.ownerReceiptStep));
          assert.equal(seen.get(ref.ownerReceiptStep).objectName, request.objectName);
          assert.equal(seen.get(ref.ownerReceiptStep).operation, "upload");
        }
      }
      seen.set(value.id, request);
    }
  }
  assert.equal(
    new Set(programs.flatMap((p) => p.firestoreDocumentNames)).size,
    programs.reduce((n, p) => n + p.firestoreDocumentNames.length, 0),
  );
  assert.equal(
    new Set(programs.flatMap((p) => p.storageObjectNames)).size,
    programs.reduce((n, p) => n + p.storageObjectNames.length, 0),
  );
  const get = programs.find((p) => p.id === "firestore-get-transition");
  const getSubjects = get.steps.filter((s) => s.id.startsWith("subject-"));
  assert.deepEqual(
    getSubjects.map((s) => s.id),
    ["subject-true", "subject-false", "subject-missing"],
  );
  assert.equal(new Set(getSubjects.map((s) => s.request.objectName)).size, 3);
  assert.match(get.rulesSource, /allow create:/);
  assert.doesNotMatch(get.rulesSource, /allow get:/);
  assert.deepEqual(get.steps.find((s) => s.id === "doc-create-true").request.body.json.fields, {
    allowed: { booleanValue: true },
  });
  assert.deepEqual(get.steps.find((s) => s.id === "doc-update-false").request.body.json.fields, {
    allowed: { booleanValue: false },
  });
  assert.equal(
    get.steps.find((s) => s.id === "doc-update-false").request.query["currentDocument.updateTime"]
      .fromStep,
    "doc-read-true",
  );
  assert.equal(
    get.steps.find((s) => s.id === "doc-delete").request.query["currentDocument.updateTime"]
      .fromStep,
    "doc-read-false",
  );
  assert.deepEqual(
    get.cleanup.find((s) => s.id === "doc-cleanup-delete").request.query[
      "currentDocument.updateTime"
    ].ownerWriteSteps,
    ["doc-create-true", "doc-update-false"],
  );
  assert.deepEqual(
    get.steps.filter((s) => s.id.startsWith("doc-read-")).map((s) => s.requiredState),
    ["present-allowed-true", "present-allowed-false", "absent"],
  );
  for (const tag of ["true", "false", "missing"])
    assert.deepEqual(
      get.steps.filter((s) => s.id.startsWith(`after-${tag}-`)).map((s) => s.request.operation),
      ["get-metadata", "get-media"],
    );
  assert.match(
    get.rulesSource,
    /firestore\.get\(\/databases\/\(default\)\/documents\/STORAGE-RULES\/\$\(doc\)\)/,
  );
  const exists = programs.find((p) => p.id === "firestore-exists-transition");
  assert.match(exists.rulesSource, /allow get:/);
  assert.doesNotMatch(exists.rulesSource, /allow create:/);
  assert.equal(
    exists.steps.find((s) => s.id === "doc-delete").request.query["currentDocument.updateTime"]
      .fromStep,
    "doc-read-present",
  );
  assert.deepEqual(
    exists.steps.filter((s) => s.id.startsWith("subject-")).map((s) => s.id),
    ["subject-present", "subject-missing"],
  );
  assert.match(
    exists.rulesSource,
    /firestore\.exists\(\/databases\/\(default\)\/documents\/STORAGE-RULES\/\$\(doc\)\)/,
  );
  for (const tag of ["present", "missing"])
    assert.deepEqual(
      exists.steps.filter((s) => s.id.startsWith(`after-${tag}-`)).map((s) => s.request.operation),
      ["get-metadata", "get-media"],
    );
  const budget = programs.filter((p) => p.recipeId === "storage-rules/firestore-access-budget");
  assert.deepEqual(
    budget.map((p) => p.accessOrder),
    [
      ["a", "b"],
      ["a", "b", "c"],
      ["a", "b", "a"],
    ],
  );
  for (const program of budget) {
    assert.match(program.rulesSource, /allow get:/);
    assert.doesNotMatch(program.rulesSource, /allow create:/);
    assert.ok(
      program.steps
        .filter((s) => s.id.startsWith("doc-read-"))
        .every((s) => s.requiredState === "present-allowed-true"),
    );
  }
  assert.ok(
    budget.every((program) =>
      program.steps
        .filter((s) => s.id.startsWith("before-"))
        .every((s) => s.requiredState === "present"),
    ),
  );
});

test("Firestore programs reject changed project, document path, access order, receipt and result claims", () => {
  const changes = [
    (c) => {
      c.firestorePrograms[0].projectId = "other-project";
    },
    (c) => {
      c.firestorePrograms[0].firestoreDocumentNames[0] =
        "projects/fireemu-oracle-query/databases/(default)/documents/OTHER/x";
    },
    (c) => {
      c.firestorePrograms[2].accessOrder.reverse();
    },
    (c) => {
      c.firestorePrograms[1].steps.splice(
        c.firestorePrograms[1].steps.findIndex((s) => s.id === "doc-read-missing"),
        1,
      );
    },
    (c) => {
      c.firestorePrograms[3].expectedStatus = 200;
    },
    (c) => {
      c.firestorePrograms[4].steps[0].request.headers = { authorization: "secret" };
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("upload request.resource declares exact simple, multipart and resumable finalization inputs", () => {
  const all = rows(build(), "request-resource-upload");
  const matrix = new Set();
  for (const protocol of ["simple", "multipart", "resumable"])
    for (const field of ["size", "contentType", "name", "metadata"])
      for (const matches of [true, false]) matrix.add(`${protocol}/${field}/${matches}`);
  assert.equal(all.length, 24);
  assert.deepEqual(
    new Set(all.map((row) => `${row.uploadProtocol}/${row.rule.field}/${row.rule.matches}`)),
    matrix,
  );
  for (const row of all) {
    assert.equal(row.initialState, "absent");
    assert.equal(row.operation, "upload");
    assert.equal(row.subject.credential, "user-a");
    assert.equal(row.subject.dialect, "firebase");
    assert.equal(row.subject.method, "POST");
    assert.equal(row.baseline.length, 2);
    assert.equal(row.before.length, 2);
    assert.equal(row.after.length, 2);
    assert.equal(row.cleanup.at(-1).operation, "get-media");
    assert.equal(Object.hasOwn(row, "expectedStatus"), false);
    assert.equal(Object.hasOwn(row, "observedStatus"), false);
    assert.match(row.rulesSource, /request\.resource/);
    assert.match(row.rulesSource, /allow create:/);
    if (row.uploadProtocol === "simple" && row.rule.field === "metadata") {
      assert.ok(
        row.rulesSource.includes(
          row.rule.matches
            ? '!("owner" in request.resource.metadata)'
            : '"owner" in request.resource.metadata',
        ),
      );
    } else {
      const fieldExpression =
        row.rule.field === "metadata"
          ? "request.resource.metadata.owner"
          : `request.resource.${row.rule.field}`;
      const expectedLiteral = {
        size: row.rule.matches ? "4" : "5",
        contentType: row.rule.matches ? "'text/plain'" : "'application/octet-stream'",
        name: `'${row.rule.matches ? row.objectName : `${row.casePrefix}different.bin`}'`,
        metadata: row.rule.matches ? "'probe'" : "'other'",
      }[row.rule.field];
      assert.ok(row.rulesSource.includes(`${fieldExpression} == ${expectedLiteral}`));
    }
    if (row.uploadProtocol === "simple") {
      assert.equal(Buffer.from(row.subject.body.base64, "base64").toString(), "next");
      assert.equal(row.setup.length, 0);
      assert.equal(row.subject.path, `/v0/b/${input.bucket}/o`);
      assert.deepEqual(row.subject.query, { name: row.objectName });
      assert.equal(row.subject.headers["content-type"], "text/plain");
      assert.equal(row.subject.sessionUrlReference, undefined);
    } else if (row.uploadProtocol === "multipart") {
      assert.equal(row.setup.length, 0);
      assert.deepEqual(row.subject.query, { name: row.objectName, uploadType: "multipart" });
      assert.equal(row.subject.headers["x-goog-upload-protocol"], "multipart");
      const bytes = Buffer.from(row.subject.body.base64, "base64");
      assert.match(
        bytes.toString(),
        /^--rules-boundary\r\nContent-Type: application\/json; charset=UTF-8\r\n\r\n/,
      );
      assert.match(
        bytes.toString(),
        /\r\nContent-Type: text\/plain\r\n\r\nnext\r\n--rules-boundary--\r\n$/,
      );
      assert.ok(
        bytes.toString().includes(
          JSON.stringify({
            name: row.objectName,
            contentType: "text/plain",
            metadata: { owner: "probe" },
          }),
        ),
      );
    } else {
      assert.equal(Buffer.from(row.subject.body.base64, "base64").toString(), "next");
      assert.equal(row.setup.length, 1);
      const start = row.setup[0];
      assert.equal(start.id, "start");
      assert.equal(start.method, "POST");
      assert.equal(start.headers["x-goog-upload-command"], "start");
      assert.deepEqual(start.body.json, {
        name: row.objectName,
        contentType: "text/plain",
        metadata: { owner: "probe" },
      });
      assert.equal(row.subject.path, null);
      assert.deepEqual(row.subject.query, {});
      assert.deepEqual(row.subject.sessionUrlReference, {
        kind: "firebase-resumable-session-url",
        fromStep: "start",
        fromHeader: "x-goog-upload-url",
        expectedBucket: input.bucket,
        expectedObjectName: row.objectName,
        secretHandling: "private-only",
        resolveOnlyAfterVerifiedStart: true,
      });
      assert.equal(row.subject.headers["x-goog-upload-command"], "upload, finalize");
      assert.equal(row.subject.headers["x-goog-upload-offset"], "0");
      assert.equal(row.cleanup[0].headers["x-goog-upload-command"], "cancel");
      assert.equal(row.cleanup[0].when, "session-active-or-outcome-unknown");
      assert.deepEqual(row.cleanup[0].sessionUrlReference, row.subject.sessionUrlReference);
    }
  }
});

test("upload declaration rejects a changed session source, payload, metadata or result claim", () => {
  const changes = [
    (c) => {
      rows(c, "request-resource-upload")[0].expectedStatus = 200;
    },
    (c) => {
      rows(c, "request-resource-upload").find(
        (r) => r.uploadProtocol === "simple",
      ).subject.body.base64 = "bm90LWNvcnJlY3Q=";
    },
    (c) => {
      rows(c, "request-resource-upload").find(
        (r) => r.uploadProtocol === "multipart",
      ).subject.body.base64 = Buffer.from("not multipart").toString("base64");
    },
    (c) => {
      rows(c, "request-resource-upload").find(
        (r) => r.uploadProtocol === "resumable",
      ).subject.sessionUrlReference.fromStep = "other";
    },
    (c) => {
      rows(c, "request-resource-upload").find(
        (r) => r.uploadProtocol === "resumable",
      ).setup[0].body.json.metadata.owner = "other";
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("method matrix independently covers seven grants, six operations and two initial states", () => {
  const actual = rows(build(), "method-grants");
  const expected = new Set();
  for (const grant of ["read", "write", "get", "list", "create", "update", "delete"])
    for (const operation of ["get-metadata", "get-media", "list", "upload", "patch", "delete"])
      for (const initial of ["absent", "present"]) expected.add(`${grant}/${operation}/${initial}`);
  assert.equal(actual.length, 84);
  assert.deepEqual(
    new Set(actual.map((c) => `${c.rule.grant}/${c.operation}/${c.initialState}`)),
    expected,
  );
  for (const c of actual)
    assert.match(c.rulesSource, new RegExp(`allow ${c.rule.grant}: if true;`));
});

test("version and recursive controls distinguish list/get and zero/one/multiple segments", () => {
  const corpus = build();
  const lists = rows(corpus, "list-v2");
  assert.equal(lists.length, 16);
  assert.deepEqual(
    new Set(lists.map((c) => `${c.rule.version}/${c.rule.grant}`)),
    new Set(["1/read", "2/read", "2/get", "2/list"]),
  );
  for (const c of lists)
    assert.equal(c.rulesSource.includes("rules_version = '2'"), c.rule.version === 2);
  const recursive = rows(corpus, "recursive-wildcard");
  assert.equal(recursive.length, 6);
  for (const c of recursive) {
    assert.match(c.rulesSource, /anchor\/\{tail=\*\*\}/);
    assert.equal(c.objectName.slice(c.casePrefix.length).split("/").length - 1, c.depth);
  }
});

test("principal and claim declarations use references, owned paths and separate mismatching fixtures", () => {
  const corpus = build();
  const principal = rows(corpus, "principals");
  assert.equal(principal.length, 15);
  assert.equal(rows(corpus, "token-claims").length, 18);
  for (const c of principal.filter((row) => row.rule.kind === "uid")) {
    assert.match(c.rulesSource, /request.auth.uid == owner/);
    assert.ok(c.objectName.includes(c.owner === "a" ? input.uidA : input.uidB));
  }
  for (const c of corpus.cases) {
    assert.equal(c.subject.credential, c.principal);
    assert.equal(Object.hasOwn(c.subject.headers, "authorization"), false);
    assert.equal(Object.hasOwn(c, "expectedStatus"), false);
  }
  for (const row of principal.filter((value) => value.rule.kind === "anonymous"))
    assert.match(row.rulesSource, /request.auth == null/);
  const predicates = {
    verified: "request.auth.token.email_verified == true",
    role: "request.auth.token.role == 'reader'",
    number: "request.auth.token.level == 7",
  };
  for (const row of rows(corpus, "token-claims"))
    assert.ok(row.rulesSource.includes(predicates[row.rule.field]));
  assert.equal(corpus.principals["user-a"].requiredClaims.role, "reader");
  assert.equal(corpus.principals["user-b"].requiredClaims.email_verified, false);
  assert.equal(Object.hasOwn(corpus.principals["user-plain"].requiredClaims, "role"), false);
});

test("token refusal cases keep five in-scope credential states under one auth rule", () => {
  const corpus = build();
  const actual = rows(corpus, "token-refusal");
  const credentials = new Map([
    ["missing", "anonymous"],
    ["malformed", "malformed-token"],
    ["foreign-project", "foreign-project-token"],
    ["revoked", "revoked-token"],
    ["valid", "user-a"],
  ]);
  assert.equal(actual.length, credentials.size);
  assert.deepEqual(
    new Set(actual.map((c) => c.id)),
    new Set([...credentials.keys()].map((kind) => `token-${kind}`)),
  );
  for (const row of actual) {
    const kind = row.id.slice("token-".length);
    assert.equal(row.principal, credentials.get(kind));
    assert.equal(row.subject.credential, credentials.get(kind));
    assert.equal(row.operation, "get-media");
    assert.equal(row.initialState, "present");
    assert.match(row.rulesSource, /allow get: if request\.auth != null;/);
    assert.equal(row.subject.headers.authorization, undefined);
    assert.equal(Object.hasOwn(row, "expectedStatus"), false);
    assert.equal(row.setup.length, 2);
    assert.equal(row.before.length, 2);
    assert.equal(row.after.length, 2);
  }
  assert.equal(corpus.principals["malformed-token"].kind, "invalid-authorization-reference");
  assert.match(corpus.principals["malformed-token"].requirement, /keep the actual header private/);
  for (const kind of ["foreign-project", "revoked"])
    assert.equal(corpus.principals[`${kind}-token`].kind, "firebase-id-token-reference");
  assert.match(corpus.principals["foreign-project-token"].requirement, /different project/);
  assert.match(corpus.principals["revoked-token"].requirement, /verified account token revocation/);
  assert.equal(Object.hasOwn(corpus.principals, "expired-token"), false);
});

test("token refusal declaration rejects changed credential, missing case or invented status", () => {
  const changes = [
    (corpus) =>
      corpus.cases.splice(
        corpus.cases.findIndex((c) => c.id === "token-revoked"),
        1,
      ),
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-foreign-project").subject.credential = "user-a";
    },
    (corpus) => {
      corpus.principals["foreign-project-token"].requirement = "unchecked";
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-valid").expectedStatus = 200;
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("token refusal declaration rejects extra secret or outcome fields at every level", () => {
  const changes = [
    (corpus) => {
      corpus.tokenBytes = "private-value";
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-revoked").tokenBytes = "private-value";
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-foreign-project").observedStatus = 200;
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-malformed").subject.headers.tokenBytes =
        "private-value";
    },
    (corpus) => {
      Object.defineProperty(
        corpus.cases.find((c) => c.id === "token-valid"),
        "rawToken",
        {
          value: "private-value",
        },
      );
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-malformed").subject.headers.rawToken = undefined;
    },
    (corpus) => {
      corpus.cases.find((c) => c.id === "token-foreign-project")[Symbol("rawToken")] =
        "private-value";
    },
    (corpus) => {
      Object.defineProperty(
        corpus.cases.find((c) => c.id === "token-valid"),
        "principal",
        {
          get: () => "user-a",
          enumerable: true,
        },
      );
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("denial precedence declares the full state, dialect, credential and input matrix", () => {
  const corpus = build();
  const all = rows(corpus, "errors/precedence");
  const actual = all.filter((row) => row.rule.kind === "deny");
  const expected = new Set();
  for (const state of ["absent", "present"])
    for (const dialect of ["firebase", "gcs"])
      for (const credential of ["valid", "malformed"])
        for (const inputState of ["valid", "malformed"])
          expected.add(`${state}/${dialect}/${credential}/${inputState}`);
  assert.equal(actual.length, 16);
  assert.equal(all.length, 24);
  assert.deepEqual(
    new Set(
      actual.map(
        (row) => `${row.initialState}/${row.dialect}/${row.credentialState}/${row.inputState}`,
      ),
    ),
    expected,
  );
  for (const row of actual) {
    assert.equal(row.operation, "patch");
    assert.equal(row.subject.credential, row.principal);
    assert.equal(row.subject.dialect, row.dialect);
    assert.deepEqual(row.subject.query, {});
    assert.equal(row.subject.method, "PATCH");
    if (row.inputState === "malformed") {
      assert.equal(row.subject.body.base64, Buffer.from("{").toString("base64"));
      assert.equal(row.subject.headers["content-type"], "application/json");
    } else assert.deepEqual(row.subject.body.json, {});
    assert.equal(
      row.principal,
      row.dialect === "firebase"
        ? row.credentialState === "valid"
          ? "user-a"
          : "malformed-token"
        : row.credentialState === "valid"
          ? "admin"
          : "malformed-oauth",
    );
    assert.match(row.rulesSource, /allow read, write: if false;/);
    assert.equal(row.setup.length, row.initialState === "present" ? 2 : 0);
    assert.equal(row.before.length, 2);
    assert.equal(row.after.length, 2);
    assert.equal(Object.hasOwn(row, "expectedStatus"), false);
    assert.equal(Object.hasOwn(row, "observedStatus"), false);
    assert.ok(row.objectName.startsWith(input.prefix));
  }
  for (const initial of ["absent", "present"])
    for (const dialect of ["firebase", "gcs"])
      for (const inputState of ["valid", "malformed"]) {
        const control = all.find(
          (row) => row.id === `precedence-control-${initial}-${dialect}-${inputState}`,
        );
        assert.ok(control);
        assert.equal(control.initialState, initial);
        assert.deepEqual(control.rule, { version: 2, kind: "grant", grant: "write" });
        assert.equal(control.credentialState, "valid");
        assert.equal(control.subject.method, "PATCH");
        assert.equal(control.subject.body.base64 !== undefined, inputState === "malformed");
        assert.equal(control.subject.body.json !== undefined, inputState === "valid");
      }
  assert.equal(corpus.principals["malformed-oauth"].kind, "invalid-oauth-token-reference");
  assert.match(corpus.principals["malformed-oauth"].requirement, /outside this corpus/);
});

test("denial precedence refuses missing controls, changed references and invented results", () => {
  const changes = [
    (corpus) =>
      corpus.cases.splice(
        corpus.cases.findIndex((row) => row.id === "precedence-control-present-firebase-malformed"),
        1,
      ),
    (corpus) => {
      corpus.cases.find((row) => row.id === "precedence-control-absent-gcs-valid").rule.kind =
        "deny";
    },
    (corpus) =>
      corpus.cases.splice(
        corpus.cases.findIndex((row) => row.id === "precedence-present-gcs-malformed-malformed"),
        1,
      ),
    (corpus) => {
      corpus.cases.find(
        (row) => row.id === "precedence-absent-firebase-valid-malformed",
      ).subject.body = { json: {} };
    },
    (corpus) => {
      corpus.cases.find((row) => row.id === "precedence-present-gcs-malformed-valid").principal =
        "admin";
    },
    (corpus) => {
      corpus.cases.find(
        (row) => row.id === "precedence-present-firebase-valid-valid",
      ).expectedStatus = 403;
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("download token boundary pairs anonymous reads of one owned object", () => {
  const corpus = build();
  const cases = rows(corpus, "download-token-boundary");
  assert.equal(cases.length, 1);
  const row = cases[0];
  assert.equal(row.initialState, "present");
  assert.equal(row.rule.kind, "deny");
  assert.deepEqual(
    row.setup.map((request) => request.id),
    ["seed", "seed-metadata", "pre-token-metadata", "create-token"],
  );
  assert.equal(row.setup[2].dialect, "gcs");
  assert.equal(row.setup[2].method, "GET");
  assert.equal(row.setup[3].dialect, "firebase");
  assert.equal(row.setup[3].credential, "admin");
  assert.equal(row.setup[3].method, "POST");
  assert.deepEqual(row.setup[3].query, { create_token: "true" });
  assert.equal(row.subject.credential, "anonymous");
  assert.equal(row.comparison.credential, "anonymous");
  assert.equal(row.subject.path, row.comparison.path);
  assert.equal(row.subject.objectName, row.comparison.objectName);
  assert.equal(row.subject.method, "GET");
  assert.equal(row.comparison.method, "GET");
  assert.deepEqual(row.subject.query, { alt: "media" });
  assert.deepEqual(row.comparison.query, {
    alt: "media",
    token: {
      kind: "firebase-download-token",
      fromStep: "create-token",
      priorStep: "pre-token-metadata",
      fromField: "downloadTokens",
      priorField: "metadata.firebaseStorageDownloadTokens",
      selection: "exactly-one-new",
      objectName: row.objectName,
      secretHandling: "private-only",
    },
  });
  assert.equal(row.before.length, 2);
  assert.equal(row.after.length, 2);
  assert.equal(row.sendAuthorized, false);
  assert.equal(row.tokenResolutionImplemented, false);
  assert.equal(Object.hasOwn(row, "expectedStatus"), false);
  assert.doesNotMatch(JSON.stringify(row), /Bearer |Authorization|eyJ/);
});

test("download token boundary rejects changed token provenance and unpaired reads", () => {
  const changes = [
    (corpus) => {
      delete rows(corpus, "download-token-boundary")[0].comparison;
    },
    (corpus) => {
      rows(corpus, "download-token-boundary")[0].comparison.query.token.priorStep = "seed";
    },
    (corpus) => {
      rows(corpus, "download-token-boundary")[0].comparison.credential = "user-a";
    },
    (corpus) => {
      rows(corpus, "download-token-boundary")[0].comparison.expectedStatus = 200;
    },
    (corpus) => {
      rows(corpus, "download-token-boundary")[0].comparison.query.token.value = "private-value";
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("proposed and stored resource cases retain both predicate outcomes and state readbacks", () => {
  const corpus = build();
  const proposed = rows(corpus, "request-resource-metadata");
  assert.equal(proposed.length, 8);
  assert.equal(rows(corpus, "stored-resource").length, 64);
  for (const c of proposed) {
    assert.equal(c.operation, "patch");
    assert.equal(c.initialState, "present");
    assert.match(c.rulesSource, /request.resource/);
    assert.equal(c.subject.body.json.metadata.owner, "new");
  }
  for (const c of corpus.cases) {
    assert.equal(c.before.length, 2);
    assert.equal(c.after.length, 2);
    assert.deepEqual(
      c.after.map((r) => r.query.alt ?? "metadata"),
      ["metadata", "media"],
    );
    assert.ok(c.after.every((r) => r.dialect === "gcs" && r.credential === "admin"));
    assert.equal(
      c.cleanup.length,
      c.recipeId === "storage-rules/request-resource-upload" && c.uploadProtocol === "resumable"
        ? 4
        : 3,
    );
  }
});

test("state transitions distinguish overwrite operation and delete request.resource", () => {
  const state = rows(build(), "state-transitions");
  assert.equal(state.length, 8);
  const actual = new Set(
    state.map(
      (c) =>
        `${c.rule.kind}/${c.rule.permit ?? c.rule.matchesNull}/${c.operation}/${c.initialState}`,
    ),
  );
  const expected = new Set();
  for (const permit of ["create", "update"])
    for (const initial of ["absent", "present"])
      expected.add(`state-dispatch/${permit}/upload/${initial}`);
  for (const matchesNull of [true, false])
    for (const initial of ["absent", "present"])
      expected.add(`delete-request-resource/${matchesNull}/delete/${initial}`);
  assert.deepEqual(actual, expected);
  for (const c of state) {
    assert.equal(c.observationStatus, "PENDING_PRODUCTION");
    assert.equal(Object.hasOwn(c, "expectedStatus"), false);
    assert.ok(c.objectName.startsWith(input.prefix));
    assert.equal(c.setup.length, c.initialState === "present" ? 2 : 0);
    assert.deepEqual(
      c.before.map((r) => r.operation),
      ["get-metadata", "get-media"],
    );
    assert.deepEqual(
      c.after.map((r) => r.operation),
      ["get-metadata", "get-media"],
    );
    assert.deepEqual(
      c.cleanup.map((r) => r.operation),
      ["delete", "get-metadata", "get-media"],
    );
    if (c.rule.kind === "state-dispatch") {
      assert.match(c.rulesSource, /allow create: if (true|false);/);
      assert.match(c.rulesSource, /allow update: if (true|false);/);
      assert.ok(c.rulesSource.includes(`allow ${c.rule.permit}: if true;`));
      assert.ok(
        c.rulesSource.includes(
          `allow ${c.rule.permit === "create" ? "update" : "create"}: if false;`,
        ),
      );
      assert.equal(c.subject.method, "POST");
      assert.equal(c.subject.query.name, c.objectName);
    } else {
      assert.match(c.rulesSource, /allow delete: if request\.resource (==|!=) null;/);
      assert.ok(
        c.rulesSource.includes(`request.resource ${c.rule.matchesNull ? "==" : "!="} null`),
      );
      assert.equal(c.subject.method, "DELETE");
    }
  }
});

test("request time cases retain a bounded server-clock decision requirement", () => {
  const timed = rows(build(), "request-time");
  assert.equal(timed.length, 4);
  const expected = new Set();
  for (const inside of [true, false])
    for (const operation of ["get-media", "upload"]) expected.add(`${inside}/${operation}`);
  assert.deepEqual(new Set(timed.map((c) => `${c.rule.inside}/${c.operation}`)), expected);
  for (const c of timed) {
    assert.equal(c.rule.kind, "time-window");
    assert.deepEqual(c.timeEvidence, {
      lowerUtc: "2000-01-01T00:00:00Z",
      upperUtc: "2100-01-01T00:00:00Z",
      serverClockIntervalRequired: true,
      uncertainDecision: "INDETERMINATE",
    });
    assert.equal(c.initialState, c.operation === "upload" ? "absent" : "present");
    assert.ok(c.rulesSource.includes("request.time >= timestamp.date(2000, 1, 1)"));
    assert.ok(c.rulesSource.includes("request.time < timestamp.date(2100, 1, 1)"));
    assert.ok(c.rulesSource.includes(c.rule.inside ? "&&" : "!"));
    assert.ok(c.rulesSource.includes(`allow ${c.operation === "upload" ? "create" : "get"}: if`));
    assert.equal(c.observationStatus, "PENDING_PRODUCTION");
    assert.equal(Object.hasOwn(c, "expectedStatus"), false);
    assert.deepEqual(
      c.before.map((r) => r.operation),
      ["get-metadata", "get-media"],
    );
    assert.deepEqual(
      c.after.map((r) => r.operation),
      ["get-metadata", "get-media"],
    );
  }
});

test("denial and bypass controls preserve raw observations under the same deny rule", () => {
  const corpus = build();
  assert.equal(rows(corpus, "errors/firebase-denial").length, 12);
  const boundary = rows(corpus, "gcs-admin-boundary");
  assert.equal(boundary.length, 36);
  assert.deepEqual(
    new Set(boundary.map((c) => `${c.subject.dialect}/${c.principal}`)),
    new Set(["firebase/user-a", "firebase/admin", "gcs/admin"]),
  );
  for (const c of boundary) {
    assert.match(c.rulesSource, /allow read, write: if false;/);
    assert.deepEqual(c.subject.capture, { status: true, headers: "all", body: "raw-bytes" });
  }
});

test("declaration guards reject loss of recipes/cases, unsafe requests and changed rules", () => {
  const changes = [
    (c) => c.cases.pop(),
    (c) => c.pendingRecipes.push("storage-rules/unreviewed"),
    (c) => c.cases.push(structuredClone(c.cases[0])),
    (c) => {
      c.cases[0].subject.path = "https://example.com/";
    },
    (c) => {
      c.cases[0].subject.objectName = "outside/object";
    },
    (c) => {
      c.cases[0].subject.headers.authorization = "Bearer owner";
    },
    (c) => {
      c.cases[0].subject.credential = "unlisted";
    },
    (c) => {
      c.cases[0].after = [];
    },
    (c) => {
      c.cases[0].cleanup = [];
    },
    (c) => {
      c.cases[0].rulesSource += "\nservice cloud.firestore {}";
    },
    (c) => {
      c.cases[0].subject.capture.body = "normalized-json";
    },
    (c) => {
      c.cases.find(
        (r) => r.recipeId === "storage-rules/request-time",
      ).timeEvidence.serverClockIntervalRequired = false;
    },
    (c) => {
      c.sendAuthorized = true;
    },
    (c) => {
      c.cases.find((r) => r.operation === "list").subject.query.prefix = "";
    },
    (c) => {
      c.cases.find((r) => r.operation === "upload").subject.body.base64 =
        Buffer.alloc(2049).toString("base64");
    },
  ];
  for (const change of changes) {
    const corpus = build();
    change(corpus);
    assert.throws(() => validateCorpus(corpus, closure));
  }
});

test("inputs cannot escape the owned namespace or inject rule source", () => {
  for (const prefix of [
    "",
    "other/run/",
    "STORAGE-RULES/../",
    "STORAGE-RULES/x/y/",
    "STORAGE-RULES/run'evil/",
  ])
    assert.throws(() => buildCorpus({ ...input, prefix }));
  for (const bucket of ["https://bucket", "x/y", "bucket'", "a"])
    assert.throws(() => buildCorpus({ ...input, bucket }));
  for (const uidA of [input.uidB, "a/b", "a'", "", "a".repeat(129)])
    assert.throws(() => buildCorpus({ ...input, uidA }));
});

test("REST routes, bodies and list scope are independently fixed by operation and dialect", () => {
  const corpus = build();
  for (const c of corpus.cases) {
    for (const r of [
      ...c.baseline,
      ...c.setup,
      ...c.before,
      c.subject,
      ...(c.comparison ? [c.comparison] : []),
      ...c.after,
      ...c.cleanup,
    ]) {
      const root = `${r.dialect === "firebase" ? "/v0" : "/storage/v1"}/b/${input.bucket}/o`;
      if (r.operation === "list") {
        assert.equal(r.method, "GET");
        assert.equal(r.path, root);
        assert.deepEqual(r.query, { prefix: c.casePrefix, maxResults: "3" });
      } else if (r.operation === "upload") {
        if (c.recipeId === "storage-rules/request-resource-upload") continue;
        assert.equal(r.method, "POST");
        assert.equal(r.path, r.dialect === "gcs" ? `/upload${root}` : root);
        assert.equal(r.query.name, c.objectName);
        assert.equal(r.query.uploadType, r.dialect === "gcs" ? "media" : undefined);
        assert.equal(
          Buffer.from(r.body.base64, "base64").toString(),
          r.id === "seed" ? "base" : "next",
        );
        assert.equal(r.headers["content-type"], "text/plain");
      } else {
        assert.equal(r.path, `${root}/${encodeURIComponent(c.objectName)}`);
        assert.equal(
          r.method,
          r.operation === "patch"
            ? "PATCH"
            : r.operation === "delete"
              ? "DELETE"
              : r.operation === "create-token"
                ? "POST"
                : "GET",
        );
        if (r.operation === "create-token") assert.deepEqual(r.query, { create_token: "true" });
      }
    }
    assert.equal(
      c.setup.length,
      c.recipeId === "storage-rules/download-token-boundary"
        ? 4
        : c.recipeId === "storage-rules/request-resource-upload" && c.uploadProtocol === "resumable"
          ? 1
          : c.initialState === "present"
            ? 2
            : 0,
    );
    if (c.initialState === "present")
      assert.deepEqual(c.setup[1].body.json, {
        contentType: "text/plain",
        metadata: { owner: "old" },
      });
  }
});

test("absent resources retain direct controls without out-of-scope IAM mutation", () => {
  const corpus = build();
  const nullRows = rows(corpus, "stored-resource").filter((row) => row.rule.kind === "stored-null");
  assert.equal(nullRows.length, 16);
  assert.deepEqual(
    new Set(nullRows.map((row) => `${row.rule.matches}/${row.operation}/${row.initialState}`)).size,
    16,
  );
  for (const row of nullRows)
    assert.ok(row.rulesSource.includes(`if resource ${row.rule.matches ? "==" : "!="} null;`));
  assert.equal(Object.hasOwn(corpus.principals, "iam-denied"), false);
  assert.equal(
    rows(corpus, "gcs-admin-boundary").some((row) => row.principal === "iam-denied"),
    false,
  );
});

test("owner-excluded credentials cannot return through an added fixture or case", () => {
  for (const excluded of ["iam-denied", "expired-token"]) {
    const changed = build();
    changed.principals[excluded] = { kind: "credential-reference" };
    assert.throws(() => validateCorpus(changed, closure));
  }
  const changed = build();
  const added = structuredClone(changed.cases.find((row) => row.id === "token-valid"));
  added.id = "token-expired";
  added.principal = "expired-token";
  changed.cases.push(added);
  assert.throws(() => validateCorpus(changed, closure));
});
