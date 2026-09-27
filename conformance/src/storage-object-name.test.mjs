import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertAcceptedNamesListed,
  assertNameScopePageExhaustion,
  listedNameScopeEntries,
} from "./storage-object/name-scope.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const scope = `${input.prefix}errors/object-name/`;
const recipe = () =>
  buildCorpus(input).recipes.find((entry) => entry.id === "storage-object/errors/object-name");

function assertPageChain(steps, label) {
  const pages = steps.filter((step) => step.id.startsWith(`${label}-page-`));
  assert.deepEqual(
    pages.map((step) => step.id),
    Array.from({ length: 4 }, (_, index) => `${label}-page-${index}`),
  );
  for (const [index, page] of pages.entries()) {
    assert.equal(page.collection, true);
    assert.equal(page.query.prefix, scope);
    assert.equal(page.query.maxResults, "100");
    assert.deepEqual(
      page.continuation,
      index === 0
        ? undefined
        : {
            kind: "next-page-token",
            sourceStep: `${label}-page-${index - 1}`,
            targetQuery: "pageToken",
            skipIfMissing: true,
            maxTokenBytes: 4096,
          },
    );
  }
}

test("object-name recipe declares owned names and bounded preflight listing", () => {
  const entry = recipe();
  assert.ok(entry);
  assert.equal(entry.objects.length, 4);
  assert.ok(entry.objects.every((name) => name.startsWith(scope)));
  assert.equal(entry.objects.filter((name) => name.includes("\n")).length, 2);
  assert.equal(entry.objects.filter((name) => Buffer.byteLength(name) === 1025).length, 2);
  assert.equal(new Set(entry.objects).size, 4);
  assert.ok(entry.objects.some((name) => name.startsWith(`${scope}firebase-`)));
  assert.ok(entry.objects.some((name) => name.startsWith(`${scope}gcs-`)));
  assert.equal(entry.preflight.filter((step) => step.collection).length, 8);
  for (const dialect of ["firebase", "gcs"]) {
    assertPageChain(entry.preflight, `baseline-list-${dialect}`);
  }
  assert.equal(entry.nameScopePagination.maxPages, 4);
  assert.equal(entry.nameScopePagination.exhaustedOnlyWhenNoNextPageToken, true);
});

test("the last declared name-scope page cannot leave an unseen continuation", () => {
  const entry = recipe();
  const page2 = entry.preflight.find((step) => step.id === "baseline-list-gcs-page-2");
  const page3 = entry.preflight.find((step) => step.id === "baseline-list-gcs-page-3");
  assert.doesNotThrow(() =>
    assertNameScopePageExhaustion(page2, "next", entry.nameScopePagination),
  );
  assert.doesNotThrow(() => assertNameScopePageExhaustion(page3, null, entry.nameScopePagination));
  assert.throws(
    () => assertNameScopePageExhaustion(page3, "unseen", entry.nameScopePagination),
    /not exhausted/,
  );
});

test("name-scope pages retain exact names and reject missing accepted or alternate objects", () => {
  const name = `${scope}gcs-line\nbreak.bin`;
  const encoded = encodeURI(name);
  const entries = listedNameScopeEntries(
    { items: [{ name: encoded, bucket: input.bucket }] },
    { bucket: input.bucket, scopePrefix: scope },
  );
  assert.deepEqual(entries.names, [encoded]);
  assert.doesNotThrow(() => assertAcceptedNamesListed(new Set(entries.names), [name]));
  assert.throws(() => assertAcceptedNamesListed(new Set(), [name]), /missing/);
  assert.throws(
    () => assertAcceptedNamesListed(new Set([encoded, `${scope}alias.bin`]), [name]),
    /unowned/,
  );
  assert.throws(
    () =>
      listedNameScopeEntries(
        { items: [{ name: "outside" }] },
        { bucket: input.bucket, scopePrefix: scope },
      ),
    /invalid object/,
  );
});

test("both dialects observe owned linefeed and oversized names without fixed status assumptions", () => {
  const entry = recipe();
  for (const dialect of ["firebase", "gcs"]) {
    for (const variant of ["linefeed", "oversized"]) {
      const upload = entry.steps.find((step) => step.id === `${dialect}-upload-${variant}-name`);
      assert.equal(upload?.method, "POST");
      assert.equal(upload.dialect, dialect);
      assert.equal(upload.expectedStatus, undefined);
      assert.equal(upload.malformedObjectName.kind, variant);
      assert.equal(upload.malformedObjectName.scopePrefix, scope);
      assert.equal(upload.query.name, upload.malformedObjectName.attemptedName);
      assert.equal(upload.malformedObjectName.attemptedName.startsWith(scope), true);
      const emptyOrInvalidGet = entry.steps.find(
        (step) => step.id === `${dialect}-get-${variant}-name`,
      );
      assert.equal(emptyOrInvalidGet?.method, "GET");
      assert.equal(emptyOrInvalidGet.dialect, dialect);
      assert.equal(emptyOrInvalidGet.expectedStatus, undefined);
      assert.equal(emptyOrInvalidGet.malformedObjectName.kind, variant);
      const uploadIndex = entry.steps.indexOf(upload);
      const postIds = ["firebase", "gcs"].flatMap((reader) => [
        `${dialect}-${variant}-after-${reader}-metadata`,
        `${dialect}-${variant}-after-${reader}-media`,
        ...Array.from(
          { length: 4 },
          (_, index) => `${dialect}-${variant}-after-list-${reader}-page-${index}`,
        ),
      ]);
      assert.deepEqual(
        entry.steps.slice(uploadIndex + 1, uploadIndex + 1 + postIds.length).map((step) => step.id),
        postIds,
      );
      assert.equal(entry.steps[uploadIndex + 1 + postIds.length], emptyOrInvalidGet);
      for (const reader of ["firebase", "gcs"]) {
        assert.ok(
          entry.steps.some((step) => step.id === `${dialect}-${variant}-after-${reader}-metadata`),
        );
        assert.ok(
          entry.steps.some((step) => step.id === `${dialect}-${variant}-after-${reader}-media`),
        );
        assertPageChain(entry.steps, `${dialect}-${variant}-after-list-${reader}`);
      }
    }
    assert.ok(entry.steps.some((step) => step.id === `${dialect}-list-linefeed-prefix`));
    assert.ok(entry.steps.some((step) => step.id === `${dialect}-list-oversized-prefix`));
  }
  assert.ok(entry.steps.every((step) => step.expectedStatus === undefined));
  assert.ok(entry.steps.every((step) => step.malformedObjectName?.kind !== "missing"));
  assert.ok(
    entry.steps
      .filter((step) => step.method === "POST")
      .every((step) => step.query.name?.startsWith(scope)),
  );
  assert.ok(
    entry.steps
      .filter((step) => step.method === "GET" && !step.collection)
      .every(
        (step) =>
          step.path !== `/v0/b/${input.bucket}/o/` &&
          step.path !== `/storage/v1/b/${input.bucket}/o/`,
      ),
  );
});

test("object-name recipe reserves cleanup for every attempted owned name", () => {
  const entry = recipe();
  assert.deepEqual(
    entry.cleanup.filter((step) => step.method === "DELETE").map((step) => step.objectName),
    entry.objects,
  );
  assert.equal(entry.coverage, "partial-missing-name-and-list-path-semantics");
  assert.ok(
    buildCorpus(input).remainingObligations.includes(
      "object-name-missing-name-safe-boundary-and-list-path-semantics",
    ),
  );
});
