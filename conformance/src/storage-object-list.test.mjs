import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const recipeFor = (dialect) =>
  buildCorpus(input).recipes.find((recipe) => recipe.id === `storage-object/${dialect}/list`);

test("each dialect declares an isolated six-object list fixture with readbacks", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeFor(dialect);
    const scope = `${input.prefix}list/${dialect}/`;
    assert.equal(recipe.objects.length, 6);
    assert.deepEqual(
      recipe.objects.map((name) => name.slice(scope.length)),
      ["a.txt", "b.txt", "dir/c.txt", "dir/d.txt", "dir2/e.txt", "zz.txt"],
    );
    assert.ok(recipe.objects.every((name) => name.startsWith(scope)));
    assert.equal(recipe.steps.filter((step) => step.method === "POST").length, 6);
    assert.equal(
      recipe.steps.filter((step) => step.method === "GET" && !step.collection).length,
      12,
    );
    for (const [index, name] of recipe.objects.entries()) {
      assert.deepEqual(
        recipe.steps
          .slice(index * 3, index * 3 + 3)
          .map((step) => [step.id, step.objectName, step.method, step.query.alt ?? null]),
        [
          [`seed-${index}`, name, "POST", null],
          [`seed-${index}-metadata`, name, "GET", null],
          [`seed-${index}-media`, name, "GET", "media"],
        ],
      );
    }
    assert.deepEqual(
      recipe.preflight.filter((step) => step.collection).map((step) => step.dialect),
      ["firebase", "gcs"],
    );
    assert.equal(recipe.cleanup.length, 18);
  }
});

test("collection requests stay inside the fixture prefix and use bucket collection routes", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeFor(dialect);
    const scope = `${input.prefix}list/${dialect}/`;
    const requests = [...recipe.preflight, ...recipe.steps].filter((step) => step.collection);
    assert.ok(requests.length >= 18);
    for (const request of requests) {
      assert.equal(request.method, "GET");
      assert.equal(request.objectName, undefined);
      assert.equal(request.scopePrefix, scope);
      assert.equal(
        request.path,
        `${request.dialect === "gcs" ? "/storage/v1" : "/v0"}/b/${input.bucket}/o`,
      );
      assert.ok(request.query.prefix.startsWith(scope));
      assert.deepEqual(request.headers, {});
      assert.equal(request.credential, "admin");
      assert.deepEqual(request.responseCapture, {
        status: true,
        headers: "all",
        body: "raw-bytes",
      });
    }
  }
});

test("each list recipe declares flat, delimiter, subdirectory, empty and zero-limit observations", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeFor(dialect);
    const byId = (id) => recipe.steps.find((step) => step.id === id);
    const scope = `${input.prefix}list/${dialect}/`;
    assert.deepEqual(byId("flat").query, { prefix: scope });
    assert.deepEqual(byId("delimited").query, { prefix: scope, delimiter: "/" });
    assert.deepEqual(byId("subdirectory").query, { prefix: `${scope}dir/`, delimiter: "/" });
    assert.deepEqual(byId("empty").query, { prefix: `${scope}nothing/`, delimiter: "/" });
    assert.deepEqual(byId("max-results-zero").query, { prefix: scope, maxResults: "0" });
  }
});

test("pagination is a bounded conditional chain with no invented page token", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeFor(dialect);
    const pages = recipe.steps.filter((step) => /^page-\d+$/.test(step.id));
    assert.equal(pages.length, 12);
    assert.deepEqual(recipe.pagination, {
      pageSteps: pages.map((step) => step.id),
      maxPages: 12,
      exhaustedOnlyWhenNoNextPageToken: true,
      ...(dialect === "gcs" ? { requiredMixedItemPrefixPage: true } : {}),
    });
    assert.equal(pages[0].continuation, undefined);
    for (const [index, page] of pages.entries()) {
      assert.deepEqual(page.query, {
        prefix: `${input.prefix}list/${dialect}/`,
        delimiter: "/",
        maxResults: dialect === "gcs" ? "3" : "2",
      });
      assert.equal(page.query.pageToken, undefined);
      if (index === 0) continue;
      assert.deepEqual(page.continuation, {
        kind: "next-page-token",
        sourceStep: `page-${index - 1}`,
        targetQuery: "pageToken",
        skipIfMissing: true,
        maxTokenBytes: 4096,
      });
    }
  }
});

test("GCS pagination targets a mixed item and directory-prefix page", () => {
  const recipe = recipeFor("gcs");
  assert.equal(recipe.pagination.requiredMixedItemPrefixPage, true);
  const scope = `${input.prefix}list/gcs/`;
  const entries = [
    ...recipe.objects
      .filter((name) => !name.slice(scope.length).includes("/"))
      .map((name) => ({ type: "item", name })),
    ...new Set(
      recipe.objects
        .filter((name) => name.slice(scope.length).includes("/"))
        .map((name) => `${scope}${name.slice(scope.length).split("/")[0]}/`),
    ),
  ]
    .map((entry) => (typeof entry === "string" ? { type: "prefix", name: entry } : entry))
    .sort((left, right) => left.name.localeCompare(right.name, "en"));
  const firstPage = entries.slice(
    0,
    Number(recipe.steps.find((step) => step.id === "page-0").query.maxResults),
  );
  assert.ok(firstPage.some((entry) => entry.type === "item"));
  assert.ok(firstPage.some((entry) => entry.type === "prefix"));
});

test("GCS filter declarations remain inside the owned prefix", () => {
  const recipe = recipeFor("gcs");
  const scope = `${input.prefix}list/gcs/`;
  const byId = (id) => recipe.steps.find((step) => step.id === id);
  assert.deepEqual(byId("offset-filter").query, {
    prefix: scope,
    startOffset: `${scope}b.txt`,
    endOffset: `${scope}zz.txt`,
  });
  assert.deepEqual(byId("glob-filter").query, {
    prefix: scope,
    matchGlob: `${scope}dir/*`,
  });
  assert.equal(
    recipeFor("firebase").steps.some((step) => step.id === "glob-filter"),
    false,
  );
});
