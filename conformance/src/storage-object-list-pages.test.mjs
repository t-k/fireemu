import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { evaluateListPages } from "./storage-object/list-pages.mjs";

const bucket = "example.firebasestorage.app";
const prefix = "owned/run-012345/";
const bodyBase64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64");
const listRecipe = (dialect) =>
  buildCorpus({ bucket, prefix }).recipes.find(
    (recipe) => recipe.id === `storage-object/${dialect}/list`,
  );

function validPages(dialect) {
  const recipe = listRecipe(dialect);
  const scope = `${prefix}list/${dialect}/`;
  const item = (name) => ({ kind: "storage#object", bucket, name: `${scope}${name}` });
  const parts =
    dialect === "gcs"
      ? [
          { items: [item("a.txt"), item("b.txt")], prefixes: [`${scope}dir/`] },
          { items: [item("zz.txt")], prefixes: [`${scope}dir2/`] },
        ]
      : [
          { items: [item("a.txt"), item("b.txt")] },
          { prefixes: [`${scope}dir/`, `${scope}dir2/`] },
          { items: [item("zz.txt")] },
        ];
  const pages = parts.map((part, index) => {
    const step = recipe.steps.find((entry) => entry.id === `page-${index}`);
    return {
      stepId: step.id,
      query: { ...step.query, ...(index ? { pageToken: `opaque-${index}` } : {}) },
      status: 200,
      bodyBase64: bodyBase64({
        kind: "storage#objects",
        ...part,
        ...(index < parts.length - 1 ? { nextPageToken: `opaque-${index + 1}` } : {}),
      }),
    };
  });
  return { recipe, pages };
}

const evaluate = (dialect, mutate = () => {}) => {
  const { recipe, pages } = validPages(dialect);
  mutate({ recipe, pages });
  return evaluateListPages({ recipe, pages, bucket });
};
const rewriteBody = (page, change) => {
  const body = JSON.parse(Buffer.from(page.bodyBase64, "base64").toString("utf8"));
  change(body);
  page.bodyBase64 = bodyBase64(body);
};

test("complete Firebase and GCS page records match their declared fixture without authorizing use", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const result = evaluate(dialect);
    assert.deepEqual(result, {
      status: "MATCHED_SUPPLIED_PAGES",
      pageCount: dialect === "gcs" ? 2 : 3,
      itemCount: 3,
      prefixCount: 2,
      mixedPageObserved: dialect === "gcs",
      sendAuthorized: false,
      cleanupAuthorized: false,
    });
    assert.ok(Object.isFrozen(result));
  }
});

test("the supplied page sequence must be consecutive and end without a continuation token", () => {
  assert.throws(() => evaluate("gcs", ({ pages }) => pages.pop()), /incomplete/i);
  assert.throws(() => evaluate("firebase", ({ pages }) => (pages[1].stepId = "page-3")), /page/i);
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages.at(-1), (body) => (body.nextPageToken = "more")),
      ),
    /incomplete/i,
  );
});

test("next-page queries must use the preceding raw token exactly", () => {
  assert.throws(
    () => evaluate("gcs", ({ pages }) => (pages[1].query.pageToken = "other")),
    /token/i,
  );
  assert.throws(
    () => evaluate("gcs", ({ pages }) => (pages[0].query.pageToken = "invented")),
    /query/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => rewriteBody(pages[0], (body) => (body.nextPageToken = ""))),
    /token/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        const token = "x".repeat(4097);
        rewriteBody(pages[0], (body) => (body.nextPageToken = token));
        pages[1].query.pageToken = token;
      }),
    /token/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => rewriteBody(pages[0], (body) => (body.nextPageToken = null))),
    /token/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        const token = "bad\nvalue";
        rewriteBody(pages[0], (body) => (body.nextPageToken = token));
        pages[1].query.pageToken = token;
      }),
    /token/i,
  );
});

test("item and prefix names must be exact, owned and nonduplicated", () => {
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => (body.items[0].name = `${prefix}foreign`)),
      ),
    /scope/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => (body.prefixes[0] = `${prefix}foreign/`)),
      ),
    /scope/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => (body.items[0].name = body.prefixes[0])),
      ),
    /fixture|order|duplicate|direct child/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => (body.items[0].bucket = "other")),
      ),
    /bucket/i,
  );
});

test("complete traversal rejects missing, extra, duplicate or reordered entries", () => {
  assert.throws(
    () => evaluate("gcs", ({ pages }) => rewriteBody(pages[1], (body) => (body.items = []))),
    /fixture/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => body.items.push({ name: `${prefix}list/gcs/extra` })),
      ),
    /fixture|limit|order/i,
  );
  assert.throws(
    () =>
      evaluate("firebase", ({ pages }) =>
        rewriteBody(pages[1], (body) => body.prefixes.push(body.prefixes[0])),
      ),
    /duplicate|limit/i,
  );
  assert.throws(
    () =>
      evaluate("firebase", ({ pages }) => rewriteBody(pages[0], (body) => body.items.reverse())),
    /order/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) =>
        rewriteBody(pages[1], (body) => (body.prefixes[0] = `${prefix}list/gcs/dir/`)),
      ),
    /duplicate/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        rewriteBody(pages[0], (body) => (body.prefixes[0] = `${prefix}list/gcs/dir2/`));
        rewriteBody(pages[1], (body) => (body.prefixes[0] = `${prefix}list/gcs/dir/`));
      }),
    /order/i,
  );
});

test("GCS requires an observed mixed item and prefix page", () => {
  assert.throws(
    () =>
      evaluate("gcs", ({ recipe, pages }) => {
        rewriteBody(pages[0], (body) => {
          body.prefixes = [];
        });
        rewriteBody(pages[1], (body) => {
          body.items = [];
          body.prefixes = [`${prefix}list/gcs/dir/`, `${prefix}list/gcs/dir2/`];
          body.nextPageToken = "opaque-2";
        });
        const step = recipe.steps.find((entry) => entry.id === "page-2");
        pages.push({
          stepId: step.id,
          query: { ...step.query, pageToken: "opaque-2" },
          status: 200,
          bodyBase64: bodyBase64({
            kind: "storage#objects",
            items: [{ name: `${prefix}list/gcs/zz.txt`, bucket }],
          }),
        });
      }),
    /mixed/i,
  );
});

test("raw records must be bounded canonical successful JSON lists", () => {
  assert.throws(() => evaluate("gcs", ({ pages }) => (pages[0].status = 403)), /status/i);
  assert.throws(() => evaluate("gcs", ({ pages }) => (pages[0].bodyBase64 += "=")), /base64/i);
  const { recipe, pages } = validPages("gcs");
  let paddedBytes = Buffer.from(pages[0].bodyBase64, "base64");
  while (paddedBytes.length % 3 === 0) paddedBytes = Buffer.concat([paddedBytes, Buffer.from(" ")]);
  pages[0].bodyBase64 = paddedBytes.toString("base64");
  const raw = pages[0].bodyBase64;
  const index = raw.length - (raw.endsWith("==") ? 3 : 2);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  pages[0].bodyBase64 = `${raw.slice(0, index)}${alphabet[alphabet.indexOf(raw[index]) ^ 1]}${raw.slice(index + 1)}`;
  assert.deepEqual(Buffer.from(pages[0].bodyBase64, "base64"), Buffer.from(raw, "base64"));
  assert.throws(() => evaluateListPages({ recipe, pages, bucket }), /base64/i);
  assert.throws(
    () =>
      evaluate(
        "gcs",
        ({ pages }) => (pages[0].bodyBase64 = Buffer.from("{broken").toString("base64")),
      ),
    /json/i,
  );
  assert.throws(
    () => evaluate("gcs", ({ pages }) => (pages[0].bodyBase64 = "A".repeat(1_400_000))),
    /limit/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        rewriteBody(pages[0], (body) => {
          body.items.push({ name: `${prefix}list/gcs/zz.txt`, bucket });
          body.prefixes.push(`${prefix}list/gcs/dir2/`);
          delete body.nextPageToken;
        });
        pages.pop();
      }),
    /limit/i,
  );
  assert.throws(
    () => evaluate("gcs", ({ pages }) => rewriteBody(pages[0], (body) => (body.items = "wrong"))),
    /items/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => rewriteBody(pages[0], (body) => (body.prefixes = "wrong"))),
    /prefixes/i,
  );
  assert.throws(
    () => evaluate("gcs", ({ pages }) => rewriteBody(pages[0], (body) => (body.kind = "other"))),
    /kind/i,
  );
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        const body = JSON.parse(Buffer.from(pages[0].bodyBase64, "base64").toString("utf8"));
        body.unused = "x";
        const bytes = Buffer.from(JSON.stringify(body));
        const marker = Buffer.from('"unused":"');
        bytes[bytes.indexOf(marker) + marker.length] = 0xff;
        pages[0].bodyBase64 = bytes.toString("base64");
      }),
    /UTF-8|JSON/i,
  );
});

test("page count above the declared cap is rejected before examining raw responses", () => {
  assert.throws(
    () =>
      evaluate("gcs", ({ pages }) => {
        while (pages.length <= 12) pages.push({});
      }),
    /page count/i,
  );
});

test("the evaluator cannot trust a changed collection route or page limit", () => {
  assert.throws(
    () =>
      evaluate(
        "gcs",
        ({ recipe }) => (recipe.steps.find((step) => step.id === "page-0").path += "/other"),
      ),
    /route/i,
  );
  assert.throws(
    () =>
      evaluate(
        "gcs",
        ({ recipe }) =>
          (recipe.steps.find((step) => step.id === "page-0").query.maxResults = "1000"),
      ),
    /declaration/i,
  );
  assert.throws(
    () =>
      evaluate(
        "gcs",
        ({ recipe }) =>
          (recipe.steps.find((step) => step.id === "page-0").headers.range = "bytes=0-1"),
      ),
    /declaration/i,
  );
  assert.throws(() => evaluate("gcs", ({ recipe }) => (recipe.steps = {})), /declaration/i);
  assert.throws(
    () => evaluate("gcs", ({ recipe }) => (recipe.pagination.requiredMixedItemPrefixPage = false)),
    /declaration/i,
  );
});

test("page consistency evaluation does not mutate supplied records", () => {
  const { recipe, pages } = validPages("gcs");
  const before = JSON.stringify({ recipe, pages });
  evaluateListPages({ recipe, pages, bucket });
  assert.equal(JSON.stringify({ recipe, pages }), before);
});
