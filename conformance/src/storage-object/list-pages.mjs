const MAX_BODY_BYTES = 1_048_576;
const MAX_BODY_BASE64_CHARS = 4 * Math.ceil(MAX_BODY_BYTES / 3);
const FIXTURE_SUFFIXES = ["a.txt", "b.txt", "dir/c.txt", "dir/d.txt", "dir2/e.txt", "zz.txt"];
const utf8 = new TextDecoder("utf-8", { fatal: true });

function fail(reason) {
  throw new Error(`list pages: ${reason}`);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rawList(bodyBase64) {
  if (
    typeof bodyBase64 !== "string" ||
    bodyBase64.length > MAX_BODY_BASE64_CHARS ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bodyBase64)
  )
    fail("raw body base64 is invalid or over the limit");
  const bytes = Buffer.from(bodyBase64, "base64");
  if (bytes.length > MAX_BODY_BYTES || bytes.toString("base64") !== bodyBase64)
    fail("raw body base64 is noncanonical or over the limit");
  let body;
  try {
    body = JSON.parse(utf8.decode(bytes));
  } catch {
    fail("raw body is not valid UTF-8 JSON");
  }
  if (!plainObject(body)) fail("raw JSON list is not an object");
  if (Object.hasOwn(body, "kind") && body.kind !== "storage#objects")
    fail("list resource kind differs");
  if (Object.hasOwn(body, "items") && !Array.isArray(body.items)) fail("items must be an array");
  if (Object.hasOwn(body, "prefixes") && !Array.isArray(body.prefixes))
    fail("prefixes must be an array");
  return body;
}

function exactQuery(actual, expected, reason) {
  if (!plainObject(actual)) fail(reason);
  const keys = Object.keys(expected);
  if (Object.keys(actual).length !== keys.length) fail(reason);
  for (const key of keys) if (actual[key] !== expected[key]) fail(reason);
}

function pageDeclarations(recipe, bucket) {
  if (!plainObject(recipe) || !/^(?:storage-object\/(firebase|gcs)\/list)$/.test(recipe.id))
    fail("recipe declaration is not a list");
  if (!Array.isArray(recipe.steps) || typeof bucket !== "string" || !bucket)
    fail("page declaration inputs are invalid");
  const dialect = recipe.id.split("/")[1];
  const first = recipe.steps?.find((step) => step.id === "page-0");
  const scope = first?.scopePrefix;
  if (typeof scope !== "string" || !scope.endsWith(`list/${dialect}/`))
    fail("scope declaration differs");
  if (
    !Array.isArray(recipe.objects) ||
    recipe.objects.length !== FIXTURE_SUFFIXES.length ||
    recipe.objects.some((name, index) => name !== `${scope}${FIXTURE_SUFFIXES[index]}`)
  )
    fail("fixture declaration differs");
  const pageSteps = Array.from({ length: 12 }, (_, index) => `page-${index}`);
  if (
    !plainObject(recipe.pagination) ||
    recipe.pagination.maxPages !== 12 ||
    recipe.pagination.exhaustedOnlyWhenNoNextPageToken !== true ||
    JSON.stringify(recipe.pagination.pageSteps) !== JSON.stringify(pageSteps) ||
    (dialect === "gcs" && recipe.pagination.requiredMixedItemPrefixPage !== true)
  )
    fail("pagination declaration differs");
  const expectedPath = `${dialect === "gcs" ? "/storage/v1" : "/v0"}/b/${bucket}/o`;
  const maxResults = dialect === "gcs" ? "3" : "2";
  const steps = pageSteps.map((id, index) => {
    const matches = recipe.steps.filter((step) => step.id === id);
    if (matches.length !== 1) fail("page declaration is missing or duplicate");
    const step = matches[0];
    if (
      step.collection !== true ||
      step.dialect !== dialect ||
      step.method !== "GET" ||
      step.objectName !== undefined ||
      step.credential !== "admin" ||
      step.path !== expectedPath
    )
      fail("collection route declaration differs");
    if (step.scopePrefix !== scope) fail("scope declaration differs");
    if (!plainObject(step.headers) || Object.keys(step.headers).length)
      fail("page headers declaration differs");
    exactQuery(
      step.query,
      { prefix: scope, delimiter: "/", maxResults },
      "page declaration query differs",
    );
    if (index === 0) {
      if (step.continuation !== undefined) fail("first page continuation declaration differs");
    } else {
      exactQuery(
        step.continuation,
        {
          kind: "next-page-token",
          sourceStep: pageSteps[index - 1],
          targetQuery: "pageToken",
          skipIfMissing: true,
          maxTokenBytes: 4096,
        },
        "page continuation declaration differs",
      );
    }
    return step;
  });
  const expectedItems = recipe.objects.filter((name) => !name.slice(scope.length).includes("/"));
  const expectedPrefixes = [
    ...new Set(
      recipe.objects
        .filter((name) => name.slice(scope.length).includes("/"))
        .map((name) => `${scope}${name.slice(scope.length).split("/")[0]}/`),
    ),
  ];
  return { dialect, scope, steps, expectedEntries: [...expectedItems, ...expectedPrefixes].sort() };
}

function namesFromPage(body, scope, bucket, maxResults) {
  const items = body.items ?? [];
  const prefixes = body.prefixes ?? [];
  if (items.length + prefixes.length > maxResults) fail("page entry count exceeds declared limit");
  const itemNames = items.map((item) => {
    if (!plainObject(item) || typeof item.name !== "string") fail("item name is invalid");
    if (Object.hasOwn(item, "kind") && item.kind !== "storage#object")
      fail("item resource kind differs");
    if (Object.hasOwn(item, "bucket") && item.bucket !== bucket) fail("item bucket differs");
    const relative = item.name.slice(scope.length);
    if (!item.name.startsWith(scope)) fail("item name escapes scope");
    if (!relative || relative.includes("/")) fail("item name is not a direct child");
    return item.name;
  });
  const prefixNames = prefixes.map((name) => {
    if (typeof name !== "string" || !name.startsWith(scope)) fail("prefix escapes scope");
    const relative = name.slice(scope.length);
    if (!relative.endsWith("/") || !relative.slice(0, -1) || relative.slice(0, -1).includes("/"))
      fail("prefix is not an immediate child");
    return name;
  });
  for (const names of [itemNames, prefixNames]) {
    for (let index = 1; index < names.length; index++) {
      if (names[index] <= names[index - 1])
        fail(names[index] === names[index - 1] ? "duplicate name" : "page order differs");
    }
  }
  return { itemNames, prefixNames, entries: [...itemNames, ...prefixNames].sort() };
}

function nextToken(body) {
  if (!Object.hasOwn(body, "nextPageToken")) return undefined;
  const token = body.nextPageToken;
  if (
    typeof token !== "string" ||
    !token ||
    Buffer.byteLength(token) > 4096 ||
    [...token].some((character) => {
      const code = character.codePointAt(0);
      return code < 32 || code === 127;
    })
  )
    fail("next page token is invalid or over the limit");
  return token;
}

// Supplied raw records have no durable request provenance. A match is not send or cleanup authority.
export function evaluateListPages({ recipe, pages, bucket }) {
  const { dialect, scope, steps, expectedEntries } = pageDeclarations(recipe, bucket);
  if (!Array.isArray(pages) || pages.length === 0 || pages.length > steps.length)
    fail("page count is invalid or incomplete");
  const observedEntries = [];
  const seen = new Set();
  let previousToken;
  let mixedPageObserved = false;
  let itemCount = 0;
  let prefixCount = 0;
  for (const [index, record] of pages.entries()) {
    if (!plainObject(record) || record.stepId !== steps[index].id)
      fail("page sequence differs from declaration");
    const expectedQuery = {
      ...steps[index].query,
      ...(index ? { pageToken: previousToken } : {}),
    };
    if (index && previousToken === undefined) fail("incomplete page token chain");
    exactQuery(
      record.query,
      expectedQuery,
      index ? "page token query differs" : "first page query differs",
    );
    if (record.status !== 200) fail("page HTTP status is not successful");
    const body = rawList(record.bodyBase64);
    const { itemNames, prefixNames, entries } = namesFromPage(
      body,
      scope,
      bucket,
      Number(steps[index].query.maxResults),
    );
    itemCount += itemNames.length;
    prefixCount += prefixNames.length;
    if (itemNames.length && prefixNames.length) mixedPageObserved = true;
    for (const name of entries) {
      if (seen.has(name)) fail("duplicate name across pages");
      if (observedEntries.length && name <= observedEntries.at(-1)) fail("page order differs");
      seen.add(name);
      observedEntries.push(name);
    }
    previousToken = nextToken(body);
    if (index < pages.length - 1 && previousToken === undefined)
      fail("incomplete page token chain");
  }
  if (previousToken !== undefined) fail("incomplete page traversal");
  if (JSON.stringify(observedEntries) !== JSON.stringify(expectedEntries))
    fail("list fixture entries differ");
  if (dialect === "gcs" && !mixedPageObserved) fail("mixed item/prefix page was not observed");
  return Object.freeze({
    status: "MATCHED_SUPPLIED_PAGES",
    pageCount: pages.length,
    itemCount,
    prefixCount,
    mixedPageObserved,
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
}
