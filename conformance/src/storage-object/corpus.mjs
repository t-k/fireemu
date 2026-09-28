const FROZEN_RECIPES = [
  "storage-object/firebase/simple-upload",
  "storage-object/firebase/multipart-upload",
  "storage-object/firebase/resumable-upload",
  "storage-object/firebase/download",
  "storage-object/firebase/download-tokens",
  "storage-object/firebase/metadata",
  "storage-object/firebase/delete",
  "storage-object/firebase/list",
  "storage-object/firebase/overwrite",
  "storage-object/gcs/simple-multipart-upload",
  "storage-object/gcs/resumable-upload",
  "storage-object/gcs/download",
  "storage-object/gcs/metadata",
  "storage-object/gcs/delete",
  "storage-object/gcs/list",
  "storage-object/gcs/copy-rewrite",
  "storage-object/gcs/generation-preconditions",
  "storage-object/gcs/metageneration-preconditions",
  "storage-object/gcs/checksums",
  "storage-object/errors/missing",
  "storage-object/errors/authorization",
  "storage-object/errors/object-name",
  "storage-object/errors/range",
  "storage-object/auth/admin",
  "storage-object/auth/firebase-id-token",
  "storage-object/cross-dialect/state",
];

// A partial request declaration. This module cannot send requests or grant production access.
// A future runner must prove initial absence and ownership before executing cleanup.
export function buildCorpus({ bucket, prefix }) {
  if (
    typeof bucket !== "string" ||
    bucket.length < 3 ||
    bucket.length > 222 ||
    !bucket.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))
  )
    throw new Error("bucket must be a plain bucket name");
  if (
    typeof prefix !== "string" ||
    prefix.length > 256 ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]*\/$/.test(prefix) ||
    prefix
      .slice(0, -1)
      .split("/")
      .some((part) => !part || part === "." || part === "..")
  )
    throw new Error("prefix must be a bounded relative owned directory without traversal");

  function request(dialect, method, name, id, extra = {}) {
    const root = `${dialect === "firebase" ? "/v0" : "/storage/v1"}/b/${bucket}/o`;
    return {
      id,
      dialect,
      method,
      objectName: name,
      credential: "admin",
      responseCapture: { status: true, headers: "all", body: "raw-bytes" },
      path:
        method === "POST"
          ? `${dialect === "gcs" ? "/upload" : ""}${root}`
          : `${root}/${encodeURIComponent(name)}`,
      query:
        method === "POST" ? { ...(dialect === "gcs" ? { uploadType: "media" } : {}), name } : {},
      headers: {},
      ...extra,
    };
  }
  const metadata = (dialect, name, id) => request(dialect, "GET", name, id);
  const media = (dialect, name, id) =>
    request(dialect, "GET", name, id, { query: { alt: "media" } });
  const upload = (dialect, name, id, bytes) =>
    request(dialect, "POST", name, id, {
      headers: { "content-type": "application/octet-stream" },
      body: { base64: Buffer.from(bytes).toString("base64") },
    });
  const collection = (dialect, scopePrefix, id, query, extra = {}) => ({
    id,
    dialect,
    method: "GET",
    collection: true,
    scopePrefix,
    credential: "admin",
    responseCapture: { status: true, headers: "all", body: "raw-bytes" },
    path: `${dialect === "firebase" ? "/v0" : "/storage/v1"}/b/${bucket}/o`,
    query,
    headers: {},
    ...extra,
  });
  function recipe(id, names, steps) {
    const objects = Array.isArray(names) ? names : [names];
    return {
      id,
      initialState: "objects-absent",
      objects,
      preflight: objects.flatMap((name, index) => [
        metadata("firebase", name, `baseline-firebase${objects.length === 1 ? "" : `-${index}`}`),
        metadata("gcs", name, `baseline-gcs${objects.length === 1 ? "" : `-${index}`}`),
      ]),
      steps,
      cleanup: objects.flatMap((name, index) => {
        const suffix = objects.length === 1 ? "" : `-${index}`;
        return [
          request("gcs", "DELETE", name, `cleanup-delete${suffix}`),
          metadata("firebase", name, `cleanup-firebase-absence${suffix}`),
          metadata("gcs", name, `cleanup-gcs-absence${suffix}`),
        ];
      }),
    };
  }
  const simple = `${prefix}simple/object.bin`;
  const cross = `${prefix}cross/a b%+snow.bin`;
  const recipes = [
    recipe("storage-object/firebase/simple-upload", simple, [
      upload("firebase", simple, "upload", [0, 1, 127, 128, 255]),
      metadata("firebase", simple, "metadata"),
      media("firebase", simple, "media"),
    ]),
    recipe("storage-object/cross-dialect/state", cross, [
      upload("gcs", cross, "gcs-upload", [255, 128, 127, 1, 0]),
      metadata("firebase", cross, "firebase-metadata"),
      media("firebase", cross, "firebase-media"),
      request("firebase", "PATCH", cross, "firebase-update", {
        headers: { "content-type": "application/json" },
        body: { json: { metadata: { marker: "cross-dialect-updated" } } },
      }),
      metadata("gcs", cross, "gcs-metadata"),
      media("gcs", cross, "gcs-media"),
      request("firebase", "DELETE", cross, "firebase-delete"),
      metadata("firebase", cross, "firebase-absence"),
      metadata("gcs", cross, "gcs-absence"),
    ]),
  ];
  const bytes = [0, 1, 127, 128, 255];
  const readback = (dialect, name, label) => [
    metadata(dialect, name, `${label}-metadata`),
    media(dialect, name, `${label}-media`),
  ];
  const update = (dialect, name, id, value, method = "PATCH") =>
    request(dialect, method, name, id, {
      headers: { "content-type": "application/json" },
      body: { json: value },
    });
  const transfer = (operation, sourceName, destinationName, id, query, body = {}) =>
    request("gcs", "POST", destinationName, id, {
      transfer: { operation, sourceName, destinationName },
      path: `/storage/v1/b/${bucket}/o/${encodeURIComponent(sourceName)}/${operation}/b/${bucket}/o/${encodeURIComponent(destinationName)}`,
      query,
      headers: body === null ? {} : { "content-type": "application/json" },
      ...(body === null ? {} : { body: { json: body } }),
    });
  const range = (dialect, name, id, value) =>
    request(dialect, "GET", name, id, {
      query: { alt: "media" },
      headers: { range: value },
    });

  for (const dialect of ["firebase", "gcs"]) {
    const downloadName = `${prefix}download/${dialect}.bin`;
    recipes.push(
      recipe(`storage-object/${dialect}/download`, downloadName, [
        upload(dialect, downloadName, "upload", bytes),
        ...readback(dialect, downloadName, "before"),
        range(dialect, downloadName, "bounded-range", "bytes=0-2"),
        range(dialect, downloadName, "open-ended-range", "bytes=3-"),
        range(dialect, downloadName, "suffix-range", "bytes=-2"),
        ...readback(dialect, downloadName, "after-ranges"),
      ]),
    );

    const metadataName = `${prefix}metadata/${dialect}.bin`;
    recipes.push(
      recipe(`storage-object/${dialect}/metadata`, metadataName, [
        upload(dialect, metadataName, "upload", bytes),
        ...readback(dialect, metadataName, "before"),
        update(dialect, metadataName, "patch", {
          cacheControl: "private, max-age=0",
          metadata: { marker: "first", remove: "present" },
        }),
        ...readback(dialect, metadataName, "after-patch"),
        update(
          dialect,
          metadataName,
          "replace-or-clear",
          dialect === "gcs"
            ? { contentType: "application/octet-stream", metadata: { marker: "second" } }
            : { metadata: { marker: "second", remove: null } },
          dialect === "gcs" ? "PUT" : "PATCH",
        ),
        ...readback(dialect, metadataName, "after-replace-or-clear"),
      ]),
    );

    const deleteName = `${prefix}delete/${dialect}.bin`;
    recipes.push(
      recipe(`storage-object/${dialect}/delete`, deleteName, [
        upload(dialect, deleteName, "upload", bytes),
        ...readback(dialect, deleteName, "before"),
        request(dialect, "DELETE", deleteName, "delete"),
        ...readback(dialect, deleteName, "after-delete"),
        request(dialect, "DELETE", deleteName, "repeat-delete"),
        ...readback(dialect, deleteName, "after-repeat-delete"),
      ]),
    );

    if (dialect === "firebase") {
      const name = `${prefix}overwrite/firebase.bin`;
      recipes.push(
        recipe("storage-object/firebase/overwrite", name, [
          upload(dialect, name, "original-upload", bytes),
          update(dialect, name, "original-metadata", {
            cacheControl: "no-store",
            metadata: { marker: "before-overwrite" },
          }),
          ...readback(dialect, name, "before-overwrite"),
          upload(dialect, name, "overwrite", [255, 128, 127, 1, 0]),
          ...readback(dialect, name, "after-overwrite"),
        ]),
      );
    }
  }

  const missing = `${prefix}errors/missing.bin`;
  recipes.push(
    recipe(
      "storage-object/errors/missing",
      missing,
      ["firebase", "gcs"].flatMap((dialect) =>
        readback(dialect, missing, `${dialect}-initial`).concat(
          update(dialect, missing, `${dialect}-update`, {
            metadata: { marker: "missing-observation" },
          }),
          readback(dialect, missing, `${dialect}-after-update`),
          request(dialect, "DELETE", missing, `${dialect}-delete`),
          readback(dialect, missing, `${dialect}-after-delete`),
        ),
      ),
    ),
  );

  const objectNameScope = `${prefix}errors/object-name/`;
  function objectNameVariants(dialect) {
    const dialectScope = `${objectNameScope}${dialect}-`;
    return [
      ["linefeed", `${dialectScope}line\nbreak.bin`],
      ["oversized", `${dialectScope}${"x".repeat(1025 - Buffer.byteLength(dialectScope))}`],
    ];
  }
  function objectNameScopePages(dialect, label) {
    return Array.from({ length: 4 }, (_, index) =>
      collection(
        dialect,
        objectNameScope,
        `${label}-page-${index}`,
        { prefix: objectNameScope, maxResults: "100" },
        index === 0
          ? {}
          : {
              continuation: {
                kind: "next-page-token",
                sourceStep: `${label}-page-${index - 1}`,
                targetQuery: "pageToken",
                skipIfMissing: true,
                maxTokenBytes: 4096,
              },
            },
      ),
    );
  }
  const objectNameSteps = [];
  for (const dialect of ["firebase", "gcs"]) {
    const variants = objectNameVariants(dialect);
    for (const [variant, attemptedName] of variants) {
      const malformedObjectName = { kind: variant, attemptedName, scopePrefix: objectNameScope };
      objectNameSteps.push(
        request(dialect, "POST", attemptedName, `${dialect}-upload-${variant}-name`, {
          query: { name: attemptedName, ...(dialect === "gcs" ? { uploadType: "media" } : {}) },
          headers: { "content-type": "application/octet-stream" },
          body: { base64: Buffer.from([0, 1, 255]).toString("base64") },
          malformedObjectName,
        }),
        ...["firebase", "gcs"].flatMap((reader) => [
          ...readback(reader, attemptedName, `${dialect}-${variant}-after-${reader}`),
          ...objectNameScopePages(reader, `${dialect}-${variant}-after-list-${reader}`),
        ]),
        request(dialect, "GET", attemptedName, `${dialect}-get-${variant}-name`, {
          malformedObjectName,
        }),
      );
    }
    objectNameSteps.push(
      collection(dialect, objectNameScope, `${dialect}-list-linefeed-prefix`, {
        prefix: `${objectNameScope}list\n`,
      }),
      collection(dialect, objectNameScope, `${dialect}-list-oversized-prefix`, {
        prefix: variants[1][1],
      }),
    );
  }
  const objectNameRecipe = recipe(
    "storage-object/errors/object-name",
    ["firebase", "gcs"].flatMap((dialect) => objectNameVariants(dialect).map(([, name]) => name)),
    objectNameSteps,
  );
  objectNameRecipe.preflight.push(
    ...["firebase", "gcs"].flatMap((dialect) =>
      objectNameScopePages(dialect, `baseline-list-${dialect}`),
    ),
  );
  objectNameRecipe.nameScopePagination = {
    scopePrefix: objectNameScope,
    maxPages: 4,
    exhaustedOnlyWhenNoNextPageToken: true,
  };
  objectNameRecipe.invalidNameAbsenceProof = {
    dialect: "gcs",
    scopePrefix: prefix,
    delimiter: null,
    maxPagesPerRefusal: 32,
    maxRefusals: objectNameRecipe.objects.length,
    maxRequests: 32 * objectNameRecipe.objects.length,
    requiresExactKnownOwnedNames: true,
  };
  objectNameRecipe.observationAspects = [
    "invalid-name-create-refusal",
    "listed-name-or-url-encoded-form",
    "normalized-name-or-no-created-object",
    "malformed-prefix-list-status",
  ];
  objectNameRecipe.coverage = "partial-missing-name-and-list-path-semantics";
  recipes.push(objectNameRecipe);

  const invalidRange = `${prefix}errors/range.bin`;
  const rangeSteps = [
    upload("gcs", invalidRange, "upload", bytes),
    ...readback("gcs", invalidRange, "before-invalid-ranges"),
  ];
  function rangeObservations(label, values) {
    return ["firebase", "gcs"].flatMap((dialect) =>
      values.flatMap((value, index) => {
        const id = `${dialect}-${label}-${index}`;
        return [
          range(dialect, invalidRange, id, value),
          ...readback(dialect, invalidRange, `${id}-after`),
        ];
      }),
    );
  }
  rangeSteps.push(
    ...rangeObservations("invalid-range", ["invalid", "bytes=3-1", "bytes=99-", "bytes=-0"]),
  );
  rangeSteps.push(
    upload("gcs", invalidRange, "empty-overwrite", []),
    ...readback("gcs", invalidRange, "before-empty-ranges"),
  );
  rangeSteps.push(...rangeObservations("empty-range", ["bytes=0-0", "bytes=0-", "bytes=-1"]));
  recipes.push(recipe("storage-object/errors/range", invalidRange, rangeSteps));

  // Fixed binary fixtures cannot contain this delimiter. No response value enters request bytes.
  function multipart(dialect, name, id, content, fields = {}, malformed = null) {
    const boundary = "fireemu-object-multipart-v1";
    const value = {
      name,
      contentType: "application/octet-stream",
      metadata: { marker: "multipart-observation" },
      ...fields,
    };
    const json = malformed === "invalid-json" ? "{invalid-json" : JSON.stringify(value);
    const parts = [
      Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n${json}`),
    ];
    if (malformed !== "missing-media") {
      parts.push(
        Buffer.from(`\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`),
        Buffer.from(content),
      );
    }
    parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
    return request(dialect, "POST", name, id, {
      query: { name, ...(dialect === "gcs" ? { uploadType: "multipart" } : {}) },
      headers: {
        "content-type": `multipart/related; boundary=${boundary}`,
        ...(dialect === "firebase" ? { "x-goog-upload-protocol": "multipart" } : {}),
      },
      body: { base64: Buffer.concat(parts).toString("base64") },
    });
  }
  const bothReadbacks = (name, label) =>
    ["firebase", "gcs"].flatMap((dialect) => readback(dialect, name, `${label}-${dialect}`));
  for (const dialect of ["firebase", "gcs"]) {
    const variants = [
      ...(dialect === "gcs" ? ["media"] : []),
      "valid",
      "invalid-json",
      "missing-media",
    ];
    const names = variants.map((variant) => `${prefix}multipart/${dialect}/${variant}.bin`);
    const steps = variants.flatMap((variant, index) => {
      const name = names[index];
      const attempt =
        variant === "media"
          ? upload(dialect, name, variant, bytes)
          : multipart(dialect, name, variant, bytes, {}, variant === "valid" ? null : variant);
      return [attempt].concat(bothReadbacks(name, `${variant}-after`));
    });
    recipes.push(
      recipe(
        `storage-object/${dialect}/${dialect === "gcs" ? "simple-multipart-upload" : "multipart-upload"}`,
        names,
        steps,
      ),
    );
  }

  // Standard "123456789" check vector; checksum validation is observed, never assumed.
  const checksumCases = [
    ["valid-md5", { md5Hash: "JfnnlDI7RTiF9RgfG2JNCw==" }],
    ["valid-crc32c", { crc32c: "4waSgw==" }],
    ["valid-both", { md5Hash: "JfnnlDI7RTiF9RgfG2JNCw==", crc32c: "4waSgw==" }],
    ["mismatch-md5", { md5Hash: "AAAAAAAAAAAAAAAAAAAAAA==" }],
    ["mismatch-crc32c", { crc32c: "AAAAAA==" }],
    ["malformed-md5", { md5Hash: "!not-base64!" }],
    ["malformed-crc32c", { crc32c: "!not-base64!" }],
  ];
  const checksumNames = checksumCases.map(([id]) => `${prefix}checksums/${id}.bin`);
  recipes.push(
    recipe(
      "storage-object/gcs/checksums",
      checksumNames,
      checksumCases.flatMap(([id, fields], index) => {
        const name = checksumNames[index];
        return [multipart("gcs", name, id, Buffer.from("123456789"), fields)].concat(
          bothReadbacks(name, `${id}-after`),
        );
      }),
    ),
  );

  const metadataReference = (step, field) => ({
    kind: "metadata-field",
    step,
    field,
    format: "positive-decimal-string",
  });
  const changedBytes = [255, 128, 127, 1, 0];
  function preconditionRecipe(field, operations, samples) {
    const names = [],
      steps = [];
    const guards =
      field === "generation"
        ? ["ifGenerationMatch", "ifGenerationNotMatch"]
        : ["ifMetagenerationMatch", "ifMetagenerationNotMatch"];
    for (const operation of operations)
      for (const guard of guards)
        for (const sample of samples) {
          const id = `${operation}-${guard}-${sample}`;
          const name = `${prefix}preconditions/${field}/${id}.bin`;
          names.push(name);
          const absent = sample === "zero-absent";
          const seed = `${id}-seed`;
          let before = seed,
            currentBytes = bytes;
          if (!absent) steps.push(upload("gcs", name, `${id}-seed-upload`, bytes));
          steps.push(...bothReadbacks(name, seed));
          const relations = [];
          if (sample === "stale") {
            before = `${id}-advanced`;
            if (field === "generation") {
              currentBytes = changedBytes;
              steps.push(upload("gcs", name, `${id}-advance`, currentBytes));
            } else {
              steps.push(
                update("gcs", name, `${id}-advance`, {
                  metadata: { preconditionMarker: "advanced" },
                }),
              );
              relations.push({
                field: "generation",
                leftStep: `${seed}-gcs-metadata`,
                rightStep: `${before}-gcs-metadata`,
                relation: "equal",
              });
            }
            steps.push(...bothReadbacks(name, before));
            relations.push({
              field,
              leftStep: `${seed}-gcs-metadata`,
              rightStep: `${before}-gcs-metadata`,
              relation: "different",
            });
          }
          const malformed = {
            "malformed-empty": "",
            "malformed-negative": "-1",
            "malformed-fraction": "1.5",
            "malformed-text": "not-a-number",
          };
          const guardValue = sample.startsWith("zero-")
            ? "0"
            : Object.hasOwn(malformed, sample)
              ? malformed[sample]
              : metadataReference(`${sample === "stale" ? seed : before}-gcs-metadata`, field);
          const subject =
            operation === "upload"
              ? upload("gcs", name, id, changedBytes)
              : operation === "metadata-read"
                ? metadata("gcs", name, id)
                : operation === "media-read"
                  ? media("gcs", name, id)
                  : operation === "delete"
                    ? request("gcs", "DELETE", name, id)
                    : update(
                        "gcs",
                        name,
                        id,
                        {
                          contentType: "application/octet-stream",
                          metadata: { preconditionMarker: "subject-update" },
                        },
                        operation === "put" ? "PUT" : "PATCH",
                      );
          subject.query = {
            ...subject.query,
            ...(field === "metageneration"
              ? { ifGenerationMatch: metadataReference(`${before}-gcs-metadata`, "generation") }
              : {}),
            [guard]: guardValue,
          };
          subject.preconditionCase = { operation, guard, sample };
          subject.requires = {
            state: absent ? "absent" : "present",
            metadata: ["firebase", "gcs"].map((dialect) => `${before}-${dialect}-metadata`),
            media: ["firebase", "gcs"].map((dialect) => `${before}-${dialect}-media`),
            bodyBase64: absent ? null : Buffer.from(currentBytes).toString("base64"),
            relations,
            ...(field === "metageneration" && sample === "stale"
              ? { metadataSubset: { metadata: { preconditionMarker: "advanced" } } }
              : {}),
          };
          steps.push(subject, ...bothReadbacks(name, `${id}-after`));
        }
    return recipe(`storage-object/gcs/${field}-preconditions`, names, steps);
  }
  recipes.push(
    preconditionRecipe(
      "generation",
      ["upload", "metadata-read", "media-read", "delete"],
      ["current", "stale", "zero-present", "zero-absent"],
    ),
  );
  recipes.push(
    preconditionRecipe(
      "metageneration",
      ["patch", "put", "delete"],
      [
        "current",
        "stale",
        "malformed-empty",
        "malformed-negative",
        "malformed-fraction",
        "malformed-text",
      ],
    ),
  );

  // Observe only the current generation captured in metadata; archived versions remain out of scope.
  const download = recipes.find((entry) => entry.id === "storage-object/gcs/download");
  const downloadName = download.objects[0];
  let previous = "after-ranges";
  for (const kind of ["metadata", "media", "range"]) {
    const id = `selected-generation-${kind}`;
    const subject =
      kind === "metadata"
        ? metadata("gcs", downloadName, id)
        : kind === "media"
          ? media("gcs", downloadName, id)
          : range("gcs", downloadName, id, "bytes=0-2");
    subject.query.generation = metadataReference("after-ranges-metadata", "generation");
    subject.requires = {
      state: "present",
      metadata: [`${previous}-metadata`],
      media: [`${previous}-media`],
      bodyBase64: Buffer.from(bytes).toString("base64"),
      relations:
        previous === "after-ranges"
          ? []
          : [
              {
                field: "generation",
                leftStep: "after-ranges-metadata",
                rightStep: `${previous}-metadata`,
                relation: "equal",
              },
            ],
    };
    download.steps.push(subject, ...readback("gcs", downloadName, `${id}-after`));
    previous = `${id}-after`;
  }

  for (const dialect of ["firebase", "gcs"]) {
    const listPrefix = `${prefix}list/${dialect}/`;
    const names = ["a.txt", "b.txt", "dir/c.txt", "dir/d.txt", "dir2/e.txt", "zz.txt"].map(
      (suffix) => `${listPrefix}${suffix}`,
    );
    const listRecipe = recipe(
      `storage-object/${dialect}/list`,
      names,
      names.flatMap((name, index) => [
        upload(dialect, name, `seed-${index}`, Buffer.from(name)),
        ...readback(dialect, name, `seed-${index}`),
      ]),
    );
    listRecipe.preflight.unshift(
      ...["firebase", "gcs"].map((reader) =>
        collection(reader, listPrefix, `baseline-list-${reader}`, { prefix: listPrefix }),
      ),
    );
    listRecipe.steps.push(
      collection(dialect, listPrefix, "flat", { prefix: listPrefix }),
      collection(dialect, listPrefix, "delimited", { prefix: listPrefix, delimiter: "/" }),
      collection(dialect, listPrefix, "subdirectory", {
        prefix: `${listPrefix}dir/`,
        delimiter: "/",
      }),
      collection(dialect, listPrefix, "empty", {
        prefix: `${listPrefix}nothing/`,
        delimiter: "/",
      }),
      collection(dialect, listPrefix, "max-results-zero", {
        prefix: listPrefix,
        maxResults: "0",
      }),
    );
    if (dialect === "gcs") {
      listRecipe.steps.push(
        collection(dialect, listPrefix, "offset-filter", {
          prefix: listPrefix,
          startOffset: `${listPrefix}b.txt`,
          endOffset: `${listPrefix}zz.txt`,
        }),
        collection(dialect, listPrefix, "glob-filter", {
          prefix: listPrefix,
          matchGlob: `${listPrefix}dir/*`,
        }),
      );
    }
    const pageSteps = Array.from({ length: 12 }, (_, index) => `page-${index}`);
    for (const [index, id] of pageSteps.entries()) {
      listRecipe.steps.push(
        collection(
          dialect,
          listPrefix,
          id,
          { prefix: listPrefix, delimiter: "/", maxResults: dialect === "gcs" ? "3" : "2" },
          index === 0
            ? {}
            : {
                continuation: {
                  kind: "next-page-token",
                  sourceStep: pageSteps[index - 1],
                  targetQuery: "pageToken",
                  skipIfMissing: true,
                  maxTokenBytes: 4096,
                },
              },
        ),
      );
    }
    listRecipe.pagination = {
      pageSteps,
      maxPages: pageSteps.length,
      exhaustedOnlyWhenNoNextPageToken: true,
      ...(dialect === "gcs" ? { requiredMixedItemPrefixPage: true } : {}),
    };
    recipes.push(listRecipe);
  }

  const copyNames = [
    "source.bin",
    "copied.bin",
    "rewritten.bin",
    "missing-source.bin",
    "missing-destination.bin",
    "rewrite-missing-source.bin",
    "rewrite-missing-destination.bin",
    "refused-copy.bin",
    "refused-rewrite.bin",
  ].map((suffix) => `${prefix}copy/${suffix}`);
  const [
    sourceName,
    copiedName,
    rewrittenName,
    missingSource,
    missingDestination,
    rewriteMissingSource,
    rewriteMissingDestination,
    refusedCopy,
    refusedRewrite,
  ] = copyNames;
  const bothReadback = (name, label) => [
    ...readback("gcs", name, `${label}-gcs`),
    ...readback("firebase", name, `${label}-firebase`),
  ];
  const copyReadback = (name, label) => [
    ...readback("firebase", name, `${label}-firebase`),
    ...readback("gcs", name, `${label}-gcs`),
  ];
  const fieldRef = (step, field) => ({
    kind: "metadata-field",
    step,
    field,
    format: "positive-decimal-string",
  });
  const sourceGuard = {
    ifGenerationMatch: "0",
    ifSourceGenerationMatch: fieldRef("source-before-gcs-metadata", "generation"),
    ifSourceMetagenerationMatch: fieldRef("source-before-gcs-metadata", "metageneration"),
  };
  const copySteps = [
    upload("gcs", sourceName, "source-upload", bytes),
    update("gcs", sourceName, "source-marker", {
      metadata: { marker: "copy-source" },
    }),
    metadata("gcs", sourceName, "source-first-read-before-gcs-metadata"),
    metadata("firebase", sourceName, "source-first-read-firebase-metadata"),
    metadata("gcs", sourceName, "source-first-read-after-gcs-metadata"),
    ...copyReadback(sourceName, "source-before"),
    transfer("copyTo", sourceName, copiedName, "copy", sourceGuard),
    ...copyReadback(copiedName, "copy"),
  ];
  const rewriteSteps = Array.from({ length: 8 }, (_, index) => `rewrite-${index}`);
  for (const [index, id] of rewriteSteps.entries()) {
    const step = transfer(
      "rewriteTo",
      sourceName,
      rewrittenName,
      id,
      index === 0 ? sourceGuard : {},
      index === 0 ? { contentType: "text/plain", metadata: { marker: "rewrite-override" } } : null,
    );
    if (index > 0) {
      step.continuation = {
        kind: "rewrite-token",
        sourceStep: rewriteSteps[index - 1],
        targetQuery: "rewriteToken",
        whenDone: false,
        maxTokenBytes: 4096,
      };
    }
    copySteps.push(step);
  }
  copySteps.push(
    ...copyReadback(rewrittenName, "rewrite"),
    ...copyReadback(missingSource, "copy-missing-source-before-source"),
    ...copyReadback(missingDestination, "copy-missing-source-before-destination"),
    transfer("copyTo", missingSource, missingDestination, "copy-missing-source", {
      ifGenerationMatch: "0",
    }),
    ...copyReadback(missingSource, "copy-missing-source-after-source"),
    ...copyReadback(missingDestination, "copy-missing-source-after-destination"),
    ...copyReadback(rewriteMissingSource, "rewrite-missing-source-before-source"),
    ...copyReadback(rewriteMissingDestination, "rewrite-missing-source-before-destination"),
    transfer(
      "rewriteTo",
      rewriteMissingSource,
      rewriteMissingDestination,
      "rewrite-missing-source",
      {
        ifGenerationMatch: "0",
      },
    ),
    ...copyReadback(rewriteMissingSource, "rewrite-missing-source-after-source"),
    ...copyReadback(rewriteMissingDestination, "rewrite-missing-source-after-destination"),
    upload("gcs", refusedCopy, "copy-refusal-seed", [255, 0, 127]),
    ...copyReadback(refusedCopy, "copy-refusal-before"),
    transfer("copyTo", sourceName, refusedCopy, "copy-refused-live-destination", sourceGuard),
    ...copyReadback(refusedCopy, "copy-refusal-after"),
    upload("gcs", refusedRewrite, "rewrite-refusal-seed", [128, 1, 255]),
    ...copyReadback(refusedRewrite, "rewrite-refusal-before"),
    transfer(
      "rewriteTo",
      sourceName,
      refusedRewrite,
      "rewrite-refused-live-destination",
      sourceGuard,
    ),
    ...copyReadback(refusedRewrite, "rewrite-refusal-after"),
    ...copyReadback(sourceName, "source-after"),
  );
  const copyRecipe = recipe("storage-object/gcs/copy-rewrite", copyNames, copySteps);
  copyRecipe.rewritePagination = {
    stepIds: rewriteSteps,
    maxCalls: rewriteSteps.length,
    completeOnlyWhenDone: true,
  };
  copyRecipe.firstFirebaseMetadataRead = {
    stepIds: [
      "source-first-read-before-gcs-metadata",
      "source-first-read-firebase-metadata",
      "source-first-read-after-gcs-metadata",
    ],
    tokenValues: "private-only",
    publicFields: ["metageneration", "hasDownloadToken"],
  };
  recipes.push(copyRecipe);

  const adminFirebase = `${prefix}auth/admin-firebase.bin`;
  const adminGcs = `${prefix}auth/admin-gcs.bin`;
  const adminUpload = (dialect, name, id, value) => {
    const step = upload(dialect, name, id, value);
    if (dialect === "gcs") step.query.ifGenerationMatch = "0";
    return step;
  };
  const adminRecipe = recipe(
    "storage-object/auth/admin",
    [adminFirebase, adminGcs],
    [
      adminUpload("firebase", adminFirebase, "firebase-upload", [11, 0, 255]),
      ...bothReadback(adminFirebase, "firebase-after-upload"),
      request("firebase", "DELETE", adminFirebase, "firebase-delete"),
      ...bothReadback(adminFirebase, "firebase-after-delete"),
      adminUpload("gcs", adminGcs, "gcs-upload", [22, 1, 128]),
      ...bothReadback(adminGcs, "gcs-after-upload"),
      request("gcs", "DELETE", adminGcs, "gcs-delete", {
        query: { ifGenerationMatch: fieldRef("gcs-after-upload-gcs-metadata", "generation") },
      }),
      ...bothReadback(adminGcs, "gcs-after-delete"),
    ],
  );
  adminRecipe.credentialContract = {
    kind: "owner-adc",
    tokenType: "google-oauth2-access-token",
    wireScheme: "Bearer",
    secretHandling: "private-only",
  };
  recipes.push(adminRecipe);

  const tokenName = `${prefix}firebase/tokens.bin`;
  const tokenReference = {
    kind: "firebase-download-token",
    fromStep: "create-token",
    priorStep: "after-upload-firebase-metadata",
    field: "downloadTokens",
    selection: "exactly-one-new",
    secretHandling: "private-only",
  };
  const tokenMedia = (id) =>
    request("firebase", "GET", tokenName, id, {
      credential: "none",
      query: { alt: "media", token: { ...tokenReference } },
    });
  const tokenRecipe = recipe("storage-object/firebase/download-tokens", tokenName, [
    upload("firebase", tokenName, "upload", [0, 1, 255]),
    ...bothReadback(tokenName, "after-upload"),
    request("firebase", "POST", tokenName, "create-token", {
      path: `/v0/b/${bucket}/o/${encodeURIComponent(tokenName)}`,
      query: { create_token: "true" },
    }),
    metadata("firebase", tokenName, "metadata-with-token"),
    metadata("firebase", tokenName, "metadata-with-token-again"),
    tokenMedia("download-with-token"),
    tokenMedia("download-with-token-again"),
    request("firebase", "POST", tokenName, "delete-token", {
      path: `/v0/b/${bucket}/o/${encodeURIComponent(tokenName)}`,
      query: { delete_token: { ...tokenReference } },
    }),
    tokenMedia("download-with-deleted-token"),
    ...bothReadback(tokenName, "after-delete"),
  ]);
  tokenRecipe.tokenHandling = "private-only";
  tokenRecipe.tokenResolutionImplemented = false;
  tokenRecipe.sendAuthorized = false;
  tokenRecipe.cleanupAuthorized = false;
  recipes.push(tokenRecipe);

  const firebaseResumableName = `${prefix}firebase/resumable.bin`;
  const firebaseWrongName = `${prefix}firebase/resumable-wrong-offset.bin`;
  const firebaseCancelName = `${prefix}firebase/resumable-cancel.bin`;
  const firebaseResumableTotal = 262147;
  const firebaseSessionRequestFor =
    (name, initiateStep) =>
    (id, headers, body, continuation, extra = {}) => ({
      id,
      dialect: "firebase",
      method: "POST",
      objectName: name,
      credential: "admin",
      responseCapture: { status: true, headers: "all", body: "raw-bytes" },
      sessionUriReference: {
        kind: "firebase-resumable-url",
        initiateStep,
        expectedOrigin: "https://firebasestorage.googleapis.com",
        expectedPath: `/v0/b/${bucket}/o`,
        expectedName: name,
        secretHandling: "private-only",
      },
      query: {},
      headers,
      ...(body ? { body: { base64: Buffer.from(body).toString("base64") } } : {}),
      continuation,
      ...extra,
    });
  const firebaseSessionRequest = firebaseSessionRequestFor(firebaseResumableName, "initiate");
  const firebaseWrongRequest = firebaseSessionRequestFor(firebaseWrongName, "initiate-wrong");
  const firebaseCancelRequest = firebaseSessionRequestFor(firebaseCancelName, "initiate-cancel");
  const firebaseInitiate = (name, id) =>
    request("firebase", "POST", name, id, {
      headers: {
        "x-goog-upload-protocol": "resumable",
        "x-goog-upload-command": "start",
        "x-goog-upload-header-content-length": String(firebaseResumableTotal),
        "x-goog-upload-header-content-type": "application/octet-stream",
        "content-type": "application/json; charset=utf-8",
      },
      body: { json: { name, contentType: "application/octet-stream" } },
    });
  const firebaseResumableRecipe = recipe(
    "storage-object/firebase/resumable-upload",
    [firebaseResumableName, firebaseWrongName, firebaseCancelName],
    [
      firebaseInitiate(firebaseResumableName, "initiate"),
      firebaseSessionRequest("query-initial", { "x-goog-upload-command": "query" }, null, {
        afterStep: "initiate",
        status: 200,
        uploadStatus: "active",
        sessionUrlRequired: true,
      }),
      firebaseSessionRequest(
        "chunk-0",
        { "x-goog-upload-command": "upload", "x-goog-upload-offset": "0" },
        Buffer.alloc(262144, 90),
        { afterStep: "query-initial", status: 200, uploadStatus: "active", receivedBytes: 0 },
      ),
      firebaseSessionRequest("query-progress", { "x-goog-upload-command": "query" }, null, {
        afterStep: "chunk-0",
        status: 200,
        uploadStatus: "active",
      }),
      firebaseSessionRequest(
        "finish",
        { "x-goog-upload-command": "upload, finalize", "x-goog-upload-offset": "262144" },
        [0, 1, 255],
        { afterStep: "query-progress", status: 200, uploadStatus: "active", receivedBytes: 262144 },
      ),
      ...bothReadback(firebaseResumableName, "after"),
      firebaseInitiate(firebaseWrongName, "initiate-wrong"),
      firebaseWrongRequest("query-wrong-initial", { "x-goog-upload-command": "query" }, null, {
        afterStep: "initiate-wrong",
        status: 200,
        uploadStatus: "active",
        sessionUrlRequired: true,
      }),
      firebaseWrongRequest(
        "wrong-offset",
        { "x-goog-upload-command": "upload", "x-goog-upload-offset": "1" },
        [42],
        { afterStep: "query-wrong-initial", status: 200, uploadStatus: "active", receivedBytes: 0 },
        { responseExpectation: { statusClass: "4xx" } },
      ),
      ...bothReadback(firebaseWrongName, "after-wrong-offset").map((step) => ({
        ...step,
        responseExpectation: { status: 404 },
      })),
      firebaseWrongRequest(
        "query-wrong-after",
        { "x-goog-upload-command": "query" },
        null,
        { afterStep: "wrong-offset", requestAttempted: true },
        { responseExpectation: { receivedBytes: 0 } },
      ),
      firebaseWrongRequest("cancel-wrong-active", { "x-goog-upload-command": "cancel" }, null, {
        afterStep: "query-wrong-after",
        status: 200,
        uploadStatus: "active",
      }),
      firebaseWrongRequest("query-after-cancel-wrong", { "x-goog-upload-command": "query" }, null, {
        afterStep: "cancel-wrong-active",
        requestAttempted: true,
      }),
      ...bothReadback(firebaseWrongName, "after-cancel-wrong").map((step) => ({
        ...step,
        responseExpectation: { status: 404 },
      })),
      firebaseInitiate(firebaseCancelName, "initiate-cancel"),
      firebaseCancelRequest("cancel-session", { "x-goog-upload-command": "cancel" }, null, {
        afterStep: "initiate-cancel",
        status: 200,
        uploadStatus: "active",
        sessionUrlRequired: true,
      }),
      firebaseCancelRequest("query-cancelled-session", { "x-goog-upload-command": "query" }, null, {
        afterStep: "cancel-session",
        requestAttempted: true,
      }),
      ...bothReadback(firebaseCancelName, "after-cancel").map((step) => ({
        ...step,
        responseExpectation: { status: 404 },
      })),
    ],
  );
  firebaseResumableRecipe.sessionUriHandling = "private-only";
  firebaseResumableRecipe.sendAuthorized = false;
  firebaseResumableRecipe.cleanupAuthorized = false;
  firebaseResumableRecipe.cleanup.unshift(
    firebaseSessionRequest(
      "cancel-unconfirmed-firebase-session",
      { "x-goog-upload-command": "cancel" },
      null,
      { afterStep: "initiate", status: 200, completionUnconfirmed: true, sessionUrlRequired: true },
    ),
    firebaseSessionRequest(
      "query-cancelled-firebase-session",
      { "x-goog-upload-command": "query" },
      null,
      { afterStep: "cancel-unconfirmed-firebase-session", requestAttempted: true },
    ),
    firebaseWrongRequest(
      "cancel-unconfirmed-wrong-session",
      { "x-goog-upload-command": "cancel" },
      null,
      {
        afterStep: "initiate-wrong",
        status: 200,
        cancellationUnconfirmed: true,
        sessionUrlRequired: true,
      },
    ),
    firebaseWrongRequest(
      "query-cancelled-wrong-session",
      { "x-goog-upload-command": "query" },
      null,
      { afterStep: "cancel-unconfirmed-wrong-session", requestAttempted: true },
    ),
    firebaseCancelRequest(
      "recancel-unconfirmed-cancel-session",
      { "x-goog-upload-command": "cancel" },
      null,
      {
        afterStep: "initiate-cancel",
        status: 200,
        cancellationUnconfirmed: true,
        sessionUrlRequired: true,
      },
    ),
    firebaseCancelRequest(
      "query-after-recancel-session",
      { "x-goog-upload-command": "query" },
      null,
      { afterStep: "recancel-unconfirmed-cancel-session", requestAttempted: true },
    ),
  );
  recipes.push(firebaseResumableRecipe);

  const resumableName = `${prefix}gcs/resumable.bin`;
  const resumableTotal = 262147;
  const resumableLocation = {
    kind: "gcs-resumable-location",
    initiateStep: "initiate",
    expectedOrigin: "https://storage.googleapis.com",
    expectedPath: `/upload/storage/v1/b/${bucket}/o`,
    expectedName: resumableName,
    secretHandling: "private-only",
  };
  const sessionRequest = (id, headers, body, continuation) => ({
    id,
    dialect: "gcs",
    method: "PUT",
    objectName: resumableName,
    credential: "admin",
    responseCapture: { status: true, headers: "all", body: "raw-bytes" },
    sessionUriReference: { ...resumableLocation },
    query: {},
    headers,
    ...(body ? { body: { base64: Buffer.from(body).toString("base64") } } : {}),
    continuation,
  });
  const resumableRecipe = recipe("storage-object/gcs/resumable-upload", resumableName, [
    request("gcs", "POST", resumableName, "initiate", {
      query: { uploadType: "resumable", name: resumableName, ifGenerationMatch: "0" },
      headers: {
        "content-type": "application/json",
        "x-upload-content-type": "application/octet-stream",
        "x-upload-content-length": String(resumableTotal),
      },
      body: {
        json: {
          name: resumableName,
          contentType: "application/octet-stream",
          metadata: { marker: "gcs-resumable" },
        },
      },
    }),
    sessionRequest(
      "chunk-0",
      { "content-length": "262144", "content-range": "bytes 0-262143/262147" },
      Buffer.alloc(262144, 90),
      { afterStep: "initiate", status: 200, locationRequired: true },
    ),
    sessionRequest(
      "query-progress",
      { "content-length": "0", "content-range": "bytes */262147" },
      null,
      { afterStep: "chunk-0", status: 308 },
    ),
    sessionRequest(
      "finish",
      { "content-length": "3", "content-range": "bytes 262144-262146/262147" },
      [0, 1, 255],
      { afterStep: "query-progress", status: 308, range: "bytes=0-262143" },
    ),
    ...bothReadback(resumableName, "after"),
  ]);
  resumableRecipe.sessionUriHandling = "private-only";
  resumableRecipe.sendAuthorized = false;
  resumableRecipe.cleanupAuthorized = false;
  resumableRecipe.cleanup.unshift(
    {
      ...sessionRequest("cancel-unconfirmed-session", { "content-length": "0" }, null, {
        afterStep: "initiate",
        status: 200,
        completionUnconfirmed: true,
        locationRequired: true,
      }),
      method: "DELETE",
      responseExpectation: { status: 499 },
    },
    {
      ...sessionRequest(
        "verify-session-cancelled",
        { "content-length": "0", "content-range": "bytes */262147" },
        null,
        { afterStep: "cancel-unconfirmed-session", status: 499 },
      ),
      responseExpectation: { statusClass: "4xx" },
    },
  );
  recipes.push(resumableRecipe);

  return {
    status: "LOCAL_DRAFT",
    evidenceHandling: "private-only-until-reviewed-normalization",
    remainingObligations: [
      "refused-simple-upload-post-state",
      "remaining-frozen-recipes",
      "typed-reference-resolution-and-preconditions",
      "list-token-resolution-and-exhaustion",
      "rewrite-token-resolution-and-completion",
      "owner-adc-credential-proof",
      "resumable-session-uri-resolution-and-progress",
      "resumable-session-cancellation",
      "download-token-provenance-and-authorization",
      "object-name-missing-name-safe-boundary-and-list-path-semantics",
      "production-two-recordings",
      "credential-and-wire-request-budget",
      "resource-ownership-journal",
      "step-preconditions-and-state-admission",
      "response-normalization",
      "final-artifact-comparison",
      "independent-closure-review",
    ],
    requestsPerRecording: recipes.reduce(
      (n, r) => n + r.preflight.length + r.steps.length + r.cleanup.length,
      0,
    ),
    remainingRecipeIds: FROZEN_RECIPES.filter((id) => !recipes.some((r) => r.id === id)),
    recipes,
  };
}
