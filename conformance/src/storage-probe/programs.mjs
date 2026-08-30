// The storage-probe corpus: raw HTTP programs run against both Storage emulators.
//
// Each program is independent and works under its own object-name prefix, so programs can
// be filtered and reordered without changing a row. A step records the status, a fixed set
// of response headers and the normalized body of one request, or the trigger events the
// handlers of `storage-probe-functions` reported. Object names are derived from the program
// id, never from a clock, so a re-record produces a byte-identical matrix.

const OWNER = { authorization: "Bearer owner" };
const FIREBASE_OWNER = { authorization: "Firebase owner" };

const text = (s) => Buffer.from(s, "utf8");

/** `/v0/b/{bucket}/o/{name}` with the object name encoded as one segment. */
const fbObject = (ctx, name) => `/v0/b/${ctx.bucket}/o/${ctx.enc(name)}`;
const fbBucket = (ctx) => `/v0/b/${ctx.bucket}/o`;
const gcsObject = (ctx, name) => `/storage/v1/b/${ctx.bucket}/o/${ctx.enc(name)}`;
const gcsBucket = (ctx) => `/storage/v1/b/${ctx.bucket}/o`;
const gcsUpload = (ctx) => `/upload/storage/v1/b/${ctx.bucket}/o`;

/** A one-shot Firebase-dialect media upload. */
async function fbMedia(ctx, name, body, contentType = "text/plain", headers = {}) {
  return ctx.http({
    method: "POST",
    path: fbBucket(ctx),
    query: { name },
    headers: { ...OWNER, "content-type": contentType, ...headers },
    body,
  });
}

/** A JSON API media insert with owner credentials. */
async function gcsMedia(ctx, name, body, contentType = "text/plain", query = {}) {
  return ctx.http({
    method: "POST",
    path: gcsUpload(ctx),
    query: { uploadType: "media", name, ...query },
    headers: { ...OWNER, "content-type": contentType },
    body,
  });
}

/** The recorded shape of a response: everything but the raw bytes. */
const rec = ({ status, headers, body }) => ({ status, headers, body });

// ------------------------------------------------------------------------------------------
// Firebase protocol
// ------------------------------------------------------------------------------------------

const fbMediaUpload = {
  id: "fb-media-upload",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/media/hello.txt";
    await ctx.step("upload", () => fbMedia(ctx, name, text("hello probe"), "text/plain"));
    await ctx.step("metadata", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("download", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("download-range", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: { ...OWNER, range: "bytes=2-6" },
      }),
    );
    await ctx.step("download-open-ended-range", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: { ...OWNER, range: "bytes=6-" },
      }),
    );
    await ctx.step("download-suffix-range", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: { ...OWNER, range: "bytes=-5" },
      }),
    );
    await ctx.step("download-unsatisfiable-range", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: { ...OWNER, range: "bytes=100-200" },
      }),
    );
    await ctx.step("upload-without-content-type", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/media/untyped.bin" },
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.from([0, 1, 2, 3]),
      }),
    );
    await ctx.step("upload-with-firebase-owner-credential", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "closed/firebase-owner.txt" },
        headers: { ...FIREBASE_OWNER, "content-type": "text/plain" },
        body: text("owner bypasses rules"),
      }),
    );
    await ctx.step("upload-to-object-url", () =>
      ctx.http({
        method: "POST",
        path: fbObject(ctx, "open/media/at-object-url.txt"),
        headers: { ...OWNER, "content-type": "text/plain" },
        body: text("posted to the object url"),
      }),
    );
    await ctx.step("upload-without-name", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        headers: { ...OWNER, "content-type": "text/plain" },
        body: text("no name"),
      }),
    );
    await ctx.step("unicode-name-round-trip", async () => {
      const unicode = "open/media/日本語 ファイル+name.txt";
      await fbMedia(ctx, unicode, text("unicode"));
      return ctx.http({ method: "GET", path: fbObject(ctx, unicode), headers: OWNER });
    });
    await ctx.step("root-route", () => ctx.http({ method: "GET", path: "/v0/", headers: OWNER }));
  },
};

const fbMultipartUpload = {
  id: "fb-multipart-upload",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/multipart/photo.png";
    const { contentType, body } = ctx.multipart(
      {
        name,
        contentType: "image/png",
        cacheControl: "public, max-age=60",
        contentDisposition: "attachment; filename=photo.png",
        contentLanguage: "en",
        contentEncoding: "identity",
        metadata: { origin: "probe", n: "1" },
      },
      "image/png",
      Buffer.from("PNGBYTES"),
    );
    await ctx.step("upload", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name, uploadType: "multipart" },
        headers: { ...OWNER, "content-type": contentType, "x-goog-upload-protocol": "multipart" },
        body,
      }),
    );
    await ctx.step("download-headers", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("upload-name-from-metadata-part", async () => {
      const part = ctx.multipart(
        { name: "open/multipart/named-in-part.txt", contentType: "text/plain" },
        "text/plain",
        Buffer.from("named in the metadata part"),
      );
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": part.contentType,
          "x-goog-upload-protocol": "multipart",
        },
        body: part.body,
      });
    });
    await ctx.step("upload-bad-boundary", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/multipart/bad.txt", uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": "multipart/related; boundary=other",
          "x-goog-upload-protocol": "multipart",
        },
        body,
      }),
    );
    await ctx.step("upload-one-part-only", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/multipart/one.txt", uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": "multipart/related; boundary=probe-boundary",
          "x-goog-upload-protocol": "multipart",
        },
        body: text(
          "--probe-boundary\r\nContent-Type: text/plain\r\n\r\nonly one\r\n--probe-boundary--\r\n",
        ),
      }),
    );
    await ctx.step("multipart-data-ending-in-line-breaks", async () => {
      const part = ctx.multipart(
        { name: "open/multipart/crlf.txt", contentType: "text/plain" },
        "text/plain",
        Buffer.from("line\r\n\r\n"),
      );
      await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/multipart/crlf.txt", uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": part.contentType,
          "x-goog-upload-protocol": "multipart",
        },
        body: part.body,
      });
      const got = await ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/multipart/crlf.txt"),
        query: { alt: "media" },
        headers: OWNER,
      });
      return { status: got.status, bytes: [...got.raw] };
    });
  },
};

const fbResumable = {
  id: "fb-resumable-upload",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/resumable/big.bin";
    const start = await ctx.step("start", async () => {
      const r = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name, uploadType: "resumable" },
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
          "x-goog-upload-header-content-type": "application/octet-stream",
          "x-goog-upload-header-content-length": "20",
        },
        body: text(
          JSON.stringify({
            name,
            contentType: "application/octet-stream",
            metadata: { via: "resumable" },
          }),
        ),
      });
      const url = r.headers["x-goog-upload-url"] ?? "";
      const id = new URL(url, "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id>");
      return r;
    });
    const uploadUrl = start.headers["x-goog-upload-url"];
    if (!uploadUrl) throw new Error("no upload url");
    await ctx.step("query-empty", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "query",
        },
      }),
    );
    await ctx.step("upload-first-chunk", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload",
          "x-goog-upload-offset": "0",
        },
        body: Buffer.alloc(10, 1),
      }),
    );
    await ctx.step("query-after-chunk", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "query",
        },
      }),
    );
    await ctx.step("upload-and-finalize", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload, finalize",
          "x-goog-upload-offset": "10",
        },
        body: Buffer.alloc(10, 2),
      }),
    );
    await ctx.step("query-finalized", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "query",
        },
      }),
    );
    await ctx.step("finalize-again", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "finalize",
        },
      }),
    );
    await ctx.step("upload-after-finalize", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload",
          "x-goog-upload-offset": "20",
        },
        body: Buffer.alloc(5, 3),
      }),
    );
    await ctx.step("cancel-finalized", () =>
      ctx.http({
        method: "POST",
        path: uploadUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "cancel",
        },
      }),
    );
    await ctx.step("committed-object", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("committed-bytes", async () => {
      const r = await ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      });
      return {
        status: r.status,
        length: r.raw.length,
        first: r.raw[0],
        last: r.raw[r.raw.length - 1],
      };
    });
    await ctx.step("query-unknown-session", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name, upload_id: "does-not-exist", upload_protocol: "resumable" },
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "query",
        },
      }),
    );
    await ctx.step("start-without-name", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
        },
        body: text("{}"),
      }),
    );
    // A second session: cancelled before it finishes.
    const second = await ctx.step("start-second", async () => {
      const r = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/resumable/cancelled.bin", uploadType: "resumable" },
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
        },
        body: text(JSON.stringify({ name: "open/resumable/cancelled.bin" })),
      });
      const id = new URL(r.headers["x-goog-upload-url"] ?? "", "http://x").searchParams.get(
        "upload_id",
      );
      if (id) ctx.redact(id, "<upload-id-2>");
      return r;
    });
    const secondUrl = second.headers["x-goog-upload-url"];
    await ctx.step("cancel-active", () =>
      ctx.http({
        method: "POST",
        path: secondUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "cancel",
        },
      }),
    );
    await ctx.step("upload-after-cancel", () =>
      ctx.http({
        method: "POST",
        path: secondUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload",
          "x-goog-upload-offset": "0",
        },
        body: Buffer.alloc(4, 9),
      }),
    );
    await ctx.step("finalize-after-cancel", () =>
      ctx.http({
        method: "POST",
        path: secondUrl,
        headers: {
          ...OWNER,
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "finalize",
        },
      }),
    );
    await ctx.step("cancelled-object-absent", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/resumable/cancelled.bin"),
        headers: OWNER,
      }),
    );
    // A third session: a chunk whose offset disagrees with what was received.
    const third = await ctx.step("start-third", async () => {
      const r = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/resumable/offset.bin", uploadType: "resumable" },
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
        },
        body: text(JSON.stringify({ name: "open/resumable/offset.bin" })),
      });
      const id = new URL(r.headers["x-goog-upload-url"] ?? "", "http://x").searchParams.get(
        "upload_id",
      );
      if (id) ctx.redact(id, "<upload-id-3>");
      return r;
    });
    const thirdUrl = third.headers["x-goog-upload-url"];
    await ctx.step("upload-with-wrong-offset", () =>
      ctx.http({
        method: "POST",
        path: thirdUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload, finalize",
          "x-goog-upload-offset": "100",
        },
        body: Buffer.alloc(4, 7),
      }),
    );
    await ctx.step("wrong-offset-object", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "open/resumable/offset.bin"), headers: OWNER }),
    );
  },
};

const fbDownloadTokens = {
  id: "fb-download-tokens",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/tokens/doc.txt";
    const uploaded = await ctx.step("upload", () => fbMedia(ctx, name, text("token me")));
    const token = String(uploaded.body?.downloadTokens ?? "").split(",")[0];
    await ctx.step("download-with-token-no-credentials", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), query: { alt: "media", token } }),
    );
    await ctx.step("metadata-with-token-no-credentials", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), query: { token } }),
    );
    await ctx.step("download-with-wrong-token", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media", token: "00000000-0000-4000-8000-000000000000" },
      }),
    );
    // The closed area: a token is the only way in for an anonymous caller.
    const closedName = "closed/tokens/secret.txt";
    const closed = await ctx.step("owner-uploads-closed-object", () =>
      fbMedia(ctx, closedName, text("secret")),
    );
    const closedToken = String(closed.body?.downloadTokens ?? "").split(",")[0];
    await ctx.step("closed-object-with-token", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, closedName),
        query: { alt: "media", token: closedToken },
      }),
    );
    await ctx.step("closed-object-without-token", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, closedName), query: { alt: "media" } }),
    );
    await ctx.step("create-token", () =>
      ctx.http({
        method: "POST",
        path: fbObject(ctx, name),
        query: { create_token: "true" },
        headers: OWNER,
      }),
    );
    await ctx.step("create-token-without-owner", () =>
      ctx.http({ method: "POST", path: fbObject(ctx, name), query: { create_token: "true" } }),
    );
    await ctx.step("create-token-missing-object", () =>
      ctx.http({
        method: "POST",
        path: fbObject(ctx, "open/tokens/missing.txt"),
        query: { create_token: "true" },
        headers: OWNER,
      }),
    );
    await ctx.step("delete-token", () =>
      ctx.http({
        method: "POST",
        path: fbObject(ctx, name),
        query: { delete_token: token },
        headers: OWNER,
      }),
    );
    await ctx.step("deleted-token-no-longer-grants", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), query: { alt: "media", token } }),
    );
    await ctx.step("delete-last-token-mints-a-new-one", async () => {
      const meta = await ctx.http({ method: "GET", path: fbObject(ctx, name), headers: OWNER });
      const remaining = String(meta.body?.downloadTokens ?? "")
        .split(",")
        .filter(Boolean);
      let last = null;
      for (const t of remaining) {
        last = await ctx.http({
          method: "POST",
          path: fbObject(ctx, name),
          query: { delete_token: t },
          headers: OWNER,
        });
      }
      return {
        deletedCount: remaining.length,
        status: last?.status ?? null,
        tokens: String(last?.body?.downloadTokens ?? "")
          .split(",")
          .filter(Boolean).length,
        metageneration: last?.body?.metageneration ?? null,
      };
    });
    // An object created through the JSON API has no token; the Firebase dialect's GET is
    // where the official emulator mints one.
    const adminName = "open/tokens/admin-made.txt";
    await ctx.step("json-api-upload-has-no-token", async () => {
      const r = await gcsMedia(ctx, adminName, text("admin"));
      return { status: r.status, tokens: r.body?.metadata?.firebaseStorageDownloadTokens ?? null };
    });
    await ctx.step("firebase-get-mints-a-token", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, adminName), headers: OWNER }),
    );
    await ctx.step("firebase-get-again-keeps-it", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, adminName), headers: OWNER }),
    );
    await ctx.step("json-api-sees-the-minted-token", async () => {
      const r = await ctx.http({ method: "GET", path: gcsObject(ctx, adminName), headers: OWNER });
      return {
        status: r.status,
        tokens: r.body?.metadata?.firebaseStorageDownloadTokens ?? null,
        metageneration: r.body?.metageneration ?? null,
      };
    });
    await ctx.step("upload-with-client-supplied-token", async () => {
      const part = ctx.multipart(
        {
          name: "open/tokens/client-token.txt",
          metadata: { firebaseStorageDownloadTokens: "client-chosen-token" },
        },
        "text/plain",
        Buffer.from("x"),
      );
      const up = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "open/tokens/client-token.txt", uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": part.contentType,
          "x-goog-upload-protocol": "multipart",
        },
        body: part.body,
      });
      const fetched = await ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/tokens/client-token.txt"),
        query: { alt: "media", token: "client-chosen-token" },
      });
      return {
        uploadStatus: up.status,
        tokens: up.body?.downloadTokens ?? null,
        custom: up.body?.metadata ?? null,
        fetchStatus: fetched.status,
      };
    });
  },
};

const fbMetadata = {
  id: "fb-metadata-update",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/meta/doc.txt";
    await ctx.step("upload", async () => {
      const part = ctx.multipart(
        {
          name,
          contentType: "text/plain",
          cacheControl: "no-store",
          contentDisposition: "inline",
          metadata: { a: "1", b: "2" },
        },
        "text/plain",
        Buffer.from("meta"),
      );
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name, uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": part.contentType,
          "x-goog-upload-protocol": "multipart",
        },
        body: part.body,
      });
    });
    await ctx.step("patch", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(
          JSON.stringify({
            cacheControl: "private, max-age=0",
            contentType: "text/markdown",
            contentLanguage: "ja",
            metadata: { a: null, c: "3" },
          }),
        ),
      }),
    );
    await ctx.step("put-with-method-override", () =>
      ctx.http({
        method: "PUT",
        path: fbObject(ctx, name),
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-http-method-override": "PATCH",
        },
        body: text(JSON.stringify({ contentDisposition: null, metadata: { c: "4" } })),
      }),
    );
    await ctx.step("clear-all-custom-metadata", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ metadata: null })),
      }),
    );
    await ctx.step("non-string-custom-value", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ metadata: { n: 5, flag: true } })),
      }),
    );
    await ctx.step("empty-patch-bumps-metageneration", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text("{}"),
      }),
    );
    await ctx.step("patch-missing", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, "open/meta/missing.txt"),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ cacheControl: "x" })),
      }),
    );
    await ctx.step("patch-closed", async () => {
      await fbMedia(ctx, "closed/meta/doc.txt", text("closed"));
      return ctx.http({
        method: "PATCH",
        path: fbObject(ctx, "closed/meta/doc.txt"),
        headers: { "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ cacheControl: "x" })),
      });
    });
    await ctx.step("patch-closed-and-missing", () =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, "closed/meta/missing.txt"),
        headers: { "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ cacheControl: "x" })),
      }),
    );
    await ctx.step("response-headers-of-patch", async () => {
      const r = await ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(
          JSON.stringify({
            contentDisposition: "attachment",
            contentEncoding: "gzip",
            cacheControl: "max-age=1",
            contentLanguage: "en",
          }),
        ),
      });
      return { status: r.status, headers: r.headers };
    });
  },
};

const fbDelete = {
  id: "fb-delete",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/delete/doc.txt";
    await fbMedia(ctx, name, text("bye"));
    await ctx.step("delete", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("delete-again", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("get-after-delete", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("download-after-delete", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("delete-closed", async () => {
      await fbMedia(ctx, "closed/delete/doc.txt", text("closed"));
      return ctx.http({ method: "DELETE", path: fbObject(ctx, "closed/delete/doc.txt") });
    });
    await ctx.step("delete-closed-and-missing", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "closed/delete/missing.txt") }),
    );
    await ctx.step("delete-open-and-missing", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "open/delete/missing.txt") }),
    );
  },
};

const fbErrors = {
  id: "fb-errors",
  area: "firebase-protocol",
  async run(ctx) {
    await ctx.step("get-missing-metadata", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "open/errors/missing.txt"), headers: OWNER }),
    );
    await ctx.step("get-missing-media", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/errors/missing.txt"),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("get-missing-anonymous", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "open/errors/missing.txt") }),
    );
    await ctx.step("get-closed-missing-anonymous", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "closed/errors/missing.txt") }),
    );
    await ctx.step("get-closed-existing-anonymous", async () => {
      await fbMedia(ctx, "closed/errors/present.txt", text("present"));
      return ctx.http({ method: "GET", path: fbObject(ctx, "closed/errors/present.txt") });
    });
    await ctx.step("upload-closed-anonymous", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "closed/errors/upload.txt" },
        headers: { "content-type": "text/plain" },
        body: text("denied"),
      }),
    );
    await ctx.step("upload-closed-with-user-token", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "closed/errors/user.txt" },
        headers: {
          authorization: `Firebase ${ctx.mockToken("alice")}`,
          "content-type": "text/plain",
        },
        body: text("denied"),
      }),
    );
    await ctx.step("malformed-bearer", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/errors/whatever.txt"),
        headers: { authorization: "Bearer not-a-jwt" },
      }),
    );
    await ctx.step("list-prefix-without-trailing-slash", () =>
      ctx.http({ method: "GET", path: fbBucket(ctx), query: { prefix: "open" }, headers: OWNER }),
    );
    await ctx.step("unknown-method", () =>
      ctx.http({
        method: "PUT",
        path: fbBucket(ctx),
        headers: { ...OWNER, "content-type": "text/plain" },
        body: text("x"),
      }),
    );
    await ctx.step("extra-path-segment", () =>
      ctx.http({ method: "GET", path: `${fbObject(ctx, "open/errors/a")}/extra`, headers: OWNER }),
    );
    await ctx.step("cors-preflight", () =>
      ctx.http({
        method: "OPTIONS",
        path: fbObject(ctx, "open/errors/a"),
        headers: {
          origin: "http://localhost:5173",
          "access-control-request-method": "POST",
          "access-control-request-headers": "authorization,content-type,x-goog-upload-command",
        },
      }),
    );
    await ctx.step("cors-actual-request", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "open/errors/missing.txt"),
        headers: { ...OWNER, origin: "http://localhost:5173" },
      }),
    );
  },
};

const fbList = {
  id: "fb-list",
  area: "firebase-protocol",
  async run(ctx) {
    const names = [
      "lst/a.txt",
      "lst/b.txt",
      "lst/dir/c.txt",
      "lst/dir/d.txt",
      "lst/dir2/e.txt",
      "lst/zz.txt",
    ];
    for (const n of names) await fbMedia(ctx, `open/${n}`, text(n));
    await ctx.step("delimited", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/", delimiter: "/" },
        headers: OWNER,
      }),
    );
    await ctx.step("flat", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/" },
        headers: OWNER,
      }),
    );
    await ctx.step("subdirectory", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/dir/", delimiter: "/" },
        headers: OWNER,
      }),
    );
    await ctx.step("empty-prefix", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/nothing/", delimiter: "/" },
        headers: OWNER,
      }),
    );
    await ctx.step("paged", async () => {
      const pages = [];
      let pageToken;
      for (let i = 0; i < 10; i += 1) {
        const query = { prefix: "open/lst/", delimiter: "/", maxResults: "2" };
        if (pageToken) query.pageToken = pageToken;
        const r = await ctx.http({ method: "GET", path: fbBucket(ctx), query, headers: OWNER });
        pages.push({
          status: r.status,
          items: (r.body?.items ?? []).map((i) => i.name),
          prefixes: r.body?.prefixes ?? null,
          hasNext: typeof r.body?.nextPageToken === "string",
        });
        pageToken = r.body?.nextPageToken;
        if (!pageToken) break;
      }
      return pages;
    });
    await ctx.step("page-token-shape", async () => {
      const r = await ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/", maxResults: "2" },
        headers: OWNER,
      });
      return {
        nextPageToken: r.body?.nextPageToken ?? null,
        items: (r.body?.items ?? []).map((i) => i.name),
      };
    });
    await ctx.step("list-closed-prefix", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "closed/", delimiter: "/" },
      }),
    );
    await ctx.step("list-listable-prefix-anonymous", async () => {
      await fbMedia(ctx, "listable/x.txt", text("x"));
      return ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "listable/", delimiter: "/" },
      });
    });
    await ctx.step("get-in-listable-prefix-anonymous", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "listable/x.txt") }),
    );
    await ctx.step("max-results-zero", () =>
      ctx.http({
        method: "GET",
        path: fbBucket(ctx),
        query: { prefix: "open/lst/", maxResults: "0" },
        headers: OWNER,
      }),
    );
  },
};

const fbOverwrite = {
  id: "fb-overwrite",
  area: "firebase-protocol",
  async run(ctx) {
    const name = "open/overwrite/doc.txt";
    const first = await ctx.step("first", () => fbMedia(ctx, name, text("one")));
    await ctx.http({
      method: "PATCH",
      path: fbObject(ctx, name),
      headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
      body: text(JSON.stringify({ cacheControl: "max-age=5", metadata: { keep: "me" } })),
    });
    const second = await ctx.step("second", () => fbMedia(ctx, name, text("two"), "text/markdown"));
    await ctx.step("generation-changed", () => ({
      changed: first.body?.generation !== second.body?.generation,
      metagenerationReset: second.body?.metageneration,
      cacheControl: second.body?.cacheControl ?? null,
      custom: second.body?.metadata ?? null,
      contentType: second.body?.contentType ?? null,
      tokensPreserved: first.body?.downloadTokens === second.body?.downloadTokens,
    }));
    await ctx.step("old-generation-not-served", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, name),
        query: { generation: String(first.body?.generation) },
        headers: OWNER,
      }),
    );
  },
};

// ------------------------------------------------------------------------------------------
// Rules request model
// ------------------------------------------------------------------------------------------

const rulesRequestModel = {
  id: "rules-request-model",
  area: "rules",
  async run(ctx) {
    await ctx.step("size-under-limit", () =>
      fbMedia(ctx, "gated/size/small.txt", Buffer.alloc(50, 65)),
    );
    await ctx.step("size-over-limit", () =>
      fbMedia(ctx, "gated/size/big.txt", Buffer.alloc(150, 65)),
    );
    await ctx.step("size-over-limit-not-published", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "gated/size/big.txt"), headers: OWNER }),
    );
    await ctx.step("size-delete-without-request-resource", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "gated/size/small.txt") }),
    );
    await ctx.step("type-image", () =>
      fbMedia(ctx, "gated/type/a.png", Buffer.from("png"), "image/png"),
    );
    await ctx.step("type-text", () =>
      fbMedia(ctx, "gated/type/a.txt", Buffer.from("txt"), "text/plain"),
    );
    await ctx.step("type-defaulted-when-absent", async () => {
      const part = ctx.multipart({ name: "gated/type/untyped" }, "image/png", Buffer.from("x"));
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/type/untyped", uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
    });
    await ctx.step("type-from-metadata-part-wins", async () => {
      const part = ctx.multipart(
        { name: "gated/type/meta-wins", contentType: "image/gif" },
        "text/plain",
        Buffer.from("x"),
      );
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/type/meta-wins", uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
    });
    await ctx.step("custom-metadata-owner", async () => {
      const part = ctx.multipart(
        { name: "gated/meta/mine.txt", metadata: { owner: "probe" } },
        "text/plain",
        Buffer.from("x"),
      );
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/meta/mine.txt", uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
    });
    await ctx.step("custom-metadata-absent", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/meta/nobody.txt" },
        headers: { "content-type": "text/plain" },
        body: text("x"),
      }),
    );
    await ctx.step("hashes-present-in-request-resource", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/hash/h.txt" },
        headers: { "content-type": "text/plain" },
        body: text("hash me"),
      }),
    );
    // resource on update and delete.
    const locked = async (name, value) => {
      const part = ctx.multipart(
        { name, metadata: { locked: value } },
        "text/plain",
        Buffer.from("x"),
      );
      return ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name, uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
    };
    await locked("locked/open.txt", "false");
    await locked("locked/shut.txt", "true");
    const patch = (name) =>
      ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ cacheControl: "x" })),
      });
    await ctx.step("update-unlocked", () => patch("locked/open.txt"));
    await ctx.step("update-locked", () => patch("locked/shut.txt"));
    await ctx.step("overwrite-locked-is-an-update", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "locked/shut.txt" },
        headers: { "content-type": "text/plain" },
        body: text("again"),
      }),
    );
    await ctx.step("delete-locked", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "locked/shut.txt") }),
    );
    await ctx.step("delete-unlocked", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "locked/open.txt") }),
    );
    await ctx.step("delete-missing-under-resource-rule", () =>
      ctx.http({ method: "DELETE", path: fbObject(ctx, "locked/missing.txt") }),
    );
    // Path-derived fields.
    await ctx.step("fields-create", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "fields/f.txt" },
        headers: { "content-type": "text/plain" },
        body: text("f"),
      }),
    );
    await ctx.step("fields-read", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "fields/f.txt") }),
    );
    // cacheControl / contentLanguage on the stored resource.
    await ctx.step("cache-control-visible-to-rules", async () => {
      const part = ctx.multipart(
        { name: "cache/c.txt", cacheControl: "no-cache" },
        "text/plain",
        Buffer.from("c"),
      );
      await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "cache/c.txt", uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
      return ctx.http({ method: "GET", path: fbObject(ctx, "cache/c.txt") });
    });
    await ctx.step("content-language-visible-to-rules", async () => {
      const part = ctx.multipart(
        { name: "language/l.txt", contentLanguage: "ja" },
        "text/plain",
        Buffer.from("l"),
      );
      await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "language/l.txt", uploadType: "multipart" },
        headers: { "content-type": part.contentType, "x-goog-upload-protocol": "multipart" },
        body: part.body,
      });
      return ctx.http({ method: "GET", path: fbObject(ctx, "language/l.txt") });
    });
    // The caller's token.
    const alice = `Firebase ${ctx.mockToken("alice", { email: "probe@example.com" })}`;
    const bob = `Bearer ${ctx.mockToken("bob")}`;
    await ctx.step("own-prefix", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "users/alice/a.txt" },
        headers: { authorization: alice, "content-type": "text/plain" },
        body: text("a"),
      }),
    );
    await ctx.step("other-prefix", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "users/alice/b.txt" },
        headers: { authorization: bob, "content-type": "text/plain" },
        body: text("b"),
      }),
    );
    await ctx.step("anonymous-prefix", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "users/alice/a.txt") }),
    );
    await ctx.step("bearer-scheme-user-token", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "users/bob/none.txt"),
        headers: { authorization: bob },
      }),
    );
    await ctx.step("token-claims", async () => {
      await fbMedia(ctx, "claims/c.txt", text("c"));
      return ctx.http({
        method: "GET",
        path: fbObject(ctx, "claims/c.txt"),
        headers: { authorization: alice },
      });
    });
    await ctx.step("token-claims-other-email", () =>
      ctx.http({
        method: "GET",
        path: fbObject(ctx, "claims/c.txt"),
        headers: { authorization: bob },
      }),
    );
    // Firestore access.
    await ctx.seedDocument("allow/yes", { write: { booleanValue: true } });
    await ctx.seedDocument("allow/ro", { write: { booleanValue: false } });
    await ctx.step("firestore-get-allows", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "fs/yes" },
        headers: { "content-type": "text/plain" },
        body: text("y"),
      }),
    );
    await ctx.step("firestore-get-denies", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "fs/ro" },
        headers: { "content-type": "text/plain" },
        body: text("r"),
      }),
    );
    await ctx.step("firestore-get-missing-document", () =>
      ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "fs/none" },
        headers: { "content-type": "text/plain" },
        body: text("n"),
      }),
    );
    await ctx.step("firestore-exists-allows", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "fs/yes") }),
    );
    await ctx.step("firestore-exists-denies", () =>
      ctx.http({ method: "GET", path: fbObject(ctx, "fs/none") }),
    );
    // Resumable uploads are authorized when they finalize.
    await ctx.step("resumable-denied-at-finalize", async () => {
      const start = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "gated/size/resumable.bin", uploadType: "resumable" },
        headers: {
          "content-type": "application/json; charset=utf-8",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "start",
        },
        body: text(JSON.stringify({ name: "gated/size/resumable.bin" })),
      });
      const url = start.headers["x-goog-upload-url"];
      const id = new URL(url ?? "", "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id>");
      const fin = await ctx.http({
        method: "POST",
        path: url,
        headers: {
          "content-type": "application/octet-stream",
          "x-goog-upload-protocol": "resumable",
          "x-goog-upload-command": "upload, finalize",
          "x-goog-upload-offset": "0",
        },
        body: Buffer.alloc(150, 1),
      });
      const query = await ctx.http({
        method: "POST",
        path: url,
        headers: { "x-goog-upload-protocol": "resumable", "x-goog-upload-command": "query" },
      });
      const again = await ctx.http({
        method: "POST",
        path: url,
        headers: { "x-goog-upload-protocol": "resumable", "x-goog-upload-command": "finalize" },
      });
      const object = await ctx.http({
        method: "GET",
        path: fbObject(ctx, "gated/size/resumable.bin"),
        headers: OWNER,
      });
      return {
        start: start.status,
        finalize: rec(fin),
        query: rec(query),
        again: rec(again),
        object: object.status,
      };
    });
  },
};

// ------------------------------------------------------------------------------------------
// JSON API
// ------------------------------------------------------------------------------------------

const gcsInsertAndGet = {
  id: "gcs-insert-and-get",
  area: "json-api",
  async run(ctx) {
    const name = "open/gcs/media.txt";
    await ctx.step("media-insert", () => gcsMedia(ctx, name, text("gcs media"), "text/plain"));
    await ctx.step("get-metadata", () =>
      ctx.http({ method: "GET", path: gcsObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("get-media", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("get-media-range", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { alt: "media" },
        headers: { ...OWNER, range: "bytes=0-2" },
      }),
    );
    await ctx.step("download-route", () =>
      ctx.http({
        method: "GET",
        path: `/download/storage/v1/b/${ctx.bucket}/o/${ctx.enc(name)}`,
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("short-route-metadata", () =>
      ctx.http({ method: "GET", path: `/b/${ctx.bucket}/o/${ctx.enc(name)}`, headers: OWNER }),
    );
    await ctx.step("xml-style-route", () =>
      ctx.http({ method: "GET", path: `/${ctx.bucket}/${name}`, headers: OWNER }),
    );
    await ctx.step("multipart-insert", async () => {
      const part = ctx.multipart(
        {
          name: "open/gcs/multi.txt",
          contentType: "text/plain",
          cacheControl: "public",
          contentDisposition: "inline",
          contentLanguage: "en",
          metadata: { k: "v" },
        },
        "text/plain",
        Buffer.from("gcs multipart"),
      );
      return ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "multipart" },
        headers: { ...OWNER, "content-type": part.contentType },
        body: part.body,
      });
    });
    await ctx.step("multipart-name-with-leading-slash", async () => {
      const part = ctx.multipart({ name: "/open/gcs/lead.txt" }, "text/plain", Buffer.from("lead"));
      return ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "multipart" },
        headers: { ...OWNER, "content-type": part.contentType },
        body: part.body,
      });
    });
    await ctx.step("multipart-content-type-from-header", async () => {
      const part = ctx.multipart(
        { name: "open/gcs/header-ct.bin" },
        "application/pdf",
        Buffer.from("%PDF"),
      );
      return ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "multipart" },
        headers: {
          ...OWNER,
          "content-type": part.contentType,
          "x-upload-content-type": "application/pdf",
        },
        body: part.body,
      });
    });
    // Deliberately NOT probed: a JSON API media insert without a `name` crashes the pinned
    // official CLI outright (apis/gcloud.js answers 400 and then still dereferences the
    // missing name; the unhandled TypeError prints "An unexpected error has occurred." and
    // exits the whole `firebase emulators:exec` process with code 2, orphaning its child
    // emulators). Measured against firebase-tools 15.28.2 on 2026-08-31. fireemu answers a
    // plain 400 "object name is required"; the row lives in the contract as an
    // officialLimitations entry because no fixture can record a crash.
    await ctx.step("insert-without-credentials", () =>
      ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "media", name: "closed/gcs/anon.txt" },
        headers: { "content-type": "text/plain" },
        body: text("anon"),
      }),
    );
    await ctx.step("insert-with-user-token-bypasses-rules", () =>
      ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "media", name: "closed/gcs/user.txt" },
        headers: {
          authorization: `Firebase ${ctx.mockToken("alice")}`,
          "content-type": "text/plain",
        },
        body: text("user"),
      }),
    );
    await ctx.step("get-closed-with-user-token", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, "closed/gcs/user.txt"),
        headers: { authorization: `Firebase ${ctx.mockToken("alice")}` },
      }),
    );
    await ctx.step("get-with-garbage-bearer", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        headers: { authorization: "Bearer ya29.garbage" },
      }),
    );
  },
};

const gcsResumable = {
  id: "gcs-resumable-upload",
  area: "json-api",
  async run(ctx) {
    const name = "open/gcs/resumable.bin";
    const start = await ctx.step("start", async () => {
      const r = await ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable" },
        headers: {
          ...OWNER,
          "content-type": "application/json; charset=utf-8",
          "x-upload-content-type": "application/octet-stream",
        },
        body: text(JSON.stringify({ name, metadata: { via: "gcs-resumable" } })),
      });
      const id = new URL(r.headers.location ?? "", "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id>");
      return r;
    });
    const url = start.headers.location;
    if (!url) throw new Error("no location");
    await ctx.step("put-whole-body", () =>
      ctx.http({
        method: "PUT",
        path: url,
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.alloc(12, 4),
      }),
    );
    await ctx.step("put-after-finish", () =>
      ctx.http({
        method: "PUT",
        path: url,
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.alloc(3, 5),
      }),
    );
    await ctx.step("put-unknown-session", () =>
      ctx.http({
        method: "PUT",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable", upload_id: "nope" },
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.alloc(3, 5),
      }),
    );
    await ctx.step("put-without-upload-id", () =>
      ctx.http({
        method: "PUT",
        path: gcsUpload(ctx),
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.alloc(3, 5),
      }),
    );
    await ctx.step("start-without-name", () =>
      ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable" },
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text("{}"),
      }),
    );
    await ctx.step("start-name-in-query", async () => {
      const r = await ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable", name: "open/gcs/query-named.bin" },
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text("{}"),
      });
      const id = new URL(r.headers.location ?? "", "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id-2>");
      return r;
    });
    // Chunked with Content-Range, as the production protocol allows.
    const chunked = await ctx.step("start-chunked", async () => {
      const r = await ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable", name: "open/gcs/chunked.bin" },
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text("{}"),
      });
      const id = new URL(r.headers.location ?? "", "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id-3>");
      return r;
    });
    const chunkedUrl = chunked.headers.location;
    await ctx.step("chunk-one", () =>
      ctx.http({
        method: "PUT",
        path: chunkedUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "content-range": "bytes 0-4/10",
        },
        body: Buffer.alloc(5, 1),
      }),
    );
    await ctx.step("chunk-two", () =>
      ctx.http({
        method: "PUT",
        path: chunkedUrl,
        headers: {
          ...OWNER,
          "content-type": "application/octet-stream",
          "content-range": "bytes 5-9/10",
        },
        body: Buffer.alloc(5, 2),
      }),
    );
    await ctx.step("chunked-object", async () => {
      const r = await ctx.http({
        method: "GET",
        path: gcsObject(ctx, "open/gcs/chunked.bin"),
        headers: OWNER,
      });
      return { status: r.status, size: r.body?.size ?? null };
    });
  },
};

const gcsUpdateAndList = {
  id: "gcs-update-list-delete",
  area: "json-api",
  async run(ctx) {
    const name = "open/gcsu/doc.txt";
    await gcsMedia(ctx, name, text("doc"));
    await ctx.step("patch", () =>
      ctx.http({
        method: "PATCH",
        path: gcsObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(
          JSON.stringify({
            contentType: "text/markdown",
            cacheControl: "no-cache",
            contentDisposition: "attachment",
            contentEncoding: "identity",
            contentLanguage: "de",
            metadata: { a: "1", b: "2" },
          }),
        ),
      }),
    );
    await ctx.step("patch-remove-custom-key", () =>
      ctx.http({
        method: "PATCH",
        path: gcsObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ metadata: { a: null }, contentDisposition: null })),
      }),
    );
    await ctx.step("patch-missing", () =>
      ctx.http({
        method: "PATCH",
        path: gcsObject(ctx, "open/gcsu/missing.txt"),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("put-update", () =>
      ctx.http({
        method: "PUT",
        path: gcsObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ contentType: "text/x-put" })),
      }),
    );
    for (const n of [
      "open/gcsu/list/a.txt",
      "open/gcsu/list/b.txt",
      "open/gcsu/list/dir/c.txt",
      "open/gcsu/list/dir/d.txt",
    ]) {
      await gcsMedia(ctx, n, text(n));
    }
    await ctx.step("list-delimited", () =>
      ctx.http({
        method: "GET",
        path: gcsBucket(ctx),
        query: { prefix: "open/gcsu/list/", delimiter: "/" },
        headers: OWNER,
      }),
    );
    await ctx.step("list-flat-names", async () => {
      const r = await ctx.http({
        method: "GET",
        path: gcsBucket(ctx),
        query: { prefix: "open/gcsu/list/" },
        headers: OWNER,
      });
      return {
        status: r.status,
        kind: r.body?.kind,
        names: (r.body?.items ?? []).map((i) => i.name),
        prefixes: r.body?.prefixes ?? null,
      };
    });
    await ctx.step("list-empty", () =>
      ctx.http({
        method: "GET",
        path: gcsBucket(ctx),
        query: { prefix: "open/gcsu/nothing/" },
        headers: OWNER,
      }),
    );
    await ctx.step("list-paged", async () => {
      const pages = [];
      let pageToken;
      for (let i = 0; i < 10; i += 1) {
        const query = { prefix: "open/gcsu/list/", delimiter: "/", maxResults: "1" };
        if (pageToken) query.pageToken = pageToken;
        const r = await ctx.http({ method: "GET", path: gcsBucket(ctx), query, headers: OWNER });
        pages.push({
          status: r.status,
          names: (r.body?.items ?? []).map((i) => i.name),
          prefixes: r.body?.prefixes ?? null,
          hasNext: typeof r.body?.nextPageToken === "string",
        });
        pageToken = r.body?.nextPageToken;
        if (!pageToken) break;
      }
      return pages;
    });
    await ctx.step("list-short-route", async () => {
      const r = await ctx.http({
        method: "GET",
        path: `/b/${ctx.bucket}/o`,
        query: { prefix: "open/gcsu/list/dir/" },
        headers: OWNER,
      });
      return { status: r.status, names: (r.body?.items ?? []).map((i) => i.name) };
    });
    await ctx.step("list-without-credentials", () =>
      ctx.http({ method: "GET", path: gcsBucket(ctx), query: { prefix: "closed/" } }),
    );
    await ctx.step("delete", () =>
      ctx.http({ method: "DELETE", path: gcsObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("delete-again", () =>
      ctx.http({ method: "DELETE", path: gcsObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("get-missing-metadata", () =>
      ctx.http({ method: "GET", path: gcsObject(ctx, name), headers: OWNER }),
    );
    await ctx.step("get-missing-media", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
    await ctx.step("delete-short-route-missing", () =>
      ctx.http({ method: "DELETE", path: `/b/${ctx.bucket}/o/${ctx.enc(name)}`, headers: OWNER }),
    );
  },
};

const gcsCopyRewrite = {
  id: "gcs-copy-rewrite",
  area: "json-api",
  async run(ctx) {
    const src = "open/copy/src.txt";
    await ctx.step("source", async () => {
      const part = ctx.multipart(
        {
          name: src,
          contentType: "text/plain",
          cacheControl: "max-age=3",
          contentDisposition: "inline",
          metadata: { k: "v", firebaseStorageDownloadTokens: "src-token" },
        },
        "text/plain",
        Buffer.from("copy me"),
      );
      return ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "multipart" },
        headers: { ...OWNER, "content-type": part.contentType },
        body: part.body,
      });
    });
    const copyPath = (verb, dst) =>
      `/storage/v1/b/${ctx.bucket}/o/${ctx.enc(src)}/${verb}/b/${ctx.bucket}/o/${ctx.enc(dst)}`;
    await ctx.step("copy-to", () =>
      ctx.http({
        method: "POST",
        path: copyPath("copyTo", "open/copy/dst-copy.txt"),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("rewrite-to", () =>
      ctx.http({
        method: "POST",
        path: copyPath("rewriteTo", "open/copy/dst-rewrite.txt"),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("rewrite-with-metadata-override", () =>
      ctx.http({
        method: "POST",
        path: copyPath("rewriteTo", "open/copy/dst-override.txt"),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ contentType: "text/markdown", metadata: { only: "this" } })),
      }),
    );
    await ctx.step("copy-into-closed-path", () =>
      ctx.http({
        method: "POST",
        path: copyPath("copyTo", "closed/copy/dst.txt"),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("copy-without-credentials", () =>
      ctx.http({
        method: "POST",
        path: copyPath("copyTo", "open/copy/anon.txt"),
        headers: { "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("copy-missing-source", () =>
      ctx.http({
        method: "POST",
        path: `/storage/v1/b/${ctx.bucket}/o/${ctx.enc("open/copy/missing.txt")}/copyTo/b/${ctx.bucket}/o/${ctx.enc("open/copy/x.txt")}`,
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("copy-short-route", () =>
      ctx.http({
        method: "POST",
        path: `/b/${ctx.bucket}/o/${ctx.enc(src)}/copyTo/b/${ctx.bucket}/o/${ctx.enc("open/copy/short.txt")}`,
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("copy-onto-itself", () =>
      ctx.http({
        method: "POST",
        path: copyPath("copyTo", src),
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      }),
    );
    await ctx.step("copied-bytes", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, "open/copy/dst-copy.txt"),
        query: { alt: "media" },
        headers: OWNER,
      }),
    );
  },
};

const gcsPreconditions = {
  id: "gcs-preconditions",
  area: "json-api",
  async run(ctx) {
    const name = "open/pre/doc.txt";
    const created = await gcsMedia(ctx, name, text("v1"));
    const generation = String(created.body?.generation ?? "");
    await ctx.step("insert-if-generation-match-zero-on-existing", () =>
      gcsMedia(ctx, name, text("v2"), "text/plain", { ifGenerationMatch: "0" }),
    );
    await ctx.step("insert-if-generation-match-current", () =>
      gcsMedia(ctx, name, text("v3"), "text/plain", { ifGenerationMatch: generation }),
    );
    await ctx.step("patch-if-metageneration-mismatch", () =>
      ctx.http({
        method: "PATCH",
        path: gcsObject(ctx, name),
        query: { ifMetagenerationMatch: "999" },
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ cacheControl: "x" })),
      }),
    );
    await ctx.step("get-if-generation-not-match-current", async () => {
      const meta = await ctx.http({ method: "GET", path: gcsObject(ctx, name), headers: OWNER });
      return ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { ifGenerationNotMatch: String(meta.body?.generation ?? "") },
        headers: OWNER,
      });
    });
    await ctx.step("delete-if-generation-mismatch", () =>
      ctx.http({
        method: "DELETE",
        path: gcsObject(ctx, name),
        query: { ifGenerationMatch: "1" },
        headers: OWNER,
      }),
    );
    await ctx.step("malformed-precondition", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { ifGenerationMatch: "abc" },
        headers: OWNER,
      }),
    );
    await ctx.step("get-selected-generation-missing", () =>
      ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { generation: "12345" },
        headers: OWNER,
      }),
    );
    await ctx.step("object-still-present", async () => {
      const r = await ctx.http({
        method: "GET",
        path: gcsObject(ctx, name),
        query: { alt: "media" },
        headers: OWNER,
      });
      return { status: r.status, body: r.body };
    });
  },
};

const gcsChecksums = {
  id: "gcs-checksums",
  area: "json-api",
  async run(ctx) {
    const md5Ok = Buffer.from("5d41402abc4b2a76b9719d911017c592", "hex").toString("base64"); // md5("hello")
    await ctx.step("matching-md5", () =>
      ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "media", name: "open/sum/ok.txt" },
        headers: { ...OWNER, "content-type": "text/plain", "x-goog-hash": `md5=${md5Ok}` },
        body: text("hello"),
      }),
    );
    await ctx.step("mismatching-md5", () =>
      ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "media", name: "open/sum/bad.txt" },
        headers: { ...OWNER, "content-type": "text/plain", "x-goog-hash": `md5=${md5Ok}` },
        body: text("hellp"),
      }),
    );
    await ctx.step("mismatching-md5-not-published", () =>
      ctx.http({ method: "GET", path: gcsObject(ctx, "open/sum/bad.txt"), headers: OWNER }),
    );
    await ctx.step("mismatching-crc32c-in-metadata", async () => {
      const part = ctx.multipart(
        { name: "open/sum/crc.txt", crc32c: "AAAAAA==" },
        "text/plain",
        Buffer.from("hello"),
      );
      return ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "multipart" },
        headers: { ...OWNER, "content-type": part.contentType },
        body: part.body,
      });
    });
    await ctx.step("reported-hashes", async () => {
      const r = await ctx.http({
        method: "GET",
        path: gcsObject(ctx, "open/sum/ok.txt"),
        headers: OWNER,
      });
      return { md5Hash: r.body?.md5Hash ?? null, crc32c: r.body?.crc32c ?? null };
    });
  },
};

const gcsUnsupported = {
  id: "gcs-unsupported-surface",
  area: "json-api",
  async run(ctx) {
    await gcsMedia(ctx, "open/unsupported/o.txt", text("o"));
    const o = gcsObject(ctx, "open/unsupported/o.txt");
    await ctx.step("compose", () =>
      ctx.http({
        method: "POST",
        path: `${gcsObject(ctx, "open/unsupported/composed.txt")}/compose`,
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ sourceObjects: [{ name: "open/unsupported/o.txt" }] })),
      }),
    );
    await ctx.step("acl-list", () => ctx.http({ method: "GET", path: `${o}/acl`, headers: OWNER }));
    await ctx.step("acl-insert", () =>
      ctx.http({
        method: "POST",
        path: `${o}/acl`,
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ entity: "allUsers", role: "READER" })),
      }),
    );
    await ctx.step("bucket-get", () =>
      ctx.http({ method: "GET", path: `/storage/v1/b/${ctx.bucket}`, headers: OWNER }),
    );
    await ctx.step("bucket-list", async () => {
      const r = await ctx.http({
        method: "GET",
        path: "/storage/v1/b",
        query: { project: ctx.project },
        headers: OWNER,
      });
      return {
        status: r.status,
        kind: r.body?.kind ?? null,
        names: (r.body?.items ?? []).map((b) => b.name),
        keys: r.body?.items?.[0] ? Object.keys(r.body.items[0]).toSorted() : null,
        body: r.status >= 400 ? r.body : undefined,
      };
    });
    await ctx.step("bucket-list-short-route", async () => {
      const r = await ctx.http({ method: "GET", path: "/b", headers: OWNER });
      return {
        status: r.status,
        kind: r.body?.kind ?? null,
        names: (r.body?.items ?? []).map((b) => b.name),
      };
    });
    await ctx.step("bucket-insert", () =>
      ctx.http({
        method: "POST",
        path: "/storage/v1/b",
        query: { project: ctx.project },
        headers: { ...OWNER, "content-type": "application/json" },
        body: text(JSON.stringify({ name: "another-bucket" })),
      }),
    );
    await ctx.step("bucket-iam", () =>
      ctx.http({ method: "GET", path: `/storage/v1/b/${ctx.bucket}/iam`, headers: OWNER }),
    );
    await ctx.step("notifications", () =>
      ctx.http({
        method: "GET",
        path: `/storage/v1/b/${ctx.bucket}/notificationConfigs`,
        headers: OWNER,
      }),
    );
    await ctx.step("unknown-object-verb", () =>
      ctx.http({ method: "POST", path: `${o}/frobnicate`, headers: OWNER }),
    );
    await ctx.step("signed-url-style-query", () =>
      ctx.http({
        method: "GET",
        path: `/${ctx.bucket}/open/unsupported/o.txt`,
        query: { "X-Goog-Algorithm": "GOOG4-RSA-SHA256", "X-Goog-Signature": "00" },
      }),
    );
  },
};

// ------------------------------------------------------------------------------------------
// Functions triggers
// ------------------------------------------------------------------------------------------

const triggers = {
  id: "triggers",
  area: "triggers",
  async run(ctx) {
    ctx.drainEvents();
    const name = "open/trig/doc.txt";
    await ctx.step("finalize-on-firebase-media-upload", async () => {
      const r = await fbMedia(ctx, name, text("trigger me"));
      return { status: r.status, events: await ctx.events(2, 20_000) };
    });
    await ctx.step("metadata-update-on-patch", async () => {
      const r = await ctx.http({
        method: "PATCH",
        path: fbObject(ctx, name),
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text(JSON.stringify({ cacheControl: "max-age=7", metadata: { touched: "yes" } })),
      });
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
    await ctx.step("finalize-on-overwrite", async () => {
      const r = await fbMedia(ctx, name, text("trigger me again"));
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
    await ctx.step("finalize-on-json-api-copy", async () => {
      const r = await ctx.http({
        method: "POST",
        path: `/storage/v1/b/${ctx.bucket}/o/${ctx.enc(name)}/copyTo/b/${ctx.bucket}/o/${ctx.enc("open/trig/copy.txt")}`,
        headers: { ...OWNER, "content-type": "application/json" },
        body: text("{}"),
      });
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
    await ctx.step("delete", async () => {
      const r = await ctx.http({ method: "DELETE", path: fbObject(ctx, name), headers: OWNER });
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
    await ctx.step("no-event-on-denied-upload", async () => {
      const r = await ctx.http({
        method: "POST",
        path: fbBucket(ctx),
        query: { name: "closed/trig/denied.txt" },
        headers: { "content-type": "text/plain" },
        body: text("denied"),
      });
      return { status: r.status, events: await ctx.events(1, 2_000) };
    });
    await ctx.step("no-event-on-missing-delete", async () => {
      const r = await ctx.http({
        method: "DELETE",
        path: fbObject(ctx, "open/trig/missing.txt"),
        headers: OWNER,
      });
      return { status: r.status, events: await ctx.events(1, 2_000) };
    });
    await ctx.step("metadata-update-on-token-creation", async () => {
      const r = await ctx.http({
        method: "POST",
        path: fbObject(ctx, "open/trig/copy.txt"),
        query: { create_token: "true" },
        headers: OWNER,
      });
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
    await ctx.step("json-api-resumable-finalize", async () => {
      const start = await ctx.http({
        method: "POST",
        path: gcsUpload(ctx),
        query: { uploadType: "resumable", name: "open/trig/resumable.bin" },
        headers: { ...OWNER, "content-type": "application/json; charset=utf-8" },
        body: text("{}"),
      });
      const id = new URL(start.headers.location ?? "", "http://x").searchParams.get("upload_id");
      if (id) ctx.redact(id, "<upload-id>");
      const r = await ctx.http({
        method: "PUT",
        path: start.headers.location,
        headers: { ...OWNER, "content-type": "application/octet-stream" },
        body: Buffer.alloc(3, 1),
      });
      return { status: r.status, events: await ctx.events(2, 10_000) };
    });
  },
};

export const PROGRAMS = [
  fbMediaUpload,
  fbMultipartUpload,
  fbResumable,
  fbDownloadTokens,
  fbMetadata,
  fbDelete,
  fbErrors,
  fbList,
  fbOverwrite,
  rulesRequestModel,
  gcsInsertAndGet,
  gcsResumable,
  gcsUpdateAndList,
  gcsCopyRewrite,
  gcsPreconditions,
  gcsChecksums,
  gcsUnsupported,
  triggers,
];
