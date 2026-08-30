// Storage rows: the Admin JSON API dialect, the Firebase protocol used by the web SDK,
// object metadata and listing, and the shape of a Rules denial on each dialect.

import {
  deleteObject,
  getBytes,
  getDownloadURL,
  getMetadata,
  listAll,
  ref,
  updateMetadata,
  uploadBytes,
  uploadBytesResumable,
} from "firebase/storage";

import { VARIANTS } from "../config.mjs";
import { sortStrings } from "../normalize.mjs";

const adminObjects = {
  id: "storage/admin-upload-download-metadata",
  product: "storage",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin"],
  title: "Admin uploads, downloads, metadata and listing over the JSON API dialect",
  async run(ctx) {
    const bucket = ctx.shared.adminBucket();

    await ctx.step("save-and-download", async () => {
      const file = bucket.file("conf_public/hello.txt");
      await file.save(Buffer.from("hello conformance"), {
        contentType: "text/plain",
        metadata: { metadata: { origin: "conformance" } },
        resumable: false,
      });
      const [buffer] = await file.download();
      return { text: buffer.toString("utf8") };
    });

    await ctx.step("metadata-shape", async () => {
      const [meta] = await bucket.file("conf_public/hello.txt").getMetadata();
      return {
        keys: sortStrings(Object.keys(meta)),
        name: meta.name,
        bucket: meta.bucket,
        contentType: meta.contentType,
        size: String(meta.size),
        custom: meta.metadata,
      };
    });

    await ctx.step("resumable-save", async () => {
      const file = bucket.file("conf_public/big.bin");
      await file.save(Buffer.alloc(300_000, 7), {
        contentType: "application/octet-stream",
        resumable: true,
      });
      const [meta] = await file.getMetadata();
      return { size: String(meta.size), contentType: meta.contentType };
    });

    await ctx.step("exists-list-copy-delete", async () => {
      const [exists] = await bucket.file("conf_public/hello.txt").exists();
      const [files] = await bucket.getFiles({ prefix: "conf_public/" });
      await bucket.file("conf_public/hello.txt").copy(bucket.file("conf_public/copy.txt"));
      await bucket.file("conf_public/copy.txt").delete();
      const [gone] = await bucket.file("conf_public/copy.txt").exists();
      return { exists, names: sortStrings(files.map((f) => f.name)), gone };
    });

    await ctx.step("download-a-missing-object", async () => {
      await bucket.file("conf_public/definitely-missing.txt").download();
      return "downloaded";
    });

    // The Admin JSON API dialect bypasses Security Rules on both sides.
    await ctx.step("admin-writes-into-a-rules-closed-path", async () => {
      const file = bucket.file("conf_closed/admin.txt");
      await file.save(Buffer.from("admin"), { contentType: "text/plain", resumable: false });
      const [buffer] = await file.download();
      return { text: buffer.toString("utf8") };
    });
  },
};

const clientObjects = {
  id: "storage/client-protocol-and-rules",
  product: "storage",
  variant: VARIANTS.baseline,
  sdks: ["firebase/storage"],
  title: "The Firebase Storage protocol: uploads, resumable uploads, listing and Rules denials",
  async run(ctx) {
    const storage = ctx.shared.webStorage();

    await ctx.step("upload-bytes-and-read-back", async () => {
      const target = ref(storage, "conf_public/client/notes.txt");
      await uploadBytes(target, new TextEncoder().encode("konnichiwa"), {
        contentType: "text/plain",
        customMetadata: { mood: "good" },
      });
      const bytes = await getBytes(target);
      const meta = await getMetadata(target);
      return {
        text: new TextDecoder().decode(bytes),
        name: meta.name,
        fullPath: meta.fullPath,
        bucket: meta.bucket,
        contentType: meta.contentType,
        size: meta.size,
        custom: meta.customMetadata,
      };
    });

    await ctx.step("update-metadata", async () => {
      const target = ref(storage, "conf_public/client/notes.txt");
      await updateMetadata(target, {
        cacheControl: "private, max-age=0",
        customMetadata: { mood: "great" },
      });
      const meta = await getMetadata(target);
      return { cacheControl: meta.cacheControl, custom: meta.customMetadata };
    });

    await ctx.step("resumable-upload", async () => {
      const task = uploadBytesResumable(
        ref(storage, "conf_public/client/big.bin"),
        new Uint8Array(600_000),
        { contentType: "application/octet-stream" },
      );
      const snapshot = await task;
      return { totalBytes: snapshot.totalBytes, state: snapshot.state };
    });

    await ctx.step("list-all", async () => {
      const listing = await listAll(ref(storage, "conf_public"));
      return {
        prefixes: sortStrings(listing.prefixes.map((p) => p.fullPath)),
        items: sortStrings(listing.items.map((i) => i.fullPath)),
      };
    });

    await ctx.step("download-url-serves-the-object", async () => {
      const url = await getDownloadURL(ref(storage, "conf_public/client/notes.txt"));
      const response = await fetch(url);
      return { status: response.status, text: await response.text() };
    });

    await ctx.step("upload-into-a-rules-closed-path-is-denied", async () => {
      await uploadBytes(ref(storage, "conf_closed/client.txt"), new TextEncoder().encode("x"));
      return "uploaded";
    });

    await ctx.step("read-a-rules-closed-object-is-denied", async () => {
      await getBytes(ref(storage, "conf_closed/admin.txt"));
      return "read";
    });

    await ctx.step("get-metadata-of-a-missing-object", async () => {
      await getMetadata(ref(storage, "conf_public/definitely-missing.txt"));
      return "found";
    });

    await ctx.step("delete-and-then-read", async () => {
      await deleteObject(ref(storage, "conf_public/client/big.bin"));
      await getMetadata(ref(storage, "conf_public/client/big.bin"));
      return "still there";
    });
  },
};

export const scenarios = [adminObjects, clientObjects];
