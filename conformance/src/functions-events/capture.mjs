import assert from "node:assert/strict";
import { chmod, mkdir, open, unlink } from "node:fs/promises";
import net from "node:net";
import { join } from "node:path";

const defaultLimits = {
  maxFrameBytes: 1024 * 1024,
  maxFrames: 10_000,
  maxRunBytes: 16 * 1024 * 1024,
};
export const publicHandlerNames = new Set([
  "fsCreatedV1",
  "fsCreatedV2",
  "fsUpdatedV1",
  "fsUpdatedV2",
  "fsDeletedV1",
  "fsDeletedV2",
  "fsWrittenV1",
  "fsWrittenV2",
  "fsWrittenWithAuthContextV2",
  "fsRetryV2",
  "storageFinalizedV1",
  "storageFinalizedV2",
  "storageDeletedV1",
  "storageDeletedV2",
  "storageMetadataUpdatedV1",
  "storageMetadataUpdatedV2",
  "storageArchivedV1",
  "storageArchivedV2",
  "authCreatedV1",
  "authDeletedV1",
  "pubsubPublishedV1",
  "pubsubPublishedV2",
]);
export const publicEventTypes = new Set([
  "providers/cloud.firestore/eventTypes/document.create",
  "providers/cloud.firestore/eventTypes/document.update",
  "providers/cloud.firestore/eventTypes/document.delete",
  "providers/cloud.firestore/eventTypes/document.write",
  "google.cloud.firestore.document.v1.created",
  "google.cloud.firestore.document.v1.updated",
  "google.cloud.firestore.document.v1.deleted",
  "google.cloud.firestore.document.v1.written",
  "google.cloud.firestore.document.v1.written.withAuthContext",
  "google.storage.object.finalize",
  "google.storage.object.delete",
  "google.storage.object.metadataUpdate",
  "google.storage.object.archive",
  "google.cloud.storage.object.v1.finalized",
  "google.cloud.storage.object.v1.deleted",
  "google.cloud.storage.object.v1.metadataUpdated",
  "google.cloud.storage.object.v1.archived",
  "providers/firebase.auth/eventTypes/user.create",
  "providers/firebase.auth/eventTypes/user.delete",
  "google.pubsub.topic.publish",
  "google.cloud.pubsub.topic.v1.messagePublished",
]);
const publicSources = new Set(["firestore", "storage", "auth", "pubsub"]);

function present(value) {
  return typeof value === "string" && value.length > 0 ? "<present>" : "<absent>";
}

/** A deliberately narrow public view; raw event values remain in the private capture file. */
export function exportPublicFrames(records) {
  return records.map(({ sequence, frame }) => {
    const event = frame.event ?? {};
    const context = event.context ?? {};
    const eventType = event.type ?? context.eventType ?? null;
    return {
      sequence: Number.isSafeInteger(sequence) && sequence >= 0 ? sequence : null,
      handler: publicHandlerNames.has(frame.handler) ? frame.handler : "<invalid>",
      generation: [1, 2].includes(frame.generation) ? frame.generation : null,
      source: publicSources.has(frame.source) ? frame.source : "<invalid>",
      eventType: publicEventTypes.has(eventType) ? eventType : "<invalid>",
      eventId: present(event.id ?? context.eventId),
      eventTime: present(event.time ?? context.timestamp),
      resource:
        event.source != null || event.subject != null || context.resource != null
          ? "<private>"
          : "<absent>",
      payload: event.data != null ? "<private>" : "<absent>",
    };
  });
}

export class CaptureSink {
  static async open(options) {
    const sink = new CaptureSink(options);
    await sink.#open();
    return sink;
  }

  constructor({ privateDir, allowedHandlers, ...limits }) {
    assert.ok(typeof privateDir === "string" && privateDir.length > 0);
    assert.ok(Array.isArray(allowedHandlers) && allowedHandlers.length > 0);
    this.privateDir = privateDir;
    this.socketPath = join(privateDir, "events.sock");
    this.rawPath = join(privateDir, "raw.jsonl");
    this.allowedHandlers = new Set(allowedHandlers);
    this.limits = { ...defaultLimits, ...limits };
    for (const count of Object.values(this.limits)) {
      assert.ok(Number.isSafeInteger(count) && count > 0);
    }
    this.frames = [];
    this.issues = [];
    this.lossCount = 0;
    this.storedBytes = 0;
    this.pending = Promise.resolve();
    this.sockets = new Set();
    this.closed = false;
  }

  async #open() {
    await mkdir(this.privateDir, { recursive: true, mode: 0o700 });
    await chmod(this.privateDir, 0o700);
    this.file = await open(this.rawPath, "wx", 0o600);
    await this.file.chmod(0o600);
    this.server = net.createServer((socket) => this.#accept(socket));
    try {
      await new Promise((resolve, reject) => {
        this.server.once("error", reject);
        this.server.listen(this.socketPath, () => {
          this.server.off("error", reject);
          resolve();
        });
      });
      await chmod(this.socketPath, 0o600);
    } catch (error) {
      await this.file.close();
      throw error;
    }
  }

  #issue(reason, loss = true) {
    this.issues.push({ reason, receivedAt: new Date().toISOString() });
    if (loss) this.lossCount += 1;
  }

  #accept(socket) {
    this.sockets.add(socket);
    let chunks = [];
    let size = 0;
    let completed = false;
    const reject = (reason) => {
      if (completed) return;
      completed = true;
      this.#issue(reason);
      socket.end('{"ok":false}\n');
    };
    socket.on("data", (chunk) => {
      if (completed) {
        this.#issue("extra-bytes-after-frame");
        return;
      }
      size += chunk.length;
      if (size > this.limits.maxFrameBytes + 1) return reject("frame-size-limit");
      chunks.push(chunk);
      const data = Buffer.concat(chunks, size);
      const newline = data.indexOf(10);
      if (newline < 0) return;
      if (newline > this.limits.maxFrameBytes || newline !== data.length - 1) {
        return reject("invalid-frame-boundary");
      }
      completed = true;
      const rawJson = data.subarray(0, newline).toString("utf8");
      chunks = [];
      const processed = this.pending.then(() => this.#record(rawJson));
      this.pending = processed.then(
        () => undefined,
        () => undefined,
      );
      processed.then(
        (ok) => socket.end(JSON.stringify({ ok }) + "\n"),
        () => {
          this.#issue("capture-write-failure");
          socket.end('{"ok":false}\n');
        },
      );
    });
    socket.on("end", () => {
      if (!completed && !this.closed) this.#issue("connection-ended-before-frame");
    });
    socket.on("close", () => this.sockets.delete(socket));
    socket.on("error", () => {
      if (!completed && !this.closed) this.#issue("connection-error");
    });
  }

  async #record(rawJson) {
    let frame;
    try {
      frame = JSON.parse(rawJson);
    } catch {
      this.#issue("malformed-json");
      return false;
    }
    if (!frame || typeof frame !== "object" || Array.isArray(frame)) {
      this.#issue("invalid-frame");
      return false;
    }
    if (this.frames.length >= this.limits.maxFrames) {
      this.#issue("frame-count-limit");
      return false;
    }
    const sequence = this.frames.length + 1;
    const receivedAt = new Date().toISOString();
    const stored = `${JSON.stringify({ sequence, receivedAt, rawJson, frame })}\n`;
    const bytes = Buffer.byteLength(stored);
    if (this.storedBytes + bytes > this.limits.maxRunBytes) {
      this.#issue("run-byte-limit");
      return false;
    }
    await this.file.writeFile(stored);
    await this.file.sync();
    this.storedBytes += bytes;
    this.frames.push({ sequence, receivedAt, rawJson, frame });
    if (
      !this.allowedHandlers.has(frame.handler) ||
      ![1, 2].includes(frame.generation) ||
      !["firestore", "storage", "auth", "pubsub"].includes(frame.source) ||
      !frame.event ||
      typeof frame.event !== "object" ||
      Array.isArray(frame.event)
    ) {
      this.#issue("unknown-or-invalid-frame", false);
      return false;
    }
    return true;
  }

  since(cursor) {
    assert.ok(Number.isSafeInteger(cursor) && cursor >= 0 && cursor <= this.frames.length);
    return this.frames.slice(cursor);
  }

  async barrier() {
    await this.pending;
    return {
      cursor: this.frames.length,
      frameCount: this.frames.length,
      lossCount: this.lossCount,
      issueCount: this.issues.length,
    };
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    for (const socket of this.sockets) socket.destroy();
    await new Promise((resolve) => this.server.close(resolve));
    await this.pending;
    await this.file.close();
    await unlink(this.socketPath).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}
