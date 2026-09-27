import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { verifyNativeFirestoreV2Frame } from "./functions-events/native_firestore.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const documentName = "projects/project-a/databases/(default)/documents/tasks/subject";
const resource = "projects/project-a/databases/(default)/documents/tasks";
const time = "2026-09-27T00:00:00.123Z";
const type = (kind) => `google.cloud.firestore.document.v1.${kind}`;
const encode = (value) => {
  const bytes = Buffer.from(JSON.stringify(value));
  return { base64: bytes.toString("base64"), sha256: hash(bytes) };
};

function fixture(kind = "created") {
  const native = {
    specversion: "1.0",
    id: "native-event-1",
    source: documentName,
    subject: "documents/tasks/subject",
    type: type(kind),
    time,
    datacontenttype: "application/json",
    project: "project-a",
    database: "(default)",
    document: "tasks/subject",
    data: {},
  };
  const operation = { resource, entity: "subject" };
  const row = { source: "firestore", generation: 2, handlerEvent: kind };
  const frame = {
    source: "firestore",
    generation: 2,
    handlerEvent: kind,
    resource,
    entity: "subject",
    eventSource: documentName,
    eventId: native.id,
    eventTime: time,
    raw: encode(native),
  };
  return { native, operation, row, frame };
}
const check = (value) => verifyNativeFirestoreV2Frame(value.frame, value.operation, value.row);
const changeNative = (value, change) => {
  change(value.native);
  value.frame.raw = encode(value.native);
};

test("derives a Firestore v2 document identity from native bytes without an authority claim", () => {
  const result = check(fixture());
  assert.equal(result.documentName, documentName);
  assert.equal(result.eventId, "native-event-1");
  assert.equal(result.eventTime, time);
  assert.equal(result.eventSource, documentName);
  assert.equal(result.nativeFrameConsistent, true);
  assert.equal(result.captureProvenanceVerified, false);
  assert.equal(result.compatibilityEstablished, false);
  assert.equal(result.sendAuthorized, false);
});

test("accepts the service URI source only when project and database agree", () => {
  const value = fixture();
  const service = "//firestore.googleapis.com/projects/project-a/databases/(default)";
  changeNative(value, (native) => {
    native.source = service;
  });
  value.frame.eventSource = service;
  assert.equal(check(value).eventSource, service);
});

test("requires the reported Firestore type for create, update, delete and written handlers", () => {
  for (const kind of ["created", "updated", "deleted"])
    assert.equal(check(fixture(kind)).nativeFrameConsistent, true);
  const written = fixture("written");
  assert.equal(check(written).nativeFrameConsistent, true);
  changeNative(written, (native) => {
    native.type = type("created");
  });
  assert.throws(() => check(written));
});

test("requires the Auth context event suffix and native auth type", () => {
  const value = fixture("written");
  value.row.handlerEvent = "written-with-auth-context";
  value.frame.handlerEvent = "written-with-auth-context";
  changeNative(value, (native) => {
    native.type += ".withAuthContext";
    native.authtype = "USER";
  });
  assert.equal(check(value).nativeFrameConsistent, true);
  changeNative(value, (native) => {
    native.type = `${type("created")}.withAuthContext`;
  });
  assert.throws(() => check(value));
  changeNative(value, (native) => {
    native.type = `${type("written")}.withAuthContext`;
  });
  changeNative(value, (native) => {
    delete native.authtype;
  });
  assert.throws(() => check(value));
});

test("rejects relabeled source, id, time and operation identity", () => {
  const changes = [
    (v) => {
      v.frame.eventSource = "other";
    },
    (v) => {
      v.frame.eventId = "other";
    },
    (v) => {
      v.frame.eventTime = "2026-09-28T00:00:00Z";
    },
    (v) => {
      v.frame.resource = "projects/project-a/databases/(default)/documents/other";
    },
    (v) => {
      v.frame.entity = "other";
    },
    (v) => {
      v.frame.handlerEvent = "deleted";
    },
    (v) => {
      v.frame.generation = 1;
    },
    (v) => {
      v.row.generation = 1;
    },
  ];
  for (const change of changes) {
    const value = fixture();
    change(value);
    assert.throws(() => check(value));
  }
});

test("rejects a self-consistent native event outside the owned operation document", () => {
  const value = fixture();
  const other = "projects/project-a/databases/(default)/documents/tasks/other";
  changeNative(value, (native) => {
    native.document = "tasks/other";
    native.subject = "documents/tasks/other";
    native.source = other;
  });
  value.frame.eventSource = other;
  assert.throws(() => check(value));
});

test("rejects a self-consistent event source for another project", () => {
  const value = fixture();
  const other = "//firestore.googleapis.com/projects/other/databases/(default)";
  changeNative(value, (native) => {
    native.source = other;
  });
  value.frame.eventSource = other;
  assert.throws(() => check(value));
});

test("rejects a self-consistent but invalid event time", () => {
  const value = fixture();
  changeNative(value, (native) => {
    native.time = "2026-02-30T00:00:00Z";
  });
  value.frame.eventTime = value.native.time;
  assert.throws(() => check(value));
});

test("rejects native project, database, document, subject and source conflicts", () => {
  const changes = [
    (native) => {
      native.project = "other";
    },
    (native) => {
      native.database = "other";
    },
    (native) => {
      native.document = "other/subject";
    },
    (native) => {
      native.subject = "documents/tasks/other";
    },
    (native) => {
      native.source = "projects/other/databases/(default)/documents/tasks/subject";
    },
    (native) => {
      native.time = "yesterday";
    },
    (native) => {
      native.time = "2026-02-30T00:00:00Z";
    },
    (native) => {
      native.project = "project-a/other";
    },
  ];
  for (const change of changes) {
    const value = fixture();
    changeNative(value, change);
    assert.throws(() => check(value));
  }
});

test("rejects malformed or altered raw bytes", () => {
  const invalid = [
    { base64: "", sha256: hash("") },
    { base64: Buffer.from("{").toString("base64"), sha256: hash("{") },
    { base64: Buffer.from([0xff]).toString("base64"), sha256: hash(Buffer.from([0xff])) },
  ];
  for (const raw of invalid) {
    const value = fixture();
    value.frame.raw = raw;
    assert.throws(() => check(value));
  }
  const changed = fixture();
  changed.frame.raw.sha256 = "0".repeat(64);
  assert.throws(() => check(changed));
  const duplicate = fixture();
  const raw = Buffer.from(
    JSON.stringify(duplicate.native).replace(
      '"id":"native-event-1",',
      '"id":"hidden", "id":"native-event-1",',
    ),
  );
  duplicate.frame.raw = { base64: raw.toString("base64"), sha256: hash(raw) };
  assert.throws(() => check(duplicate));
});
