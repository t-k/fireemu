// Production answers recorded by earlier stages, kept byte for byte as fixtures: the stage 2d probe (2026-09-29T23:27Z), stage 2c-pre (2026-09-29T14:19Z), stage 3 v7 recording 1 (2026-09-30T00:16Z), stage 2e (02:27Z) and stage 2f (03:28Z).
// They hold no secret: names of the sandbox project, its bucket and its rulesets, times, and Google error text. The simulator and the classifier tests use
// these instead of answers written to fit the classifiers.
export const PRODUCTION = Object.freeze({
  // GET rulesets?pageSize=100 on the query project (stage 2d probe, 2026-09-29T23:27Z)
  rulesetList: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "rulesets": [\n    {\n      "name": "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8",\n      "createTime": "2026-09-25T11:08:54.358767Z",\n      "metadata": {\n        "services": [\n          "firebase.storage"\n        ]\n      }\n    },\n    {\n      "name": "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1",\n      "createTime": "2026-09-23T23:02:05.839536Z",\n      "metadata": {\n        "services": [\n          "cloud.firestore"\n        ]\n      }\n    }\n  ]\n}\n',
  }),
  // GET metadata of an absent object (stage 2d probe)
  objectMetadataAbsent: Object.freeze({
    status: 404,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 404,\n    "message": "No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin",\n    "errors": [\n      {\n        "message": "No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin",\n        "domain": "global",\n        "reason": "notFound"\n      }\n    ]\n  }\n}\n',
  }),
  // GET media (alt=media) of an absent object (stage 2d probe)
  objectMediaAbsent: Object.freeze({
    status: 404,
    contentType: "text/html; charset=UTF-8",
    body: "No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin",
  }),
  // POST :test with a valid storage source (stage 2d probe)
  rulesTestValid: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: "{}\n",
  }),
  // POST :test with an invalid storage source (stage 2d probe)
  rulesTestInvalid: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "issues": [\n    {\n      "sourcePosition": {\n        "fileName": "storage.rules",\n        "line": 5,\n        "column": 21,\n        "currentOffset": 115,\n        "endOffset": 115\n      },\n      "description": "Missing conditional expression after \'if\'.",\n      "severity": "ERROR"\n    }\n  ]\n}\n',
  }),
  // GET of an absent Firestore document (stage 2d probe)
  documentAbsent: Object.freeze({
    status: 404,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 404,\n    "message": "Document \\"projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document\\" not found.",\n    "status": "NOT_FOUND"\n  }\n}\n',
  }),
  // GET of the bucket release after its deletion (stage 2c-pre, 2026-09-29T14:19Z)
  releaseAbsent: Object.freeze({
    status: 404,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 404,\n    "message": "Requested entity was not found.",\n    "status": "NOT_FOUND"\n  }\n}\n',
  }),
  // GET of the bucketless release (stage 2c-pre)
  releaseBucketlessAbsent: Object.freeze({
    status: 404,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 404,\n    "message": "Requested entity was not found.",\n    "status": "NOT_FOUND"\n  }\n}\n',
  }),
  // GET of the bucket release before its deletion (stage 2c-pre)
  releasePresent: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "name": "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app",\n  "rulesetName": "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8",\n  "createTime": "2026-09-25T11:09:23.326708Z",\n  "updateTime": "2026-09-25T11:09:23.326708Z"\n}\n',
  }),
  // stage 3 v7 recording 1 (2026-09-30T00:16:49Z), recovery/settle/restore/3/0: a v0 read of a bucket with no release, after the removal reached the serving plane
  noRelease: Object.freeze({
    status: 400,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 400,\n    "message": "Your bucket has not been set up properly for Firebase Storage. Please visit \'https://console.firebase.google.com/project/fireemu-oracle-query/storage/rules\' to set up security rules."\n  }\n}',
  }),
  // stage 3 v7 recording 1, recovery/settle/restore/1/0: a v0 read denied by the rules the serving plane still held
  settleDenied: Object.freeze({
    status: 403,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 403,\n    "message": "Permission denied."\n  }\n}',
  }),
  // stage 2e (2026-09-30T02:27:58Z), cleanup/ruleset/0/delete: DELETE of a ruleset
  rulesetDeleted: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: "{}\n",
  }),
  // stage 2e, cleanup/account/0/delete: POST accounts:delete
  accountDeleted: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "kind": "identitytoolkit#DeleteAccountResponse"\n}\n',
  }),
  // stage 2e, verify/accounts/lookup: accounts:lookup of deleted accounts
  accountsNone: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "kind": "identitytoolkit#GetAccountInfoResponse"\n}\n',
  }),
  // stage 2e, verify/objects/list: the object list of an empty prefix
  prefixEmpty: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "kind": "storage#objects"\n}\n',
  }),
  // stage 2f (2026-09-30T03:28:13Z), shape/ruleset/create: POST rulesets (the read of the same ruleset answers the same body)
  rulesetCreated: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "name": "projects/fireemu-oracle-query/rulesets/b3adea19-08cf-48d9-ad0c-c38d83034efb",\n  "source": {\n    "files": [\n      {\n        "content": "rules_version = \'2\';\\nservice firebase.storage {\\n  match /b/{bucket}/o {\\n    match /STORAGE-RULES/probe-2f/{name} {\\n      allow get: if false;\\n    }\\n  }\\n}\\n",\n        "name": "storage.rules"\n      }\n    ]\n  },\n  "createTime": "2026-09-30T03:28:19.468143Z",\n  "metadata": {\n    "services": [\n      "firebase.storage"\n    ]\n  }\n}\n',
  }),
  // stage 2f, shape/ruleset/never: GET of a ruleset name that never existed (the read after its deletion answers the same 114 bytes)
  rulesetNeverExisted: Object.freeze({
    status: 404,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "error": {\n    "code": 404,\n    "message": "Requested entity was not found.",\n    "status": "NOT_FOUND"\n  }\n}\n',
  }),
  // stage 2f, shape/object/create: POST upload uploadType=media, ifGenerationMatch=0
  objectCreated: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "kind": "storage#object",\n  "id": "fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2f/object.bin/1790738903174378",\n  "selfLink": "https://www.googleapis.com/storage/v1/b/fireemu-oracle-query.firebasestorage.app/o/STORAGE-RULES%2Fprobe-2f%2Fobject.bin",\n  "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/fireemu-oracle-query.firebasestorage.app/o/STORAGE-RULES%2Fprobe-2f%2Fobject.bin?generation=1790738903174378&alt=media",\n  "name": "STORAGE-RULES/probe-2f/object.bin",\n  "bucket": "fireemu-oracle-query.firebasestorage.app",\n  "generation": "1790738903174378",\n  "metageneration": "1",\n  "contentType": "text/plain",\n  "storageClass": "STANDARD",\n  "size": "8",\n  "md5Hash": "/BIIABQvb8fCULQZVvVvVw==",\n  "crc32c": "PYnuZA==",\n  "etag": "COqZ1qGulZcDEAE=",\n  "timeCreated": "2026-09-30T03:28:23.182Z",\n  "updated": "2026-09-30T03:28:23.182Z",\n  "timeStorageClassUpdated": "2026-09-30T03:28:23.182Z",\n  "timeFinalized": "2026-09-30T03:28:23.182Z"\n}\n',
  }),
  // stage 2f, shape/object/list: the object list of a prefix with one object
  objectListed: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "kind": "storage#objects",\n  "items": [\n    {\n      "kind": "storage#object",\n      "id": "fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2f/object.bin/1790738903174378",\n      "selfLink": "https://www.googleapis.com/storage/v1/b/fireemu-oracle-query.firebasestorage.app/o/STORAGE-RULES%2Fprobe-2f%2Fobject.bin",\n      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/fireemu-oracle-query.firebasestorage.app/o/STORAGE-RULES%2Fprobe-2f%2Fobject.bin?generation=1790738903174378&alt=media",\n      "name": "STORAGE-RULES/probe-2f/object.bin",\n      "bucket": "fireemu-oracle-query.firebasestorage.app",\n      "generation": "1790738903174378",\n      "metageneration": "1",\n      "contentType": "text/plain",\n      "storageClass": "STANDARD",\n      "size": "8",\n      "md5Hash": "/BIIABQvb8fCULQZVvVvVw==",\n      "crc32c": "PYnuZA==",\n      "etag": "COqZ1qGulZcDEAE=",\n      "timeCreated": "2026-09-30T03:28:23.182Z",\n      "updated": "2026-09-30T03:28:23.182Z",\n      "timeStorageClassUpdated": "2026-09-30T03:28:23.182Z",\n      "timeFinalized": "2026-09-30T03:28:23.182Z"\n    }\n  ]\n}\n',
  }),
  // stage 2f, shape/object/delete: DELETE with ifGenerationMatch (status 204, no body)
  objectDeleted: Object.freeze({ status: 204, contentType: "application/json", body: "" }),
  // stage 2f, shape/document/create: POST createDocument (the read answers the same body)
  documentCreated: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: '{\n  "name": "projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2f-doc",\n  "fields": {\n    "probe": {\n      "stringValue": "2f"\n    }\n  },\n  "createTime": "2026-09-30T03:28:25.413574Z",\n  "updateTime": "2026-09-30T03:28:25.413574Z"\n}\n',
  }),
  // stage 2f, shape/document/delete: DELETE with currentDocument.updateTime
  documentDeleted: Object.freeze({
    status: 200,
    contentType: "application/json; charset=UTF-8",
    body: "{}\n",
  }),
});
/** A recorded answer as the transport hands it to a classifier. */
export const rawOf = (fixture) => ({
  status: fixture.status,
  rawHeaders: fixture.contentType === null ? [] : ["Content-Type", fixture.contentType],
  bytes: Buffer.from(fixture.body, "utf8"),
});
