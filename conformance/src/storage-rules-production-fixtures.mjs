// Production answers recorded by earlier stages, kept byte for byte as fixtures: the stage 2d probe (2026-09-29T23:27Z) and stage 2c-pre (2026-09-29T14:19Z).
// They hold no secret: names of the sandbox project, its bucket and its rulesets, times, and Google error text. The simulator and the classifier tests use
// these instead of answers written to fit the classifiers.
export const PRODUCTION = Object.freeze({
  // GET rulesets?pageSize=100 on the query project (stage 2d probe, 2026-09-29T23:27Z)
  rulesetList: Object.freeze({ status: 200, contentType: "application/json; charset=UTF-8", body: "{\n  \"rulesets\": [\n    {\n      \"name\": \"projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8\",\n      \"createTime\": \"2026-09-25T11:08:54.358767Z\",\n      \"metadata\": {\n        \"services\": [\n          \"firebase.storage\"\n        ]\n      }\n    },\n    {\n      \"name\": \"projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1\",\n      \"createTime\": \"2026-09-23T23:02:05.839536Z\",\n      \"metadata\": {\n        \"services\": [\n          \"cloud.firestore\"\n        ]\n      }\n    }\n  ]\n}\n" }),
  // GET metadata of an absent object (stage 2d probe)
  objectMetadataAbsent: Object.freeze({ status: 404, contentType: "application/json; charset=UTF-8", body: "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin\",\n    \"errors\": [\n      {\n        \"message\": \"No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin\",\n        \"domain\": \"global\",\n        \"reason\": \"notFound\"\n      }\n    ]\n  }\n}\n" }),
  // GET media (alt=media) of an absent object (stage 2d probe)
  objectMediaAbsent: Object.freeze({ status: 404, contentType: "text/html; charset=UTF-8", body: "No such object: fireemu-oracle-query.firebasestorage.app/STORAGE-RULES/probe-2d/absent-object.bin" }),
  // POST :test with a valid storage source (stage 2d probe)
  rulesTestValid: Object.freeze({ status: 200, contentType: "application/json; charset=UTF-8", body: "{}\n" }),
  // POST :test with an invalid storage source (stage 2d probe)
  rulesTestInvalid: Object.freeze({ status: 200, contentType: "application/json; charset=UTF-8", body: "{\n  \"issues\": [\n    {\n      \"sourcePosition\": {\n        \"fileName\": \"storage.rules\",\n        \"line\": 5,\n        \"column\": 21,\n        \"currentOffset\": 115,\n        \"endOffset\": 115\n      },\n      \"description\": \"Missing conditional expression after 'if'.\",\n      \"severity\": \"ERROR\"\n    }\n  ]\n}\n" }),
  // GET of an absent Firestore document (stage 2d probe)
  documentAbsent: Object.freeze({ status: 404, contentType: "application/json; charset=UTF-8", body: "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Document \\\"projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document\\\" not found.\",\n    \"status\": \"NOT_FOUND\"\n  }\n}\n" }),
  // GET of the bucket release after its deletion (stage 2c-pre, 2026-09-29T14:19Z)
  releaseAbsent: Object.freeze({ status: 404, contentType: "application/json; charset=UTF-8", body: "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Requested entity was not found.\",\n    \"status\": \"NOT_FOUND\"\n  }\n}\n" }),
  // GET of the bucketless release (stage 2c-pre)
  releaseBucketlessAbsent: Object.freeze({ status: 404, contentType: "application/json; charset=UTF-8", body: "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Requested entity was not found.\",\n    \"status\": \"NOT_FOUND\"\n  }\n}\n" }),
  // GET of the bucket release before its deletion (stage 2c-pre)
  releasePresent: Object.freeze({ status: 200, contentType: "application/json; charset=UTF-8", body: "{\n  \"name\": \"projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app\",\n  \"rulesetName\": \"projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8\",\n  \"createTime\": \"2026-09-25T11:09:23.326708Z\",\n  \"updateTime\": \"2026-09-25T11:09:23.326708Z\"\n}\n" }),
});
/** A recorded answer as the transport hands it to a classifier. */
export const rawOf = (fixture) => ({ status: fixture.status, rawHeaders: fixture.contentType === null ? [] : ["Content-Type", fixture.contentType], bytes: Buffer.from(fixture.body, "utf8") });
