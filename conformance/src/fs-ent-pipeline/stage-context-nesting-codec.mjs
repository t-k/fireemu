// Offline codec proof: a fresh process changes only its own protobuf recursion bound.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { stageContextCases } from './stage-context-corpus.mjs';
import { buildGrpcRequest, guardGrpcRequest } from './harness.mjs';

const depth = Number(process.argv[2]);
if (process.argv.length !== 3 || ![48, 100].includes(depth)) throw new Error('unapproved nesting depth');
const require = createRequire(import.meta.url);
const firestoreRequire = createRequire(require.resolve('@google-cloud/firestore'));
const gaxRequire = createRequire(firestoreRequire.resolve('google-gax'));
const loaderRequire = createRequire(gaxRequire.resolve('@grpc/proto-loader'));
const protobuf = loaderRequire('protobufjs');
protobuf.util.recursionLimit = 1024;
protobuf.Reader.recursionLimit = 1024;
const { v1 } = require('@google-cloud/firestore');
const ctx = { project: 'demo-local', database: 'demo-db' };
const step = stageContextCases().find((x) => x.id === `chain-${depth}-grpc`);
const built = buildGrpcRequest(step, ctx, new Map());
guardGrpcRequest(built, ctx);
const type = new v1.FirestoreClient({ projectId: ctx.project })._protos.google.firestore.v1.ExecutePipelineRequest;
const bytes = type.serialize(built.request);
const decoded = type.deserialize(bytes);
assert.deepEqual(type.serialize(decoded), bytes);
let value = decoded.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.v;
let observed = 0;
while (value.functionValue) { assert.equal(value.functionValue.name, 'array'); assert.equal(value.functionValue.args.length, 1); observed++; value = value.functionValue.args[0]; }
assert.equal(observed, depth);
assert.equal(value.fieldReferenceValue, 'i');
process.stdout.write(JSON.stringify({ depth, recursionLimit: protobuf.util.recursionLimit, roundTrip: true, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }) + '\n');
