const { initializeApp, getApps } = require("firebase-admin/app");
const functions = require("firebase-functions/v1");
const {
  onValueCreated,
  onValueUpdated,
  onValueDeleted,
  onValueWritten,
} = require("firebase-functions/v2/database");
const { data, report, v1Context, v2Event } = require("./frames");

const INSTANCE = "fireemu-q-rtdb2";
const LOCATION = "us-central1";
const ITEM_PATH = "/k9-rtdb/{group}/items/{id}";
const GROUP_PATH = "/k9-rtdb/{group}";
if (getApps().length === 0) initializeApp();

// No handler asks for redelivery and none throws: the recording is of what each kind delivers, once.
const v1 = functions
  .region(LOCATION)
  .runWith({ maxInstances: 1, timeoutSeconds: 30 })
  .database.instance(INSTANCE)
  .ref(ITEM_PATH);
const options = { region: LOCATION, maxInstances: 1, timeoutSeconds: 30 };
const item = { ...options, ref: ITEM_PATH, instance: INSTANCE };
const frame2 = (handler) => (event) => report({ handler, generation: 2, event: v2Event(event) });
const frame1 = (handler) => (value, context) =>
  report({ handler, generation: 1, event: { context: v1Context(context), data: data(value) } });

exports.k9CreatedV2 = onValueCreated(item, frame2("k9CreatedV2"));
exports.k9UpdatedV2 = onValueUpdated(item, frame2("k9UpdatedV2"));
exports.k9DeletedV2 = onValueDeleted(item, frame2("k9DeletedV2"));
exports.k9CreatedV1 = v1.onCreate(frame1("k9CreatedV1"));
exports.k9UpdatedV1 = v1.onUpdate(frame1("k9UpdatedV1"));
exports.k9DeletedV1 = v1.onDelete(frame1("k9DeletedV1"));
// No `instance`: the SDK then names `*`, any instance of the project.
exports.k9AnyWrittenV2 = onValueWritten({ ...options, ref: ITEM_PATH }, frame2("k9AnyWrittenV2"));
// The group, the ancestor of the item pattern.
exports.k9GroupWrittenV2 = onValueWritten(
  { ...options, ref: GROUP_PATH, instance: INSTANCE },
  frame2("k9GroupWrittenV2"),
);
