// Eight RTDB trigger handlers on the CV14 run prefix, four 1st gen and four 2nd gen. Each handler only
// prints a frame: no network, no other side effect.
const { initializeApp, getApps } = require("firebase-admin/app");
const functions = require("firebase-functions/v1");
const { onValueCreated, onValueDeleted, onValueUpdated, onValueWritten } = require("firebase-functions/v2/database");
const { data, report, v1Context, v2Event } = require("./frames");

const INSTANCE = "fireemu-q-rtdb2";
const LOCATION = "us-central1";
const ITEM_PATH = "/cv14-rtdb/items/{id}";

if (getApps().length === 0) initializeApp();

const v1Ref = functions.region(LOCATION).database.instance(INSTANCE).ref(ITEM_PATH);
const v1 = (handler) => (value, context) =>
  report({ handler, generation: 1, event: { context: v1Context(context), data: data(value) } });
exports.rtdbCreatedV1 = v1Ref.onCreate(v1("rtdbCreatedV1"));
exports.rtdbUpdatedV1 = v1Ref.onUpdate(v1("rtdbUpdatedV1"));
exports.rtdbDeletedV1 = v1Ref.onDelete(v1("rtdbDeletedV1"));
exports.rtdbWrittenV1 = v1Ref.onWrite(v1("rtdbWrittenV1"));

const options = { ref: ITEM_PATH, instance: INSTANCE, region: LOCATION };
const v2 = (handler) => (event) => report({ handler, generation: 2, event: v2Event(event) });
exports.rtdbCreatedV2 = onValueCreated(options, v2("rtdbCreatedV2"));
exports.rtdbUpdatedV2 = onValueUpdated(options, v2("rtdbUpdatedV2"));
exports.rtdbDeletedV2 = onValueDeleted(options, v2("rtdbDeletedV2"));
exports.rtdbWrittenV2 = onValueWritten(options, v2("rtdbWrittenV2"));
