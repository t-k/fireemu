const { initializeApp, getApps } = require("firebase-admin/app");
const functions = require("firebase-functions/v1");
const { onValueWritten } = require("firebase-functions/v2/database");
const { data, report, v1Context, v2Event } = require("./frames");

const INSTANCE = "fireemu-q-rtdb2";
const LOCATION = "us-central1";
const ITEM_PATH = "/g9-rtdb/{group}/items/{id}";
if (getApps().length === 0) initializeApp();

function invoke(handler, generation, change, params, time, event) {
  const value = change.after.exists() ? change.after.val() : change.before.val();
  const ageMs = Date.now() - Date.parse(time);
  const threw =
    params?.group === "gr" &&
    typeof value?.failForMs === "number" &&
    Number.isFinite(ageMs) &&
    ageMs < Math.min(value.failForMs, 45000);
  report({
    handler,
    generation,
    event,
    attempt: { ageMs: Number.isFinite(ageMs) ? ageMs : null, threw },
  });
  if (threw) throw new Error("deliberate retry");
}
const v1 = functions
  .region(LOCATION)
  .runWith({ failurePolicy: true, maxInstances: 1, timeoutSeconds: 30 })
  .database.instance(INSTANCE)
  .ref(ITEM_PATH);
exports.g9WrittenV1Retry = v1.onWrite((change, context) =>
  invoke("g9WrittenV1Retry", 1, change, context.params, context.timestamp, {
    context: v1Context(context),
    data: data(change),
  }),
);
const options = {
  ref: ITEM_PATH,
  instance: INSTANCE,
  region: LOCATION,
  maxInstances: 1,
  timeoutSeconds: 30,
};
exports.g9WrittenV2Retry = onValueWritten({ ...options, retry: true }, (event) =>
  invoke("g9WrittenV2Retry", 2, event.data, event.params, event.time, v2Event(event)),
);
exports.g9WrittenV2 = onValueWritten(options, (event) =>
  invoke("g9WrittenV2", 2, event.data, event.params, event.time, v2Event(event)),
);
