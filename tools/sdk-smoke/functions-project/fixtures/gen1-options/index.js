const functions = require("firebase-functions/v1");
const { defineInt } = require("firebase-functions/params");

const memory = defineInt("GEN1_MEMORY_MB");
const minInstances = defineInt("GEN1_MIN_INSTANCES");
const maxInstances = defineInt("GEN1_MAX_INSTANCES");

exports.fxV1 = functions
  .runWith({
    memory,
    minInstances,
    maxInstances,
    ingressSettings: "ALLOW_INTERNAL_ONLY",
    serviceAccount: "runner@example.iam.gserviceaccount.com",
    vpcConnector: "projects/demo-options/locations/us-central1/connectors/default",
    vpcConnectorEgressSettings: "PRIVATE_RANGES_ONLY",
    labels: { fixture: "gen1" },
    secrets: ["API_KEY"],
  })
  .https.onRequest((_request, response) => response.send("ok"));
