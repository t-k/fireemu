const v1 = require('firebase-functions/v1');
const {onConfigUpdated} = require('firebase-functions/v2/remoteConfig');
const fs = require('node:fs');
const attempts = new Map();
function record(generation, data, context) {
  const key = `${generation}:${data.versionNumber}`;
  const attempt = (attempts.get(key) || 0) + 1;
  attempts.set(key, attempt);
  const row = {generation, data, context, attempt};
  if (process.env.REMOTE_CONFIG_OUTPUT) fs.appendFileSync(process.env.REMOTE_CONFIG_OUTPUT, JSON.stringify(row) + '\n');
  console.log('REMOTE_CONFIG_EVENT ' + JSON.stringify(row));
  if (data.description === 'fail once' && attempt === 1) throw new Error('requested first failure');
}
exports.configV1 = v1.runWith({failurePolicy: true}).remoteConfig.onUpdate((data, context) => record(1, data, context));
exports.configV2 = onConfigUpdated({retry: true}, event => {
  const {data, ...context} = event;
  record(2, data, context);
});

// A deliberately malformed descriptor must not become an update subscription.
if (process.env.REMOTE_CONFIG_NEAR_MISS === '1') {
  exports.nearMiss = () => {};
  exports.nearMiss.__endpoint = {platform: 'gcfv2', eventTrigger: {eventType: 'google.firebase.remoteconfig.remoteConfig.v1.updated.extra', eventFilters: {}}};
}
