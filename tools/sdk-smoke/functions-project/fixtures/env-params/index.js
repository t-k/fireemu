// What the runtime actually sees: the dotenv chain, the local secret override, the legacy
// runtime config and the parameters resolved from all of it.
//
// The values are printed at load time rather than served, because discovery is the moment
// the environment has to be right: `firebase-functions/params` reads `process.env` when the
// module is evaluated, so a variable that arrives later never reaches a parameter.
//
// The daemon forwards everything a runner writes to its own stderr, so the line below is what
// `crates/fireemu/tests/functions_environment.rs` asserts on.
const { onRequest } = require("firebase-functions/v2/https");
const params = require("firebase-functions/params");

const observed = {
  // The chain: .env, .env.<projectId> and .env.local in that order of precedence.
  fromDotEnv: process.env.FX_FROM_DOTENV ?? null,
  overriddenByProject: process.env.FX_OVERRIDDEN_BY_PROJECT ?? null,
  overriddenByLocal: process.env.FX_OVERRIDDEN_BY_LOCAL ?? null,
  quoted: process.env.FX_QUOTED ?? null,
  // Parameters, resolved from the same variables.
  paramString: params.defineString("FX_FROM_DOTENV").value(),
  paramInt: params.defineInt("FX_INT").value(),
  paramBoolean: params.defineBoolean("FX_BOOL").value(),
  paramList: params.defineList("FX_LIST").value(),
  // A parameter nothing defines: the SDK answers with the empty string, and a declared
  // default is a deploy-time value the runtime never sees.
  paramMissing: params.defineString("FX_ABSENT").value(),
  paramMissingWithDefault: params.defineString("FX_ABSENT_2", { default: "unused" }).value(),
  // A secret, from .secret.local.
  paramSecret: params.defineSecret("FX_SECRET").value(),
  // The Cloud Run identity the emulator sets process-wide.
  kRevision: process.env.K_REVISION ?? null,
  tz: process.env.TZ ?? null,
  quotaProject: process.env.GOOGLE_CLOUD_QUOTA_PROJECT ?? null,
  functionsEmulator: process.env.FUNCTIONS_EMULATOR ?? null,
  firebaseConfigKeys: Object.keys(JSON.parse(process.env.FIREBASE_CONFIG || "{}")).sort(),
  // The legacy runtime configuration, as the emulator hands it over. `functions.config()`
  // itself is gone in firebase-functions v7 ("functions.config() has been removed in
  // firebase-functions v7"), so what is checked is that CLOUD_RUNTIME_CONFIG arrives with the
  // file's contents, which is all the official emulator promises.
  legacyConfig: JSON.parse(process.env.CLOUD_RUNTIME_CONFIG || "null")?.someservice ?? null,
};

console.error(`FIXTURE_ENV ${JSON.stringify(observed)}`);

exports.fxEnvEcho = onRequest((_req, res) => res.status(200).json(observed));
