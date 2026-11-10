// firebase.json `hosting` object to the Hosting REST `ServingConfig`, for the keys the observation
// corpus uses. It is a copy of the conversion in firebase-tools 15.28.2
// (`lib/deploy/hosting/convertConfig.js`, `convertConfig`) minus the function and Cloud Run paths,
// which this parent does not cover; convert.test.mjs runs the real function and compares.
function pattern(type, rule) {
  const glob = rule.source ?? rule.glob;
  if (glob !== undefined && rule.regex !== undefined) {
    throw new Error(`Cannot specify a ${type} pattern with both a glob and regex.`);
  }
  if (glob !== undefined) return { glob };
  if (rule.regex !== undefined) return { regex: rule.regex };
  throw new Error(`Cannot specify a ${type} with no pattern (either a glob or regex required).`);
}

export function servingConfig(hosting) {
  const config = {};
  config.rewrites = hosting.rewrites?.map((rewrite) => {
    if (!("destination" in rewrite)) {
      throw new Error("only destination rewrites are covered (no function, run or dynamicLinks)");
    }
    return { ...pattern("rewrite", rewrite), path: rewrite.destination };
  });
  config.redirects = hosting.redirects?.map((redirect) => {
    const api = { ...pattern("redirect", redirect), location: redirect.destination };
    if (redirect.type) api.statusCode = redirect.type;
    return api;
  });
  config.headers = hosting.headers?.map((header) => {
    const headers = {};
    for (const { key, value } of header.headers ?? []) headers[key] = value;
    return { ...pattern("header", header), headers };
  });
  for (const key of ["cleanUrls", "appAssociation", "i18n"]) {
    if (hosting[key] !== undefined) config[key] = hosting[key];
  }
  if (hosting.trailingSlash !== undefined) {
    config.trailingSlashBehavior = hosting.trailingSlash ? "ADD" : "REMOVE";
  }
  for (const key of Object.keys(config)) if (config[key] === undefined) delete config[key];
  return config;
}
