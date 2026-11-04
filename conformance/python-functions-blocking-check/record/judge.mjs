// The judge of the blocking check: a pure function of the frames the fixture printed, the ERROR log entries, and what
// the run observed (the sign-up answer, the trigger registration, the service's public invoker). It decides case by case
// whether production delivered what the Python runner assumes, and records what it observed either way. It never throws
// on a shape it does not know: a frame that is missing is `not-delivered`, and a value that is not one the judge has a
// rule for is `differs`, with the value kept. Importing it sends and reads nothing.
//
// Statuses: `as-expected` (every rule held), `differs` (a delivery arrived and a rule did not hold), `observed` (a value
// was recorded that has no expectation to hold it to), `not-delivered` (the operation was sent and no frame arrived),
// `not-sent` (the operation or the read was not made, so there is nothing to judge).
import { BLOCKING_EVENT, FIREBASE_FUNCTIONS_PY_VERSION, FUNCTION } from "./plan.mjs";

/** The addresses the function answers on: the Cloud Run service's and the function's own url. */
const addressesOf = (registration) =>
  [registration.serviceUri, registration.functionUrl].filter((uri) => typeof uri === "string");
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export const REQUIRED_CLAIMS = Object.freeze([
  "aud",
  "event_id",
  "event_type",
  "exp",
  "iat",
  "ip_address",
  "iss",
  "user_agent",
  "user_record",
]);
export const OPTIONAL_CLAIMS = Object.freeze(["locale", "sign_in_method", "sub", "tenant_id"]);

const result = (status, observed, expected, notes = []) => ({ status, observed, expected, notes });

/** `as-expected` when every check passed, else `differs` listing the checks that did not. */
function verdict(checks, observed, expected) {
  const failed = Object.entries(checks)
    .filter(([, ok]) => ok !== true)
    .map(([name]) => name);
  return result(failed.length === 0 ? "as-expected" : "differs", observed, expected, failed);
}

/** The frames of the function that belong to this run (the synthetic address names the run) and have `kind`. */
export function framesOf(frames, kind, email) {
  return frames
    .map((entry) => entry?.frame ?? entry)
    .filter(
      (f) =>
        isObject(f) &&
        f.function === FUNCTION &&
        f.kind === kind &&
        (kind === "blocking-raw" ? f.request?.token?.email : f.data?.email) === email,
    );
}

export function judge({
  email,
  localId = null,
  frames,
  errors = [],
  observed = {},
  mode = "production",
}) {
  const cases = {};
  const raw = framesOf(frames, "blocking-raw", email)[0];
  const sdk = framesOf(frames, "blocking-sdk", email)[0];
  const signUp = observed.signUp ?? null;
  const production = mode === "production";

  cases["signup-allowed"] = signUp
    ? verdict(
        {
          "answered-2xx": signUp.class === "2xx",
          "local-id": typeof signUp.localId === "string" && signUp.localId.length > 0,
        },
        {
          class: signUp.class,
          status: signUp.status ?? null,
          hasLocalId: typeof signUp.localId === "string",
        },
        { class: "2xx" },
      )
    : result("not-sent", null, null, ["sign-up"]);

  cases["trigger-registered"] = observed.registration
    ? verdict(
        {
          "trigger-present": isObject(observed.registration.trigger),
          // The CLI registers the function's own address (`url`, on cloudfunctions.net); the Cloud Run service has another
          // (`serviceConfig.uri`, run.app). Either is the function's address.
          "uri-is-the-function-address":
            typeof observed.registration.trigger?.functionUri === "string" &&
            addressesOf(observed.registration).includes(observed.registration.trigger.functionUri),
        },
        {
          trigger: observed.registration.trigger ?? null,
          serviceUri: observed.registration.serviceUri ?? null,
          functionUrl: observed.registration.functionUrl ?? null,
          event: BLOCKING_EVENT,
        },
        { functionUri: "the function's address (its url, or the Cloud Run service address)" },
      )
    : result("not-sent", null, null, ["config read"]);

  cases["invoker-public"] = observed.invoker
    ? verdict(
        { "all-users-invoker": observed.invoker.allUsersInvoker === true },
        { members: observed.invoker.members ?? null },
        { allUsers: "roles/run.invoker" },
      )
    : result("not-sent", null, null, ["invoker read"]);

  if (!signUp) {
    for (const id of ["blocking-request", "blocking-claims", "blocking-sdk"])
      cases[id] = result("not-sent", null, null, ["sign-up"]);
  } else {
    cases["blocking-request"] = raw
      ? (() => {
          const r = raw.request;
          const token = r.token ?? {};
          const names = Array.isArray(token.claim_names) ? token.claim_names : [];
          const missing = REQUIRED_CLAIMS.filter((n) => !names.includes(n));
          const extra = names.filter((n) => ![...REQUIRED_CLAIMS, ...OPTIONAL_CLAIMS].includes(n));
          const checks = {
            method: r.method === "POST",
            "content-type-json": String(r.headers?.["content-type"] ?? "").startsWith(
              "application/json",
            ),
            "body-has-data-only": JSON.stringify(r.body_keys) === JSON.stringify(["data"]),
            "data-has-jwt-only": JSON.stringify(r.data_keys) === JSON.stringify(["jwt"]),
            "three-segments": token.segments === 3,
            "required-claims": missing.length === 0,
            ...(production
              ? {
                  "alg-rs256": token.header?.alg === "RS256",
                  "has-kid": token.header?.has_kid === true,
                }
              : {}),
          };
          return verdict(
            checks,
            {
              headerNames: r.header_names ?? null,
              authorization: r.authorization ?? null,
              tokenHeader: token.header ?? null,
              claimNames: names,
              missing,
              extra,
              ipFamily: token.ip_family ?? null,
            },
            { claimNames: REQUIRED_CLAIMS },
          );
        })()
      : result("not-delivered", null, null, ["no raw frame"]);

    cases["blocking-claims"] = raw
      ? (() => {
          const token = raw.request?.token ?? {};
          const claims = token.claims ?? {};
          const checks = {
            "event-type-names-before-create": String(claims.event_type ?? "").includes(
              BLOCKING_EVENT,
            ),
            "user-is-this-sign-up": localId === null || token.uid === localId,
            "iss-is-https": String(claims.iss ?? "").startsWith("https://"),
            ...(production
              ? {
                  "aud-is-the-function-uri":
                    typeof claims.aud === "string" &&
                    [
                      ...addressesOf(observed.registration ?? {}),
                      observed.registration?.trigger?.functionUri,
                    ].includes(claims.aud),
                }
              : {}),
            "not-expired-at-issue": isObject(token.timing) && token.timing.exp > token.timing.iat,
          };
          return verdict(
            checks,
            {
              claims,
              userRecordNames: token.user_record_names ?? null,
              timing: token.timing ?? null,
            },
            { eventType: "names beforeCreate" },
          );
        })()
      : result("not-delivered", null, null, ["no raw frame"]);

    cases["blocking-sdk"] = sdk
      ? (() => {
          const info = sdk.additional_user_info ?? {};
          return verdict(
            {
              "event-type-names-before-create": String(sdk.event_type ?? "").includes(
                BLOCKING_EVENT,
              ),
              "new-user": info.is_new_user === true,
              "password-provider": info.provider_id === "password",
              "user-is-this-sign-up": localId === null || sdk.uid === localId,
              "no-credential": sdk.credential === null,
              "event-id": sdk.event_id_present === true,
            },
            {
              eventType: sdk.event_type ?? null,
              additionalUserInfo: info,
              locale: sdk.locale ?? null,
              ipFamily: sdk.ip_family ?? null,
              dataNames: sdk.data_names ?? null,
              timestamp: sdk.timestamp ?? null,
            },
            { eventType: "names beforeCreate", isNewUser: true },
          );
        })()
      : raw
        ? result("differs", { rawDelivered: true, errors: errors.length }, { sdkRan: true }, [
            "sdk-did-not-run",
          ])
        : result("not-delivered", null, null, ["no SDK frame"]);
  }

  const versions = {};
  for (const entry of frames) {
    const f = entry?.frame ?? entry;
    if (isObject(f?.versions)) versions[f.kind] = f.versions;
  }
  const seen = new Set(Object.values(versions).map((v) => v["firebase-functions"]));
  cases["sdk-versions"] =
    Object.keys(versions).length === 0
      ? result("not-delivered", null, null, ["no frame carries versions"])
      : verdict(
          { "pinned-sdk": seen.size === 1 && seen.has(FIREBASE_FUNCTIONS_PY_VERSION) },
          { versions: Object.values(versions)[0], sdkVersionsSeen: [...seen] },
          { "firebase-functions": FIREBASE_FUNCTIONS_PY_VERSION },
        );

  const counts = { "as-expected": 0, differs: 0, observed: 0, "not-delivered": 0, "not-sent": 0 };
  for (const c of Object.values(cases)) counts[c.status] = (counts[c.status] ?? 0) + 1;
  return {
    mode,
    cases,
    counts,
    errors: errors.map((e) => ({
      function: e.function,
      timestamp: e.timestamp ?? null,
      text: e.text,
    })),
    complete: counts["not-delivered"] === 0 && counts["not-sent"] === 0,
  };
}
