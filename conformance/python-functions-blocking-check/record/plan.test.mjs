// The plan and the script: names, waits, and the sign-up the check makes.
import assert from "node:assert/strict";
import test from "node:test";
import {
  ACCOUNTS_URL,
  BLOCKING_EVENT,
  BLOCKING_EVENT_TYPE,
  CODEBASE,
  CONFIG_URL,
  DELIVERY_WINDOW_SECONDS,
  FUNCTION,
  LOG_DELAY_SECONDS,
  PROJECT,
  PROPAGATION_WAIT_SECONDS,
  REGION,
  REQUIRED_SERVICES,
  RUN_ID,
  SIGN_UP_URL,
  functionName,
  packageId,
  packageIds,
  sourceBuckets,
} from "./plan.mjs";
import {
  countAccounts,
  deleteAccount,
  emailOf,
  lookupAccount,
  passwordOf,
  signUp,
  signUpBody,
} from "./script.mjs";

test("names, waits and URLs are the packet's", () => {
  assert.deepEqual(
    [PROJECT, REGION, CODEBASE, FUNCTION, BLOCKING_EVENT],
    ["fireemu-oracle-idp", "us-central1", "pcblock", "pcblock", "beforeCreate"],
  );
  assert.equal(BLOCKING_EVENT_TYPE, "providers/cloud.auth/eventTypes/user.beforeCreate");
  assert.equal(
    functionName(),
    "projects/fireemu-oracle-idp/locations/us-central1/functions/pcblock",
  );
  assert.equal(packageId(), "fireemu--oracle--idp__us--central1__pcblock");
  assert.deepEqual(packageIds(), [packageId(), packageId() + "%2Fcache"]);
  assert.deepEqual(
    [PROPAGATION_WAIT_SECONDS, DELIVERY_WINDOW_SECONDS, LOG_DELAY_SECONDS],
    [60, 120, 120],
  );
  assert.equal(
    CONFIG_URL,
    "https://identitytoolkit.googleapis.com/admin/v2/projects/fireemu-oracle-idp/config",
  );
  assert.equal(SIGN_UP_URL, "https://identitytoolkit.googleapis.com/v1/accounts:signUp");
  assert.equal(
    ACCOUNTS_URL,
    "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-idp/accounts",
  );
  assert.deepEqual(sourceBuckets("1"), [
    "gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com",
    "gcf-v2-sources-1-us-central1",
  ]);
  assert.equal(RUN_ID.test("0123456789abcdef"), true);
  assert.equal(RUN_ID.test("0123456789abcdeg"), false);
});

test("the services the CLI ensures are required, so the deploy enables nothing", () => {
  for (const id of [
    "compute",
    "firebaseextensions",
    "identitytoolkit",
    "cloudfunctions",
    "cloudbuild",
    "artifactregistry",
    "run",
    "eventarc",
    "pubsub",
    "storage",
  ])
    assert.ok(REQUIRED_SERVICES.includes(id + ".googleapis.com"), id);
});

test("the sign-up is an email and password one that names the run (anonymous sign-up does not trigger blocking functions)", () => {
  assert.equal(emailOf("0123456789abcdef"), "pcblock-0123456789abcdef@example.com");
  assert.match(passwordOf("0123456789abcdef"), /^Pcblock-0123456789abcdef-Aa1!$/);
  assert.deepEqual(signUpBody("0123456789abcdef"), {
    email: emailOf("0123456789abcdef"),
    password: passwordOf("0123456789abcdef"),
    returnSecureToken: true,
  });
  assert.deepEqual(signUp("0123456789abcdef"), {
    method: "POST",
    url: SIGN_UP_URL,
    json: signUpBody("0123456789abcdef"),
  });
  assert.equal(emailOf("0123456789abcdef") === emailOf("fedcba9876543210"), false);
});

test("the account requests are the Admin ones for this project", () => {
  assert.deepEqual(deleteAccount("abc"), {
    method: "POST",
    url: ACCOUNTS_URL + ":delete",
    json: { localId: "abc" },
  });
  assert.deepEqual(lookupAccount("abc"), {
    method: "POST",
    url: ACCOUNTS_URL + ":lookup",
    json: { localId: ["abc"] },
  });
  assert.deepEqual(countAccounts(), {
    method: "POST",
    url: ACCOUNTS_URL + ":query",
    json: { returnUserInfo: false },
  });
});
