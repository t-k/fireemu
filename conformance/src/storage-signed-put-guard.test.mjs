import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  GuardError,
  RequestBudget,
  classifyRequest,
  dropSignature,
  isUnknownStatus,
  redactSignedUrl,
  tamperSignature,
  validateSigner,
} from "./storage-signed-put/guard.mjs";
import { ROLE_ID } from "./storage-signed-put/plan.mjs";
import { LOCAL_LIKE, PRODUCTION_LIKE } from "./storage-signed-put/world.fake.mjs";

const prefix = "storage-signed-put/sp-0123abcd/";
const sig = "ab".repeat(256);
const signed = (name, extra = "") =>
  `https://storage.googleapis.com/${PRODUCTION_LIKE.bucket}/${prefix}${name}?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=s%40x%2F20261103%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261103T120000Z&X-Goog-Expires=300&X-Goog-SignedHeaders=host&X-Goog-Signature=${sig}${extra}`;
const json = (suffix) =>
  `https://storage.googleapis.com/storage/v1/b/${PRODUCTION_LIKE.bucket}${suffix}`;
const kind = (request, target = PRODUCTION_LIKE) => classifyRequest(target, request, prefix);
const refused = (request, target = PRODUCTION_LIKE) =>
  assert.throws(() => kind(request, target), GuardError, `${request.method} ${request.url}`);

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

describe("signed PUT request guard", () => {
  it("accepts exactly the forms the observer sends", () => {
    assert.equal(kind({ method: "GET", url: json("") }), "bucket-get");
    assert.equal(
      kind({ method: "GET", url: json(`/o?prefix=${encodeURIComponent(prefix)}&maxResults=1000`) }),
      "list",
    );
    assert.equal(
      kind({ method: "GET", url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}`) }),
      "object-get",
    );
    assert.equal(
      kind({
        method: "GET",
        url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}?alt=media`),
      }),
      "object-get",
    );
    assert.equal(
      kind({
        method: "DELETE",
        url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}?ifGenerationMatch=12`),
      }),
      "object-delete",
    );
    assert.equal(kind({ method: "PUT", url: signed("rec1/ok.png") }), "xml-put");
    assert.equal(kind({ method: "OPTIONS", url: signed("rec1/ok.png") }), "xml-options");
    assert.equal(
      kind({
        method: "GET",
        url: `https://iam.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}/serviceAccounts/${PRODUCTION_LIKE.signer}`,
      }),
      "signer-get",
    );
    assert.equal(
      kind({
        method: "POST",
        url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${PRODUCTION_LIKE.signer}:signBlob`,
      }),
      "sign-blob",
    );
  });

  it("refuses other hosts, schemes, ports, users and redirect-style hosts", () => {
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace(
        "https://storage.googleapis.com",
        "http://storage.googleapis.com",
      ),
    });
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace("storage.googleapis.com", "storage.googleapis.com:8443"),
    });
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace("storage.googleapis.com", "evil.example.com"),
    });
    refused({ method: "PUT", url: signed("rec1/ok.png").replace("https://", "https://user:pw@") });
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace(
        "storage.googleapis.com",
        "storage.googleapis.com.evil.example",
      ),
    });
    refused({ method: "GET", url: "https://firestore.googleapis.com/v1/projects/p" });
  });

  it("refuses objects outside the run prefix, other buckets, dot segments and control characters", () => {
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace(prefix, "storage-signed-put/sp-ffffffff/"),
    });
    refused({ method: "PUT", url: signed("rec1/ok.png").replace(prefix, "other/") });
    refused({
      method: "PUT",
      url: signed("rec1/ok.png").replace(PRODUCTION_LIKE.bucket, "other-bucket"),
    });
    refused({ method: "PUT", url: signed("rec1/../../x.png") });
    refused({ method: "PUT", url: signed("rec1/a%00b.png") });
    refused({ method: "GET", url: json(`/o/${encodeURIComponent("elsewhere/ok.png")}`) });
    refused({ method: "GET", url: json(`/o?prefix=${encodeURIComponent("storage-signed-put/")}`) });
    refused({ method: "GET", url: json("/o") });
    refused({ method: "GET", url: "https://storage.googleapis.com/storage/v1/b/other-bucket" });
  });

  it("refuses wrong methods and extra query parameters", () => {
    refused({ method: "DELETE", url: json("") });
    refused({ method: "POST", url: json("") });
    refused({ method: "POST", url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}`) });
    refused({ method: "GET", url: signed("rec1/ok.png") });
    refused({ method: "DELETE", url: signed("rec1/ok.png") });
    refused({ method: "PUT", url: signed("rec1/ok.png", "&uploadType=media") });
    refused({
      method: "GET",
      url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}?alt=json`),
    });
    refused({
      method: "DELETE",
      url: json(`/o/${encodeURIComponent(`${prefix}rec1/ok.png`)}?force=1`),
    });
    refused({
      method: "POST",
      url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/other@x.iam.gserviceaccount.com:signBlob`,
    });
  });

  it("never lets a signed request carry an Authorization header, and needs the signing parameters", () => {
    refused({ method: "PUT", url: signed("rec1/ok.png"), headers: { Authorization: "Bearer x" } });
    refused({ method: "PUT", url: signed("rec1/ok.png").replace("X-Goog-Expires=300&", "") });
    refused({
      method: "PUT",
      url: `https://storage.googleapis.com/${PRODUCTION_LIKE.bucket}/${prefix}rec1/ok.png`,
    });
  });

  it("holds the local target to its own origin", () => {
    const local = (path) => `${LOCAL_LIKE.origin}${path}`;
    assert.equal(
      kind({ method: "GET", url: local(`/storage/v1/b/${LOCAL_LIKE.bucket}`) }, LOCAL_LIKE),
      "bucket-get",
    );
    refused(
      { method: "GET", url: "http://127.0.0.1:9200/storage/v1/b/" + LOCAL_LIKE.bucket },
      LOCAL_LIKE,
    );
    refused({ method: "GET", url: json("") }, LOCAL_LIKE);
    refused(
      { method: "GET", url: local(`/storage/v1/b/${LOCAL_LIKE.bucket}`) },
      { ...LOCAL_LIKE, name: "elsewhere" },
    );
  });

  it("property: random mutations of a good object URL never pass outside the prefix", () => {
    const next = prng(0x51a9ed);
    const alphabet = ["", "x", "..", "%2e%2e", "%00", "a/b", "/", " ", "%2F", "é"];
    for (let i = 0; i < 400; i += 1) {
      const part = alphabet[Math.floor(next() * alphabet.length)];
      const name = `${part}${i}.png`;
      const url = signed(name).replace(
        prefix,
        next() < 0.5 ? "storage-signed-put/sp-aaaaaaaa/" : "",
      );
      assert.throws(() => kind({ method: "PUT", url }), GuardError, url);
    }
  });

  it("budgets requests with a main cap and a higher total cap for cleanup", () => {
    const budget = new RequestBudget(2, 4);
    budget.take();
    budget.take();
    assert.throws(() => budget.take(), GuardError);
    budget.cleanup = true;
    budget.take();
    budget.take();
    assert.throws(() => budget.take(), GuardError);
    assert.equal(budget.count, 4);
  });

  it("property: a status is unknown exactly when below 200, 3xx or 5xx and above", () => {
    for (let status = 0; status < 700; status += 1) {
      const expected = status < 200 || (status >= 300 && status < 400) || status >= 500;
      assert.equal(isUnknownStatus(status), expected, String(status));
    }
    assert.equal(isUnknownStatus(Number.NaN), true);
    assert.equal(isUnknownStatus(undefined), true);
    assert.equal(isUnknownStatus(409), false);
    assert.equal(isUnknownStatus(412), false);
  });

  it("property: tampering flips one hex digit and keeps every other byte; dropping removes only the signature", () => {
    const next = prng(0xbadc0de);
    for (let i = 0; i < 200; i += 1) {
      const hex = Array.from(
        { length: 512 },
        () => "0123456789abcdef"[Math.floor(next() * 16)],
      ).join("");
      const url = signed("rec1/ok.png").replace(sig, hex);
      const tampered = tamperSignature(url);
      assert.equal(tampered.length, url.length);
      const diffs = [...url].flatMap((c, k) => (c === tampered[k] ? [] : [k]));
      assert.deepEqual(diffs, [url.length - 1]);
      assert.match(tampered, /X-Goog-Signature=[0-9a-f]{512}$/);
      const dropped = dropSignature(url);
      assert.ok(!dropped.includes("X-Goog-Signature"));
      assert.equal(dropped, url.replace(`&X-Goog-Signature=${hex}`, ""));
    }
    assert.throws(() => tamperSignature(signed("a").replace(sig, "")), GuardError);
    assert.throws(() => dropSignature("https://x/y?a=b"), GuardError);
  });

  it("redacts signatures and credentials from any stored text", () => {
    const text = redactSignedUrl(signed("rec1/ok.png"));
    assert.ok(!text.includes(sig));
    assert.ok(!text.includes("s%40x"));
    assert.match(text, /X-Goog-Signature=<redacted>/);
    assert.match(text, /X-Goog-Credential=<redacted>/);
    assert.ok(text.includes("X-Goog-Expires=300"));
  });

  it("refuses a bad run prefix whichever half is wrong", () => {
    const request = { method: "GET", url: json("") };
    for (const bad of [
      "other/",
      "storage-signed-put/sp-1",
      "storage-signed-put",
      "",
      "/storage-signed-put/sp-1/",
    ]) {
      assert.throws(() => classifyRequest(PRODUCTION_LIKE, request, bad), GuardError, bad);
    }
  });

  it("refuses a user name alone in the URL", () => {
    refused({ method: "PUT", url: signed("rec1/ok.png").replace("https://", "https://user@") });
  });

  it("refuses dot segments hidden in one encoded JSON segment, and allows only control characters out of a name", () => {
    for (const name of [`${prefix}rec1/../x`, `${prefix}rec1/./x`, `${prefix}..`, `${prefix}.`]) {
      refused({ method: "GET", url: json(`/o/${encodeURIComponent(name)}`) });
    }
    for (const name of [`${prefix}rec1/a b.png`, `${prefix}rec1/~x.png`, `${prefix}rec1/..x.png`]) {
      assert.equal(
        kind({ method: "GET", url: json(`/o/${encodeURIComponent(name)}`) }),
        "object-get",
        name,
      );
    }
    for (const control of ["\u0000", "\u001f", "\u007f", "\n"]) {
      refused({
        method: "GET",
        url: json(`/o/${encodeURIComponent(`${prefix}rec1/a${control}b`)}`),
      });
    }
  });

  it("holds the IAM and signBlob requests to the signer, the project and the right method", () => {
    const iam = `https://iam.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}/serviceAccounts/${PRODUCTION_LIKE.signer}`;
    refused({ method: "POST", url: iam });
    refused({
      method: "GET",
      url: iam.replace(PRODUCTION_LIKE.signer, "other@x.iam.gserviceaccount.com"),
    });
    refused({ method: "GET", url: iam.replace(PRODUCTION_LIKE.project, "other-project") });
    refused({ method: "GET", url: `${iam}/keys` });
    refused({ method: "GET", url: `${iam}?alt=json` });
    const blob = `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${PRODUCTION_LIKE.signer}:signBlob`;
    refused({ method: "GET", url: blob });
    refused({ method: "POST", url: `${blob}?key=1` });
    refused({ method: "POST", url: blob.replace("/v1/", "/v2/") });
  });

  it("holds the JSON API to the exact list and object forms", () => {
    refused({ method: "POST", url: json(`/o?prefix=${encodeURIComponent(prefix)}`) });
    refused({ method: "DELETE", url: json(`/o?prefix=${encodeURIComponent(prefix)}`) });
    const name = encodeURIComponent(`${prefix}rec1/ok.png`);
    refused({ method: "GET", url: json(`/acl/${name}`) });
    refused({ method: "GET", url: json(`/xyz/${name}`) });
    refused({ method: "GET", url: json(`/o/${name}/extra`) });
    refused({ method: "PATCH", url: json(`/o/${name}`) });
    refused({ method: "GET", url: json(`/o/${name}?generation=1`) });
  });

  it("refuses an XML path with no object, and the bucket alone", () => {
    refused({
      method: "PUT",
      url: `https://storage.googleapis.com/${PRODUCTION_LIKE.bucket}?X-Goog-Algorithm=a&X-Goog-Credential=b&X-Goog-Date=c&X-Goog-Expires=1&X-Goog-SignedHeaders=host`,
    });
    refused({
      method: "PUT",
      url: `https://storage.googleapis.com/${PRODUCTION_LIKE.bucket}/?X-Goog-Algorithm=a&X-Goog-Credential=b&X-Goog-Date=c&X-Goog-Expires=1&X-Goog-SignedHeaders=host`,
    });
  });

  it("accepts only a service account of the sandbox project as the signer", () => {
    const project = "demo-project";
    const good = `firebase-adminsdk-fbsvc@${project}.iam.gserviceaccount.com`;
    assert.equal(validateSigner(good, project), good);
    assert.equal(
      validateSigner(`signer-abc@${project}.iam.gserviceaccount.com`, project),
      `signer-abc@${project}.iam.gserviceaccount.com`,
    );
    for (const bad of [
      undefined,
      "",
      null,
      42,
      "user@gmail.com",
      `a@${project}.iam.gserviceaccount.com`,
      `firebase-adminsdk-fbsvc@other-project.iam.gserviceaccount.com`,
      `firebase-adminsdk-fbsvc@${project}.iam.gserviceaccount.com.evil.example`,
      `x-firebase-adminsdk-fbsvc@${project}Xiam.gserviceaccount.com`,
      `firebase-adminsdk-fbsvc@${project}.iam.gserviceaccount.com:signBlob`,
      `firebase-adminsdk-fbsvc@${project}.iam.gserviceaccount.com/keys`,
      `Firebase-adminsdk-fbsvc@${project}.iam.gserviceaccount.com`,
      ` ${good}`,
      `${good}\n`,
      `${"a".repeat(31)}@${project}.iam.gserviceaccount.com`,
      `-abcdef@${project}.iam.gserviceaccount.com`,
      `abcdef-@${project}.iam.gserviceaccount.com`,
    ]) {
      assert.throws(() => validateSigner(bad, project), GuardError, String(bad));
    }
  });

  describe("IAM request forms", () => {
    const iam = (path) => `https://iam.googleapis.com/v1/${path}`;
    const account = `projects/${PRODUCTION_LIKE.project}/serviceAccounts/${PRODUCTION_LIKE.signer}`;
    const roles = `projects/${PRODUCTION_LIKE.project}/roles`;

    it("accepts exactly the signer, its policy, the signer role and role definitions", () => {
      const cases = [
        ["GET", iam(account), "signer-get"],
        [
          "POST",
          iam(`${account}:getIamPolicy?options.requestedPolicyVersion=3`),
          "signer-get-policy",
        ],
        ["POST", iam(`${account}:setIamPolicy`), "signer-set-policy"],
        ["POST", iam(roles), "role-create"],
        ["GET", iam(`${roles}/${ROLE_ID}`), "role-get"],
        ["DELETE", iam(`${roles}/${ROLE_ID}`), "role-delete"],
        ["DELETE", iam(`${roles}/${ROLE_ID}?etag=abc`), "role-delete"],
        ["GET", iam(`${roles}/customRole_1`), "role-read"],
        ["GET", iam(`${roles}/x`), "role-read"],
        ["GET", iam("roles/x"), "role-read"],
        ["GET", iam("roles/firebase.sdkAdminServiceAgent"), "role-read"],
        ["GET", iam("roles/storage.objectAdmin"), "role-read"],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}:getIamPolicy`,
          "project-policy",
        ],
        ["GET", json("/iam"), "bucket-policy"],
        ["GET", json("/iam?optionsRequestedPolicyVersion=3"), "bucket-policy"],
      ];
      for (const [method, url, expected] of cases)
        assert.equal(kind({ method, url }), expected, `${method} ${url}`);
    });

    it("refuses every other IAM form", () => {
      const other = "other@demo-project.iam.gserviceaccount.com";
      const bad = [
        ["PUT", iam(account)],
        ["DELETE", iam(account)],
        ["POST", iam(account)],
        ["GET", iam(`${account}:getIamPolicy`)],
        ["GET", iam(`${account}:setIamPolicy`)],
        ["POST", iam(`${account}:testIamPermissions`)],
        ["POST", iam(`${account}:signBlob`)],
        ["POST", iam(`${account}:disable`)],
        ["POST", iam(`${account}/keys`)],
        ["GET", iam(`${account}?x=1`)],
        ["POST", iam(`${account}:setIamPolicy?x=1`)],
        ["POST", iam(`projects/${PRODUCTION_LIKE.project}/serviceAccounts/${other}:setIamPolicy`)],
        ["GET", iam(`projects/other-project/serviceAccounts/${PRODUCTION_LIKE.signer}`)],
        ["GET", iam(`projects/${PRODUCTION_LIKE.project}/serviceAccounts`)],
        ["PATCH", iam(`${roles}/${ROLE_ID}`)],
        ["POST", iam(`${roles}/${ROLE_ID}`)],
        ["DELETE", iam(`${roles}/customRole_1`)],
        ["DELETE", iam(`${roles}/${ROLE_ID}?force=1`)],
        ["DELETE", iam("roles/viewer")],
        ["GET", iam(`${roles}/${ROLE_ID}?x=1`)],
        ["GET", iam(`${roles}/bad%20name`)],
        ["GET", iam(`${roles}/${"a".repeat(65)}`)],
        ["GET", iam("roles/bad/name")],
        ["GET", iam("roles/")],
        ["GET", iam("organizations/1/roles/x")],
        ["GET", iam("projects/other-project/roles/x")],
        ["POST", iam("roles")],
        ["PUT", iam(roles)],
        ["GET", iam(roles)],
        ["GET", "https://iam.googleapis.com/v2/roles/viewer"],
        ["GET", "https://iam.googleapis.com/"],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v1/projects/other-project:getIamPolicy`,
        ],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}:setIamPolicy`,
        ],
        [
          "GET",
          `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}:getIamPolicy`,
        ],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}:getIamPolicy?x=1`,
        ],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}`,
        ],
        [
          "POST",
          `https://cloudresourcemanager.googleapis.com/v3/projects/${PRODUCTION_LIKE.project}:getIamPolicy`,
        ],
        ["POST", json("/iam")],
        ["PUT", json("/iam")],
        ["GET", json("/iam?alt=json")],
        ["GET", json("/acl")],
        ["GET", "https://storage.googleapis.com/storage/v1/b/other-bucket/iam"],
        ["GET", "https://cloudresourcemanager.googleapis.com:8443/v1/projects/x:getIamPolicy"],
      ];
      for (const [method, url] of bad) refused({ method, url });
    });

    it("keeps IAM requests out of the local target", () => {
      refused({ method: "GET", url: iam(account) }, LOCAL_LIKE);
      refused(
        {
          method: "POST",
          url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}:getIamPolicy`,
        },
        LOCAL_LIKE,
      );
    });
  });
});
