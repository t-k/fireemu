import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { restrictionsSha256 } from "./storage-rules/acceptance-preflight.mjs";

// Test support for the assembled runner: a private packet whose facts a production-shaped preflight stream matches, and one
// transport that answers the preflight reads, the OAuth and signing-key endpoints and a small Identity Toolkit, and hands
// everything else to the simulator. Nothing here reaches a network.
export const sha = (value) => createHash("sha256").update(value).digest("hex");
export const CERT_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
export const OWNER_TOKEN = "synthetic-owner-access-token-00003";
export const ADC = {
  type: "authorized_user",
  client_id: "synthetic-client.apps.googleusercontent.com",
  client_secret: "synthetic-client-secret-00001",
  refresh_token: "synthetic-refresh-token-with/slash+00002",
  quota_project_id: "some-project",
};
export const NUMBERS = { query: "111111111111", idp: "222222222222" };
// The two key shapes production has: query's dedicated key has a custom ID and only the two sign-in services; idp's is the Browser key
// Firebase created, with a UUID ID, empty browser restrictions and many API targets.
export const KEY_IDS = {
  query: "fireemu-query-auth-20260925",
  idp: "00000000-0000-4000-8000-000000000002",
};
const IDP_SERVICES = [
  "identitytoolkit.googleapis.com",
  "securetoken.googleapis.com",
  "firebaserules.googleapis.com",
  "firestore.googleapis.com",
  "firebasestorage.googleapis.com",
  "firebase.googleapis.com",
  "firebaseinstallations.googleapis.com",
  "firebaseappcheck.googleapis.com",
  "fcm.googleapis.com",
  "fcmregistrations.googleapis.com",
  "firebaseremoteconfig.googleapis.com",
  "firebasedynamiclinks.googleapis.com",
  "firebaseml.googleapis.com",
  "firebasehosting.googleapis.com",
  "firebaseperusertopics.googleapis.com",
  "firebasecrashlytics.googleapis.com",
  "mobilecrashreporting.googleapis.com",
  "cloudconfig.googleapis.com",
  "growth.googleapis.com",
  "playintegrity.googleapis.com",
  "androidcheck.googleapis.com",
  "cloudfunctions.googleapis.com",
  "identity.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "firebaseinappmessaging.googleapis.com",
  "firebaselogging-pa.googleapis.com",
  "fireperf.googleapis.com",
];
export const KEY_RESTRICTIONS = {
  query: {
    apiTargets: [
      { service: "identitytoolkit.googleapis.com" },
      { service: "securetoken.googleapis.com" },
    ],
  },
  idp: { browserKeyRestrictions: {}, apiTargets: IDP_SERVICES.map((service) => ({ service })) },
};
export const KEY_TARGETS = {
  query: KEY_RESTRICTIONS.query.apiTargets.map((target) => target.service).sort(),
  idp: [...IDP_SERVICES].sort(),
};
export const API_KEYS = { query: "Q".repeat(39), idp: "I".repeat(39) };
export const BUCKET = "fireemu-fixture-rules-bucket";
export const SUBJECT = "107364905517293846281";
const bucketBindings = [{ role: "roles/storage.admin", members: ["user:owner@example.test"] }];
const projectBindings = [{ role: "roles/owner", members: ["user:owner@example.test"] }];
const canonical = (bindings) =>
  sha(
    JSON.stringify(
      bindings
        .map((entry) => ({ role: entry.role, members: [...entry.members].sort() }))
        .sort((a, b) => (a.role < b.role ? -1 : a.role > b.role ? 1 : 0)),
    ),
  );
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

export function privatePacket(adcPath) {
  return {
    schemaVersion: 1,
    adcPath,
    owner: { emailSha256: sha("owner@example.test"), subjectSha256: sha(SUBJECT) },
    projects: {
      query: {
        projectId: "fireemu-oracle-query",
        projectNumber: NUMBERS.query,
        apiKeyId: KEY_IDS.query,
        apiKey: API_KEYS.query,
        keyUid: "query-key-uid",
        apiTargets: KEY_TARGETS.query,
        restrictionsSha256: restrictionsSha256(KEY_RESTRICTIONS.query),
      },
      idp: {
        projectId: "fireemu-oracle-idp",
        projectNumber: NUMBERS.idp,
        apiKeyId: KEY_IDS.idp,
        apiKey: API_KEYS.idp,
        keyUid: "idp-key-uid",
        apiTargets: KEY_TARGETS.idp,
        restrictionsSha256: restrictionsSha256(KEY_RESTRICTIONS.idp),
      },
    },
    bucket: {
      name: BUCKET,
      location: "US-CENTRAL1",
      uniformBucketLevelAccess: true,
      iamPolicySha256: canonical(bucketBindings),
    },
    database: { locationId: "us-central1", type: "FIRESTORE_NATIVE" },
    queryProjectIamPolicySha256: canonical(projectBindings),
  };
}

const json = (body, status = 200) => ({
  status,
  rawHeaders: ["Content-Type", "application/json; charset=UTF-8"],
  bytes: Buffer.from(JSON.stringify(body)),
  startedAtMs: 1,
  finishedAtMs: 2,
});

// What production answers for the preflight reads when every fact matches the packet; `bad` may replace one route's body.
export function preflightAnswer(spec, bad = {}) {
  const url = new URL(spec.url);
  const path = url.pathname;
  const pick = (name, body) => json(bad[name] ?? body);
  if (url.host === "www.googleapis.com" && path === "/oauth2/v2/userinfo")
    return pick("identity", { id: SUBJECT, email: "owner@example.test", verified_email: true });
  let match = /^\/v3\/projects\/(\d+)$/.exec(path);
  if (url.host === "cloudresourcemanager.googleapis.com" && match) {
    const project = match[1] === NUMBERS.query ? "fireemu-oracle-query" : "fireemu-oracle-idp";
    return pick(`project-${match[1]}`, {
      name: `projects/${match[1]}`,
      projectId: project,
      state: "ACTIVE",
    });
  }
  match = /^\/v3\/projects\/(\d+):testIamPermissions$/.exec(path);
  if (url.host === "cloudresourcemanager.googleapis.com" && match)
    return pick(`permissions-${match[1]}`, {
      permissions: JSON.parse(spec.body.toString()).permissions,
    });
  if (url.host === "cloudresourcemanager.googleapis.com" && path.endsWith(":getIamPolicy"))
    return pick("project-iam", { bindings: projectBindings, version: 3 });
  match = /^\/v2\/projects\/(\d+)\/locations\/global\/keys\/([a-z0-9-]+)(\/keyString)?$/.exec(path);
  if (url.host === "apikeys.googleapis.com" && match) {
    const which = match[1] === NUMBERS.query ? "query" : "idp";
    if (match[3]) return pick(`keystring-${which}`, { keyString: API_KEYS[which] });
    return pick(`key-${which}`, {
      name: `projects/${match[1]}/locations/global/keys/${match[2]}`,
      uid: `${which}-key-uid`,
      restrictions: KEY_RESTRICTIONS[which],
    });
  }
  if (url.host === "storage.googleapis.com" && path === `/storage/v1/b/${BUCKET}`)
    return pick("bucket", {
      kind: "storage#bucket",
      name: BUCKET,
      projectNumber: NUMBERS.query,
      location: "US-CENTRAL1",
      iamConfiguration: { uniformBucketLevelAccess: { enabled: true } },
    });
  if (url.host === "storage.googleapis.com" && path === `/storage/v1/b/${BUCKET}/iam`)
    return pick("bucket-iam", { kind: "storage#policy", bindings: bucketBindings, version: 1 });
  if (
    url.host === "storage.googleapis.com" &&
    path === `/storage/v1/b/${BUCKET}/iam/testPermissions`
  )
    return pick("bucket-permissions", {
      kind: "storage#testIamPermissionsResponse",
      permissions: url.searchParams.getAll("permissions"),
    });
  if (
    url.host === "firestore.googleapis.com" &&
    path === "/v1/projects/fireemu-oracle-query/databases/(default)"
  )
    return pick("database", {
      name: "projects/fireemu-oracle-query/databases/(default)",
      locationId: "us-central1",
      type: "FIRESTORE_NATIVE",
    });
  return undefined;
}

export function fakeIdentity(clock) {
  const users = new Map();
  const secrets = ["private-refresh-secret"];
  let nextForeign = 0;
  const mint = (user, project) => {
    const iat = clock.now - 1;
    const payload = {
      iss: `https://securetoken.google.com/${project}`,
      aud: project,
      sub: user.localId,
      user_id: user.localId,
      iat,
      exp: iat + 3600,
      auth_time: iat,
      email: user.email,
      email_verified: user.emailVerified,
      firebase: { identities: { email: [user.email] }, sign_in_provider: "password" },
      ...JSON.parse(user.customAttributes || "{}"),
    };
    const data = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "test", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
    const token = `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
    secrets.push(token);
    return token;
  };
  return {
    users,
    secrets: () => [...secrets],
    handle(spec) {
      const url = new URL(spec.url);
      const body = JSON.parse(spec.body.toString("utf8"));
      const project = url.pathname.startsWith("/v1/projects/")
        ? url.pathname.split("/")[3]
        : url.searchParams.get("key") === API_KEYS.idp
          ? "fireemu-oracle-idp"
          : "fireemu-oracle-query";
      const path = url.pathname;
      const key = (uid) => `${project}/${uid}`;
      if (path.endsWith("/accounts") || path === "/v1/accounts:signUp") {
        const uid = body.localId || `foreign-captured-uid-${++nextForeign}`;
        const user = {
          localId: uid,
          email: body.email,
          emailVerified: body.emailVerified || false,
          customAttributes: "{}",
          validSince: String(clock.now - 100),
        };
        users.set(key(uid), user);
        return json({
          localId: uid,
          email: body.email,
          ...(path.endsWith(":signUp")
            ? { idToken: mint(user, project), refreshToken: "private-refresh-secret" }
            : {}),
        });
      }
      if (path.endsWith(":lookup")) {
        let found;
        if (body.idToken)
          found = [
            users.get(key(JSON.parse(Buffer.from(body.idToken.split(".")[1], "base64url")).sub)),
          ].filter(Boolean);
        else if (body.localId)
          found = body.localId.map((uid) => users.get(key(uid))).filter(Boolean);
        else
          found = [...users.entries()]
            .filter(([k, user]) => k.startsWith(`${project}/`) && body.email.includes(user.email))
            .map(([, user]) => user);
        return json({ users: structuredClone(found) });
      }
      if (path.endsWith(":update")) {
        const user = users.get(key(body.localId));
        if (Object.hasOwn(body, "customAttributes")) user.customAttributes = body.customAttributes;
        if (Object.hasOwn(body, "validSince")) user.validSince = body.validSince;
        return json({ localId: user.localId, email: user.email });
      }
      if (path.endsWith(":signInWithPassword")) {
        const user = [...users.entries()].find(
          ([k, u]) => k.startsWith(`${project}/`) && u.email === body.email,
        )?.[1];
        return json({
          localId: user.localId,
          email: user.email,
          idToken: mint(user, project),
          refreshToken: "private-refresh-secret",
        });
      }
      if (path.endsWith(":delete")) {
        users.delete(key(body.localId));
        return json({});
      }
      throw new Error(`unexpected identity route ${path}`);
    },
  };
}

// Everything the wire can reach, in one function; `simulator` answers the Storage, Rules and Firestore rows.
export function endpoints({
  simulator,
  clock: _clock,
  identity,
  bad = {},
  hook = () => undefined,
}) {
  return async (spec) => {
    const replaced = hook(spec);
    if (replaced !== undefined) return replaced;
    if (spec.url === CERT_URL)
      return {
        status: 200,
        rawHeaders: ["Cache-Control", "public, max-age=3600", "Age", "0"],
        bytes: Buffer.from(
          JSON.stringify({ test: publicKey.export({ type: "spki", format: "pem" }) }),
        ),
        startedAtMs: 1,
        finishedAtMs: 2,
      };
    if (spec.url.startsWith("https://oauth2.googleapis.com/"))
      return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (spec.url.startsWith("https://identitytoolkit.googleapis.com/"))
      return identity.handle(spec);
    const answer = preflightAnswer(spec, bad);
    if (answer !== undefined) return answer;
    return simulator.send(spec);
  };
}
