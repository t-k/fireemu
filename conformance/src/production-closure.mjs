import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BASELINE_PINS = {
  "AUTH-ACCOUNT": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-ACCOUNT.json",
      blob: "d19ebdceb2ad3b7e426847a4399d7105e34cd055",
      rawSha256: "d04ac6a82f575b2e6d107d7b4433f8bed2305330202dd69d14963ed574788c92",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 32,
  },
  "AUTH-ACTION": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-ACTION.json",
      blob: "e1ce0c2336547b24e7c8a6ade9456f80def99d5d",
      rawSha256: "9949c4d3b6b7fed48135b631239eb6070b6d7fd7e8fa14cd05320faceea73c7e",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 12,
  },
  "AUTH-CONFIG-SDK": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-CONFIG-SDK.json",
      blob: "b864eec5fdc4e0c8cfab532018c43742dec7b70c",
      rawSha256: "d49f1e87557bdf901fe93b450bae7b55d606681633e1de5bbd4243709179532b",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 21,
  },
  "AUTH-CREDENTIAL": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-CREDENTIAL.json",
      blob: "60b460d842e4b8e426d18e05cfaed4f4b8385db1",
      rawSha256: "4cc8ea55e03ad1825cddd527f910fd597c0f1e7d7696ecb9318d481d6dea0335",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 15,
  },
  "AUTH-FEDERATION": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-FEDERATION.json",
      blob: "8b10cc648677a6ad6e1f8563ea953c98abfef057",
      rawSha256: "6db291bb4d553a6c42537c416e8e2ec3650474495d4617786c606b85e8767a1d",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 24,
  },
  "AUTH-FS-CROSS": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-FS-CROSS.json",
      blob: "a0b5d1a2e5ee042a7fdd198ce2f97b5434741f3d",
      rawSha256: "ecc1d2c0a917a249990935cab3524f4428a18a7d275bd6ce3ea2beade38a2ee4",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 11,
  },
  "AUTH-MFA": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-MFA.json",
      blob: "cd501a49dc142ed5f5b4a565d7099120f0f35f63",
      rawSha256: "a1e72883bbb1974cdaa26013013c46487eb99ba11d6625916b9a4e5f33a59da7",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 14,
  },
  "AUTH-TENANT-BLOCKING": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/AUTH-TENANT-BLOCKING.json",
      blob: "7f66c34f448e8f4dd1453ce12d7ac79a9ffe9983",
      rawSha256: "abfc0d92fb63497b2f0fbd32fd6374c68d665886e9026cd19864e83bf52aae0c",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 27,
  },
  "FS-CONFIG-LIFECYCLE": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FS-CONFIG-LIFECYCLE.json",
      blob: "871b3688d23176faeff32dac8163dece0cf50209",
      rawSha256: "21ff48041dc4d09f777a7a59571e230a40db54c98a33e8239c9ac4982d5415ce",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 20,
  },
  "FS-DATA-WRITE": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FS-DATA-WRITE.json",
      blob: "503f090e549b1c07dded1f9df347d07aa20cfcd4",
      rawSha256: "418f10039714d8367ad573300982a2bfd6dd70fbd33c78932da69e8ea5c636a7",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 38,
  },
  "FS-QUERY-INDEX": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FS-QUERY-INDEX.json",
      blob: "c23a0d5ce7fa7d72df3583f66a7f74fe0005b0fb",
      rawSha256: "8d1b27fa081c77aeedce616a8194c5e85118cc1549a031aeccea35478db38736",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 21,
  },
  "FS-RULES": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FS-RULES.json",
      blob: "14ab75b92d86caa660449d07acc84d2f6735b102",
      rawSha256: "5f45a16bdec5e6968e2b818decb73fd1f680185ce3b6e4ad622c5bbaf5eb03a0",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 17,
  },
  "FS-TRANSACTION": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FS-TRANSACTION.json",
      blob: "8146f9ddbd7eb9d65cfb86adcfd8e31ff706ef87",
      rawSha256: "7f0633ab6a948890a4c742b17f50912c920a925a2a018cfdd636dc20278ef93f",
      snapshotPath:
        "spec/compatibility/official-compatibility/history/e57a78e0/FS-TRANSACTION.json",
      snapshotSha256: "7f0633ab6a948890a4c742b17f50912c920a925a2a018cfdd636dc20278ef93f",
    },
    track: "PRODUCTION_PENDING",
    conditionRegistrySha256: "1aa7850b3d7da2d085da904a3f795e3e371426d48e29edb27725e54e6c95f453",
    conditionCount: 18,
  },
  "FUNCTIONS-HTTP": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/FUNCTIONS-HTTP.json",
      blob: "5e0fc481dbd639f1bab1c9d225bb0d7fa9902eb9",
      rawSha256: "3f38facca11152463a4b272120681eb630eb4c290737127a156e0c82c6a69e96",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "PRESERVED_HISTORICAL",
    conditionRegistrySha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    conditionCount: 19,
  },
  "SCHEDULED-FUNCTIONS": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/SCHEDULED-FUNCTIONS.json",
      blob: "fc4e8138989530bbf53e7df67c82a3805e1476b5",
      rawSha256: "cc2218eb413d53db064f807b956a44ec81236aa6f2e662bd9acff6b45bcc1983",
      snapshotPath:
        "spec/compatibility/official-compatibility/history/e57a78e0/SCHEDULED-FUNCTIONS.json",
      snapshotSha256: "cc2218eb413d53db064f807b956a44ec81236aa6f2e662bd9acff6b45bcc1983",
    },
    track: "PRODUCTION_PENDING",
    conditionRegistrySha256: "3b30bd49dc9fc788308d78f4abd3406c39aa307c5aae5ac462591944205f3eec",
    conditionCount: 25,
  },
  "STORAGE-OBJECT": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/STORAGE-OBJECT.json",
      blob: "210652382062c5d7b7c9a485fd52793ef28b04cf",
      rawSha256: "0857ad38cdbd7655d1d46a8f72a233994dc38da20774ae4b339909279c8c162e",
      snapshotPath:
        "spec/compatibility/official-compatibility/history/e57a78e0/STORAGE-OBJECT.json",
      snapshotSha256: "0857ad38cdbd7655d1d46a8f72a233994dc38da20774ae4b339909279c8c162e",
    },
    track: "PRODUCTION_PENDING",
    conditionRegistrySha256: "20a426a13a746e6cbf9224ae70a7050a427ed9fcd078590b96c22174a7dd0689",
    conditionCount: 28,
  },
  "STORAGE-RULES": {
    sourceIdentity: {
      commit: "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
      gitObject:
        "e57a78e0f5c4852894d14fad31438b2fa9d681e0:spec/compatibility/closure/STORAGE-RULES.json",
      blob: "9eb23b1842e1fca2b6a3cd3f2465ce5c04c6adc8",
      rawSha256: "30d6f6f8b28cdebec4b2e1b8cc2aa6bb2aeaa0d86a2bcd58aa9e05a8b43379d8",
      snapshotPath: "spec/compatibility/official-compatibility/history/e57a78e0/STORAGE-RULES.json",
      snapshotSha256: "30d6f6f8b28cdebec4b2e1b8cc2aa6bb2aeaa0d86a2bcd58aa9e05a8b43379d8",
    },
    track: "PRODUCTION_PENDING",
    conditionRegistrySha256: "2c8277f1de58f92c6e91452f91e79b2caaa1e0502ac22ef527c6f849fc4a2888",
    conditionCount: 24,
  },
  "FS-LISTEN-SDK": {
    sourceIdentity: {
      commit: "e4f549410c1cd4aba58476988f5d07fa8eb5afed",
      gitObject:
        "e4f549410c1cd4aba58476988f5d07fa8eb5afed:spec/compatibility/closure/FS-LISTEN-SDK.json",
      blob: "e7e6452f2996ea1cacb4589c586d5c8b10bc2a6a",
      rawSha256: "0067836d43f427496eb7bb105e4c338aba8bbadfb07174b5b62fcd325041e716",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "UNPUBLISHED_FROZEN",
    conditionRegistrySha256: "7ebc576e8827cacf70a1b363e7717a1d15c83b90b2ba750a9cd2605854cca5de",
    conditionCount: 15,
  },
  "FUNCTIONS-EVENTS": {
    sourceIdentity: {
      commit: "391d5c239f60cb855ef310842e25318b72a80d45",
      gitObject:
        "391d5c239f60cb855ef310842e25318b72a80d45:spec/compatibility/closure/FUNCTIONS-EVENTS.json",
      blob: "c2c2df29695af0a29eeffe2266ba4c6cd46bcbe9",
      rawSha256: "c19f68def2ad700d628ed12171ca646f61793dd8d5eb1cfa576543a2a0b2bc27",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "UNPUBLISHED_FROZEN",
    conditionRegistrySha256: "8498fe04b4826a053ef8f54148412b5c66abad6a24ea5f252bc995c6a17ec7e4",
    conditionCount: 22,
  },
  PUBSUB: {
    sourceIdentity: {
      commit: "2f7da4b355f6ae4b3a69a6bb5392bbf4d00d0b07",
      gitObject: "2f7da4b355f6ae4b3a69a6bb5392bbf4d00d0b07:spec/compatibility/closure/PUBSUB.json",
      blob: "b88d71a4cb739431643b008e17081390304a4d3b",
      rawSha256: "75fc1fbab923cc3a6ddb0b01393a57ef85a61e76d58c41945ee7ae73fc55cfc5",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "UNPUBLISHED_FROZEN",
    conditionRegistrySha256: "f999d4f84b8d2b43dfa090abeb3e454070aebc12cc993dd56c13c8b4a804d3ae",
    conditionCount: 18,
  },
  EVENTARC: {
    sourceIdentity: {
      commit: "2f7da4b355f6ae4b3a69a6bb5392bbf4d00d0b07",
      gitObject:
        "2f7da4b355f6ae4b3a69a6bb5392bbf4d00d0b07:spec/compatibility/closure/EVENTARC.json",
      blob: "240597c17733022bf23439757a236e30c7da05b2",
      rawSha256: "a85cf91322b7c087ce9ba5635f2f49fa24c0c196c734d44f66cc3b7ef42fc68e",
      snapshotPath: null,
      snapshotSha256: null,
    },
    track: "UNPUBLISHED_FROZEN",
    conditionRegistrySha256: "739dd599e56cc50a2184ce91970729d6a8746e3b3ffccaca429f0be4aa33f6e1",
    conditionCount: 11,
  },
};
const REQUIRED_PARENTS = [
  "AUTH-ACCOUNT",
  "AUTH-ACTION",
  "AUTH-CONFIG-SDK",
  "AUTH-CREDENTIAL",
  "AUTH-FEDERATION",
  "AUTH-FS-CROSS",
  "AUTH-MFA",
  "AUTH-TENANT-BLOCKING",
  "FS-CONFIG-LIFECYCLE",
  "FS-DATA-WRITE",
  "FS-QUERY-INDEX",
  "FS-RULES",
  "FS-TRANSACTION",
  "FUNCTIONS-HTTP",
  "SCHEDULED-FUNCTIONS",
  "STORAGE-OBJECT",
  "STORAGE-RULES",
  "FS-LISTEN-SDK",
  "FUNCTIONS-EVENTS",
  "PUBSUB",
  "EVENTARC",
];

export const REGISTRY_PATH = "spec/compatibility/production-parent-registry.json";
const OFFICIAL_PATH = "spec/compatibility/official-compatibility/registry.json";
const LOCK_PATH = "spec/compatibility/closure/record-digests.json";
const STATUS_PATH = "docs/compatibility/production-parent-status.md";
const BASE_COMMIT = "e57a78e0f5c4852894d14fad31438b2fa9d681e0";
const CONSUMERS = [
  "conformance/src/fs-transaction-closure.test.mjs",
  "conformance/src/storage-object-closure.test.mjs",
  "conformance/src/storage-rules-closure.test.mjs",
  "conformance/src/scheduled-functions-closure.test.mjs",
];
const REQUIRED_KINDS = new Set([
  "PRODUCTION_BEHAVIOR",
  "LOCAL_PRODUCT",
  "FINAL_PRODUCT",
  "CLEAN_REVIEW",
  "EMULATOR_PROFILE_CONTRACT",
]);
const sha = (value) => createHash("sha256").update(value).digest("hex");

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .toSorted()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function parseStrictJson(input) {
  let text;
  try {
    text =
      typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new Error("JSON input must be valid UTF-8");
  }
  const document = JSON.parse(text);
  let offset = 0;
  const whitespace = () => {
    while (/\s/.test(text[offset] ?? "") && offset < text.length) offset++;
  };
  const string = () => {
    const start = offset++;
    while (text[offset] !== '"') {
      if (text[offset] === "\\") offset++;
      offset++;
    }
    offset++;
    return JSON.parse(text.slice(start, offset));
  };
  const value = () => {
    whitespace();
    if (text[offset] === "{") {
      offset++;
      const keys = new Set();
      whitespace();
      while (text[offset] !== "}") {
        const key = string();
        if (keys.has(key)) throw new Error(`duplicate JSON key ${key}`);
        keys.add(key);
        whitespace();
        offset++;
        value();
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
        whitespace();
      }
      offset++;
    } else if (text[offset] === "[") {
      offset++;
      whitespace();
      while (text[offset] !== "]") {
        value();
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
      }
      offset++;
    } else if (text[offset] === '"') string();
    else while (offset < text.length && !/[\s,}\]]/.test(text[offset])) offset++;
  };
  value();
  return document;
}

function demand(condition, reason) {
  if (!condition) throw new Error(reason);
}

function closed(value, keys, label) {
  demand(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label}: object required`,
  );
  demand(
    canonical(Object.keys(value).toSorted()) === canonical([...keys].toSorted()),
    `${label}: closed fields differ`,
  );
}

function equal(actual, expected, label) {
  demand(
    canonical(actual) === canonical(expected),
    `${label} differs from the immutable original contract`,
  );
}

function pointer(document, selector) {
  return selector
    .slice(1)
    .split("/")
    .reduce((value, key) => value?.[key.replaceAll("~1", "/").replaceAll("~0", "~")], document);
}

function conditionRegistry(conditions) {
  return conditions.map((condition, index) => ({
    conditionId: condition.conditionId,
    originalPointer: `/conditions/${index}`,
    originalSha256: sha(canonical(condition)),
    cases: condition.cases ?? [],
    casesSha256: sha(canonical(condition.cases ?? [])),
  }));
}

function expectedFacet(condition, index, kind) {
  return {
    facetId: `${condition.conditionId}::${kind.toLowerCase()}`,
    kind,
    originalSelectors: [`/conditions/${index}`],
    state: "OPEN",
    evidence: null,
  };
}

function expectedConditions(parent, original) {
  return original.conditions.map((condition, index) => {
    const kind = condition.conditionId.endsWith("/final-artifact-regression")
      ? "FINAL_PRODUCT"
      : condition.conditionId.endsWith("/closure-review")
        ? "CLEAN_REVIEW"
        : condition.evidenceType === "fireemu-only"
          ? "LOCAL_PRODUCT"
          : "PRODUCTION_BEHAVIOR";
    const mixed = ["STORAGE-OBJECT", "STORAGE-RULES"].includes(parent) && kind === "FINAL_PRODUCT";
    const facets = [expectedFacet(condition, index, kind)];
    if (mixed) facets.push(expectedFacet(condition, index, "OFFICIAL_COMPARISON"));
    return {
      conditionId: condition.conditionId,
      originalPointer: `/conditions/${index}`,
      classification: mixed ? "MIXED" : "PRODUCTION_REQUIRED",
      facets,
    };
  });
}

function expectedProfile(parent) {
  const selector =
    parent === "FS-TRANSACTION"
      ? "/profileComparison"
      : ["STORAGE-OBJECT", "STORAGE-RULES"].includes(parent)
        ? "/observationContract"
        : "/conditions/23/cases/3";
  return {
    facetId: `${parent}::emulator-profile-contract`,
    kind: "EMULATOR_PROFILE_CONTRACT",
    originalSelectors: [selector],
    state: "OPEN",
    evidence: null,
  };
}

function expectedOfficial(parent, original, identity) {
  const tasks = [];
  if (parent === "FS-TRANSACTION") {
    tasks.push({
      facetId: `${parent}::official-profile-comparison`,
      parent,
      conditionId: null,
      snapshotPath: identity.snapshotPath,
      snapshotSha256: identity.snapshotSha256,
      originalSelectors: ["/profileComparison/note"],
      originalTextSha256: [sha(canonical(original.profileComparison.note))],
      originalStatus: original.profileComparison.emulatorCompatibilityCheck,
      state: "OPEN",
      evidence: null,
    });
  } else if (["STORAGE-OBJECT", "STORAGE-RULES"].includes(parent)) {
    const index = original.conditions.findIndex((condition) =>
      condition.conditionId.endsWith("/final-artifact-regression"),
    );
    const condition = original.conditions[index];
    const facet = expectedFacet(condition, index, "OFFICIAL_COMPARISON");
    tasks.push({
      facetId: facet.facetId,
      parent,
      conditionId: condition.conditionId,
      snapshotPath: identity.snapshotPath,
      snapshotSha256: identity.snapshotSha256,
      originalSelectors: facet.originalSelectors,
      originalTextSha256: [sha(canonical(condition))],
      originalStatus: condition.status,
      state: "OPEN",
      evidence: null,
    });
  }
  return tasks;
}

/** A pure necessary-state predicate. It does not admit evidence or issue closure authority. */
export function productionEligible(facets) {
  if (!Array.isArray(facets) || facets.length === 0) return false;
  const mandatory = facets.filter((facet) => facet?.kind !== "OFFICIAL_COMPARISON");
  return (
    mandatory.length > 0 &&
    mandatory.every((facet) => REQUIRED_KINDS.has(facet?.kind) && facet.state === "VERIFIED")
  );
}

export function loadRepository(root) {
  const documents = new Map();
  const read = (path) => {
    if (!documents.has(path)) documents.set(path, readFileSync(resolve(root, path)));
    return parseStrictJson(documents.get(path));
  };
  const registry = read(REGISTRY_PATH);
  const official = read(OFFICIAL_PATH);
  const lock = read(LOCK_PATH);
  for (const parent of REQUIRED_PARENTS) {
    const pin = BASELINE_PINS[parent];
    if (pin.track !== "UNPUBLISHED_FROZEN") read(`spec/compatibility/closure/${parent}.json`);
    if (pin.sourceIdentity.snapshotPath) read(pin.sourceIdentity.snapshotPath);
  }
  for (const path of CONSUMERS) documents.set(path, readFileSync(resolve(root, path)));
  return { registry, official, documents, lock };
}

export function checkProjection({ registry, official, documents, lock }) {
  const result = {
    problems: [],
    requiredParents: 21,
    historicalAccepted: [],
    remaining: [],
    publicOriginalConditions: 0,
    unpublishedOriginalConditions: 0,
    currentProductionVerified: [],
    officialRemaining: [],
    requireAll: false,
    canonicalPins: "PENDING_ROOT_GENERATION",
    pendingPins: [],
    consumerMigration: "PENDING_SECOND_DELTA",
    globalFinalProduct: "PENDING",
  };
  try {
    closed(
      registry,
      [
        "schemaVersion",
        "policy",
        "baselineSourceCommit",
        "requiredParentIds",
        "originalPendingConditionCount",
        "officialRegistryPath",
        "officialRegistrySha256",
        "consumerMigration",
        "globalFinalProduct",
        "parents",
      ],
      "production registry",
    );
    equal(registry.schemaVersion, 1, "schema version");
    equal(registry.policy, "production-first-original-facets-v1", "production policy");
    equal(registry.baselineSourceCommit, BASE_COMMIT, "baseline source");
    equal(registry.requiredParentIds, REQUIRED_PARENTS, "required parent IDs");
    demand(Array.isArray(registry.parents), "required parent entries must be an array");
    equal(
      registry.parents.map((parent) => parent.parent).toSorted(),
      [...REQUIRED_PARENTS].toSorted(),
      "required parent entries",
    );
    equal(registry.originalPendingConditionCount, 161, "original pending condition count");
    equal(registry.officialRegistryPath, OFFICIAL_PATH, "official registry path");
    demand(
      sha(documents.get(OFFICIAL_PATH)) === registry.officialRegistrySha256,
      "official registry real digest differs",
    );
    equal(
      registry.consumerMigration,
      {
        state: "PENDING_SECOND_DELTA",
        consumers: CONSUMERS,
        evidenceAdmission: "PENDING_SOURCE_BOUND_EVIDENCE_ADOPTION",
      },
      "consumer migration and evidence admission",
    );
    equal(
      registry.globalFinalProduct,
      {
        state: "PENDING",
        sourceCommit: null,
        artifactSha256: null,
        runnerSha256: null,
        comparison: null,
        independentReview: null,
      },
      "global final product and independent review",
    );
    const tasks = [];
    for (const row of registry.parents) {
      const label = row.parent;
      const pin = BASELINE_PINS[label];
      closed(
        row,
        [
          "parent",
          "publicationState",
          "track",
          "inventoryPath",
          "sourceIdentity",
          "conditionRegistry",
          "conditions",
          "profileContract",
        ],
        label,
      );
      equal(row.track, pin.track, `${label} track`);
      equal(row.sourceIdentity, pin.sourceIdentity, `${label} source identity`);
      const unpublished = pin.track === "UNPUBLISHED_FROZEN";
      equal(
        row.publicationState,
        unpublished ? "UNKNOWN" : "PUBLISHED",
        `${label} publication state`,
      );
      equal(
        row.inventoryPath,
        unpublished ? null : `spec/compatibility/closure/${label}.json`,
        `${label} inventory path`,
      );
      demand(
        sha(canonical(row.conditionRegistry)) === pin.conditionRegistrySha256,
        `${label} original condition registry differs`,
      );
      if (unpublished) {
        demand(
          row.conditionRegistry.length === pin.conditionCount,
          `${label} frozen conditions missing`,
        );
        equal(row.conditions, [], `${label} unpublished conditions cannot be adopted`);
        equal(row.profileContract, null, `${label} unpublished profile`);
        result.unpublishedOriginalConditions += pin.conditionCount;
        result.remaining.push({
          parent: label,
          state: "UNKNOWN_PUBLICATION",
          conditions: pin.conditionCount,
        });
        continue;
      }
      demand(documents.has(row.inventoryPath), `${label} current inventory missing`);
      if (pin.track === "PRESERVED_HISTORICAL") {
        const raw = documents.get(row.inventoryPath);
        demand(
          sha(raw) === pin.sourceIdentity.rawSha256,
          `${label} historical approval inventory bytes changed`,
        );
        const original = parseStrictJson(raw);
        demand(
          original.parentStatus === "COMPAT_VERIFIED" &&
            original.closureReview.decision === "APPROVED",
          `${label} historical acceptance missing`,
        );
        demand(
          original.conditions.every((condition) =>
            ["VERIFIED", "KNOWN_DIFFERENCE_APPROVED"].includes(condition.status),
          ),
          `${label} historical condition acceptance missing`,
        );
        equal(row.conditions, [], `${label} historical approvals must not be reissued`);
        equal(row.profileContract, null, `${label} historical profile must not be reissued`);
        result.historicalAccepted.push(label);
        continue;
      }
      const raw = documents.get(pin.sourceIdentity.snapshotPath);
      demand(
        raw && sha(raw) === pin.sourceIdentity.rawSha256,
        `${label} original history snapshot bytes changed`,
      );
      const original = parseStrictJson(raw);
      equal(
        row.conditionRegistry,
        conditionRegistry(original.conditions),
        `${label} original IDs, cases and text`,
      );
      equal(
        row.conditions,
        expectedConditions(label, original),
        `${label} production, mixed, local, final and review obligations`,
      );
      equal(row.profileContract, expectedProfile(label), `${label} emulator profile contract`);
      for (const selector of row.profileContract.originalSelectors)
        demand(
          pointer(original, selector) !== undefined,
          `${label} original profile selector missing`,
        );
      tasks.push(...expectedOfficial(label, original, pin.sourceIdentity));
      result.publicOriginalConditions += original.conditions.length;
      result.remaining.push({
        parent: label,
        state: "PENDING_PRODUCTION_ADOPTION",
        conditions: original.conditions.length,
      });
    }
    closed(official, ["schemaVersion", "policy", "historyAuthority", "tasks"], "official registry");
    equal(official.schemaVersion, 1, "official schema");
    equal(official.policy, "official-comparison-independent-v1", "official policy");
    equal(
      official.historyAuthority,
      "IMMUTABLE_ORIGINAL_NOT_CURRENT_APPROVAL",
      "official historical authority",
    );
    const sortedTasks = tasks.toSorted((a, b) => a.facetId.localeCompare(b.facetId, "en"));
    equal(official.tasks, sortedTasks, "official tasks, selectors and preserved statuses");
    result.officialRemaining = sortedTasks.map((task) => ({
      facetId: task.facetId,
      originalStatus: task.originalStatus,
    }));
    demand(
      result.publicOriginalConditions === 95 && result.unpublishedOriginalConditions === 66,
      "original 95 public and 66 unpublished conditions must remain",
    );
    const requiredPins = new Map([
      [REGISTRY_PATH, sha(documents.get(REGISTRY_PATH))],
      [OFFICIAL_PATH, sha(documents.get(OFFICIAL_PATH))],
      ...REQUIRED_PARENTS.filter((parent) => BASELINE_PINS[parent].track !== "UNPUBLISHED_FROZEN")
        .map((parent) => `spec/compatibility/closure/${parent}.json`)
        .map((path) => [path, sha(documents.get(path))]),
      ...CONSUMERS.map((path) => [path, sha(documents.get(path))]),
      ...Object.values(BASELINE_PINS)
        .filter((pin) => pin.sourceIdentity.snapshotPath)
        .map((pin) => [pin.sourceIdentity.snapshotPath, pin.sourceIdentity.rawSha256]),
    ]);
    for (const [path, digest] of requiredPins) {
      if (lock?.records?.[path] !== digest) result.pendingPins.push(path);
    }
    if (result.pendingPins.length === 0) result.canonicalPins = "CURRENT";
  } catch (error) {
    result.problems.push(error.message);
  }
  result.historicalAccepted.sort();
  result.remaining.sort((a, b) => a.parent.localeCompare(b.parent, "en"));
  result.pendingPins.sort();
  // This first slice admits no new evidence. Pure fixture success is not closure authority.
  result.requireAll =
    result.problems.length === 0 &&
    result.remaining.length === 0 &&
    result.globalFinalProduct === "VERIFIED" &&
    result.consumerMigration === "COMPLETE" &&
    result.canonicalPins === "CURRENT";
  return result;
}

export function renderStatus(result) {
  const lines = [
    "# Production parent status",
    "",
    "Status: `IN_PROGRESS`",
    "",
    "This deterministic report covers the fixed 21-parent production scope. Original approvals and observations remain historical; this source integrity checkpoint issues no new production acceptance.",
    "",
    "## Resolved production gaps",
    "",
    "None newly accepted by this checkpoint.",
    "",
    "## Remaining production gaps or unobserved conditions",
    "",
    "| Parent | Current production state | Original conditions |",
    "| --- | --- | ---: |",
    ...result.remaining.map((row) => `| ${row.parent} | \`${row.state}\` | ${row.conditions} |`),
    "",
    `The four published pending inventories retain ${result.publicOriginalConditions} original conditions. The four unpublished frozen inventories retain ${result.unpublishedOriginalConditions} condition and case bindings with UNKNOWN publication. Their immutable source references are provenance, not public adoption.`,
    "",
    "## Production verification completed",
    "",
    `The following ${result.historicalAccepted.length} parent approvals are preserved from the immutable integration baseline; they are not reissued for a new final artifact:`,
    "",
    ...result.historicalAccepted.map((parent) => `- ${parent}`),
    "",
    "Current final-artifact production verification for the remaining eight parents is incomplete. Saved partial equality, synthetic fixtures and source-only checks do not complete those conditions.",
    "",
    "## Official-only remaining work",
    "",
    "| Independent official comparison | Current state | Preserved original status |",
    "| --- | --- | --- |",
    ...result.officialRemaining.map(
      (task) => `| ${task.facetId} | \`OPEN\` | \`${task.originalStatus}\` |`,
    ),
    "",
    "An official comparison may remain OPEN independently of production closure. Mixed production obligations, local product checks, final artifact and independent review requirements, and the emulator profile contract remain mandatory. Shared original text is retained in full rather than rewritten.",
    "",
    "## Integration conditions",
    "",
    `- Canonical projection record pins: \`${result.canonicalPins}\`; the full \`closure_records.py --check\` gate remains required.`,
    `- Existing Node consumer migration: \`${result.consumerMigration}\`.`,
    "- New evidence admission: `PENDING_SOURCE_BOUND_EVIDENCE_ADOPTION`.",
    `- Same final product and independent review: \`${result.globalFinalProduct}\`.`,
    "- `--check` validates honest pending integrity. It does not certify closure; `--require-all` refuses this checkpoint.",
    "",
    "The original four closure JSON files, their existing Node contracts and the historical 13 approvals remain unchanged. The subsequent consumer delta and the coordinator's canonical lock generation require fresh checks on the resulting tree.",
    "",
  ];
  return lines.join("\n");
}

function main(argv) {
  demand(
    argv.length === 1 && ["--check", "--require-all"].includes(argv[0]),
    "usage: node conformance/src/production-closure.mjs --check|--require-all",
  );
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const result = checkProjection(loadRepository(root));
  demand(
    readFileSync(resolve(root, STATUS_PATH), "utf8") === renderStatus(result),
    "deterministic public status differs; regenerate and review it",
  );
  console.log(JSON.stringify(result));
  return result.problems.length || (argv[0] === "--require-all" && !result.requireAll) ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
