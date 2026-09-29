import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { originalProductionOwnerAuthorizationProvider } from "./production-owner.mjs";
import { originalProductionAuthAuthorizationProvider } from "./production-auth.mjs";
import { isProductionSecretRegistry } from "./production-secret-registry.mjs";
import {
  isProductionStandaloneFailStop,
  callProductionStandaloneProvider,
  failStopProductionStandalone,
} from "./production-standalone-fail-stop.mjs";

const bindings = new WeakMap();

function context(supplied) {
  try {
    const row = copyProductionCaptureRecord(supplied, [
      "recording",
      "kind",
      "phase",
      "operationId",
    ]);
    if (
      Object.keys(row).length !== 4 ||
      ![1, 2].includes(row.recording) ||
      !["subject", "cleanup"].includes(row.phase) ||
      typeof row.kind !== "string" ||
      !/^[a-z][a-z0-9-]{0,63}$/.test(row.kind) ||
      typeof row.operationId !== "string" ||
      !new RegExp(`^r${row.recording}/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)/[a-f0-9]{64}$`).test(
        row.operationId,
      )
    )
      throw new Error();
    return Object.freeze(row);
  } catch {
    throw new Error("invalid production credential context");
  }
}

/** Original credential methods and the shared registry stay private; the runtime must also pin their full callback/source closure. */
export function createProductionCredentialProviders(supplied) {
  let boundary, registry;
  try {
    const input = copyProductionCaptureRecord(supplied, ["boundary", "registry"]);
    if (
      Object.keys(input).length !== 2 ||
      !isProductionStandaloneFailStop(input.boundary) ||
      !isProductionSecretRegistry(input.registry)
    )
      throw new Error();
    ({ boundary, registry } = input);
    registry.openScan();
  } catch {
    throw new Error("invalid production credential providers");
  }
  const owners = new Map(),
    accounts = new Map();
  let closed = false;
  function bind(map, original, recording, state) {
    try {
      if (closed || ![1, 2].includes(recording) || map.has(recording)) throw new Error();
      const provider = original(state, recording);
      map.set(recording, provider);
    } catch {
      throw new Error("invalid production credential binding");
    }
  }
  const remember = (value) => {
    registry.register(value);
  };
  function call(kind, provider, args, row) {
    if (closed || !provider)
      failStopProductionStandalone(boundary, {
        recording: row.recording,
        operationId: row.operationId,
        providerKind: kind,
        reason: "PROVIDER_THREW",
      });
    return callProductionStandaloneProvider({
      boundary,
      kind,
      provider,
      args,
      recording: row.recording,
      operationId: row.operationId,
    });
  }
  function register(row, value) {
    call("secret", remember, [value], row);
  }
  const providers = Object.freeze({
    bindOwner: (recording, state) =>
      bind(owners, originalProductionOwnerAuthorizationProvider, recording, state),
    bindAuth: (recording, state) =>
      bind(accounts, originalProductionAuthAuthorizationProvider, recording, state),
    ownerAuthorization(suppliedContext) {
      const row = context(suppliedContext);
      const value = call("owner", owners.get(row.recording), [row], row);
      register(row, value.slice(7));
      return value;
    },
    accountAuthorization(ref, suppliedContext) {
      const row = context(suppliedContext);
      const value = call("account", accounts.get(row.recording), [ref, row], row);
      register(row, value.slice(9));
      return value;
    },
    registerSecret(suppliedContext, value) {
      register(context(suppliedContext), value);
    },
    close() {
      closed = true;
      owners.clear();
      accounts.clear();
    },
  });
  bindings.set(providers, {
    registry,
    ownerAuthorization: providers.ownerAuthorization,
    accountAuthorization: providers.accountAuthorization,
  });
  return providers;
}

/** A copied facade or a different task registry cannot supply wire providers. */
export function originalProductionCredentialProviderFunctions(providers, registry) {
  const binding = bindings.get(providers);
  if (!binding || registry !== binding.registry)
    throw new Error("invalid production credential providers");
  return Object.freeze({
    ownerAuthorization: binding.ownerAuthorization,
    accountAuthorization: binding.accountAuthorization,
  });
}
