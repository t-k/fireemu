import assert from "node:assert/strict";
export function endpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("explicit loopback HTTP endpoint required");
  }
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname) ||
    !url.port ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("explicit loopback HTTP endpoint required");
  }
  return url;
}

export async function boundedRequest(promise, milliseconds = 10000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              Object.assign(new Error("fixture request deadline"), { code: "FIXTURE_TIMEOUT" }),
            ),
          milliseconds,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const item = "00000000-0000-4000-8000-000000000001";
const parent = "00000000-0000-4000-8000-000000000002";
const second = "00000000-0000-4000-8000-000000000004";
const rolledBack = "00000000-0000-4000-8000-000000000003";

export async function runCorpus(target, raw) {
  const url = endpoint(target);
  const { initializeApp, deleteApp } = await import("firebase/app");
  const {
    getDataConnect,
    connectDataConnectEmulator,
    queryRef,
    mutationRef,
    executeQuery,
    executeMutation,
    terminate,
    QueryFetchPolicy,
  } = await import("firebase/data-connect");
  const app = initializeApp({
    projectId: "demo-fireemu-dataconnect",
    apiKey: "synthetic-key",
    appId: "synthetic-app",
  });
  const dc = getDataConnect(app, {
    service: "fixture",
    connector: "fixture",
    location: "us-central1",
  });
  connectDataConnectEmulator(dc, url.hostname.replace(/^\[|\]$/g, ""), Number(url.port));
  const results = [];
  const call = async (id, kind, operation, variables, shouldFail = false) => {
    let result;
    try {
      const ref =
        kind === "query"
          ? queryRef(dc, operation, variables)
          : mutationRef(dc, operation, variables);
      const response = await boundedRequest(
        kind === "query"
          ? executeQuery(ref, { fetchPolicy: QueryFetchPolicy.SERVER_ONLY })
          : executeMutation(ref),
      );
      result = { id, data: response.data };
    } catch (error) {
      if (error.code === "FIXTURE_TIMEOUT") throw error;
      result = { id, error: { code: error.code ?? null, message: error.message } };
    }
    raw({ id, operation, variables, result });
    assert.equal(
      Boolean(result.error),
      shouldFail,
      `${id}: unexpected success/error: ${JSON.stringify(result)}`,
    );
    results.push(result);
    return result;
  };
  try {
    assert.deepEqual((await call("empty", "query", "ListItems", {})).data, { items: [] });
    await call("parent", "mutation", "SetParent", { id: parent, name: "Fixture parent" });
    await call("insert", "mutation", "SetItem", {
      id: item,
      title: "Alpha",
      note: "café",
      parentId: parent,
    });
    await call("read", "query", "GetItem", { id: item });
    await call("nullable", "mutation", "SetItem", {
      id: item,
      title: "Alpha",
      note: null,
      parentId: parent,
    });
    await call("relationship", "query", "ListItems", {});
    await call("second-item", "mutation", "SetItem", { id: second, title: "Beta", note: null });
    const ordered = await call("ordering", "query", "ListItems", {});
    assert.deepEqual(
      ordered.data.items.map((row) => row.title),
      ["Alpha", "Beta"],
    );
    await call("wrong-type", "mutation", "SetItem", { id: item, title: { invalid: true } }, true);
    await call("auth-denied", "query", "ProtectedItems", {}, true);
    await call("unknown-operation", "query", "DoesNotExist", {}, true);
    for (const kind of ["query", "mutation"]) {
      for (const variable of ["valid", "missing", "null"]) {
        const variables = kind === "query" ? {} : { id: item };
        const key = kind === "query" ? "id" : "title";
        if (variable === "valid") variables[key] = kind === "query" ? item : "Updated";
        if (variable === "null") variables[key] = null;
        await call(
          `matrix-${kind}-${variable}`,
          kind,
          kind === "query" ? "GetItem" : "SetItem",
          variables,
          variable !== "valid",
        );
      }
    }
    await call("rollback", "mutation", "Rollback", { id: rolledBack }, true);
    assert.deepEqual(
      (await call("rollback-readback", "query", "GetItem", { id: rolledBack })).data,
      { item: null },
    );
    await call("delete", "mutation", "DeleteItem", { id: item });
    assert.deepEqual((await call("delete-readback", "query", "GetItem", { id: item })).data, {
      item: null,
    });
    await call("persistence-seed", "mutation", "SetItem", {
      id: item,
      title: "Persisted",
      note: null,
    });
    await call("persistence-before", "query", "GetItem", { id: item });
    return results;
  } finally {
    await boundedRequest(terminate(dc), 3000);
    await deleteApp(app);
  }
}

export async function readPersistence(target) {
  const url = endpoint(target);
  const { initializeApp, deleteApp } = await import("firebase/app");
  const {
    getDataConnect,
    connectDataConnectEmulator,
    queryRef,
    executeQuery,
    terminate,
    QueryFetchPolicy,
  } = await import("firebase/data-connect");
  const app = initializeApp({
    projectId: "demo-fireemu-dataconnect",
    apiKey: "synthetic-key",
    appId: "synthetic-app",
  });
  const dc = getDataConnect(app, {
    service: "fixture",
    connector: "fixture",
    location: "us-central1",
  });
  connectDataConnectEmulator(dc, url.hostname.replace(/^\[|\]$/g, ""), Number(url.port));
  try {
    return (
      await boundedRequest(
        executeQuery(queryRef(dc, "GetItem", { id: item }), {
          fetchPolicy: QueryFetchPolicy.SERVER_ONLY,
        }),
      )
    ).data;
  } finally {
    await boundedRequest(terminate(dc), 3000);
    await deleteApp(app);
  }
}
