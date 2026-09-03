const comparableBySubscription = (events) => {
  const subscriptions = new Map();
  for (const event of events) {
    const values = subscriptions.get(event.subscription) ?? [];
    values.push(event);
    subscriptions.set(event.subscription, values);
  }
  return subscriptions;
};

export function normalizeCallback(callback) {
  return {
    subscription: callback.subscription,
    ordinal: callback.ordinal ?? 1,
    kind: callback.kind,
    ids: callback.ids,
    revisions: callback.revisions,
    changes: callback.changes,
    fromCache: callback.metadata.fromCache,
    hasPendingWrites: callback.metadata.hasPendingWrites,
  };
}

export function compareSubscriptionTraces(oracle, actual) {
  const expected = comparableBySubscription(oracle);
  const observed = comparableBySubscription(actual);
  const names = new Set([...expected.keys(), ...observed.keys()]);
  for (const subscription of names) {
    const oracleEvents = expected.get(subscription) ?? [];
    const actualEvents = observed.get(subscription) ?? [];
    if (JSON.stringify(oracleEvents) !== JSON.stringify(actualEvents)) {
      return {
        equal: false,
        subscription,
        oracle: oracleEvents,
        actual: actualEvents,
      };
    }
  }
  return { equal: true };
}

export function projectUniqueHeadings(documents) {
  return [...new Map(documents.map((document) => [document.id, document])).values()];
}
