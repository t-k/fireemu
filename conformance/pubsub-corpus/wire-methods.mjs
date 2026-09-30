// Native types and REST annotations from the pinned @google-cloud/pubsub4.11.0 descriptor.
const definitions = {
  CreateTopic: {
    service: "Publisher",
    requestType: "Topic",
    responseType: "Topic",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "PUT",
      path: "/v1/{name=projects/*/topics/*}",
      body: "*",
    },
  },
  GetTopic: {
    service: "Publisher",
    requestType: "GetTopicRequest",
    responseType: "Topic",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{topic=projects/*/topics/*}",
      body: null,
    },
  },
  ListTopics: {
    service: "Publisher",
    requestType: "ListTopicsRequest",
    responseType: "ListTopicsResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{project=projects/*}/topics",
      body: null,
    },
  },
  ListTopicSubscriptions: {
    service: "Publisher",
    requestType: "ListTopicSubscriptionsRequest",
    responseType: "ListTopicSubscriptionsResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{topic=projects/*/topics/*}/subscriptions",
      body: null,
    },
  },
  Publish: {
    service: "Publisher",
    requestType: "PublishRequest",
    responseType: "PublishResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{topic=projects/*/topics/*}:publish",
      body: "*",
    },
  },
  DeleteTopic: {
    service: "Publisher",
    requestType: "DeleteTopicRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "DELETE",
      path: "/v1/{topic=projects/*/topics/*}",
      body: null,
    },
  },
  CreateSubscription: {
    service: "Subscriber",
    requestType: "Subscription",
    responseType: "Subscription",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "PUT",
      path: "/v1/{name=projects/*/subscriptions/*}",
      body: "*",
    },
  },
  GetSubscription: {
    service: "Subscriber",
    requestType: "GetSubscriptionRequest",
    responseType: "Subscription",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{subscription=projects/*/subscriptions/*}",
      body: null,
    },
  },
  UpdateSubscription: {
    service: "Subscriber",
    requestType: "UpdateSubscriptionRequest",
    responseType: "Subscription",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "PATCH",
      path: "/v1/{subscription.name=projects/*/subscriptions/*}",
      body: "*",
    },
  },
  ListSubscriptions: {
    service: "Subscriber",
    requestType: "ListSubscriptionsRequest",
    responseType: "ListSubscriptionsResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{project=projects/*}/subscriptions",
      body: null,
    },
  },
  DeleteSubscription: {
    service: "Subscriber",
    requestType: "DeleteSubscriptionRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "DELETE",
      path: "/v1/{subscription=projects/*/subscriptions/*}",
      body: null,
    },
  },
  ModifyAckDeadline: {
    service: "Subscriber",
    requestType: "ModifyAckDeadlineRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{subscription=projects/*/subscriptions/*}:modifyAckDeadline",
      body: "*",
    },
  },
  Acknowledge: {
    service: "Subscriber",
    requestType: "AcknowledgeRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{subscription=projects/*/subscriptions/*}:acknowledge",
      body: "*",
    },
  },
  Pull: {
    service: "Subscriber",
    requestType: "PullRequest",
    responseType: "PullResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{subscription=projects/*/subscriptions/*}:pull",
      body: "*",
    },
  },
  StreamingPull: {
    service: "Subscriber",
    requestType: "StreamingPullRequest",
    responseType: "StreamingPullResponse",
    requestStream: true,
    responseStream: true,
    http: null,
  },
  ModifyPushConfig: {
    service: "Subscriber",
    requestType: "ModifyPushConfigRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{subscription=projects/*/subscriptions/*}:modifyPushConfig",
      body: "*",
    },
  },
  ListSnapshots: {
    service: "Subscriber",
    requestType: "ListSnapshotsRequest",
    responseType: "ListSnapshotsResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{project=projects/*}/snapshots",
      body: null,
    },
  },
  CreateSnapshot: {
    service: "Subscriber",
    requestType: "CreateSnapshotRequest",
    responseType: "Snapshot",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "PUT",
      path: "/v1/{name=projects/*/snapshots/*}",
      body: "*",
    },
  },
  GetSnapshot: {
    service: "Subscriber",
    requestType: "GetSnapshotRequest",
    responseType: "Snapshot",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "GET",
      path: "/v1/{snapshot=projects/*/snapshots/*}",
      body: null,
    },
  },
  DeleteSnapshot: {
    service: "Subscriber",
    requestType: "DeleteSnapshotRequest",
    responseType: "google.protobuf.Empty",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "DELETE",
      path: "/v1/{snapshot=projects/*/snapshots/*}",
      body: null,
    },
  },
  Seek: {
    service: "Subscriber",
    requestType: "SeekRequest",
    responseType: "SeekResponse",
    requestStream: false,
    responseStream: false,
    http: {
      verb: "POST",
      path: "/v1/{subscription=projects/*/subscriptions/*}:seek",
      body: "*",
    },
  },
};

export const METHODS = Object.freeze(
  Object.fromEntries(
    Object.entries(definitions).map(([method, spec]) => [
      method,
      Object.freeze({ ...spec, ...(spec.http ? { http: Object.freeze(spec.http) } : {}) }),
    ]),
  ),
);
function operation(step) {
  const spec = METHODS[step.method];
  if (!spec) throw new Error("operation is outside the frozen broker API");
  return spec;
}
function field(request, path) {
  return path.split(".").reduce((value, key) => value?.[key], request);
}
function route(spec, step) {
  if (!spec.http) return null;
  const binding = /\{([^=]+)=[^}]+\}/.exec(spec.http.path);
  const key = binding?.[1];
  const value = step.resourceOverride ?? field(step.request, key);
  if (typeof value !== "string") throw new Error("resource routing field is required");
  return { key, value, binding: binding[0] };
}
export function buildGrpc(step) {
  const spec = operation(step);
  const routing = route(spec, step);
  return {
    path: `/google.pubsub.v1.${spec.service}/${step.method}`,
    requestType: spec.requestType,
    responseType: spec.responseType,
    requestStream: spec.requestStream,
    responseStream: spec.responseStream,
    request: step.request,
    routing: routing ? `${routing.key}=${encodeURIComponent(routing.value)}` : undefined,
  };
}
export function buildRest(step, endpoint) {
  const spec = operation(step);
  if (!spec.http) throw new Error("native stream has no REST operation");
  const routing = route(spec, step);
  const root = new URL(endpoint);
  if (
    !["http:", "https:"].includes(root.protocol) ||
    root.username ||
    root.password ||
    root.search ||
    root.hash ||
    root.pathname !== "/"
  )
    throw new Error("bare transport endpoint required");
  const path = spec.http.path.replace(
    routing.binding,
    routing.value.split("/").map(encodeURIComponent).join("/"),
  );
  const url = new URL(path, root);
  // A malformed resource cannot override the origin. Production ownership guards run separately.
  if (url.origin !== root.origin) throw new Error("routing cannot replace transport origin");
  const body = spec.http.body === "*" ? JSON.stringify(step.request) : undefined;
  if (!body)
    for (const [key, value] of Object.entries(step.request))
      if (key !== routing.key && value !== undefined) {
        if (typeof value === "object") throw new Error("query member must be scalar");
        url.searchParams.append(key, String(value));
      }
  return { method: spec.http.verb, url: url.href, ...(body !== undefined ? { body } : {}) };
}
