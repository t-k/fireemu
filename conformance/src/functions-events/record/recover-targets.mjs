// The exact resources the v4 recovery may touch (docs.local/runs/functions-events-formal-20261004T161049Z-...,
// outcome needs-recovery): two GCF v2 functions the CLI delete left behind, the Pub/Sub objects that belong to them,
// and the regions the read-backs cover. Nothing here is a pattern: each name is written out.

export const RECOVERY_REGIONS = ["us-central1", "us-east1"];

// In this order: the storage function first, alone (its trigger delete lost a race on the bucket's metadata when
// four storage functions were deleted at once), then the Pub/Sub function.
export const FUNCTION_TARGETS = [
  { region: "us-central1", id: "storageArchivedV2" },
  { region: "us-east1", id: "pubsubPublishedV2" },
];

// Subscriptions before topics. The first sits on `_deleted-topic_` (its topic was the run's own topic, deleted by the cleanup).
export const SUBSCRIPTION_TARGETS = [
  "eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
  "eventarc-us-central1-storagearchivedv2-494903-sub-488",
];
export const TOPIC_TARGETS = ["eventarc-us-central1-storagearchivedv2-494903-679"];

// The function each Pub/Sub object belongs to (its Eventarc trigger's transport). An object is deleted only after its
// owner's step ended `deleted` or `absent`: while the function and its trigger still exist, the trigger's own topic
// and subscription must stay (a bucket notification would otherwise point at a deleted topic).
export const PUBSUB_OWNER = {
  "eventarc-us-east1-pubsubpublishedv2-974238-sub-583": "us-east1/pubsubPublishedV2",
  "eventarc-us-central1-storagearchivedv2-494903-sub-488": "us-central1/storageArchivedV2",
  "eventarc-us-central1-storagearchivedv2-494903-679": "us-central1/storageArchivedV2",
};

export const ORIGIN_RUN_DIR_NAME = "functions-events-formal-20261004T161049Z-17272a4f69f41f21";
