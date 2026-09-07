//! The `google.pubsub.v1.Subscriber` service implementation.
#![allow(clippy::result_large_err)] // tonic::Status is large by design

use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS;
use fireemu_core_pubsub::{PushConfig, SubscriptionName};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::subscriber_server::Subscriber;

use crate::convert::{
    from_timestamp, received_to_proto, snapshot_to_proto, status, subscription_from_proto,
    subscription_to_proto, validate_push_config_options,
};
use crate::PubSubHandle;

/// Subscriber service over the shared Pub/Sub state.
pub struct SubscriberService {
    handle: PubSubHandle,
}

impl SubscriberService {
    /// Builds the service over a handle.
    #[must_use]
    pub fn new(handle: PubSubHandle) -> Self {
        Self { handle }
    }

    /// Builds the wire `Subscription` for a name from the current state.
    fn subscription_proto(&self, name: &SubscriptionName) -> Result<pb::Subscription, Status> {
        let state = self.handle.state();
        let config = state.subscription_config(name).map_err(|e| status(&e))?;
        let reported = state
            .reported_topic(name)
            .unwrap_or_else(|| config.topic.to_full());
        Ok(subscription_to_proto(config, &reported))
    }
}

fn project_of(resource: &str) -> Result<&str, Status> {
    resource
        .strip_prefix("projects/")
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .ok_or_else(|| Status::invalid_argument("project must be projects/{project}"))
}

fn validate_update_paths(paths: &[String]) -> Result<(), Status> {
    for path in paths {
        match path.as_str() {
            "ack_deadline_seconds" | "push_config" => {}
            "dead_letter_policy"
            | "retry_policy"
            | "filter"
            | "enable_message_ordering"
            | "bigquery_config"
            | "cloud_storage_config"
            | "bigtable_config"
            | "retain_acked_messages"
            | "message_retention_duration"
            | "expiration_policy"
            | "detached"
            | "enable_exactly_once_delivery"
            | "topic_message_retention_duration"
            | "analytics_hub_subscription_info"
            | "message_transforms"
            | "tags" => {
                return Err(Status::unimplemented(format!(
                    "updating {path} is not supported by the Pub/Sub emulator"
                )))
            }
            path if path.starts_with("push_config.") => {
                return Err(Status::unimplemented(format!(
                    "updating {path} is not supported by the Pub/Sub emulator"
                )))
            }
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unknown update_mask path {path}"
                )))
            }
        }
    }
    Ok(())
}

fn update_ack_deadline(paths: &[String], sub: &pb::Subscription) -> Result<Option<u32>, Status> {
    paths
        .iter()
        .any(|path| path == "ack_deadline_seconds")
        .then(|| {
            if sub.ack_deadline_seconds == 0 {
                Ok(DEFAULT_ACK_DEADLINE_SECONDS)
            } else {
                u32::try_from(sub.ack_deadline_seconds)
                    .map_err(|_| Status::invalid_argument("ackDeadlineSeconds must be positive"))
            }
        })
        .transpose()
}

fn update_push_config(
    paths: &[String],
    sub: &pb::Subscription,
) -> Result<Option<PushConfig>, Status> {
    paths
        .iter()
        .any(|path| path == "push_config")
        .then(|| {
            validate_push_config_options(sub.push_config.as_ref())
                .map_err(|error| status(&error))?;
            let endpoint = sub
                .push_config
                .as_ref()
                .map_or_else(String::new, |config| config.push_endpoint.clone());
            crate::push::validate_endpoint(&endpoint).map_err(Status::invalid_argument)?;
            Ok(PushConfig {
                push_endpoint: endpoint,
            })
        })
        .transpose()
}

/// Applies the acks and modify-ack-deadlines carried by one streaming-pull request.
fn apply_stream_request(
    handle: &PubSubHandle,
    sub: &SubscriptionName,
    req: &pb::StreamingPullRequest,
) {
    if !req.ack_ids.is_empty() {
        let _ = handle.acknowledge(sub, &req.ack_ids);
    }
    let now = handle.now();
    let mut state = handle.state();
    for (id, secs) in req
        .modify_deadline_ack_ids
        .iter()
        .zip(req.modify_deadline_seconds.iter())
    {
        let s = u32::try_from(*secs).unwrap_or(0);
        let _ = state.modify_ack_deadline(sub, std::slice::from_ref(id), s, now);
    }
}

#[tonic::async_trait]
impl Subscriber for SubscriberService {
    async fn create_subscription(
        &self,
        request: Request<pb::Subscription>,
    ) -> Result<Response<pb::Subscription>, Status> {
        let sub = request.into_inner();
        let config = subscription_from_proto(&sub).map_err(|e| status(&e))?;
        let name = config.name.clone();
        let topic = config.topic.clone();
        self.handle
            .state()
            .create_subscription(config)
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        self.handle.schedule_push(&topic);
        Ok(Response::new(self.subscription_proto(&name)?))
    }

    async fn get_subscription(
        &self,
        request: Request<pb::GetSubscriptionRequest>,
    ) -> Result<Response<pb::Subscription>, Status> {
        let name =
            SubscriptionName::parse(&request.into_inner().subscription).map_err(|e| status(&e))?;
        Ok(Response::new(self.subscription_proto(&name)?))
    }

    async fn update_subscription(
        &self,
        request: Request<pb::UpdateSubscriptionRequest>,
    ) -> Result<Response<pb::Subscription>, Status> {
        let req = request.into_inner();
        let sub = req
            .subscription
            .ok_or_else(|| Status::invalid_argument("update requires a subscription"))?;
        let name = SubscriptionName::parse(&sub.name).map_err(|e| status(&e))?;
        let paths = req
            .update_mask
            .ok_or_else(|| Status::invalid_argument("update_mask is required"))?
            .paths;
        if paths.is_empty() {
            return Err(Status::invalid_argument("update_mask must not be empty"));
        }
        validate_update_paths(&paths)?;
        let ack_deadline_seconds = update_ack_deadline(&paths, &sub)?;
        let push_config = update_push_config(&paths, &sub)?;
        self.handle
            .state()
            .update_subscription(&name, ack_deadline_seconds, push_config)
            .map_err(|e| status(&e))?;
        let topic = self
            .handle
            .state()
            .subscription_config(&name)
            .map_err(|e| status(&e))?
            .topic
            .clone();
        self.handle.schedule_push(&topic);
        Ok(Response::new(self.subscription_proto(&name)?))
    }

    async fn list_subscriptions(
        &self,
        request: Request<pb::ListSubscriptionsRequest>,
    ) -> Result<Response<pb::ListSubscriptionsResponse>, Status> {
        let req = request.into_inner();
        let project = project_of(&req.project)?;
        let state = self.handle.state();
        let subscriptions = state
            .list_subscriptions(project)
            .iter()
            .map(|c| {
                let reported = state
                    .reported_topic(&c.name)
                    .unwrap_or_else(|| c.topic.to_full());
                subscription_to_proto(c, &reported)
            })
            .collect();
        Ok(Response::new(pb::ListSubscriptionsResponse {
            subscriptions,
            next_page_token: String::new(),
        }))
    }

    async fn delete_subscription(
        &self,
        request: Request<pb::DeleteSubscriptionRequest>,
    ) -> Result<Response<()>, Status> {
        let name =
            SubscriptionName::parse(&request.into_inner().subscription).map_err(|e| status(&e))?;
        self.handle.invalidate_push_worker(&name);
        self.handle
            .state()
            .delete_subscription(&name)
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        Ok(Response::new(()))
    }

    async fn modify_ack_deadline(
        &self,
        request: Request<pb::ModifyAckDeadlineRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        let secs = u32::try_from(req.ack_deadline_seconds)
            .map_err(|_| Status::invalid_argument("ackDeadlineSeconds must be non-negative"))?;
        let now = self.handle.now();
        self.handle
            .state()
            .modify_ack_deadline(&name, &req.ack_ids, secs, now)
            .map_err(|e| status(&e))?;
        Ok(Response::new(()))
    }

    async fn acknowledge(
        &self,
        request: Request<pb::AcknowledgeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        self.handle
            .acknowledge(&name, &req.ack_ids)
            .map_err(|e| status(&e))?;
        Ok(Response::new(()))
    }

    async fn pull(
        &self,
        request: Request<pb::PullRequest>,
    ) -> Result<Response<pb::PullResponse>, Status> {
        let req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        let max = usize::try_from(req.max_messages.max(0)).unwrap_or(0);
        let received = self.handle.pull(&name, max).map_err(|e| status(&e))?;
        Ok(Response::new(pb::PullResponse {
            received_messages: received.iter().map(received_to_proto).collect(),
        }))
    }

    type StreamingPullStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<pb::StreamingPullResponse, Status>> + Send>>;

    async fn streaming_pull(
        &self,
        request: Request<tonic::Streaming<pb::StreamingPullRequest>>,
    ) -> Result<Response<Self::StreamingPullStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("streaming pull opened with no request"))?;
        let name = SubscriptionName::parse(&first.subscription).map_err(|e| status(&e))?;
        // Fail fast if the subscription does not exist.
        self.handle
            .state()
            .subscription_config(&name)
            .map_err(|e| status(&e))?;

        let handle = self.handle.clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::StreamingPullResponse, Status>>(16);
        tokio::spawn(async move {
            let mut first = Some(first);
            // A short poll delivers messages published after the stream opened. This is a
            // delivery cadence only; ack-deadline and redelivery timing run on the virtual clock.
            let mut interval = tokio::time::interval(Duration::from_millis(25));
            loop {
                tokio::select! {
                    biased;
                    msg = async {
                        match first.take() {
                            Some(f) => Ok(Some(f)),
                            None => inbound.message().await,
                        }
                    } => {
                        match msg {
                            Ok(Some(req)) => apply_stream_request(&handle, &name, &req),
                            Ok(None) | Err(_) => break,
                        }
                    }
                    _ = interval.tick() => {
                        let pulled = handle.pull(&name, 100);
                        match pulled {
                            Ok(msgs) if !msgs.is_empty() => {
                                let resp = pb::StreamingPullResponse {
                                    received_messages: msgs.iter().map(received_to_proto).collect(),
                                    ..pb::StreamingPullResponse::default()
                                };
                                if tx.send(Ok(resp)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                let _ = tx.send(Err(status(&e))).await;
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn modify_push_config(
        &self,
        request: Request<pb::ModifyPushConfigRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        validate_push_config_options(req.push_config.as_ref()).map_err(|e| status(&e))?;
        let push_endpoint = req
            .push_config
            .as_ref()
            .map_or_else(String::new, |config| config.push_endpoint.clone());
        crate::push::validate_endpoint(&push_endpoint).map_err(Status::invalid_argument)?;
        self.handle
            .state()
            .update_push_config(&name, PushConfig { push_endpoint })
            .map_err(|e| status(&e))?;
        let topic = self
            .handle
            .state()
            .subscription_config(&name)
            .map_err(|e| status(&e))?
            .topic
            .clone();
        self.handle.schedule_push(&topic);
        Ok(Response::new(()))
    }

    async fn get_snapshot(
        &self,
        request: Request<pb::GetSnapshotRequest>,
    ) -> Result<Response<pb::Snapshot>, Status> {
        let name = request.into_inner().snapshot;
        let snapshot = self
            .handle
            .state()
            .get_snapshot(&name, self.handle.now())
            .map_err(|e| status(&e))?;
        Ok(Response::new(snapshot_to_proto(&snapshot)))
    }

    async fn list_snapshots(
        &self,
        request: Request<pb::ListSnapshotsRequest>,
    ) -> Result<Response<pb::ListSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let project = project_of(&req.project)?;
        let snapshots = self
            .handle
            .state()
            .list_snapshots(project, self.handle.now())
            .iter()
            .map(snapshot_to_proto)
            .collect();
        Ok(Response::new(pb::ListSnapshotsResponse {
            snapshots,
            next_page_token: String::new(),
        }))
    }

    async fn create_snapshot(
        &self,
        request: Request<pb::CreateSnapshotRequest>,
    ) -> Result<Response<pb::Snapshot>, Status> {
        let req = request.into_inner();
        let subscription = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        let snapshot = self
            .handle
            .state()
            .create_snapshot(
                &req.name,
                &subscription,
                req.labels.into_iter().collect::<BTreeMap<_, _>>(),
                self.handle.now(),
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(snapshot_to_proto(&snapshot)))
    }

    async fn update_snapshot(
        &self,
        request: Request<pb::UpdateSnapshotRequest>,
    ) -> Result<Response<pb::Snapshot>, Status> {
        let req = request.into_inner();
        let snapshot = req
            .snapshot
            .ok_or_else(|| Status::invalid_argument("update requires a snapshot"))?;
        let mask = req
            .update_mask
            .ok_or_else(|| Status::invalid_argument("update requires a non-empty update mask"))?;
        if mask.paths.is_empty()
            || mask
                .paths
                .iter()
                .any(|path| path != "labels" && !path.starts_with("labels."))
        {
            return Err(Status::invalid_argument(
                "only the labels field can be updated",
            ));
        }
        let updated = self
            .handle
            .state()
            .update_snapshot(
                &snapshot.name,
                snapshot.labels.into_iter().collect::<BTreeMap<_, _>>(),
                self.handle.now(),
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(snapshot_to_proto(&updated)))
    }

    async fn delete_snapshot(
        &self,
        request: Request<pb::DeleteSnapshotRequest>,
    ) -> Result<Response<()>, Status> {
        let name = request.into_inner().snapshot;
        self.handle
            .state()
            .delete_snapshot(&name, self.handle.now())
            .map_err(|e| status(&e))?;
        Ok(Response::new(()))
    }

    async fn seek(
        &self,
        request: Request<pb::SeekRequest>,
    ) -> Result<Response<pb::SeekResponse>, Status> {
        let req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        let now = self.handle.now();
        match req.target {
            Some(pb::seek_request::Target::Time(ts)) => {
                let time = from_timestamp(&ts);
                self.handle
                    .state()
                    .seek_to_time(&name, time, now)
                    .map_err(|e| status(&e))?;
                Ok(Response::new(pb::SeekResponse::default()))
            }
            Some(pb::seek_request::Target::Snapshot(snapshot)) => {
                self.handle
                    .state()
                    .seek_to_snapshot(&name, &snapshot, now)
                    .map_err(|e| status(&e))?;
                Ok(Response::new(pb::SeekResponse::default()))
            }
            None => Err(Status::invalid_argument(
                "seek requires a time or a snapshot",
            )),
        }
    }
}
