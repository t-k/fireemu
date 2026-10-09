//! The `google.pubsub.v1.Subscriber` service implementation.
#![allow(clippy::result_large_err)] // tonic::Status is large by design

use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS;
use fireemu_core_pubsub::{PushConfig, SubscriptionName};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::subscriber_server::Subscriber;

use crate::convert::{
    duration_from_proto, from_timestamp, push_config_from_proto, received_to_proto,
    snapshot_to_proto, status, subscription_to_proto,
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
        Ok(subscription_to_proto(
            config,
            &reported,
            self.handle.paging_policy,
        ))
    }
}

fn project_of(resource: &str) -> Result<&str, Status> {
    resource
        .strip_prefix("projects/")
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .ok_or_else(|| Status::invalid_argument("project must be projects/{project}"))
}

fn validate_update_paths(paths: &[String]) -> Result<(), Status> {
    let empty = [String::new()];
    let paths = if paths.is_empty() { &empty } else { paths };
    crate::convert::validate_subscription_update_paths(paths).map_err(|error| status(&error))
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
    policy: crate::PagingPolicy,
) -> Result<Option<PushConfig>, Status> {
    paths
        .iter()
        .any(|path| path == "push_config")
        .then(|| {
            push_config_from_proto(sub.push_config.as_ref(), policy).map_err(|error| status(&error))
        })
        .transpose()
}

fn stream_pull_max(
    handle: &PubSubHandle,
    subscription: &SubscriptionName,
    message_limit: Option<usize>,
    outstanding_ack_ids: &mut BTreeSet<String>,
) -> Result<usize, fireemu_core_pubsub::PubSubError> {
    let Some(limit) = message_limit else {
        return Ok(100);
    };
    let now = handle.now();
    handle
        .state()
        .retain_outstanding_ack_ids(subscription, outstanding_ack_ids, now)?;
    Ok(limit.saturating_sub(outstanding_ack_ids.len()).min(100))
}

/// Applies the acks and modify-ack-deadlines carried by one streaming-pull request.
fn apply_stream_request(
    handle: &PubSubHandle,
    sub: &SubscriptionName,
    req: &pb::StreamingPullRequest,
) -> Result<(), Status> {
    if handle.paging_policy == crate::PagingPolicy::Strict {
        if req.modify_deadline_ack_ids.len() != req.modify_deadline_seconds.len() {
            return Err(Status::invalid_argument(
                "Invalid arguments provided: the number of ack ids to modify must be equal to the number of ack deadlines.",
            ));
        }
        for seconds in &req.modify_deadline_seconds {
            crate::admission::ack_deadline(i64::from(*seconds)).map_err(|error| status(&error))?;
        }
    }
    if !req.ack_ids.is_empty() {
        let ids: Vec<_> = req
            .ack_ids
            .iter()
            .map(|id| crate::ack_token::internal(id, handle.paging_policy))
            .collect();
        let _ = handle.acknowledge(sub, &ids);
    }
    let now = handle.now();
    let mut state = handle.state();
    for (id, secs) in req
        .modify_deadline_ack_ids
        .iter()
        .zip(req.modify_deadline_seconds.iter())
    {
        let s = u32::try_from(*secs).unwrap_or(0);
        let id = crate::ack_token::internal(id, handle.paging_policy);
        let _ = state.modify_ack_deadline(sub, std::slice::from_ref(&id), s, now);
    }
    Ok(())
}

#[tonic::async_trait]
impl Subscriber for SubscriberService {
    async fn create_subscription(
        &self,
        request: Request<pb::Subscription>,
    ) -> Result<Response<pb::Subscription>, Status> {
        let sub = request.into_inner();
        let config =
            crate::convert::subscription_from_proto_with_policy(&sub, self.handle.paging_policy)
                .map_err(|e| status(&e))?;
        let name = config.name.clone();
        let topic = config.topic.clone();
        self.handle
            .state()
            .create_subscription(config)
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        self.handle.schedule_push(&topic);
        let mut response = self.subscription_proto(&name)?;
        if self.handle.paging_policy == crate::PagingPolicy::Strict
            && !response
                .push_config
                .as_ref()
                .is_none_or(|push| push.push_endpoint.is_empty())
        {
            response
                .push_config
                .as_mut()
                .expect("push configuration")
                .attributes
                .insert("x-goog-version".into(), "v1".into());
        }
        Ok(Response::new(response))
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
        validate_update_paths(&paths)?;
        let ack_deadline_seconds = update_ack_deadline(&paths, &sub)?;
        let strict = self.handle.paging_policy == crate::PagingPolicy::Strict;
        if strict && paths.iter().any(|path| path == "ack_deadline_seconds") {
            crate::convert::validate_strict_ack_deadline(sub.ack_deadline_seconds)
                .map_err(|error| status(&error))?;
        }
        let push_config = update_push_config(&paths, &sub, self.handle.paging_policy)?;
        let selected = |path: &str| paths.iter().any(|value| value == path);
        let retention = selected("message_retention_duration")
            .then(|| {
                sub.message_retention_duration
                    .as_ref()
                    .map(duration_from_proto)
                    .transpose()
            })
            .transpose()
            .map_err(|error| status(&error))?;
        let expiration = selected("expiration_policy")
            .then(|| {
                sub.expiration_policy
                    .as_ref()
                    .map(|policy| {
                        Ok::<_, fireemu_core_pubsub::PubSubError>(
                            fireemu_core_pubsub::ExpirationPolicy {
                                ttl: policy.ttl.as_ref().map(duration_from_proto).transpose()?,
                            },
                        )
                    })
                    .transpose()
            })
            .transpose()
            .map_err(|error| status(&error))?;
        // Parse only mask-selected policies; invalid values outside the mask are ignored.
        let parsed_policies = crate::convert::subscription_from_proto(&pb::Subscription {
            name: sub.name.clone(),
            topic: self
                .handle
                .state()
                .subscription_config(&name)
                .map_err(|error| status(&error))?
                .topic
                .to_full(),
            retry_policy: selected("retry_policy")
                .then_some(sub.retry_policy)
                .flatten(),
            dead_letter_policy: selected("dead_letter_policy")
                .then(|| sub.dead_letter_policy.clone())
                .flatten(),
            ..Default::default()
        })
        .map_err(|error| status(&error))?;
        let update = fireemu_core_pubsub::SubscriptionUpdate {
            ack_deadline_seconds,
            push_config,
            labels: selected("labels").then(|| {
                sub.labels
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            }),
            retain_acked_messages: selected("retain_acked_messages")
                .then_some(sub.retain_acked_messages),
            message_retention_duration: retention,
            expiration_policy: expiration,
            retry_policy: selected("retry_policy").then_some(parsed_policies.retry_policy),
            dead_letter_policy: selected("dead_letter_policy")
                .then_some(parsed_policies.dead_letter_policy),
        };
        self.handle
            .state()
            .update_subscription_configuration(&name, update, strict)
            .map_err(|e| status(&e))?;
        let topic = self
            .handle
            .state()
            .subscription_config(&name)
            .map_err(|e| status(&e))?
            .topic
            .clone();
        self.handle.schedule_push(&topic);
        let mut response = self.subscription_proto(&name)?;
        if strict {
            response
                .push_config
                .get_or_insert_with(Default::default)
                .attributes
                .insert("x-goog-version".into(), "v1".into());
        }
        Ok(Response::new(response))
    }

    async fn list_subscriptions(
        &self,
        request: Request<pb::ListSubscriptionsRequest>,
    ) -> Result<Response<pb::ListSubscriptionsResponse>, Status> {
        let req = request.into_inner();
        let project = project_of(&req.project)?;
        let mut state = self.handle.state();
        let subscriptions: Vec<_> = state
            .list_subscriptions(project)
            .iter()
            .map(|c| {
                let reported = state
                    .reported_topic(&c.name)
                    .unwrap_or_else(|| c.topic.to_full());
                subscription_to_proto(c, &reported, self.handle.paging_policy)
            })
            .collect();
        let page = state
            .paginate(
                &format!("projects/{project}/subscriptions"),
                subscriptions,
                req.page_size,
                &req.page_token,
                self.handle.paging_policy,
                |subscription| subscription.name.clone(),
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListSubscriptionsResponse {
            subscriptions: page.resources,
            next_page_token: page.next_page_token,
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
        let mut req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        let secs = if self.handle.paging_policy == crate::PagingPolicy::Strict {
            req.ack_ids =
                crate::admission::ack_ids(&req.ack_ids).map_err(|error| status(&error))?;
            crate::admission::ack_deadline(i64::from(req.ack_deadline_seconds))
                .map_err(|error| status(&error))?
        } else {
            u32::try_from(req.ack_deadline_seconds)
                .map_err(|_| Status::invalid_argument("ackDeadlineSeconds must be non-negative"))?
        };
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
        let mut req = request.into_inner();
        let name = SubscriptionName::parse(&req.subscription).map_err(|e| status(&e))?;
        if self.handle.paging_policy == crate::PagingPolicy::Strict {
            req.ack_ids =
                crate::admission::ack_ids(&req.ack_ids).map_err(|error| status(&error))?;
        }
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
        if self.handle.paging_policy == crate::PagingPolicy::Strict
            && self
                .handle
                .state()
                .subscription_config(&name)
                .map_err(|error| status(&error))?
                .is_push()
        {
            return Err(Status::failed_precondition(
                "This method is not supported for this subscription type.",
            ));
        }
        let max = if self.handle.paging_policy == crate::PagingPolicy::Strict {
            crate::admission::max_messages(i64::from(req.max_messages))
                .map_err(|error| status(&error))?
        } else {
            usize::try_from(req.max_messages.max(0)).unwrap_or(0)
        };
        let report_attempt = self.handle.paging_policy == crate::PagingPolicy::Emulator
            || self
                .handle
                .state()
                .subscription_config(&name)
                .map_err(|error| status(&error))?
                .dead_letter_policy
                .is_some();
        let received = self.handle.pull(&name, max).map_err(|e| status(&e))?;
        Ok(Response::new(pb::PullResponse {
            received_messages: received
                .iter()
                .map(|message| {
                    received_to_proto(message, report_attempt, self.handle.paging_policy)
                })
                .collect(),
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
        // Strict responses report subscription properties even when both flags are false.
        let (report_attempt, subscription_properties) =
            if self.handle.paging_policy == crate::PagingPolicy::Emulator {
                (true, None)
            } else {
                let state = self.handle.state();
                let config = state
                    .subscription_config(&name)
                    .map_err(|error| status(&error))?;
                (
                    config.dead_letter_policy.is_some(),
                    Some(pb::streaming_pull_response::SubscriptionProperties {
                        exactly_once_delivery_enabled: false,
                        message_ordering_enabled: config.enable_message_ordering,
                    }),
                )
            };

        // Proto3 has no scalar presence: omitted and explicit initial zero decode alike.
        // ACK-only follow-up frames may omit the deadline, so validate only the opener.
        if self.handle.paging_policy == crate::PagingPolicy::Strict
            && first.stream_ack_deadline_seconds == 0
        {
            return Err(Status::internal(
                "A service error has occurred. Please retry your request. If the error persists, please report it.",
            ));
        }

        let message_limit = (self.handle.paging_policy == crate::PagingPolicy::Strict
            && first.max_outstanding_messages > 0)
            .then(|| usize::try_from(first.max_outstanding_messages).unwrap_or(usize::MAX));
        let handle = self.handle.clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::StreamingPullResponse, Status>>(16);
        tokio::spawn(async move {
            let mut outstanding_ack_ids = BTreeSet::new();
            let mut first = Some(first);
            let mut inbound_open = true;
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
                    }, if inbound_open => {
                        match msg {
                            Ok(Some(req)) => {
                                if let Err(error) = apply_stream_request(&handle, &name, &req) {
                                    let _ = tx.send(Err(error)).await;
                                    break;
                                }
                            },
                            Ok(None) if handle.paging_policy == crate::PagingPolicy::Strict => {
                                // A clean request half-close leaves the Strict response live.
                                inbound_open = false;
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }
                    () = tx.closed() => break,
                    _ = interval.tick() => {
                        let max = match stream_pull_max(&handle, &name, message_limit, &mut outstanding_ack_ids) {
                            Ok(max) => max,
                            Err(error) => {
                                let _ = tx.send(Err(status(&error))).await;
                                break;
                            }
                        };
                        if max == 0 {
                            continue;
                        }
                        let pulled = handle.pull(&name, max);
                        match pulled {
                            Ok(msgs) if !msgs.is_empty() => {
                                if message_limit.is_some() {
                                    outstanding_ack_ids.extend(msgs.iter().map(|message| message.ack_id.clone()));
                                }
                                let resp = pb::StreamingPullResponse {
                                    received_messages: msgs.iter().map(|message|received_to_proto(message,report_attempt,handle.paging_policy)).collect(),
                                    subscription_properties,
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
        let push = push_config_from_proto(req.push_config.as_ref(), self.handle.paging_policy)
            .map_err(|error| status(&error))?;
        self.handle
            .state()
            .update_push_config(&name, push)
            .map_err(|error| status(&error))?;
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
        let mut state = self.handle.state();
        let snapshots: Vec<_> = state
            .list_snapshots(project, self.handle.now())
            .iter()
            .map(snapshot_to_proto)
            .collect();
        let page = state
            .paginate(
                &format!("projects/{project}/snapshots"),
                snapshots,
                req.page_size,
                &req.page_token,
                self.handle.paging_policy,
                |snapshot| snapshot.name.clone(),
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListSnapshotsResponse {
            snapshots: page.resources,
            next_page_token: page.next_page_token,
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
            .map_err(|e| {
                status(&crate::admission::snapshot_creation_error(
                    &req.name,
                    e,
                    self.handle.paging_policy,
                ))
            })?;
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
        match req.target {
            Some(pb::seek_request::Target::Time(ts)) => {
                let time = from_timestamp(&ts);
                self.handle
                    .seek_to_time(&name, time)
                    .map_err(|e| status(&e))?;
                Ok(Response::new(pb::SeekResponse::default()))
            }
            Some(pb::seek_request::Target::Snapshot(snapshot)) => {
                self.handle
                    .seek_to_snapshot(&name, &snapshot)
                    .map_err(|e| status(&e))?;
                Ok(Response::new(pb::SeekResponse::default()))
            }
            None => Err(Status::invalid_argument(
                crate::admission::missing_seek_target(self.handle.paging_policy),
            )),
        }
    }
}

#[cfg(test)]
mod ack_wire_tests {
    use super::*;
    use fireemu_core_pubsub::{PubSubState, PubsubMessage, TopicName};
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::time::LogicalInstant;
    use std::sync::{Arc, Mutex};

    #[test]
    fn streaming_frames_decode_issued_opaque_ids() {
        let now = LogicalInstant::from_unix_seconds(1_700_000_000);
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(99))),
            Arc::new(Mutex::new(VirtualClock::new(now))),
            None,
        )
        .with_paging_policy(crate::PagingPolicy::Strict);
        let topic = TopicName::new("demo-app", "stream-ack").unwrap();
        let config = crate::convert::subscription_from_proto(&pb::Subscription {
            name: "projects/demo-app/subscriptions/stream-ack".to_owned(),
            topic: topic.to_full(),
            ..Default::default()
        })
        .unwrap();
        let sub = config.name.clone();
        handle
            .state()
            .create_topic(topic.clone(), std::collections::BTreeMap::new())
            .unwrap();
        handle.state().create_subscription(config).unwrap();
        handle
            .state()
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: vec![1],
                    ..Default::default()
                }],
                now,
            )
            .unwrap();
        let first = handle.pull(&sub, 1).unwrap();
        let issued = crate::ack_token::wire(&first[0].ack_id, handle.paging_policy);
        apply_stream_request(
            &handle,
            &sub,
            &pb::StreamingPullRequest {
                modify_deadline_ack_ids: vec![issued.clone()],
                modify_deadline_seconds: vec![0],
                ..Default::default()
            },
        )
        .unwrap();
        let renewed = handle.pull(&sub, 1).unwrap();
        assert_eq!(renewed.len(), 1);
        assert_eq!(renewed[0].message.message_id, first[0].message.message_id);
        let current = crate::ack_token::wire(&renewed[0].ack_id, handle.paging_policy);
        apply_stream_request(
            &handle,
            &sub,
            &pb::StreamingPullRequest {
                ack_ids: vec![issued, current],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(handle.pull(&sub, 1).unwrap().is_empty());
    }

    #[test]
    fn streaming_invalid_updates_leave_ack_and_deadline_state_unchanged() {
        for deadline in [None, Some(601)] {
            let now = LogicalInstant::from_unix_seconds(1_700_000_000);
            let clock = Arc::new(Mutex::new(VirtualClock::new(now)));
            let handle = PubSubHandle::new(
                Arc::new(Mutex::new(PubSubState::new(99))),
                Arc::clone(&clock),
                None,
            )
            .with_paging_policy(crate::PagingPolicy::Strict);
            let topic = TopicName::new("demo-app", "stream-atomic").unwrap();
            let config = crate::convert::subscription_from_proto(&pb::Subscription {
                name: "projects/demo-app/subscriptions/stream-atomic".to_owned(),
                topic: topic.to_full(),
                ..Default::default()
            })
            .unwrap();
            let sub = config.name.clone();
            handle
                .state()
                .create_topic(topic.clone(), BTreeMap::new())
                .unwrap();
            handle.state().create_subscription(config).unwrap();
            handle
                .state()
                .publish(
                    &topic,
                    vec![
                        PubsubMessage {
                            data: vec![1],
                            ..Default::default()
                        },
                        PubsubMessage {
                            data: vec![2],
                            ..Default::default()
                        },
                    ],
                    now,
                )
                .unwrap();
            let owned = handle.pull(&sub, 2).unwrap();
            assert_eq!(owned.len(), 2);
            let _result = apply_stream_request(
                &handle,
                &sub,
                &pb::StreamingPullRequest {
                    ack_ids: vec![crate::ack_token::wire(
                        &owned[0].ack_id,
                        handle.paging_policy,
                    )],
                    modify_deadline_ack_ids: vec![crate::ack_token::wire(
                        &owned[1].ack_id,
                        handle.paging_policy,
                    )],
                    modify_deadline_seconds: deadline.into_iter().collect(),
                    ..Default::default()
                },
            );
            clock
                .lock()
                .unwrap()
                .advance_to(LogicalInstant::from_unix_seconds(1_700_000_011))
                .unwrap();
            let retained = handle.pull(&sub, 2).unwrap();
            assert_eq!(
                retained.len(),
                2,
                "invalid frame must not ACK or extend either owned lease"
            );
            assert_eq!(
                retained
                    .iter()
                    .map(|m| &m.message.message_id)
                    .collect::<BTreeSet<_>>(),
                owned
                    .iter()
                    .map(|m| &m.message.message_id)
                    .collect::<BTreeSet<_>>()
            );
        }
    }
}
