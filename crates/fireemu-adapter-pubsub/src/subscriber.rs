//! The `google.pubsub.v1.Subscriber` service implementation.
#![allow(clippy::result_large_err)] // tonic::Status is large by design

use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
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

/// Bounds adapter-owned output separately from broker/client ACK credit. A whole batch larger
/// than the bound is admitted exclusively, preserving the existing batch and codec-error behavior.
#[derive(Debug)]
pub(crate) struct OutputBudget {
    limit: usize,
    used: Mutex<usize>,
    changed: tokio::sync::Notify,
    revision: AtomicU64,
}

impl OutputBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: Mutex::new(0),
            changed: tokio::sync::Notify::new(),
            revision: AtomicU64::new(0),
        }
    }

    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<OutputReservation> {
        let mut used = self.used.lock().expect("output budget lock");
        let total = used.checked_add(bytes)?;
        if *used != 0 && total > self.limit {
            return None;
        }
        *used = total;
        Some(OutputReservation {
            budget: self.clone(),
            bytes,
        })
    }
}

#[derive(Debug)]
struct OutputReservation {
    budget: Arc<OutputBudget>,
    bytes: usize,
}

impl Drop for OutputReservation {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().expect("output budget lock");
        *used -= self.bytes;
        drop(used);
        self.budget.revision.fetch_add(1, Ordering::Release);
        self.budget.changed.notify_waiters();
    }
}

/// Queued output shares immutable broker data. The byte permit covers this queue and conversion;
/// tonic owns the returned protobuf and its transport buffers after the stream is polled.
#[derive(Debug)]
struct QueuedResponse {
    messages: Vec<fireemu_core_pubsub::ReceivedMessage>,
    subscription_properties: Option<pb::streaming_pull_response::SubscriptionProperties>,
    report_attempt: bool,
    policy: crate::PagingPolicy,
    _reservation: OutputReservation,
}

impl QueuedResponse {
    fn into_proto(self) -> pb::StreamingPullResponse {
        pb::StreamingPullResponse {
            received_messages: self
                .messages
                .iter()
                .map(|message| received_to_proto(message, self.report_attempt, self.policy))
                .collect(),
            subscription_properties: self.subscription_properties,
            ..Default::default()
        }
    }
}

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

fn prepare_stream_response(
    handle: &PubSubHandle,
    subscription: &SubscriptionName,
    max: usize,
    budget: &Arc<OutputBudget>,
    report_attempt: bool,
    properties: Option<pb::streaming_pull_response::SubscriptionProperties>,
) -> Result<Option<QueuedResponse>, fireemu_core_pubsub::PubSubError> {
    let mut reservation = None;
    let messages = handle.pull_admitted(subscription, max, |messages| {
        reservation = budget.try_reserve(crate::convert::streaming_size_bound(messages));
        reservation.is_some()
    })?;
    if messages.is_empty() {
        return Ok(None);
    }
    Ok(Some(QueuedResponse {
        messages,
        subscription_properties: properties,
        report_attempt,
        policy: handle.paging_policy,
        _reservation: reservation.expect("nonempty batch admitted before leasing"),
    }))
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

    #[allow(deprecated)] // Pub/Sub still defines the legacy immediate-Pull request behavior.
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
        let received = self
            .handle
            .pull_unary(&name, max, req.return_immediately)
            .await
            .map_err(|e| status(&e))?;
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

    #[allow(clippy::too_many_lines)]
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
            let terminal = Status::internal(
                "A service error has occurred. Please retry your request. If the error persists, please report it. [code=e8c0]",
            );
            return Ok(Response::new(Box::pin(tokio_stream::once(Err(terminal)))));
        }

        let message_limit = (self.handle.paging_policy == crate::PagingPolicy::Strict
            && first.max_outstanding_messages > 0)
            .then(|| usize::try_from(first.max_outstanding_messages).unwrap_or(usize::MAX));
        let handle = self.handle.clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<QueuedResponse, Status>>(16);
        tokio::spawn(async move {
            #[cfg(not(test))]
            let output_budget = Arc::new(OutputBudget::new(16 * 1024 * 1024));
            #[cfg(test)]
            let output_budget = Arc::new(OutputBudget::new(handle.stream_output_budget_limit));
            #[cfg(test)]
            handle
                .stream_output_budgets
                .lock()
                .expect("test output budget registry")
                .insert(name.to_full(), Arc::downgrade(&output_budget));
            let mut outstanding_ack_ids = BTreeSet::new();
            let mut first = Some(first);
            let mut inbound_open = true;
            let mut delivered = false;
            let mut ready = true;
            let mut observed = (0, 0);
            let mut scheduled = None;
            loop {
                // Register before any broker/credit inspection. notify_waiters retains registered
                // wakeups even when publication races the interval between inspection and select.
                let changed = handle.delivery_notify.notified();
                let capacity = output_budget.changed.notified();
                tokio::pin!(changed, capacity);
                changed.as_mut().enable();
                capacity.as_mut().enable();
                let current = (
                    handle.delivery_revision.load(Ordering::Acquire),
                    output_budget.revision.load(Ordering::Acquire),
                );
                if current != observed {
                    ready = true;
                    observed = current;
                }
                let wake_at = handle.pull_recheck_at(&name, &mut scheduled);
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
                                ready = true;
                            },
                            Ok(None) if handle.paging_policy == crate::PagingPolicy::Strict && !delivered => {
                                inbound_open = false;
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }
                    () = tx.closed() => break,
                    () = &mut changed => { ready = true; }
                    () = &mut capacity => { ready = true; }
                    () = tokio::time::sleep_until(wake_at) => { ready = true; }
                    permit = tx.reserve(), if ready => {
                        let Ok(slot) = permit else { break; };
                        let max = match stream_pull_max(&handle, &name, message_limit, &mut outstanding_ack_ids) {
                            Ok(max) => max,
                            Err(error) => {
                                slot.send(Err(status(&error)));
                                break;
                            }
                        };
                        if max == 0 {
                            ready = false;
                            continue;
                        }
                        match prepare_stream_response(&handle, &name, max, &output_budget, report_attempt, subscription_properties) {
                            Ok(Some(response)) => {
                                if message_limit.is_some() {
                                    outstanding_ack_ids.extend(response.messages.iter().map(|message| message.ack_id.clone()));
                                }
                                slot.send(Ok(response));
                                delivered = true;
                            }
                            Ok(None) => { ready = false; }
                            Err(error) => {
                                slot.send(Err(status(&error)));
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(
            ReceiverStream::new(rx).map(|queued| queued.map(QueuedResponse::into_proto)),
        )))
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

#[cfg(test)]
mod output_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn unread_output_never_clones_payload_and_poll_ends_the_adapter_reservation() {
        use fireemu_core_pubsub::{PubsubMessage, ReceivedMessage, StoredMessage};
        use fireemu_core_types::time::LogicalInstant;
        let budget = Arc::new(OutputBudget::new(2048));
        let stored = Arc::new(StoredMessage {
            message_id: "id".to_owned(),
            publish_time: LogicalInstant::UNIX_EPOCH,
            message: PubsubMessage {
                data: vec![7; 1024],
                ..Default::default()
            },
        });
        let messages = vec![ReceivedMessage {
            ack_id: "ack-0000000000000000".to_owned(),
            message: stored,
            delivery_attempt: 1,
        }];
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let before = crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get);
        tx.send(Ok(QueuedResponse {
            messages,
            subscription_properties: None,
            report_attempt: true,
            policy: crate::PagingPolicy::Emulator,
            _reservation: budget.try_reserve(1536).unwrap(),
        }))
        .await
        .unwrap();
        assert_eq!(
            crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get),
            before
        );
        assert!(budget.try_reserve(1024).is_none());
        let mut responses = ReceiverStream::new(rx)
            .map(|queued: Result<QueuedResponse, Status>| queued.map(QueuedResponse::into_proto));
        let response = responses.next().await.unwrap().unwrap();
        assert_eq!(
            response.received_messages[0]
                .message
                .as_ref()
                .unwrap()
                .data
                .len(),
            1024
        );
        assert_eq!(
            crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get) - before,
            1024
        );
        assert_eq!(*budget.used.lock().unwrap(), 0);
    }

    #[test]
    fn an_unread_stream_does_not_take_another_streams_output_capacity() {
        let slow = Arc::new(OutputBudget::new(10));
        let other = Arc::new(OutputBudget::new(10));
        let _blocked = slow.try_reserve(100).unwrap();
        assert!(other.try_reserve(10).is_some());
    }

    fn handle_fixture() -> (PubSubHandle, SubscriptionName) {
        use fireemu_core_pubsub::{PubSubState, TopicName};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::time::LogicalInstant;
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(42))),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            None,
        )
        .with_paging_policy(crate::PagingPolicy::Strict);
        let topic = TopicName::new("demo-app", "wake").unwrap();
        handle
            .state()
            .create_topic(topic.clone(), BTreeMap::new())
            .unwrap();
        let config = crate::convert::subscription_from_proto(&pb::Subscription {
            name: "projects/demo-app/subscriptions/wake".to_owned(),
            topic: topic.to_full(),
            ..Default::default()
        })
        .unwrap();
        let name = config.name.clone();
        handle.state().create_subscription(config).unwrap();
        (handle, name)
    }

    #[test]
    fn delivery_andclock_observers_do_not_retain_the_handle() {
        let (handle, _) = handle_fixture();
        let state = handle.state.clone();
        let clock = handle.clock.clone();
        let delivery = Arc::downgrade(&handle.delivery_observer);
        let time = Arc::downgrade(&handle.clock_observer);
        let copy = handle.clone();
        drop(handle);
        assert!(delivery.upgrade().is_some());
        drop(copy);
        assert!(delivery.upgrade().is_none());
        assert!(time.upgrade().is_none());
        state.lock().unwrap().clear();
        clock
            .lock()
            .unwrap()
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(1))
            .unwrap();
    }

    #[tokio::test]
    async fn mutation_between_readiness_check_and_wait_is_retained() {
        let (handle, name) = handle_fixture();
        let notified = handle.delivery_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let seen = handle.delivery_revision.load(Ordering::Acquire);
        assert!(handle.pull(&name, 1).unwrap().is_empty());
        handle.state().clear();
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut notified)
            .await
            .unwrap();
        assert_ne!(seen, handle.delivery_revision.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn extreme_raw_clock_replacement_never_panics_the_deadline_task() {
        use fireemu_core_pubsub::PubsubMessage;
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::time::LogicalInstant;
        for initial in [LogicalInstant::UNIX_EPOCH, LogicalInstant::MAX] {
            let (handle, name) = handle_fixture();
            *handle.clock.lock().unwrap() = VirtualClock::new(initial);
            let topic = handle
                .state()
                .subscription_config(&name)
                .unwrap()
                .topic
                .clone();
            handle
                .publish(
                    &topic,
                    vec![PubsubMessage {
                        data: vec![1],
                        ..Default::default()
                    }],
                )
                .unwrap();
            assert_eq!(handle.pull(&name, 1).unwrap().len(), 1);
            for replacement in [
                LogicalInstant::MIN,
                LogicalInstant::from_nanos(i128::MIN + 1),
                LogicalInstant::from_nanos(-1),
                LogicalInstant::UNIX_EPOCH,
                LogicalInstant::from_nanos(i128::MAX - 1),
                LogicalInstant::MAX,
            ] {
                *handle.clock.lock().unwrap() = VirtualClock::new(replacement);
                let task_handle = handle.clone();
                let task_name = name.clone();
                tokio::spawn(async move {
                    let started = tokio::time::Instant::now();
                    let wake = task_handle.pull_recheck_at(&task_name, &mut None);
                    assert!(wake >= started);
                    assert!(
                        wake <= tokio::time::Instant::now() + std::time::Duration::from_secs(1)
                    );
                })
                .await
                .expect("raw clock replacement must not panic a stream deadline task");
            }
        }
    }

    #[tokio::test]
    async fn a_pinned_near_future_deadline_is_checked_once_without_timer_spin() {
        use fireemu_core_pubsub::PubsubMessage;
        use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
        let (handle, name) = handle_fixture();
        let topic = handle
            .state()
            .subscription_config(&name)
            .unwrap()
            .topic
            .clone();
        handle
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: vec![1],
                    ..Default::default()
                }],
            )
            .unwrap();
        handle.pull(&name, 1).unwrap();
        handle
            .clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_nanos(10_000_000_000 - 1))
            .unwrap();
        let mut scheduled = None;
        let first = handle.pull_recheck_at(&name, &mut scheduled);
        assert_eq!(
            scheduled.as_ref().unwrap().1,
            Some(LogicalInstant::from_unix_seconds(10))
        );
        tokio::time::sleep_until(first).await;
        let second = handle.pull_recheck_at(&name, &mut scheduled);
        assert!(
            second.duration_since(tokio::time::Instant::now())
                > std::time::Duration::from_millis(900)
        );
        assert_eq!(handle.pull_recheck_at(&name, &mut scheduled), second);
    }

    #[tokio::test]
    #[ignore = "bounded performance measurement; run explicitly with port-registry"]
    #[allow(clippy::too_many_lines)]
    async fn measure_streaming_idle_work_and_deferred_payload_copies() {
        use fireemu_core_pubsub::{PubsubMessage, ReceivedMessage, StoredMessage};
        use fireemu_core_types::time::LogicalInstant;
        use std::sync::atomic::AtomicUsize;
        let (handle, name) = handle_fixture();
        let port = std::env::var("PORT").unwrap_or_else(|_| "0".to_owned());
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            crate::serve_pubsub(listener, server_handle).await.unwrap();
        });
        let channel = tonic::transport::Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        for streams in [1usize, 100, 1000] {
            let mut clients = Vec::new();
            let initial = handle.stream_pull_checks.load(Ordering::Relaxed);
            for _ in 0..streams {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tx.send(pb::StreamingPullRequest {
                    subscription: name.to_full(),
                    stream_ack_deadline_seconds: 10,
                    ..Default::default()
                })
                .await
                .unwrap();
                let response = pb::subscriber_client::SubscriberClient::new(channel.clone())
                    .streaming_pull(ReceiverStream::new(rx))
                    .await
                    .unwrap()
                    .into_inner();
                clients.push((tx, response));
            }
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while handle.stream_pull_checks.load(Ordering::Relaxed) < initial + streams {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let before = handle.stream_pull_checks.load(Ordering::Relaxed);
            let candidate_started = std::time::Instant::now();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let candidate = handle.stream_pull_checks.load(Ordering::Relaxed) - before;
            let candidate_elapsed_us = candidate_started.elapsed().as_micros();
            let baseline_started = std::time::Instant::now();
            let baseline = Arc::new(AtomicUsize::new(0));
            let mut polling = Vec::new();
            for _ in 0..streams {
                let count = baseline.clone();
                let handle = handle.clone();
                let name = name.clone();
                polling.push(tokio::spawn(async move {
                    let mut ticks = tokio::time::interval(std::time::Duration::from_millis(25));
                    loop {
                        ticks.tick().await;
                        handle.pull(&name, 100).unwrap();
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            for task in polling {
                task.abort();
                let _ = task.await;
            }
            let baseline = baseline.load(Ordering::Relaxed);
            let baseline_elapsed_us = baseline_started.elapsed().as_micros();
            println!("IDLE streams={streams} requested_window_ms=250 baseline_elapsed_us={baseline_elapsed_us} candidate_elapsed_us={candidate_elapsed_us} baseline_pull_checks={baseline} candidate_pull_checks={candidate}");
            assert!(baseline >= streams * 5);
            assert!(candidate <= streams * 2);
            drop(clients);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let stored = Arc::new(StoredMessage {
            message_id: "shared".to_owned(),
            publish_time: LogicalInstant::UNIX_EPOCH,
            message: PubsubMessage {
                data: vec![7; 1024 * 1024],
                ..Default::default()
            },
        });
        let messages = (0..100)
            .map(|index| ReceivedMessage {
                ack_id: format!("ack-{index:016x}"),
                message: stored.clone(),
                delivery_attempt: 1,
            })
            .collect::<Vec<_>>();
        let before = crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get);
        let started = std::time::Instant::now();
        let baseline = messages
            .iter()
            .map(|message| received_to_proto(message, true, crate::PagingPolicy::Strict))
            .collect::<Vec<_>>();
        let baseline_us = started.elapsed().as_micros();
        let baseline_copies =
            crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get) - before;
        drop(baseline);
        let budget = Arc::new(OutputBudget::new(16 * 1024 * 1024));
        let bytes = crate::convert::streaming_size_bound(
            &messages
                .iter()
                .map(|message| message.message.as_ref())
                .collect::<Vec<_>>(),
        );
        let reservation = budget.try_reserve(bytes).unwrap();
        let queued = QueuedResponse {
            messages,
            subscription_properties: None,
            report_attempt: true,
            policy: crate::PagingPolicy::Strict,
            _reservation: reservation,
        };
        let candidate_copies = crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get)
            - before
            - baseline_copies;
        println!("COPIES messages=100 payload_bytes=1048576 baseline_bytes={baseline_copies} candidate_unread_bytes={candidate_copies} reserved_encoded_bound={bytes} baseline_us={baseline_us}");
        assert_eq!(baseline_copies, 100 * 1024 * 1024);
        assert_eq!(candidate_copies, 0);
        drop(queued);
        assert_eq!(*budget.used.lock().unwrap(), 0);
        drop(channel);
        handle.shutdown_push_dispatcher().await;
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn blocked_output_neither_copies_payload_nor_starts_delivery_leases() {
        use fireemu_core_pubsub::PubsubMessage;
        let (handle, name) = handle_fixture();
        let topic = handle
            .state()
            .subscription_config(&name)
            .unwrap()
            .topic
            .clone();
        handle
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: vec![7; 1024],
                    ..Default::default()
                }],
            )
            .unwrap();
        let budget = Arc::new(OutputBudget::new(2048));
        let occupied = budget.try_reserve(2048).unwrap();
        let before = crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get);
        assert!(
            prepare_stream_response(&handle, &name, 100, &budget, true, None)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get),
            before
        );
        drop(occupied);
        let response = prepare_stream_response(&handle, &name, 100, &budget, true, None)
            .unwrap()
            .unwrap();
        assert_eq!(response.messages[0].delivery_attempt, 1);
        assert_eq!(
            crate::convert::PAYLOAD_CLONED_BYTES.with(std::cell::Cell::get),
            before
        );
        drop(response);
        assert_eq!(*budget.used.lock().unwrap(), 0);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn an_unread_real_stream_with_occupied_bytes_does_not_block_other_delivery_or_ack() {
        use fireemu_core_pubsub::{PubsubMessage, TopicName};
        let (mut handle, slow_name) = handle_fixture();
        // Scale only the private test budget, preserving the production admission algorithm.
        // One normal 100-message response is then an exclusive oversized reservation.
        handle.stream_output_budget_limit = 16 * 1024;
        let slow_topic = handle
            .state()
            .subscription_config(&slow_name)
            .unwrap()
            .topic
            .clone();
        let fast_topic = TopicName::new("demo-app", "active").unwrap();
        handle
            .state()
            .create_topic(fast_topic.clone(), BTreeMap::new())
            .unwrap();
        let config = crate::convert::subscription_from_proto(&pb::Subscription {
            name: "projects/demo-app/subscriptions/active".to_owned(),
            topic: fast_topic.to_full(),
            ..Default::default()
        })
        .unwrap();
        let fast_name = config.name.clone();
        handle.state().create_subscription(config).unwrap();
        let port = std::env::var("PORT").unwrap_or_else(|_| "0".to_owned());
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            crate::serve_pubsub(listener, server_handle).await.unwrap();
        });
        let endpoint = format!("http://{address}");
        // A small HTTP/2 stream window makes unread transport backpressure deterministic.
        let slow_channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
            .unwrap()
            .initial_stream_window_size(1024u32)
            .connect()
            .await
            .unwrap();
        let (slow_tx, slow_rx) = tokio::sync::mpsc::channel(1);
        slow_tx
            .send(pb::StreamingPullRequest {
                subscription: slow_name.to_full(),
                stream_ack_deadline_seconds: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        let slow_response = pb::subscriber_client::SubscriberClient::new(slow_channel.clone())
            .streaming_pull(ReceiverStream::new(slow_rx))
            .await
            .unwrap()
            .into_inner();
        let slow_budget = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let observed = handle
                    .stream_output_budgets
                    .lock()
                    .unwrap()
                    .get(&slow_name.to_full())
                    .and_then(std::sync::Weak::upgrade);
                if let Some(budget) = observed {
                    break budget;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handle
            .publish(
                &slow_topic,
                (0..500)
                    .map(|_| PubsubMessage {
                        data: vec![7; 1024],
                        ..Default::default()
                    })
                    .collect(),
            )
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *slow_budget.used.lock().unwrap() > slow_budget.limit {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Allow the one body already being encoded to reach its full flow-control window.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(*slow_budget.used.lock().unwrap() > slow_budget.limit);
        let fast_channel = tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut fast_client = pb::subscriber_client::SubscriberClient::new(fast_channel);
        let (fast_tx, fast_rx) = tokio::sync::mpsc::channel(1);
        fast_tx
            .send(pb::StreamingPullRequest {
                subscription: fast_name.to_full(),
                stream_ack_deadline_seconds: 10,
                max_outstanding_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        let mut fast_response = fast_client
            .streaming_pull(ReceiverStream::new(fast_rx))
            .await
            .unwrap()
            .into_inner();
        let checks_before = handle.stream_pull_checks.load(Ordering::Relaxed);
        let started = std::time::Instant::now();
        for round in 0u8..16 {
            handle
                .publish(
                    &slow_topic,
                    vec![PubsubMessage {
                        data: vec![round],
                        ..Default::default()
                    }],
                )
                .unwrap();
            let published = handle
                .publish(
                    &fast_topic,
                    vec![PubsubMessage {
                        data: vec![round],
                        ..Default::default()
                    }],
                )
                .unwrap();
            let response = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                fast_response.message(),
            )
            .await
            .expect("occupied unread output must not block another subscription")
            .unwrap()
            .unwrap();
            assert_eq!(response.received_messages.len(), 1);
            let received = &response.received_messages[0];
            assert_eq!(
                received.message.as_ref().unwrap().message_id,
                published[0].message_id
            );
            assert_eq!(received.message.as_ref().unwrap().data, vec![round]);
            fast_client
                .acknowledge(pb::AcknowledgeRequest {
                    subscription: fast_name.to_full(),
                    ack_ids: vec![received.ack_id.clone()],
                })
                .await
                .unwrap();
            let mut ids = BTreeSet::from([crate::ack_token::internal(
                &received.ack_id,
                handle.paging_policy,
            )]);
            let now = handle.now();
            handle
                .state()
                .retain_outstanding_ack_ids(&fast_name, &mut ids, now)
                .unwrap();
            assert!(
                ids.is_empty(),
                "actual ACK retires the delivered broker lease"
            );
            assert!(
                *slow_budget.used.lock().unwrap() > slow_budget.limit,
                "slow queued output remains unread and occupies bytes"
            );
        }
        let elapsed_us = started.elapsed().as_micros();
        let checks = handle.stream_pull_checks.load(Ordering::Relaxed) - checks_before;
        println!("MIXED subscriptions=2 publications=32 delivered=16 acked=16 elapsed_us={elapsed_us} total_pull_checks={checks} slow_reserved_bytes={} slow_budget_limit={}",*slow_budget.used.lock().unwrap(),slow_budget.limit);
        drop(fast_tx);
        drop(fast_response);
        drop(fast_client);
        drop(slow_tx);
        drop(slow_response);
        drop(slow_channel);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while *slow_budget.used.lock().unwrap() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("disconnect releases queued output reservations");
        handle.shutdown_push_dispatcher().await;
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn output_reservations_release_and_preserve_oversized_batch_progress() {
        let budget = Arc::new(OutputBudget::new(10));
        let first = budget.try_reserve(6).unwrap();
        assert!(budget.try_reserve(5).is_none());
        let second = budget.try_reserve(4).unwrap();
        assert!(budget.try_reserve(20).is_none());
        drop(first);
        assert!(budget.try_reserve(7).is_none());
        drop(second);
        let oversized = budget.try_reserve(20).unwrap();
        assert!(budget.try_reserve(1).is_none());
        drop(oversized);
        assert!(budget.try_reserve(10).is_some());
    }

    #[tokio::test]
    async fn dropping_an_unread_response_releases_output_bytes() {
        let budget = Arc::new(OutputBudget::new(10));
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<QueuedResponse, Status>>(1);
        let reserved = budget.try_reserve(10).unwrap();
        tx.send(Ok(QueuedResponse {
            messages: Vec::new(),
            subscription_properties: None,
            report_attempt: true,
            policy: crate::PagingPolicy::Emulator,
            _reservation: reserved,
        }))
        .await
        .unwrap();
        assert!(budget.try_reserve(1).is_none());
        drop(rx);
        assert!(budget.try_reserve(10).is_some());
    }
}
