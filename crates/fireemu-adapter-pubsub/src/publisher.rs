//! The `google.pubsub.v1.Publisher` service implementation.
#![allow(clippy::result_large_err)] // tonic::Status is large by design

use prost::Message;
use tonic::{Request, Response, Status};

use fireemu_core_pubsub::TopicName;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_server::Publisher;

use crate::convert::{
    message_from_proto, status, storage_policy_from_proto, topic_to_proto, validate_topic_options,
    validate_topic_update_options, TopicUpdatePaths,
};
use crate::PubSubHandle;

/// Publisher service over the shared Pub/Sub state.
pub struct PublisherService {
    handle: PubSubHandle,
}

impl PublisherService {
    /// Builds the service over a handle.
    #[must_use]
    pub fn new(handle: PubSubHandle) -> Self {
        Self { handle }
    }
}

/// Strips the `projects/{p}` wrapper a `List*` request uses to name a project.
fn project_of(resource: &str) -> Result<&str, Status> {
    resource
        .strip_prefix("projects/")
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .ok_or_else(|| Status::invalid_argument("project must be projects/{project}"))
}

/// A topic as the wire carries it, read from the shared state.
fn stored_topic(
    state: &fireemu_core_pubsub::PubSubState,
    name: &TopicName,
) -> fireemu_core_pubsub::Result<pb::Topic> {
    let mut topic = topic_to_proto(name, state.topic_labels(name)?);
    topic.message_retention_duration = state
        .topic_retention(name)?
        .map(crate::convert::duration_to_proto);
    topic.message_storage_policy = state
        .topic_storage_policy(name)?
        .map(crate::convert::storage_policy_to_proto);
    Ok(topic)
}

#[tonic::async_trait]
impl Publisher for PublisherService {
    async fn create_topic(
        &self,
        request: Request<pb::Topic>,
    ) -> Result<Response<pb::Topic>, Status> {
        let topic = request.into_inner();
        validate_topic_options(&topic, self.handle.paging_policy).map_err(|e| status(&e))?;
        let name = TopicName::parse(&topic.name).map_err(|e| status(&e))?;
        let labels = topic.labels.into_iter().collect();
        if self.handle.paging_policy == crate::PagingPolicy::Strict {
            fireemu_core_pubsub::configuration::validate_labels(&labels)
                .map_err(|error| status(&error))?;
        }
        self.handle
            .state()
            .create_topic_with_storage_policy(
                name.clone(),
                labels,
                topic
                    .message_retention_duration
                    .as_ref()
                    .map(crate::convert::duration_from_proto)
                    .transpose()
                    .map_err(|error| status(&error))?,
                topic
                    .message_storage_policy
                    .as_ref()
                    .map(storage_policy_from_proto),
            )
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        let created = stored_topic(&self.handle.state(), &name).map_err(|e| status(&e))?;
        Ok(Response::new(created))
    }

    async fn update_topic(
        &self,
        request: Request<pb::UpdateTopicRequest>,
    ) -> Result<Response<pb::Topic>, Status> {
        let request = request.into_inner();
        validate_topic_update_options(&request, self.handle.paging_policy)
            .map_err(|e| status(&e))?;
        let Some(paths) = request
            .update_mask
            .as_ref()
            .and_then(|mask| TopicUpdatePaths::from_mask(&mask.paths))
        else {
            return Err(Status::unimplemented(
                "UpdateTopic is not supported by the Pub/Sub emulator",
            ));
        };
        let Some(topic) = request.topic else {
            return Err(Status::unimplemented(
                "UpdateTopic is not supported by the Pub/Sub emulator",
            ));
        };
        let name = TopicName::parse(&topic.name).map_err(|error| status(&error))?;
        let mut state = self.handle.state();
        let update = paths.build(
            &topic,
            state
                .topic_storage_policy(&name)
                .map_err(|error| status(&error))?,
        );
        state
            .update_topic(
                &name,
                update,
                self.handle.paging_policy == crate::PagingPolicy::Strict,
            )
            .map_err(|error| status(&error))?;
        Ok(Response::new(
            stored_topic(&state, &name).map_err(|e| status(&e))?,
        ))
    }

    async fn publish(
        &self,
        request: Request<pb::PublishRequest>,
    ) -> Result<Response<pb::PublishResponse>, Status> {
        let req = request.into_inner();
        let topic = TopicName::parse(&req.topic).map_err(|e| status(&e))?;
        if self.handle.paging_policy == crate::PagingPolicy::Strict {
            crate::admission::publish_request_size(req.encoded_len())
                .map_err(|error| status(&error))?;
            crate::admission::message_count(req.messages.len()).map_err(|error| status(&error))?;
        }
        let messages = req.messages.into_iter().map(message_from_proto).collect();
        let published = self.handle.publish(&topic, messages);
        if published.is_ok() {
            self.handle.retry_pending_dead_letters();
        }
        let published = published.map_err(|e| status(&e))?;
        let ids: Vec<String> = published
            .iter()
            .map(|message| message.message_id.clone())
            .collect();
        Ok(Response::new(pb::PublishResponse { message_ids: ids }))
    }

    async fn get_topic(
        &self,
        request: Request<pb::GetTopicRequest>,
    ) -> Result<Response<pb::Topic>, Status> {
        let name = TopicName::parse(&request.into_inner().topic).map_err(|e| status(&e))?;
        let topic = stored_topic(&self.handle.state(), &name).map_err(|e| status(&e))?;
        Ok(Response::new(topic))
    }

    async fn list_topics(
        &self,
        request: Request<pb::ListTopicsRequest>,
    ) -> Result<Response<pb::ListTopicsResponse>, Status> {
        let req = request.into_inner();
        let project = project_of(&req.project)?;
        let mut state = self.handle.state();
        let topics: Vec<_> = state
            .list_topics(project)
            .iter()
            .map(|n| stored_topic(&state, n).unwrap_or_default())
            .collect();
        let page = state
            .paginate(
                &format!("projects/{project}/topics"),
                topics,
                req.page_size,
                &req.page_token,
                self.handle.paging_policy,
                |topic| topic.name.clone(),
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListTopicsResponse {
            topics: page.resources,
            next_page_token: page.next_page_token,
        }))
    }

    async fn list_topic_subscriptions(
        &self,
        request: Request<pb::ListTopicSubscriptionsRequest>,
    ) -> Result<Response<pb::ListTopicSubscriptionsResponse>, Status> {
        let req = request.into_inner();
        let name = TopicName::parse(&req.topic).map_err(|e| status(&e))?;
        let mut state = self.handle.state();
        if !state.topic_exists(&name) && self.handle.paging_policy == crate::PagingPolicy::Strict {
            return Err(Status::not_found(format!(
                "Resource not found (resource={}).",
                name.topic()
            )));
        }
        let subscriptions = state.topic_subscriptions(&name);
        let page = state
            .paginate(
                &format!("{}/subscriptions", name.to_full()),
                subscriptions,
                req.page_size,
                &req.page_token,
                self.handle.paging_policy,
                Clone::clone,
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListTopicSubscriptionsResponse {
            subscriptions: page.resources,
            next_page_token: page.next_page_token,
        }))
    }

    async fn list_topic_snapshots(
        &self,
        request: Request<pb::ListTopicSnapshotsRequest>,
    ) -> Result<Response<pb::ListTopicSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let name = TopicName::parse(&req.topic).map_err(|e| status(&e))?;
        let now = self.handle.now();
        let mut state = self.handle.state();
        let snapshots = if !state.topic_exists(&name)
            && self.handle.paging_policy == crate::PagingPolicy::Emulator
        {
            Vec::new()
        } else {
            state
                .list_topic_snapshots(&name, now)
                .map_err(|e| status(&e))?
        };
        let page = state
            .paginate(
                &format!("{}/snapshots", name.to_full()),
                snapshots,
                req.page_size,
                &req.page_token,
                self.handle.paging_policy,
                Clone::clone,
            )
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListTopicSnapshotsResponse {
            snapshots: page.resources,
            next_page_token: page.next_page_token,
        }))
    }

    async fn delete_topic(
        &self,
        request: Request<pb::DeleteTopicRequest>,
    ) -> Result<Response<()>, Status> {
        let name = TopicName::parse(&request.into_inner().topic).map_err(|e| status(&e))?;
        self.handle
            .state()
            .delete_topic(&name)
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        Ok(Response::new(()))
    }

    async fn detach_subscription(
        &self,
        _request: Request<pb::DetachSubscriptionRequest>,
    ) -> Result<Response<pb::DetachSubscriptionResponse>, Status> {
        Err(Status::unimplemented(
            "DetachSubscription is not supported by the Pub/Sub emulator",
        ))
    }
}
