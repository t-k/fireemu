//! The `google.pubsub.v1.Publisher` service implementation.
#![allow(clippy::result_large_err)] // tonic::Status is large by design

use tonic::{Request, Response, Status};

use fireemu_core_pubsub::TopicName;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_server::Publisher;

use crate::convert::{message_from_proto, status, topic_to_proto};
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

#[tonic::async_trait]
impl Publisher for PublisherService {
    async fn create_topic(
        &self,
        request: Request<pb::Topic>,
    ) -> Result<Response<pb::Topic>, Status> {
        let topic = request.into_inner();
        let name = TopicName::parse(&topic.name).map_err(|e| status(&e))?;
        let labels = topic.labels.into_iter().collect();
        self.handle
            .state()
            .create_topic(name.clone(), labels)
            .map_err(|e| status(&e))?;
        self.handle.retry_pending_dead_letters();
        let created = topic_to_proto(
            &name,
            self.handle
                .state()
                .topic_labels(&name)
                .map_err(|e| status(&e))?,
        );
        Ok(Response::new(created))
    }

    async fn update_topic(
        &self,
        _request: Request<pb::UpdateTopicRequest>,
    ) -> Result<Response<pb::Topic>, Status> {
        Err(Status::unimplemented(
            "UpdateTopic is not supported by the Pub/Sub emulator",
        ))
    }

    async fn publish(
        &self,
        request: Request<pb::PublishRequest>,
    ) -> Result<Response<pb::PublishResponse>, Status> {
        let req = request.into_inner();
        let topic = TopicName::parse(&req.topic).map_err(|e| status(&e))?;
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
        let state = self.handle.state();
        let labels = state.topic_labels(&name).map_err(|e| status(&e))?;
        Ok(Response::new(topic_to_proto(&name, labels)))
    }

    async fn list_topics(
        &self,
        request: Request<pb::ListTopicsRequest>,
    ) -> Result<Response<pb::ListTopicsResponse>, Status> {
        let req = request.into_inner();
        let project = project_of(&req.project)?;
        let state = self.handle.state();
        let topics = state
            .list_topics(project)
            .iter()
            .map(|n| {
                let labels = state.topic_labels(n).cloned().unwrap_or_default();
                topic_to_proto(n, &labels)
            })
            .collect();
        Ok(Response::new(pb::ListTopicsResponse {
            topics,
            next_page_token: String::new(),
        }))
    }

    async fn list_topic_subscriptions(
        &self,
        request: Request<pb::ListTopicSubscriptionsRequest>,
    ) -> Result<Response<pb::ListTopicSubscriptionsResponse>, Status> {
        let name = TopicName::parse(&request.into_inner().topic).map_err(|e| status(&e))?;
        let state = self.handle.state();
        if !state.topic_exists(&name) {
            return Err(Status::not_found(format!(
                "topic {} not found",
                name.to_full()
            )));
        }
        Ok(Response::new(pb::ListTopicSubscriptionsResponse {
            subscriptions: state.topic_subscriptions(&name),
            next_page_token: String::new(),
        }))
    }

    async fn list_topic_snapshots(
        &self,
        request: Request<pb::ListTopicSnapshotsRequest>,
    ) -> Result<Response<pb::ListTopicSnapshotsResponse>, Status> {
        let name = TopicName::parse(&request.into_inner().topic).map_err(|e| status(&e))?;
        let now = self.handle.now();
        let snapshots = self
            .handle
            .state()
            .list_topic_snapshots(&name, now)
            .map_err(|e| status(&e))?;
        Ok(Response::new(pb::ListTopicSnapshotsResponse {
            snapshots,
            next_page_token: String::new(),
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
