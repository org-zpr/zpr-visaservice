//! Visa request worker work on matching packets to policy in order to create visas.
//! The beating heart of the visa service.
//!
//! Each worker gets a single visa request and tried to run it throught the policy.
//! There are several outcomes:
//! - One or both actors may be missing (disconnected)
//! - One or both actors may need to be refreshed from attribute services.
//! - One or both actors may have expired authentication.
//! - A visa may already exist and policy has not changed, in which case we can use existing visa.
//! - The visa may be denied by policy.
//! - If at the end of all this a visa is permitted, then
//! - If poicy has not been updated in the meawhile, we issue a visa, else we fail it and hope caller tries again.
//!
//! Once a visa is issued we need to pick the path and figure out which nodes need to be informed.
//! There may be path constraints that make the visa invalid.
//!
//! Once we have a path, the visa is queued up for install on all the impacted nodes and
//! returned to the caller.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::future::FutureExt;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::error::ServiceError;
use crate::logging::targets::VISAREQ;

use libeval::actor::Actor;
use libeval::eval::{EvalContext, EvalDecision};
use zpr::vsapi_types::{DenyCode, PacketDesc, Visa};

pub enum VisaDecision {
    Allow(Visa),
    Deny(DenyCode),
}

/// The result is either a [Visa], or a regular denial, or there was an unexpected failure
/// and you get a [ServiceError].
pub type VisaRequestResult = Result<VisaDecision, ServiceError>;

/// TODO: add a job ID for tracing/logging.
pub struct VisaRequestJob {
    pub requesting_node: IpAddr,
    pub packet_desc: PacketDesc,
    // A channel to send the result back to the requester.
    response_chan: oneshot::Sender<VisaRequestResult>,
}

// Visa requests come into the arena where they are processed by workers.
pub async fn launch_arena(
    asm: Arc<Assembly>,
    incoming: mpsc::Receiver<VisaRequestJob>,
    max_concurrent: usize,
) {
    let stream = ReceiverStream::new(incoming);

    // TODO: This looks slick but we may want to know when we are under pressure.
    stream
        .for_each_concurrent(max_concurrent, |job| {
            tokio::spawn(process_visa_request_job(asm.clone(), job)).map(|r| r.unwrap())
        })
        .await;
}

/// Helper function to submit a visa request job and wait for the decision.
/// All visa request jobs should run through this so that visa request related counters
/// are properly updated.
///
/// ### Errors
/// - [ServiceError::Timeout] if the request times out.
/// - [ServiceError::InternalError] if there is an internal error enqueuing the request or receiving the response.
pub async fn request_visa_wait_response(
    asm: &Assembly,
    requesting_node: &IpAddr,
    pkt_data: PacketDesc,
    timeout: Duration,
) -> Result<VisaDecision, ServiceError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let (job, response_rx) = VisaRequestJob::new(requesting_node.clone(), pkt_data);

    asm.counters.incr(CounterType::VisaRequests);

    match tokio::time::timeout_at(deadline, asm.vreq_chan.reserve()).await {
        Ok(Ok(permit)) => {
            permit.send(job);
            Ok(())
        }

        Ok(Err(_closed)) => {
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(
                "internal error enqueuing visa request".to_string(),
            ))
        }

        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestQueueFull);
            Err(ServiceError::Timeout("timeout enqueuing visa request".into()))
        }
    }?;

    // Now wait for a response with the remaining timeout.
    match tokio::time::timeout_at(deadline, response_rx).await {
        // Increment the appropriate counters before returning.
        Ok(Ok(vr_result)) => match vr_result {
            Ok(VisaDecision::Allow(_)) => {
                asm.counters.incr(CounterType::VisaRequestsApproved);
                vr_result
            }
            Ok(VisaDecision::Deny(_)) => {
                asm.counters.incr(CounterType::VisaRequestsDenied);
                vr_result
            }
            Err(_) => {
                asm.counters.incr(CounterType::VisaRequestFailed);
                vr_result
            }
        },
        Ok(Err(e)) => {
            // Queue read error -- probably closed?
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(format!(
                "queue error receiving visa request response: {}",
                e
            )))
        }
        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestTimeout);
            Err(ServiceError::Timeout(format!(
                "timeout waiting for visa request response after {:?}",
                timeout
            )))
        }
    }
}

impl VisaRequestJob {
    pub fn new(
        requesting_node: IpAddr,
        packet_desc: PacketDesc,
    ) -> (Self, oneshot::Receiver<VisaRequestResult>) {
        let (tx, rx) = oneshot::channel();
        (
            VisaRequestJob {
                requesting_node,
                packet_desc,
                response_chan: tx,
            },
            rx,
        )
    }

    /// Complete this job by sending a result to the requester.
    /// Logs a warning if the requester has dropped the receiver.
    pub fn complete(self, result: VisaRequestResult) {
        if let Err(_) = self.response_chan.send(result) {
            // Means the requester has dropped the receiver.
            warn!(target: VISAREQ,
                "failed to enqueue visa request result for {:?}",
                self.requesting_node
            );
        }
    }
}

/// Main processing function for processing a visa request.
///
/// This is just a rough sketch for now.
async fn process_visa_request_job(asm: Arc<Assembly>, job: VisaRequestJob) {
    // Run the job, send the result back over the job response channel.
    let vrr = process_visa_request(asm.clone(), &job).await;
    job.complete(vrr);
}

/// Run visa request.
async fn process_visa_request(asm: Arc<Assembly>, job: &VisaRequestJob) -> VisaRequestResult {
    let (source_actor, dest_actor) = get_actors(&asm, job).await?;
    let source_actor = match source_actor {
        Some(actor) => actor,
        None => return Ok(VisaDecision::Deny(DenyCode::SourceNotFound)),
    };
    let dest_actor = match dest_actor {
        Some(actor) => actor,
        None => return Ok(VisaDecision::Deny(DenyCode::DestNotFound)),
    };

    let policy = asm.policy_mgr.get_current();
    let ctx = EvalContext::new(policy);
    let decision = match ctx.eval_request(&source_actor, &dest_actor, &job.packet_desc) {
        Ok(decision) => decision,
        Err(e) => {
            debug!(target: VISAREQ,
                "error evaluating visa request from {:?}: {}",
                job.requesting_node, e
            );
            return Err(e.into());
        }
    };
    drop(ctx);

    match decision {
        EvalDecision::NoMatch(message) => {
            info!(target: VISAREQ,
                "visa request from {:?} denied (no match): {}",
                job.requesting_node, message
            );
            Ok(VisaDecision::Deny(DenyCode::NoMatch))
        }
        EvalDecision::Allow(hits) => {
            // TODO: For now we pick the first hit.
            match asm
                .visa_mgr
                .create_visa(&job.requesting_node, &job.packet_desc, &hits[0])
                .await
            {
                Ok(visa) => Ok(VisaDecision::Allow(visa)),
                Err(e) => {
                    debug!(target: VISAREQ,
                        "visa_mgr error creating visa for request from {:?}: {}",
                        job.requesting_node, e
                    );
                    Err(e)
                }
            }
        }
        EvalDecision::Deny(_hits) => {
            info!(target: VISAREQ,
                "visa request from {:?} denied by policy",
                job.requesting_node
            );
            Ok(VisaDecision::Deny(DenyCode::Denied))
        }
    }
}

// Lookup source and destination actors in the DB based on ZPR address.
async fn get_actors(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
) -> Result<(Option<Actor>, Option<Actor>), ServiceError> {
    // TODO: The source or destination could be from an unauthenticated adapter
    // using an AAA address to talk to an authentication service.

    // See prototype code in vsinst-core.go (around line 128). In there we create
    // a fake actor to use for granting the visa.  But we need to establish that
    // the AAA address is correct for the node the adapter is connected to.

    let source_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.source_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VISAREQ,
                "error retrieving source actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal(
                "error retrieving source actor".into(),
            ));
        }
    };

    let dest_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.dest_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VISAREQ,
                "error retrieving dest actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal("error retrieving dest actor".into()));
        }
    };

    Ok((source_actor, dest_actor))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::make_node_actor_defexp;
    use std::time::Duration;

    // This test just runs a request through the pipeline. There is no real policy here
    // so it will fail.  But it should be a visa-deny not some other error.
    #[tokio::test]
    async fn request_visa_wait_response_denies_when_policy_has_no_match() {
        let (vreq_tx, vreq_rx) = mpsc::channel(8);
        let asm = Arc::new(new_assembly_for_tests(Some(vreq_tx)).await);

        let source_actor =
            make_node_actor_defexp("fd5a:5052:3000::1", "source-node", "10.0.0.1:10001");
        let dest_actor = make_node_actor_defexp("fd5a:5052:3000::2", "dest-node", "10.0.0.2:10002");
        asm.actor_mgr.add_node(&source_actor).await.unwrap();
        asm.actor_mgr.add_node(&dest_actor).await.unwrap();

        let arena = tokio::spawn(launch_arena(asm.clone(), vreq_rx, 1));

        let requestor_ip: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let result =
            request_visa_wait_response(&asm, &requestor_ip, pkt_data, Duration::from_secs(1))
                .await
                .unwrap();

        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));

        arena.abort();
    }
}
