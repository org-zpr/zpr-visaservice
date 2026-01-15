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

use futures::StreamExt;
use futures::future::FutureExt;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

use crate::assembly::Assembly;
use crate::error::VSError;
use crate::logging::targets::VISAREQ;

use libeval::actor::Actor;
use libeval::eval::{EvalContext, EvalDecision};
use zpr::vsapi_types::{DenyCode, PacketDesc, Visa};

pub enum VisaDecision {
    Allow(Visa),
    Deny(DenyCode),
}

/// The result is either a [Visa], or a regular denial, or there was an unexpected failure
/// and you get a [VSError].
pub type VisaRequestResult = Result<VisaDecision, VSError>;

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
/// (TODO: Timeout)
pub async fn request_visa_wait_response(
    asm: Arc<Assembly>,
    requesting_node: &IpAddr,
    pkt_data: PacketDesc,
) -> Result<VisaDecision, VSError> {
    let (job, response_rx) = VisaRequestJob::new(requesting_node.clone(), pkt_data);

    match asm.vreq_chan.send(job).await {
        Ok(()) => (),
        Err(e) => {
            error!(target: VISAREQ, "error enqueuing visa request: {}", e);
            return Err(VSError::InternalError(
                "internal error enqueuing visa request".to_string(),
            ));
        }
    }

    // Now wait for a response (TODO: timeout?)
    // This will fill in the api response.
    match response_rx.await {
        Ok(vr_result) => match vr_result {
            Ok(vd) => return Ok(vd),
            Err(e) => {
                return Err(VSError::InternalError(format!(
                    "internal error processing visa request: {}",
                    e
                )));
            }
        },
        Err(e) => {
            return Err(VSError::InternalError(format!(
                "internal error receiving visa request response: {}",
                e
            )));
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
    let vrr = process_visa_request(asm, &job).await;
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
                        "error creating visa for request from {:?}: {}",
                        job.requesting_node, e
                    );
                    Err(e.into())
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
) -> Result<(Option<Actor>, Option<Actor>), VSError> {
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
            return Err(VSError::InternalError(
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
            return Err(VSError::InternalError("error retrieving dest actor".into()));
        }
    };

    Ok((source_actor, dest_actor))
}
