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
use tracing::{debug, info, warn};

use crate::assembly::Assembly;
use crate::error::VSError;
use libeval::eval::{EvalContext, EvalDecision};
use vs_dt::vsapi_types::{PacketDesc, Visa, VisaDenialReason};

pub enum VisaDecision {
    Allow(Visa),
    Deny(VisaDenialReason),
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
            warn!(
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

async fn process_visa_request(asm: Arc<Assembly>, job: &VisaRequestJob) -> VisaRequestResult {
    let Some(source_actor) = asm.actor_db.get_actor_by_ip(&job.packet_desc.source_addr) else {
        debug!(
            "source actor not found for visa request from {:?}",
            job.requesting_node
        );
        return Ok(VisaDecision::Deny(VisaDenialReason::SourceNotFound));
    };
    let Some(dest_actor) = asm.actor_db.get_actor_by_ip(&job.packet_desc.dest_addr) else {
        debug!(
            "dest actor not found for visa request from {:?}",
            job.requesting_node
        );
        return Ok(VisaDecision::Deny(VisaDenialReason::DestNotFound));
    };

    let policy = asm.policy_mgr.get_current();
    let ctx = EvalContext::new(policy);
    let decision = match ctx.eval_request(&source_actor, &dest_actor, &job.packet_desc) {
        Ok(decision) => decision,
        Err(e) => {
            debug!(
                "error evaluating visa request from {:?}: {}",
                job.requesting_node, e
            );
            return Err(e.into());
        }
    };
    drop(ctx);

    match decision {
        EvalDecision::NoMatch(message) => {
            info!(
                "visa request from {:?} denied (no match): {}",
                job.requesting_node, message
            );
            Ok(VisaDecision::Deny(VisaDenialReason::NoMatch))
        }
        EvalDecision::Allow(hits) => {
            // TODO: For now we pick the first hit.
            match asm.visa_mgr.create_visa(&job.packet_desc, &hits[0]) {
                Ok(visa) => Ok(VisaDecision::Allow(visa)),
                Err(e) => {
                    debug!(
                        "error creating visa for request from {:?}: {}",
                        job.requesting_node, e
                    );
                    Err(e.into())
                }
            }
        }
        EvalDecision::Deny(_hits) => {
            info!(
                "visa request from {:?} denied by policy",
                job.requesting_node
            );
            Ok(VisaDecision::Deny(VisaDenialReason::Denied))
        }
    }
}
