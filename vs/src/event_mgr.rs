//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::future::join_all;
use futures::stream::{self, StreamExt};

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1::DisconnectReason;
use zpr::vsapi_types::ServiceDescriptor;

use libeval::eval::EvalContext;

use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::EVENT;
use crate::policy_mgr::PolicySnapshot;

pub enum VsEvent {
    /// Use _after_ actor has been authenticated and the datastore updated.
    ActorJoins(IpAddr),

    /// Use when we get a signal from remote that actor is disconnected/disconnecting.
    /// EventManager takes care of state updates.
    ActorLeaves(IpAddr, DisconnectReason),

    /// Indicates that policy has been successfully updated. Pass the new `vinst`.
    PolicyUpdated(u64),
}

pub struct EventMgr {
    event_queue: mpsc::Sender<VsEvent>,
}

impl EventMgr {
    pub fn new(event_queue: mpsc::Sender<VsEvent>) -> Self {
        EventMgr { event_queue }
    }

    pub async fn record_event(&self, event: VsEvent) -> Result<(), ServiceError> {
        if let Err(e) = self.event_queue.send(event).await {
            error!(target: EVENT, "failed to send to event-queue: {}", e);
            Err(ServiceError::QueueFull("event-queue".into()))
        } else {
            Ok(())
        }
    }
}

pub async fn launch(asm: Arc<Assembly>, mut event_rx: mpsc::Receiver<VsEvent>) {
    debug!(target: EVENT, "event manager worker started");
    while let Some(event) = event_rx.recv().await {
        match event {
            VsEvent::ActorJoins(actor) => {
                if let Err(e) = handle_actor_joins(&asm, actor).await {
                    error!(target: EVENT, "failed to handle actor join event: {}", e);
                }
            }
            VsEvent::ActorLeaves(actor, reason) => {
                if let Err(e) = handle_actor_leaves(&asm, actor, reason).await {
                    error!(target: EVENT, "failed to handle actor leave event: {}", e);
                }
            }
            VsEvent::PolicyUpdated(vinst) => {
                if let Err(e) = handle_policy_updated(&asm, vinst).await {
                    error!(target: EVENT, "failed to handle policy updated event: {}", e);
                }
            }
        }
    }
    info!(target: EVENT, "event manager shutting down");
}

// Maybe will call into topology routines from here eventually.
async fn handle_actor_joins(asm: &Arc<Assembly>, actor_addr: IpAddr) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor joined: {}", actor_addr);
    let has_auth_services = match asm
        .actor_mgr
        .has_auth_services(asm.clone(), &actor_addr)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            error!(target: EVENT, "actor_mgr.has_auth_services failed: {}", e);
            false
        }
    };

    if has_auth_services {
        //let service_list =
        match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
            Ok(svcs) => set_services_all_nodes(&asm, &svcs).await?,
            Err(e) => {
                error!(
                    target: EVENT,
                    "actor_mgr.get_auth_services_list failed: {}", e
                );
            }
        }
    }
    Ok(())
}

// TODO: Not sure I love this idea of having these wide ranging functions in the 'event_mgr'.
// Things could get quite messy.
//
// The goal is somewhere to centralize high level logic that imapacts all sorts of areas in the
// visa service.
async fn handle_actor_leaves(
    asm: &Arc<Assembly>,
    actor_addr: IpAddr,
    _reason: DisconnectReason,
) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor left: {}", actor_addr);

    let prev_auth_services: HashSet<ServiceDescriptor> = HashSet::from_iter(
        asm.actor_mgr
            .get_auth_services_list(asm.clone())
            .await
            .unwrap_or_default(),
    );

    if !prev_auth_services.is_empty() {
        let new_auth_services: HashSet<ServiceDescriptor> =
            HashSet::from_iter(asm.actor_mgr.get_auth_services_list(asm.clone()).await?); // will error out on DB error

        // If there is a difference between previous and new authorized services, we need to update nodes.
        if prev_auth_services != new_auth_services {
            set_services_all_nodes(&asm, &new_auth_services.iter().cloned().collect::<Vec<_>>())
                .await?;
        }
    }

    Ok(())
}

/// Helper to use the VSS on all connected nodes to update the auth services list.
async fn set_services_all_nodes(
    asm: &Arc<Assembly>,
    service_set: &[ServiceDescriptor],
) -> Result<(), ServiceError> {
    let node_list = asm.actor_mgr.list_node_addrs().await.unwrap_or_default();

    // Make RPC calls to the nodes in parallel.

    stream::iter(node_list)
        .for_each_concurrent(None, |naddr| {
            let asm = asm.clone();
            let service_list: Vec<ServiceDescriptor> = service_set.to_vec();
            async move {
                debug!(
                    target: EVENT,
                    "attempting to use VSS to set_services on node {naddr}"
                );
                if let Some(vss_h) = asm.vss_mgr.get_handle(&naddr) {
                    if let Err(e) = vss_h.set_services(service_list).await {
                        error!(
                            target: EVENT,
                            "failed to set_services on node {}: {}",
                            naddr,
                            e
                        );
                    }
                }
            }
        })
        .await;
    Ok(())
}

async fn handle_policy_updated(asm: &Arc<Assembly>, vinst: u64) -> Result<(), ServiceError> {
    /*

    https://github.com/org-zpr/zpr-visaservice/issues/219


    When we get here we have already updated policy.

    - are there any existing visas that need to be revoked.
       - do we have the 5-tuple or whatever so that we can check them? NO, this is a TODO.

    - check our existing topology.
       - Are all the nodes and links still valid?

    - request re-auth all nodes.

    - clear revocation list? May make more sense to keep it and make admin clear manually.

    - services -> ensure all services being offered are still allowed by policy.
       - What if an already connected adapter has a new service -> will need to re-connect?
       - We can do a basic check to see that all the services we have do exist in policy.
          - But that won't detect if a service has altered its provider.
          - TO BE SAFE: expire auth from all services - force re-auth of all existing services (after removing non-existing ones)

    - all connected adapters.  Are they still allowed?
       - Well we could expire all the auth, but that seems drastic.
       - Instead we will have already killed visas. Probably ok to let them be connected but unable to do anything.

     */

    // Grab one consistent policy snapshot and use it for the entire synchronize-to-policy
    // pass below, so revalidation and per-node link computation all read the same view.
    let psnap = asm.policy_mgr.get_current_snapshot();

    // PolicyUpdated(vinst) is a trigger, not a guarantee that this handler reconciles that
    // exact revision. If updates queue faster than we process them we reconcile against the
    // latest snapshot.
    let snapshot_vinst = psnap.vinst();
    if snapshot_vinst != vinst {
        info!(
            target: EVENT,
            "policy update event called with vinst={vinst}, using current snapshot vinst={snapshot_vinst}"
        );
    }

    // The new policy may invalidate some existing nodes.
    let connected_node_addrs = match revalidate_nodes(asm, &psnap).await {
        Ok(addrs) => addrs,
        Err(e) => {
            error!(target: EVENT, "failed to load the set of connected nodes: {e}");
            Vec::new() // proceed with empty set of nodes
        }
    };

    // Only do these steps if we managed to get a set of connected nodes. If
    // there actually are no nodes connected at the moment, then topology should
    // have been updated via other code paths.  The purpose of updating the
    // topology when presented with a new policy is to verify that existing
    // links are still allowed, and send out peer messages.
    if !connected_node_addrs.is_empty() {
        info!(target: EVENT, "policy updated vinst={vinst}: revalidating topology ({} nodes)", connected_node_addrs.len());
        let report = asm
            .topo_mgr
            .revalidate_against_policy(&psnap, &connected_node_addrs)
            .await?;
        info!(
            target: EVENT,
            "topology revalidated vinst={vinst}: removed={} updated={} repaired={} orphaned={}",
            report.links_removed,
            report.links_updated,
            report.links_repaired,
            report.orphaned_nodes.len()
        );

        // Queue up setTopology messages in parallel.
        let futs = connected_node_addrs.iter().filter_map(|naddr| {
            let links = psnap.links_for_node(naddr);
            asm.vss_mgr.get_handle(naddr).map(|vss_handle| async move {
                if let Err(e) = vss_handle.set_topology(links).await {
                    error!(target: EVENT, "failed to set topology for node {}: {}", naddr, e);
                }
            })
        });
        join_all(futs).await;
    }

    Ok(())
}

/// When we get a new policy, some nodes my no longer be valid. This will check
/// that and return the set of connected nodes that are still valid under the
/// policy.
///
/// Note that the best way to revalidate a node is to prompt it to
/// re-authenticate. (TODO).
///
/// ### Errors
/// - The only error you get from this will be an error from `list_node_addrs`.
async fn revalidate_nodes(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
) -> Result<Vec<IpAddr>, ServiceError> {
    let mut connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;

    // Check existing nodes against policy.
    let ectx = EvalContext::new(psnap.policy_arc());

    // Pass each node through our gating/checking function which is not a pure
    // predicate -- it does have side effect of issuing disconnect requests and
    // firing events if the node is found to be no longer valid under the new
    // policy.
    //
    // But the nice thing is that this `keep_flags` vector is just a simple
    // `Vec<bool>` that we can use to retain only the valid nodes in the end.
    let keep_flags = join_all(
        connected_node_addrs
            .iter()
            .map(|naddr| revalidate_node_or_disconnect(asm, &ectx, naddr)),
    )
    .await;

    let mut flags_iter = keep_flags.into_iter();
    connected_node_addrs.retain(|_| flags_iter.next().unwrap());

    Ok(connected_node_addrs)
}

/// Helper function for [revalidate_nodes].
/// Loads the node `Actor` from the `actor_mgr` and then uses the `EvalContext` to check that
/// the actor is still permitted by policy. Note this does not check authentication -- just
/// attributes that were authenticated under the previous policy.
///
/// If the node passes the check, `true` is returned, meaning node looks valid.
///
/// If the check fails, this function has additional side effects:
/// - (1) Call to `ConnectionControl` to disconnect the node.
/// - (2) Record an `ActorLeaves` event in the `EventMgr` queue.
///
/// Errors in here are just logged, not propagated.
async fn revalidate_node_or_disconnect(
    asm: &Arc<Assembly>,
    ectx: &EvalContext,
    naddr: &IpAddr,
) -> bool {
    if let Ok(maybe_node_actor) = asm.actor_mgr.get_actor_by_zpr_addr(naddr).await {
        if let Some(node_actor) = maybe_node_actor {
            match ectx.approve_connected(&node_actor) {
                Ok(true) => return true,

                Ok(false) => {
                    info!(target: EVENT, "connected node {naddr} is no longer approved by policy, disconnecting");
                    if let Err(e) = asm
                        .cc
                        .disconnect(asm.clone(), *naddr, DisconnectReason::Admin)
                        .await
                    {
                        warn!(target: EVENT, "error processing disconnect of {naddr}: {e}");
                        // And in this case we do not send an actor-leaves event.
                        // But we still return false, so the node appears to caller to be invalid.
                    } else {
                        let evt = VsEvent::ActorLeaves(*naddr, DisconnectReason::Admin);
                        if let Err(e) = asm.event_mgr.record_event(evt).await {
                            warn!(target: EVENT, "failed to record actor leaves event for {naddr}: {e}");
                        }
                    }
                    return false;
                }
                Err(e) => {
                    warn!(target: EVENT, "failed to evaluate connected node {naddr} against policy: {e}");
                    return true;
                }
            }
        } else {
            // We passed a node address to ActorMgr but did not get an Actor back?
            // That's probably a problem, but not our problem.  We let it stand for now.
            return true;
        }
    } else {
        // Some issue occurred while querying for the actor. We optamistically return true here.
        return true;
    }
}
