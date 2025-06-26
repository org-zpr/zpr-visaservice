package vservice

import (
	"zpr.org/polio"
	"zpr.org/vs/pkg/actor"
)

// Callback function for adb/actordb.
//
// Note that this is often running on the vs event loop from ApproveConnection which itself is
// called from the VS thrift API which is waiting for this to return before it itself returns
// to the client (node).
func (vs *VSInst) HandleDBActorAdded(agnt *actor.Actor) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()

	if curConfig != agnt.GetConfigID() {
		// Not sure yet if this is an issue, so will log it.
		vs.log.Warn("actor added with different config id", "actor_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}

	svcAddr, hasAddr := agnt.GetZPRID()
	if !hasAddr {
		return // no address, no service!
	}

	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			switch psvc.Type {
			case polio.SvcT_SVCT_AUTH:
				ap, err := vs.authr.AddDatasourceProvider(serviceName, svcAddr, curConfig)
				if err != nil {
					vs.log.WithError(err).Error("failed to add auth service", "service_name", serviceName)
				} else {
					vs.log.Info("service added", "service", serviceName, "address", svcAddr)

					// If we have added a remove auth service addr, we now want to push a visa
					// that will allow the visa service to access the auth service from ANY
					// source port.
					if err := vs.createVsVisaForAuthServiceAndPush(serviceName, ap); err != nil {
						vs.log.WithError(err).Error("failed to create visa for auth service", "service_name", serviceName, "address", svcAddr)
					} else {
						vs.log.Info("visa created for auth service", "service_name", serviceName, "address", svcAddr)
					}
				}
			case polio.SvcT_SVCT_ACTOR_AUTH:
				vs.log.Info("actor authentication service added", "service_name", serviceName, "address", svcAddr)
				msg := &VSMsg{
					MsgType:     MTAuthServiceConnect,
					Addr:        svcAddr,
					ServiceName: psvc.GetName(),
				}
				select {
				case vs.vsMsgC <- msg: // ok
				default:
					vs.log.Warn("failed to send auth service connect message, channel full")
				}
			}
		}
	}
}

// Callback function for adb/actordb
func (vs *VSInst) HandleDBActorRemoved(agnt *actor.Actor) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()
	if curConfig != agnt.GetConfigID() {
		vs.log.Warn("host-remove with different configuration", "actor_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}
	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			switch psvc.Type {
			case polio.SvcT_SVCT_AUTH:
				if vs.authr.RemoveServiceByPrefix(psvc.GetPrefix()) > 0 {
					vs.log.Info("host_removed", "lost_service", serviceName)
				}
			case polio.SvcT_SVCT_ACTOR_AUTH:
				prevId := vs.actorAuthDB.Version()
				if newId := vs.actorAuthDB.RemoveActorAuthService(psvc.GetName()); newId != prevId {
					vs.log.Info("removed auth service", "service_name", serviceName, "db_id", newId)
					// Call to update nodes.
					msg := &VSMsg{
						MsgType: MTAuthServicesUpdated,
					}
					select {
					case vs.vsMsgC <- msg: // ok
					default:
						vs.log.Warn("failed to send auth services updated message, channel full")
					}
				} else {
					vs.log.Debug("removal of auth service did not change db version", "service_name", serviceName, "db_id", prevId)
				}
			}
		}
	}
}
