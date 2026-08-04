package app

import (
	"errors"
	"testing"
	"time"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// applySnapshot feeds an actorSnapshotMsg through Update and returns the model.
func applySnapshot(t *testing.T, m Model, msg actorSnapshotMsg) Model {
	t.Helper()

	next, _ := m.Update(msg)
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want Model", next)
	}

	return updated
}

// TestSnapshotCommitsResultsIndependently checks a failure on one of the two
// admin calls does not discard the other's fresh result.
func TestSnapshotCommitsResultsIndependently(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{CName: "node-nyc"}}
	network := []dataplane.NodeConnection{{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::2", CType: "UP"}}
	boom := errors.New("boom")

	// Actors succeed, network fails: actors land, topology stays empty.
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{actors: actors, networkErr: boom})
	if len(m.state.actor.actors) != 1 {
		t.Error("expected actors to be committed despite the network failure")
	}
	if m.state.actor.network != nil {
		t.Error("expected no topology from a failed network fetch")
	}
	if m.state.actor.networkFetchErr != boom || m.state.actor.fetchErr != nil {
		t.Error("expected only the network error to be recorded")
	}

	// Network succeeds, actors fail: the prior actor list is kept.
	m = applySnapshot(t, m, actorSnapshotMsg{network: network, actorErr: boom})
	if len(m.state.actor.actors) != 1 {
		t.Error("expected the prior actor list to be retained")
	}
	if len(m.state.actor.network) != 1 {
		t.Error("expected topology to be committed despite the actor failure")
	}
	if m.state.actor.fetchErr != boom || m.state.actor.networkFetchErr != nil {
		t.Error("expected only the actor error to be recorded")
	}
}

// TestNetworkErrorAffectsOnlineState checks a failing /admin/network still
// marks the admin service offline.
func TestNetworkErrorAffectsOnlineState(t *testing.T) {
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{networkErr: errors.New("boom")})

	if m.isAdminOnline() {
		t.Error("expected offline when the network fetch fails")
	}
	if m.adminErr() == nil {
		t.Error("expected the network error to surface as the admin error")
	}
}

// TestFormatHeaderClock checks the header clock renders wall-clock time in the
// given moment's zone, with the zone abbreviation appended.
func TestFormatHeaderClock(t *testing.T) {
	zone := time.FixedZone("IST", 5*60*60+30*60)
	now := time.Date(2026, 8, 1, 22, 47, 10, 0, zone)

	if got, want := formatHeaderClock(now), "22:47:10 IST"; got != want {
		t.Errorf("formatHeaderClock = %q, want %q", got, want)
	}
}
