package adb_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/actor"

	"zpr.org/vs/pkg/vservice/adb"
)

type DummyWatcher struct{}

func (d *DummyWatcher) HandleDBActorAdded(_ *actor.Actor)   {}
func (d *DummyWatcher) HandleDBActorRemoved(_ *actor.Actor) {}

func TestCloneNodesToBriefCopiesCounts(t *testing.T) {
	db := adb.NewActorDB(&DummyWatcher{})

	naddr := netip.MustParseAddr("fd5a:5052:90de::7")

	claims := map[string]string{
		"foo": "bar",
	}
	agnt := actor.NewActorFromUnsubstantiatedClaims(claims)

	db.AddNode(naddr, naddr, agnt, "foo", "127.0.0.1")

	{
		data := db.CloneNodesToBrief()
		require.Equal(t, 1, len(data))
		require.Equal(t, uint64(0), data[0].ConnectRequests)
		require.Equal(t, uint64(0), data[0].VisaRequests)
	}

	db.IncrNodeConnectReq(naddr)
	db.IncrNodeVisaReq(naddr)

	{
		data := db.CloneNodesToBrief()
		require.Equal(t, 1, len(data))
		require.Equal(t, uint64(1), data[0].ConnectRequests)
		require.Equal(t, uint64(1), data[0].VisaRequests)
	}

}

func TestGetNextZPRAddress(t *testing.T) {
	db := adb.NewActorDB(&DummyWatcher{})

	// Test that GetNextZPRAddress returns a valid IPv6 address
	addr1 := db.GetNextZPRAddress()
	require.True(t, addr1.IsValid(), "GetNextZPRAddress should return a valid address")
	require.True(t, addr1.Is6(), "GetNextZPRAddress should return an IPv6 address")

	// Test that consecutive calls return different addresses
	addr2 := db.GetNextZPRAddress()
	require.True(t, addr2.IsValid(), "Second call should return a valid address")
	require.True(t, addr2.Is6(), "Second call should return an IPv6 address")
	require.NotEqual(t, addr1, addr2, "Consecutive calls should return different addresses")

	// Test that we can get multiple unique addresses
	addresses := make(map[netip.Addr]bool)
	for i := 0; i < 10; i++ {
		addr := db.GetNextZPRAddress()
		require.True(t, addr.IsValid(), "Address should be valid")
		require.True(t, addr.Is6(), "Address should be IPv6")
		require.False(t, addresses[addr], "Address should be unique")
		addresses[addr] = true
	}
}
