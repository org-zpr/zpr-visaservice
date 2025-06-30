package tests

import (
	"zpr.org/vst/pkg/testfw"
)

// This is a placeholder for an eventual real test of the auth services
// VS API call.  Right now it makes the call, but there are no services
// installed on the VS yet.
//
// TODO: Waiting to have bootstrap auth with vs-conform.
type EmptyAuthServiceList struct{}

func init() {
	testfw.Register(&EmptyAuthServiceList{})
}

func (t *EmptyAuthServiceList) Name() string {
	return "EmptyAuthServiceList"
}

func (t *EmptyAuthServiceList) Order() testfw.Order {
	return testfw.OrderLater
}

// Connect node, then a client and a service and send in a visa request which should then be granted.
func (t *EmptyAuthServiceList) Run(state *testfw.TestState) *testfw.RunResult {
	node, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			return testfw.Faile(err)
		}
		if !node.HasApiKey() {
			return testfw.Fail("unable to get an API key from node")
		}
		state.Pause()
	}

	vresp, err := node.RequestServices(node.GetAPIKey())
	if err != nil {
		return testfw.Faile(err)
	}
	// There are no services.
	if vresp == nil {
		return testfw.Fail("expected non-nil ServicesResponse, got nil")
	}
	if vresp.Services == nil {
		return testfw.Fail("expected non-nil ServicesList, got nil")
	}
	if vresp.Services.Expiration == 0 {
		return testfw.Fail("expected non-zero expiration time in ServicesList, got 0")
	}
	if len(vresp.Services.Services) != 0 {
		return testfw.Fail("expected empty ServicesList, got non-empty list")
	}
	return testfw.Ok()
}
