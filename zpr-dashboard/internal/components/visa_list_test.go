package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// TestVisaTableUsesActorCNs checks the visa table labels source and destination
// with actor CNs when known, and keeps the raw address otherwise.
func TestVisaTableUsesActorCNs(t *testing.T) {
	actors := []dataplane.ActorDescriptor{
		{CName: "node-nyc", ZprAddress: "fd5a:5052:90de::1"},
	}

	visas := []dataplane.VisaDescriptor{
		{
			ID:         1,
			SourceAddr: strPtr("fd5a:5052:90de::1"),
			DestAddr:   strPtr("fd5a:5052:90de::99"),
			Proto:      "TCP",
		},
	}

	out := ansi.Strip(activeVisaTable(120, visas, actors, -1))

	if !strings.Contains(out, "node-nyc") {
		t.Errorf("expected source CN in output:\n%s", out)
	}

	if !strings.Contains(out, "fd5a:5052:90de::99") {
		t.Errorf("expected unknown destination address to survive:\n%s", out)
	}

	if strings.Contains(out, "fd5a:5052:90de::1 ") {
		t.Errorf("expected source address to be replaced by its CN:\n%s", out)
	}
}
