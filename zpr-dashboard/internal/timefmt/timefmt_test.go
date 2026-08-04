package timefmt

import (
	"testing"
	"time"
)

// TestHelpers checks both helpers render a known epoch in the local zone (not
// UTC) and that each output matches the column width its layout is chosen for.
// Not parallel: time.Local is a process global.
func TestHelpers(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60+30*60)
	t.Cleanup(func() { time.Local = saved })

	const epoch = 1785604630 // 2026-08-01 17:17:10 UTC

	cases := []struct {
		name  string
		got   string
		want  string
		width int
	}{
		{"TimeOfDay", TimeOfDay(epoch), "22:47:10", 8},
		{"DateTime", DateTime(epoch), "08-01 22:47", 11},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
		if len(c.got) != c.width {
			t.Errorf("%s width = %d, want %d", c.name, len(c.got), c.width)
		}
	}
}
