// Package timefmt holds the display layouts for timestamps shown in the TUI so
// the panes and the header cannot drift to per-pane formats.
package timefmt

import "time"

// Layouts for displayed timestamps, chosen by role.
const (
	LayoutTimeOfDay = "15:04:05"    // 8 cols: narrow table columns, header clock
	LayoutDateTime  = "01-02 15:04" // 11 cols: every display that needs a date
)

// TimeOfDay renders epoch seconds as local wall-clock time, no date.
func TimeOfDay(seconds int64) string {
	return time.Unix(seconds, 0).Format(LayoutTimeOfDay)
}

// DateTime renders epoch seconds as local month-day and time, no seconds.
func DateTime(seconds int64) string {
	return time.Unix(seconds, 0).Format(LayoutDateTime)
}
