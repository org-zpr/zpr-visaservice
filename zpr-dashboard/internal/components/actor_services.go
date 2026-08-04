package components

import (
	"cmp"
	"slices"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ActorServicesOffered(
	width, height int,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	services []dataplane.ServiceDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Services Offered", "Registered to this actor"

	if fetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		return detailPanel(width, height, title, subtitle, panelNote("Select an actor"))
	}

	actor := actors[selectedIndex]

	var offered []dataplane.ServiceDescriptor
	for _, svc := range services {
		if svc.ActorCN == actor.CName {
			offered = append(offered, svc)
		}
	}

	if len(offered) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No services registered to this actor"))
	}

	// offered is a private copy, so sorting it does not disturb the caller's
	// index into services.
	slices.SortFunc(offered, func(a, b dataplane.ServiceDescriptor) int {
		return cmp.Compare(a.ServiceName, b.ServiceName)
	})

	tableWidth := width - 5
	nameSize := int(float32(tableWidth) * 0.5)
	endpointSize := int(float32(tableWidth) * 0.5)

	t := panelTable(tableWidth,
		[]string{"Service", "Endpoints"},
		[]int{nameSize, endpointSize},
	)

	for _, svc := range offered {
		t.Row(
			ansi.Truncate(svc.ServiceName, nameSize, "..."),
			ansi.Truncate(orDash(svc.Endpoints), endpointSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}

func ActorServicesUsed(
	width, height int,
	visas []dataplane.VisaDescriptor,
	services []dataplane.ServiceDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Services Used", "Reachable through active visas"

	if fetchErr != nil && len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No visas assigned to this actor"))
	}

	tableWidth := width - 5
	nameSize := int(float32(tableWidth) * 0.4)
	destSize := int(float32(tableWidth) * 0.4)
	protoSize := int(float32(tableWidth) * 0.2)

	t := panelTable(tableWidth,
		[]string{"Service", "Destination", "Proto"},
		[]int{nameSize, destSize, protoSize},
	)

	// Column 1 holds a resolved service name, so visa order is not display
	// order: sort the rows we are about to render instead.
	type usedRow struct {
		name, dest, proto string
		id                int64
	}

	rows := make([]usedRow, 0, len(visas))
	for _, visa := range visas {
		rows = append(rows, usedRow{
			name:  serviceAt(services, visa.Dest()),
			dest:  visa.Dest(),
			proto: visa.Proto,
			id:    visa.ID,
		})
	}

	slices.SortFunc(rows, func(a, b usedRow) int {
		return cmp.Or(
			cmp.Compare(a.name, b.name),
			cmp.Compare(a.dest, b.dest),
			cmp.Compare(a.proto, b.proto),
			cmp.Compare(a.id, b.id),
		)
	})

	for _, row := range rows {
		t.Row(
			ansi.Truncate(row.name, nameSize, "..."),
			ansi.Truncate(orDash(row.dest), destSize, "..."),
			ansi.Truncate(row.proto, protoSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}

func serviceAt(services []dataplane.ServiceDescriptor, addr string) string {
	if addr == "" {
		return "unknown"
	}

	for _, svc := range services {
		if svc.ZprAddress == addr || svc.DockZprAddress == addr {
			return svc.ServiceName
		}
	}

	return "unregistered"
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}

	return value
}
