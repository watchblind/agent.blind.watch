package browse

import (
	"sort"
	"strings"
)

// selfUnitName is the agent's own systemd unit, excluded from listings.
const selfUnitName = "blindwatch-agent"

// parseListUnits parses the output of
//
//	systemctl list-units --type=service --all --no-pager --plain
//
// Columns: UNIT LOAD ACTIVE SUB DESCRIPTION. Only *.service units are kept,
// the ".service" suffix is stripped, the agent's own unit is excluded, and
// results are sorted active first, then alphabetical.
func parseListUnits(out string) []Unit {
	units := []Unit{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break // blank line separates the table from the legend/footer
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "UNIT" {
			continue
		}
		name := fields[0]
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		name = strings.TrimSuffix(name, ".service")
		if name == selfUnitName {
			continue
		}
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		units = append(units, Unit{
			Name:        name,
			Description: desc,
			Active:      fields[2] == "active",
		})
	}

	sort.SliceStable(units, func(i, j int) bool {
		if units[i].Active != units[j].Active {
			return units[i].Active
		}
		return units[i].Name < units[j].Name
	})
	return units
}
