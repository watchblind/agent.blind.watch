//go:build linux

package browse

import (
	"context"
	"fmt"
	"os/exec"
)

// listUnits enumerates systemd service units via systemctl. On non-systemd
// systems (systemctl missing or failing) the error surfaces to the dashboard
// as "journald browsing unavailable: <reason>".
func listUnits(ctx context.Context) ([]Unit, error) {
	out, err := exec.CommandContext(ctx,
		"systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl: %v", err)
	}
	return parseListUnits(string(out)), nil
}
