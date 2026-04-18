//go:build linux

package updater

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
)

// Matches the same version grammar the upgrade.sh helper enforces. Keep in
// sync with scripts/install.sh. Guarding the version here means we never
// pass anything exotic through a systemd instance name.
var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([0-9A-Za-z.+-]*)$`)

// TriggerUpdate asks systemd to start the dedicated upgrade oneshot unit.
// The unit runs as root in its own cgroup, so it is unaffected by the
// agent's NoNewPrivileges sandbox and survives the service restart that
// the upgrade performs on this very process.
//
// Exec chain:
//
//	agent (blindwatch user, NNP=1)
//	  │  exec("systemctl", "start", "blindwatch-upgrade@<ver>.service")
//	  │   → D-Bus → polkit authorizes → systemd launches unit (root, fresh NNP=0)
//	  │                                                       │
//	  │                                                       ↓
//	  │                                               /usr/local/lib/blindwatch/upgrade.sh
//	  │                                               └── curl|bash install.sh --upgrade
//	  │                                                   └── systemctl stop/start blindwatch-agent
//	  ▼
//	process killed by the stop (agent restarts on the new binary)
func TriggerUpdate(conn *transport.Connection, version string) {
	log.Printf("[updater] starting update to %s", version)

	if !versionPattern.MatchString(version) {
		errStr := fmt.Sprintf("invalid version format: %q", version)
		log.Printf("[updater] %s", errStr)
		conn.Send(protocol.UpdateStatusMessage{
			Type:   "update_status",
			Status: "failed",
			Error:  &errStr,
		})
		return
	}

	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "downloading",
	})

	unit := fmt.Sprintf("blindwatch-upgrade@%s.service", version)
	cmd := exec.Command("systemctl", "start", unit)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// The normal success path never reaches here: the upgrade unit
		// restarts blindwatch-agent, which kills this process (and the
		// `systemctl start` child) before CombinedOutput returns. So any
		// error we *do* observe is a genuine dispatch or install failure.
		errStr := fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(output)))
		log.Printf("[updater] update failed: %s", errStr)
		conn.Send(protocol.UpdateStatusMessage{
			Type:   "update_status",
			Status: "failed",
			Error:  &errStr,
		})
		return
	}

	// Reachable only if the upgrade unit exited cleanly without restarting
	// the agent — unexpected, but report "staged" so the dashboard doesn't
	// sit on "downloading" forever waiting for a version_report.
	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "staged",
	})
}
