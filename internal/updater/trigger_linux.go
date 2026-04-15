//go:build linux

package updater

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
)

// TriggerUpdate runs the upgrade script via sudo. It sends status updates
// over the WebSocket connection. On success, the upgrade script restarts
// the systemd service, killing this process.
func TriggerUpdate(conn *transport.Connection, version string) {
	log.Printf("[updater] starting update to %s", version)

	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "downloading",
	})

	cmd := exec.Command("sudo", "/usr/local/lib/blindwatch/upgrade.sh", version)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(output)))
		log.Printf("[updater] update failed: %s", errStr)
		conn.Send(protocol.UpdateStatusMessage{
			Type:   "update_status",
			Status: "failed",
			Error:  &errStr,
		})
		return
	}

	// If we get here, the upgrade script should have restarted the service.
	// This means the script completed without restarting (unexpected).
	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "staged",
	})
}
