//go:build windows

package updater

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
)

// TriggerUpdate runs the PowerShell upgrade script as a detached process.
// It sends status updates over the WebSocket connection. On success, the
// upgrade script stops the service, replaces the binary, and restarts it.
func TriggerUpdate(conn *transport.Connection, version string) {
	log.Printf("[updater] starting update to %s", version)

	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "downloading",
	})

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass",
		"-File", `C:\Program Files\blindwatch\upgrade.ps1`, version)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

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

	conn.Send(protocol.UpdateStatusMessage{
		Type:   "update_status",
		Status: "staged",
	})
}
