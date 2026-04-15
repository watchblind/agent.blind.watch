package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/watchblind/agent/internal/transport"
)

const stableEndpoint = "https://get.blind.watch/agent/version/stable"

// versionResponse is the shape returned by get.blind.watch version endpoints.
type versionResponse struct {
	Version    *string `json:"version"`
	ReleasedAt string  `json:"released_at,omitempty"`
}

// StartAutoUpdatePoller checks get.blind.watch/agent/version/stable once per
// hour and triggers an update if a newer version is available.
func StartAutoUpdatePoller(ctx context.Context, conn *transport.Connection, currentVersion string) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Printf("[updater] auto-update poller started (current: %s)", currentVersion)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ver, err := fetchStableVersion()
			if err != nil {
				log.Printf("[updater] stable version check failed: %v", err)
				continue
			}
			if ver == "" {
				continue
			}
			if compareVersions(ver, currentVersion) > 0 {
				log.Printf("[updater] auto-update: %s -> %s", currentVersion, ver)
				TriggerUpdate(conn, ver)
				return // update restarts the process
			}
		}
	}
}

// fetchStableVersion fetches the current stable version from get.blind.watch.
func fetchStableVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(stableEndpoint)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	var vr versionResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}

	if vr.Version == nil {
		return "", nil
	}
	return *vr.Version, nil
}

// compareVersions does a simple semver comparison.
// Returns >0 if a > b, <0 if a < b, 0 if equal.
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aParts := strings.SplitN(a, ".", 3)
	bParts := strings.SplitN(b, ".", 3)

	for i := 0; i < 3; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &aNum)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bNum)
		}
		if aNum != bNum {
			return aNum - bNum
		}
	}
	return 0
}
