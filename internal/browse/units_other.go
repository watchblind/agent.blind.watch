//go:build !linux && !windows

package browse

import (
	"context"
	"fmt"
	"runtime"
)

// listUnits is unavailable outside linux/windows (development platforms).
func listUnits(ctx context.Context) ([]Unit, error) {
	return nil, fmt.Errorf("systemd not available on %s", runtime.GOOS)
}
