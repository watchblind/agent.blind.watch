//go:build windows

package browse

import (
	"context"
	"fmt"
)

// listUnits is unavailable on Windows — there is no systemd/journald.
func listUnits(ctx context.Context) ([]Unit, error) {
	return nil, fmt.Errorf("not supported on windows")
}
