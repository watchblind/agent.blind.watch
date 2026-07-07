// Package browse implements spec-compliant browse_request handling
// (docs/components/log-source-config.md): directory listings via
// internal/pathbrowser and systemd unit enumeration via systemctl. Both the
// request and the response payloads are E2E encrypted with the agent DEK so
// the server never sees browsed paths or unit names (spec section 6.3).
package browse

import (
	"context"
	"encoding/json"
	"time"

	"github.com/watchblind/agent/internal/pathbrowser"
)

const (
	// maxConcurrent bounds parallel browse work agent-side (spec limits).
	maxConcurrent = 2
	// workTimeout bounds a single listing (spec: 5s).
	workTimeout = 5 * time.Second
)

// Cipher is the subset of *crypto.Encryptor the handler needs. Requests are
// decrypted and responses encrypted with the same DEK/epoch.
type Cipher interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(encoded string) ([]byte, error)
}

// RequestPayload is the decrypted browse_request payload.
type RequestPayload struct {
	Action string `json:"action"` // "list_directory" | "list_units"
	Path   string `json:"path,omitempty"`
}

// DirEntry is one row of a list_directory response, using the spec field
// names (name/type/size/modified). Size and Modified are null for
// directories (including symlinks whose target is a directory).
type DirEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`     // "file" | "dir" | "symlink"
	Size     *int64 `json:"size"`     // bytes, null for dirs
	Modified *int64 `json:"modified"` // unix seconds, null for dirs
}

// DirectoryPayload is the decrypted browse_response payload for list_directory.
type DirectoryPayload struct {
	Path      string     `json:"path"`
	Entries   []DirEntry `json:"entries"`
	Truncated bool       `json:"truncated,omitempty"`
	Error     *string    `json:"error"`
}

// Unit is one systemd service in a list_units response.
type Unit struct {
	Name        string `json:"name"` // without the ".service" suffix
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

// UnitsPayload is the decrypted browse_response payload for list_units.
type UnitsPayload struct {
	Units []Unit  `json:"units"`
	Error *string `json:"error"`
}

// ErrorPayload is returned when a request cannot be dispatched at all
// (decrypt failure, malformed payload, unknown action, concurrency limit,
// timeout). Dashboards should check "error" before the shape-specific fields.
type ErrorPayload struct {
	Error *string `json:"error"`
}

// Handler executes browse requests with a concurrency cap and a per-request
// timeout. Use NewHandler; the zero value has no semaphore.
type Handler struct {
	sem     chan struct{}
	timeout time.Duration

	// Seams for tests.
	listDir   func(path string) pathbrowser.Listing
	listUnits func(ctx context.Context) ([]Unit, error)
}

// NewHandler creates a Handler with production defaults.
func NewHandler() *Handler {
	return &Handler{
		sem:       make(chan struct{}, maxConcurrent),
		timeout:   workTimeout,
		listDir:   pathbrowser.ListDir,
		listUnits: listUnits,
	}
}

// HandleEncrypted decrypts a browse_request payload, executes it, and
// returns the encrypted browse_response payload. Failures are reported
// inside the encrypted payload so the dashboard can render them; err is
// only non-nil when the response itself cannot be marshaled or encrypted.
func (h *Handler) HandleEncrypted(encPayload string, cipher Cipher) (string, error) {
	var result interface{}

	plaintext, err := cipher.Decrypt(encPayload)
	if err != nil {
		result = errorPayload("failed to decrypt browse request")
	} else {
		var req RequestPayload
		if err := json.Unmarshal(plaintext, &req); err != nil {
			result = errorPayload("invalid browse request payload")
		} else {
			result = h.Execute(req)
		}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return cipher.Encrypt(out)
}

// Execute runs a decrypted browse request and returns the response payload
// (DirectoryPayload, UnitsPayload or ErrorPayload). At most maxConcurrent
// requests run at once; excess requests fail fast, and any single request is
// cut off after the handler timeout.
func (h *Handler) Execute(req RequestPayload) interface{} {
	select {
	case h.sem <- struct{}{}:
	default:
		return errorPayload("too many concurrent browse requests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	done := make(chan interface{}, 1)
	go func() {
		// The semaphore slot is held until the work actually finishes so
		// runaway listings keep counting against the concurrency cap even
		// after Execute has returned a timeout error.
		defer func() { <-h.sem }()
		done <- h.run(ctx, req)
	}()

	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		return errorPayload("browse timed out")
	}
}

func (h *Handler) run(ctx context.Context, req RequestPayload) interface{} {
	switch req.Action {
	case "list_directory":
		return TranslateListing(h.listDir(req.Path))
	case "list_units":
		units, err := h.listUnits(ctx)
		if err != nil {
			msg := "journald browsing unavailable: " + err.Error()
			return UnitsPayload{Units: []Unit{}, Error: &msg}
		}
		return UnitsPayload{Units: units}
	default:
		return errorPayload("unknown action")
	}
}

func errorPayload(msg string) ErrorPayload {
	return ErrorPayload{Error: &msg}
}
