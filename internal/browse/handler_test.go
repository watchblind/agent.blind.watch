package browse

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/pathbrowser"
)

// newTestHandler returns a handler with stubbed work functions.
func newTestHandler() *Handler {
	h := NewHandler()
	h.listDir = func(path string) pathbrowser.Listing {
		return pathbrowser.Listing{
			Path:    path,
			Entries: []pathbrowser.Entry{{Name: "app.log", Size: 42, Mtime: 1700000000, Readable: true}},
		}
	}
	h.listUnits = func(ctx context.Context) ([]Unit, error) {
		return []Unit{{Name: "nginx", Description: "web server", Active: true}}, nil
	}
	return h
}

func encryptRequest(t *testing.T, enc *crypto.Encryptor, payload RequestPayload) string {
	t.Helper()
	plain, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := enc.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out
}

func decryptResponse(t *testing.T, enc *crypto.Encryptor, encPayload string, into interface{}) {
	t.Helper()
	plain, err := enc.Decrypt(encPayload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if err := json.Unmarshal(plain, into); err != nil {
		t.Fatalf("unmarshal %q: %v", plain, err)
	}
}

func TestHandleEncrypted_ListDirectory(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()

	req := encryptRequest(t, enc, RequestPayload{Action: "list_directory", Path: "/var/log"})
	out, err := h.HandleEncrypted(req, enc)
	if err != nil {
		t.Fatalf("HandleEncrypted: %v", err)
	}

	var resp DirectoryPayload
	decryptResponse(t, enc, out, &resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", *resp.Error)
	}
	if resp.Path != "/var/log" || len(resp.Entries) != 1 || resp.Entries[0].Name != "app.log" {
		t.Errorf("unexpected directory payload: %+v", resp)
	}
	if resp.Entries[0].Type != "file" || resp.Entries[0].Size == nil || *resp.Entries[0].Size != 42 {
		t.Errorf("entry not translated to spec shape: %+v", resp.Entries[0])
	}
}

func TestHandleEncrypted_ListUnits(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()

	req := encryptRequest(t, enc, RequestPayload{Action: "list_units"})
	out, err := h.HandleEncrypted(req, enc)
	if err != nil {
		t.Fatalf("HandleEncrypted: %v", err)
	}

	var resp UnitsPayload
	decryptResponse(t, enc, out, &resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", *resp.Error)
	}
	if len(resp.Units) != 1 || resp.Units[0].Name != "nginx" || !resp.Units[0].Active {
		t.Errorf("unexpected units payload: %+v", resp)
	}
}

func TestHandleEncrypted_ListUnitsFailure(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	h.listUnits = func(ctx context.Context) ([]Unit, error) {
		return nil, errors.New("systemctl: exec: not found")
	}

	req := encryptRequest(t, enc, RequestPayload{Action: "list_units"})
	out, err := h.HandleEncrypted(req, enc)
	if err != nil {
		t.Fatalf("HandleEncrypted: %v", err)
	}

	var resp UnitsPayload
	decryptResponse(t, enc, out, &resp)
	if resp.Error == nil || *resp.Error != "journald browsing unavailable: systemctl: exec: not found" {
		t.Fatalf("Error = %v, want journald browsing unavailable prefix", resp.Error)
	}
	if len(resp.Units) != 0 {
		t.Errorf("failed units listing should be empty, got %+v", resp.Units)
	}
}

func TestHandleEncrypted_BadCiphertext(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()

	out, err := h.HandleEncrypted("not-valid-base64!!!", enc)
	if err != nil {
		t.Fatalf("HandleEncrypted: %v", err)
	}

	var resp ErrorPayload
	decryptResponse(t, enc, out, &resp)
	if resp.Error == nil || *resp.Error != "failed to decrypt browse request" {
		t.Fatalf("Error = %v, want decrypt failure", resp.Error)
	}
}

func TestHandleEncrypted_UnknownAction(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()

	req := encryptRequest(t, enc, RequestPayload{Action: "rm_rf"})
	out, err := h.HandleEncrypted(req, enc)
	if err != nil {
		t.Fatalf("HandleEncrypted: %v", err)
	}

	var resp ErrorPayload
	decryptResponse(t, enc, out, &resp)
	if resp.Error == nil || *resp.Error != "unknown action" {
		t.Fatalf("Error = %v, want unknown action", resp.Error)
	}
}

func TestExecute_ConcurrencyLimit(t *testing.T) {
	h := newTestHandler()
	h.timeout = 2 * time.Second

	started := make(chan struct{}, maxConcurrent)
	release := make(chan struct{})
	h.listDir = func(path string) pathbrowser.Listing {
		started <- struct{}{}
		<-release
		return pathbrowser.Listing{Path: path}
	}

	results := make(chan interface{}, maxConcurrent)
	for i := 0; i < maxConcurrent; i++ {
		go func() {
			results <- h.Execute(RequestPayload{Action: "list_directory", Path: "/var/log"})
		}()
	}

	// Wait until both slots are actually occupied.
	for i := 0; i < maxConcurrent; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}

	// Third request must be rejected immediately.
	res := h.Execute(RequestPayload{Action: "list_directory", Path: "/var/log"})
	ep, ok := res.(ErrorPayload)
	if !ok || ep.Error == nil || *ep.Error != "too many concurrent browse requests" {
		t.Fatalf("third concurrent request = %+v, want too many concurrent browse requests", res)
	}

	close(release)
	for i := 0; i < maxConcurrent; i++ {
		select {
		case r := <-results:
			if _, ok := r.(DirectoryPayload); !ok {
				t.Errorf("blocked request returned %+v, want DirectoryPayload", r)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked requests did not complete")
		}
	}

	// Slots freed — the next request succeeds again.
	h.listDir = func(path string) pathbrowser.Listing { return pathbrowser.Listing{Path: path} }
	if _, ok := h.Execute(RequestPayload{Action: "list_directory", Path: "/var/log"}).(DirectoryPayload); !ok {
		t.Error("request after release should succeed")
	}
}

func TestExecute_Timeout(t *testing.T) {
	h := newTestHandler()
	h.timeout = 20 * time.Millisecond

	release := make(chan struct{})
	defer close(release)
	h.listDir = func(path string) pathbrowser.Listing {
		<-release
		return pathbrowser.Listing{Path: path}
	}

	res := h.Execute(RequestPayload{Action: "list_directory", Path: "/var/log"})
	ep, ok := res.(ErrorPayload)
	if !ok || ep.Error == nil || *ep.Error != "browse timed out" {
		t.Fatalf("Execute = %+v, want browse timed out", res)
	}
}
