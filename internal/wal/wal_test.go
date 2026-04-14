package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeEntry(batchID string, ts int64) Entry {
	return Entry{
		BatchID:    batchID,
		AgentID:    "agent-1",
		Epoch:      1,
		Timestamp:  ts,
		EncPayload: "Y2lwaGVydGV4dA==", // base64 "ciphertext"
	}
}

func TestNew_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "wal")
	w, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	info, err := os.Stat(w.Dir())
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("path is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("directory permissions = %o, want 0700", perm)
	}
}

func TestNew_DefaultLimits(t *testing.T) {
	// Superseded by TestNew_NewDefaults — kept as a no-op to preserve function name.
	_ = t
}

func TestAppendAndPending(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	entry := makeEntry("batch-001", 1000)
	if err := w.Append(entry); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending() returned %d entries, want 1", len(pending))
	}

	got := pending[0]
	if got.BatchID != entry.BatchID {
		t.Errorf("BatchID = %q, want %q", got.BatchID, entry.BatchID)
	}
	if got.AgentID != entry.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, entry.AgentID)
	}
	if got.Epoch != entry.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, entry.Epoch)
	}
	if got.Timestamp != entry.Timestamp {
		t.Errorf("Timestamp = %d, want %d", got.Timestamp, entry.Timestamp)
	}
	if got.EncPayload != entry.EncPayload {
		t.Errorf("EncPayload = %q, want %q", got.EncPayload, entry.EncPayload)
	}
}

func TestAck_RemovesEntry(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := w.Append(makeEntry("batch-001", 1000)); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	if err := w.Append(makeEntry("batch-002", 2000)); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	if err := w.Ack("batch-001"); err != nil {
		t.Fatalf("Ack() error: %v", err)
	}

	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending() returned %d entries after Ack, want 1", len(pending))
	}
	if pending[0].BatchID != "batch-002" {
		t.Errorf("remaining entry BatchID = %q, want %q", pending[0].BatchID, "batch-002")
	}
}

func TestAck_NonexistentIsNoop(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := w.Ack("does-not-exist"); err != nil {
		t.Errorf("Ack() on nonexistent entry should not error, got: %v", err)
	}
}

func TestMultipleEntries_OrderedByTimestamp(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Append out of chronological order.
	timestamps := []int64{3000, 1000, 2000}
	for i, ts := range timestamps {
		if err := w.Append(makeEntry(fmt.Sprintf("batch-%03d", i), ts)); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("Pending() returned %d entries, want 3", len(pending))
	}

	for i := 1; i < len(pending); i++ {
		if pending[i].Timestamp < pending[i-1].Timestamp {
			t.Errorf("entries not sorted: timestamp[%d]=%d < timestamp[%d]=%d",
				i, pending[i].Timestamp, i-1, pending[i-1].Timestamp)
		}
	}
}

func TestCount(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if got := w.Count(); got != 0 {
		t.Errorf("Count() on empty WAL = %d, want 0", got)
	}

	for i := 0; i < 5; i++ {
		if err := w.Append(makeEntry(fmt.Sprintf("batch-%03d", i), int64(i*1000))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	if got := w.Count(); got != 5 {
		t.Errorf("Count() after 5 appends = %d, want 5", got)
	}

	if err := w.Ack("batch-002"); err != nil {
		t.Fatalf("Ack() error: %v", err)
	}
	if got := w.Count(); got != 4 {
		t.Errorf("Count() after Ack = %d, want 4", got)
	}
}

func TestMaxEntries_DropsOldest(t *testing.T) {
	w, err := New(t.TempDir(), 10, 3)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Fill to capacity.
	for i := 0; i < 3; i++ {
		if err := w.Append(makeEntry(fmt.Sprintf("batch-%03d", i), int64(i*1000))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	// Append a 4th entry; the oldest (batch-000) should be evicted.
	if err := w.Append(makeEntry("batch-003", 3000)); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	if got := w.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3 (maxEntries enforced)", got)
	}

	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}

	for _, e := range pending {
		if e.BatchID == "batch-000" {
			t.Error("oldest entry (batch-000) should have been evicted")
		}
	}

	// The newest entry should be present.
	found := false
	for _, e := range pending {
		if e.BatchID == "batch-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("newest entry (batch-003) not found in pending")
	}
}

func TestSizeLimitEnforcement(t *testing.T) {
	// maxSizeMB=1 means ~1MB limit. We write entries with large payloads
	// to push over the limit and verify eviction occurs.
	w, err := New(t.TempDir(), 1, 10000)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Each entry payload is ~200KB of base64 data.
	bigPayload := strings.Repeat("A", 200*1024)

	for i := 0; i < 10; i++ {
		e := makeEntry(fmt.Sprintf("batch-%03d", i), int64(i*1000))
		e.EncPayload = bigPayload
		if err := w.Append(e); err != nil {
			t.Fatalf("Append() error on entry %d: %v", i, err)
		}
	}

	// Total uncompressed would be ~2MB, but limit is 1MB.
	// Some entries must have been evicted by enforceSize.
	count := w.Count()
	if count >= 10 {
		t.Errorf("Count() = %d, expected fewer than 10 entries due to size limit", count)
	}
	if count == 0 {
		t.Fatal("Count() = 0, expected at least some entries to survive")
	}

	// The size enforcement runs before each write, so after the final
	// append the total may slightly exceed the limit by the size of the
	// last entry. Verify that eviction actually reduced the entry count
	// and the surviving size is in a reasonable range (limit + one entry).
	walFiles, _ := filepath.Glob(filepath.Join(w.Dir(), "*.wal"))
	var total int64
	var maxFile int64
	for _, f := range walFiles {
		info, err := os.Stat(f)
		if err == nil {
			total += info.Size()
			if info.Size() > maxFile {
				maxFile = info.Size()
			}
		}
	}
	maxBytes := int64(1)*1024*1024 + maxFile // limit + one entry headroom
	if total > maxBytes {
		t.Errorf("total WAL size = %d bytes, exceeds limit+entry of %d", total, maxBytes)
	}
}

func TestOnlyEncryptedDataOnDisk(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Use recognizable plaintext strings that should NOT appear raw on disk.
	entry := Entry{
		BatchID:    "batch-secret",
		AgentID:    "agent-1",
		Epoch:      1,
		Timestamp:  1000,
		EncPayload: "ZW5jcnlwdGVkLWRhdGEtaGVyZQ==", // base64 of "encrypted-data-here"
	}
	if err := w.Append(entry); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Read raw file content and verify the structure.
	walFile := filepath.Join(dir, "batch-secret.wal")
	raw, err := os.ReadFile(walFile)
	if err != nil {
		t.Fatalf("reading WAL file: %v", err)
	}

	// The file should contain valid JSON with the encrypted payload.
	var stored Entry
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("WAL file is not valid JSON: %v", err)
	}

	// The payload field should be the base64 ciphertext, not decoded plaintext.
	if stored.EncPayload != entry.EncPayload {
		t.Errorf("stored EncPayload = %q, want %q", stored.EncPayload, entry.EncPayload)
	}

	// Raw file should not contain the decoded plaintext.
	rawStr := string(raw)
	if strings.Contains(rawStr, "encrypted-data-here") {
		t.Error("raw WAL file contains decoded plaintext; only encrypted (base64) data should be stored")
	}

	// Verify the payload is stored as a JSON string value (base64), not decoded.
	if !strings.Contains(rawStr, "ZW5jcnlwdGVkLWRhdGEtaGVyZQ==") {
		t.Error("raw WAL file does not contain the base64 payload")
	}
}

func TestCrashRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wal-crash")

	// First WAL instance: write entries then "crash" (discard instance).
	w1, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := w1.Append(makeEntry(fmt.Sprintf("batch-%03d", i), int64(i*1000))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}
	// Simulate crash: drop the reference, create a new WAL on the same dir.
	w1 = nil

	w2, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New() after crash error: %v", err)
	}

	pending, err := w2.Pending()
	if err != nil {
		t.Fatalf("Pending() after recovery error: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("Pending() after recovery returned %d entries, want 3", len(pending))
	}

	// Verify ordering is preserved.
	for i := 1; i < len(pending); i++ {
		if pending[i].Timestamp < pending[i-1].Timestamp {
			t.Errorf("recovered entries not sorted: timestamp[%d]=%d < timestamp[%d]=%d",
				i, pending[i].Timestamp, i-1, pending[i-1].Timestamp)
		}
	}

	// Verify data integrity.
	for i, e := range pending {
		expected := fmt.Sprintf("batch-%03d", i)
		if e.BatchID != expected {
			t.Errorf("recovered entry[%d].BatchID = %q, want %q", i, e.BatchID, expected)
		}
	}
}

func TestConcurrentAppendSafety(t *testing.T) {
	w, err := New(t.TempDir(), 10, 1000)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	const goroutines = 20
	const perGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errCh := make(chan error, goroutines*perGoroutine)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				batchID := fmt.Sprintf("g%d-batch-%03d", gid, i)
				ts := int64(gid*1000 + i)
				if err := w.Append(makeEntry(batchID, ts)); err != nil {
					errCh <- fmt.Errorf("goroutine %d, iter %d: %w", gid, i, err)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent Append error: %v", err)
	}

	expected := goroutines * perGoroutine
	if got := w.Count(); got != expected {
		t.Errorf("Count() = %d, want %d after concurrent appends", got, expected)
	}

	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}
	if len(pending) != expected {
		t.Errorf("Pending() returned %d entries, want %d", len(pending), expected)
	}

	// Verify timestamp ordering.
	for i := 1; i < len(pending); i++ {
		if pending[i].Timestamp < pending[i-1].Timestamp {
			t.Errorf("entries not sorted at index %d: %d < %d",
				i, pending[i].Timestamp, pending[i-1].Timestamp)
			break
		}
	}
}

func TestConcurrentAppendAndAck(t *testing.T) {
	w, err := New(t.TempDir(), 10, 1000)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Pre-populate entries to ack.
	for i := 0; i < 50; i++ {
		if err := w.Append(makeEntry(fmt.Sprintf("pre-%03d", i), int64(i))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	var wg sync.WaitGroup

	// Concurrently ack existing entries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			w.Ack(fmt.Sprintf("pre-%03d", i))
		}
	}()

	// Concurrently append new entries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			w.Append(makeEntry(fmt.Sprintf("new-%03d", i), int64(1000+i)))
		}
	}()

	wg.Wait()

	// All pre- entries should be acked, all new- entries should remain.
	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending() error: %v", err)
	}

	for _, e := range pending {
		if strings.HasPrefix(e.BatchID, "pre-") {
			t.Errorf("acked entry %q still in pending", e.BatchID)
		}
	}

	if len(pending) != 50 {
		t.Errorf("Pending() = %d entries, want 50 new entries", len(pending))
	}
}

func TestNew_NewDefaults(t *testing.T) {
	w, err := New(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if w.maxSizeMB != 1024 {
		t.Errorf("maxSizeMB = %d, want 1024", w.maxSizeMB)
	}
	if w.maxEntries != 2000 {
		t.Errorf("maxEntries = %d, want 2000", w.maxEntries)
	}
	if w.maxAge != 7*24*time.Hour {
		t.Errorf("maxAge = %v, want 7d", w.maxAge)
	}
}

func TestEnforceTTL_DropsOldFiles(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Append(makeEntry("old", 100)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	old := filepath.Join(dir, "old.wal")
	past := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if err := w.Append(makeEntry("fresh", 200)); err != nil {
		t.Fatalf("Append fresh: %v", err)
	}
	pending, err := w.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].BatchID != "fresh" {
		t.Errorf("pending = %+v, want only [fresh]", pending)
	}
}

func TestAppend_AtomicWrite_NoStrayTemp(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, 10, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Append(makeEntry("b", 100)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".wal") {
			t.Errorf("stray file in WAL dir: %s", e.Name())
		}
	}
}
