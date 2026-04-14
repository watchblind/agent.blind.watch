# Agent Reconnection & Crash-Safe Buffering — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace in-memory snapshot batching with an append-as-collected NDJSON WAL, harden WS reconnection (heartbeat, half-open detection, connected-gate), and fix latent fsync/atomicity bugs — so process death never loses more than the single in-flight snapshot, and multi-hour outages drain cleanly on reconnect with no duplicates.

**Architecture:** Each in-progress 10-min batch is one append-only `<batch_id>.open` NDJSON file (meta line + one CRC-tagged encrypted entry per snapshot, fsynced per append). On batch boundary the file is atomically renamed to `<batch_id>.wal` and sent. Crash recovery scans `.open` files, drops torn final lines via CRC, and replays them via the existing `wal_sync` path. WS layer adds 15s pings with a 45s read deadline, gates "connected" on receipt of the server's `connected` message, and drains the send buffer on disconnect to prevent duplicate delivery alongside WAL replay.

**Tech Stack:** Go 1.26+, `gorilla/websocket`, `hash/crc32` (Castagnoli), stdlib `os` for file ops. No new dependencies. Tests use stdlib `testing` + `httptest` + `t.TempDir`.

**Source spec:** `docs/superpowers/specs/2026-04-14-agent-reconnection-and-crash-safe-buffering-design.md`

**Repo:** `agent.blind.watch` — runs in this worktree. All commits use `-c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com"` per the watchblind org credential rule. Never push without explicit user approval.

**File-level structure:**

| File | Action | Responsibility |
|---|---|---|
| `internal/wal/fsync.go` | create | `writeAndSync`, `atomicReplace`, `fsyncDir` helpers. |
| `internal/wal/fsync_test.go` | create | Tests for the helpers. |
| `internal/wal/wal.go` | modify | Use helpers, bump limits, add TTL enforcement. |
| `internal/wal/wal_test.go` | modify | Add TTL test, keep all existing tests green. |
| `internal/wal/openbatch.go` | create | `OpenBatch` type: Open, Append, Finalize, AbortIfEmpty. |
| `internal/wal/openbatch_test.go` | create | Tests for OpenBatch incl. CRC validation. |
| `internal/wal/recovery.go` | create | `RecoverOrphans` — scan `.open`, validate, finalize. |
| `internal/wal/recovery_test.go` | create | Tests covering torn last line, missing meta, valid file. |
| `internal/scheduler/scheduler.go` | modify | Replace `batchBuf` with `OpenBatch`; recovery in `syncWAL`. |
| `internal/scheduler/scheduler_test.go` | modify | Update existing tests; add crash-recovery integration test. |
| `internal/transport/ws.go` | modify | Ping/pong, read deadline, connected-gate, drain sendCh, log throttling. |
| `internal/transport/ws_test.go` | modify | Add half-open + connected-gate tests. |
| `internal/logtail/manager.go` | modify | Migrate idle batch to `OpenBatch`. |
| `internal/dashboard/dashboard.go` | modify | Surface `wal_pending_files`, `wal_pending_bytes`, `seconds_since_last_ack`. |

---

## Task 1: WAL fsync + atomic write helpers

**Files:**
- Create: `internal/wal/fsync.go`
- Create: `internal/wal/fsync_test.go`

- [ ] **Step 1: Write the failing tests**

Write `internal/wal/fsync_test.go`:

```go
package wal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndSync_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := writeAndSync(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("writeAndSync: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("contents = %q, want %q", string(got), "hello")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
}

func TestAtomicReplace_OverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := atomicReplace(path, []byte("new"), 0600); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("contents = %q, want %q", string(got), "new")
	}
}

func TestAtomicReplace_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := atomicReplace(path, []byte("x"), 0600); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (no temp leftover)", len(entries))
	}
}

func TestFsyncDir_OK(t *testing.T) {
	dir := t.TempDir()
	if err := fsyncDir(dir); err != nil {
		t.Errorf("fsyncDir: %v", err)
	}
}

func TestFsyncDir_NonExistent(t *testing.T) {
	err := fsyncDir(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Error("expected error for non-existent dir")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
cd /Users/tom/Documents/watchblind/agent.blind.watch
go test ./internal/wal/ -run 'TestWriteAndSync|TestAtomicReplace|TestFsyncDir' -v
```

Expected: `undefined: writeAndSync`, `undefined: atomicReplace`, `undefined: fsyncDir`.

- [ ] **Step 3: Implement helpers**

Write `internal/wal/fsync.go`:

```go
package wal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writeAndSync writes data to path with the given permissions and fsyncs the
// file. The file is created if missing or truncated if present. Use this for
// fresh writes where you want the data persisted before the function returns.
func writeAndSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	return f.Close()
}

// atomicReplace writes data to a temp file in the same directory, fsyncs it,
// then renames it over the destination. After the rename the parent directory
// is fsynced so the rename itself is durable.
func atomicReplace(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return fsyncDir(dir)
}

// fsyncDir opens dir read-only and calls Sync so a preceding Create/Rename/
// Remove is durable. On Windows directory fsync is a no-op (returned as nil).
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		// Directory fsync is not meaningful on NTFS via the normal Sync syscall.
		// Verify the dir exists so callers still get errors for bad paths.
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("not a directory: %s", dir)
		}
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return f.Close()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test ./internal/wal/ -run 'TestWriteAndSync|TestAtomicReplace|TestFsyncDir' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
cd /Users/tom/Documents/watchblind/agent.blind.watch
git add internal/wal/fsync.go internal/wal/fsync_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: add fsync/atomic-write helpers"
```

---

## Task 2: Fix existing wal.Append + bump limits + add 7-day TTL

**Files:**
- Modify: `internal/wal/wal.go`
- Modify: `internal/wal/wal_test.go`

- [ ] **Step 1: Add the failing tests**

Append to `internal/wal/wal_test.go`:

```go
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
	// Backdate the file 8 days into the past.
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
```

Add `"time"` to the test file imports if not already present.

- [ ] **Step 2: Run new tests to verify they fail**

```
go test ./internal/wal/ -run 'TestNew_NewDefaults|TestEnforceTTL_DropsOldFiles|TestAppend_AtomicWrite_NoStrayTemp' -v
```

Expected: FAIL — `w.maxSizeMB = 500`, `w.maxAge` undefined, `TestEnforceTTL` keeps both files.

- [ ] **Step 3: Implement changes**

Replace `internal/wal/wal.go` entirely:

```go
package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry represents a single finalized batch stored as a JSON file on disk.
// Used by logtail and the legacy single-file batch path. Scheduler now uses
// OpenBatch for incremental writes; both produce *.wal files that drain
// through the same Pending/Ack lifecycle.
type Entry struct {
	BatchID    string `json:"batch_id"`
	AgentID    string `json:"agent_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

// Default limits. See design doc 2026-04-14-agent-reconnection-and-crash-safe-buffering-design.md §4.5.
const (
	defaultMaxSizeMB  = 1024
	defaultMaxEntries = 2000
	defaultMaxAge     = 7 * 24 * time.Hour
)

// WAL is a directory of *.wal files plus, when scheduler is using OpenBatch,
// transient *.open files. Only *.wal files are exposed via Pending().
type WAL struct {
	dir        string
	maxSizeMB  int
	maxEntries int
	maxAge     time.Duration

	mu sync.Mutex
}

// New creates a WAL in the given directory with the given limits. Pass 0 for
// either limit to use the package defaults (1024 MB, 2000 files).
func New(dir string, maxSizeMB, maxEntries int) (*WAL, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = defaultMaxSizeMB
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating WAL directory: %w", err)
	}
	return &WAL{
		dir:        dir,
		maxSizeMB:  maxSizeMB,
		maxEntries: maxEntries,
		maxAge:     defaultMaxAge,
	}, nil
}

// Dir returns the WAL directory path.
func (w *WAL) Dir() string { return w.dir }

// Append writes a finalized Entry to disk atomically (temp + rename + dir
// fsync). Used by logtail and the legacy single-file batch path.
func (w *WAL) Append(entry Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.enforceLimitsLocked()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling WAL entry: %w", err)
	}

	safeName := filepath.Base(entry.BatchID)
	if safeName == "." || safeName == "/" || safeName == "" {
		return fmt.Errorf("invalid batch_id: %q", entry.BatchID)
	}
	path := filepath.Join(w.dir, safeName+".wal")
	return atomicReplace(path, data, 0600)
}

// Ack deletes the WAL entry for the given batch ID. Idempotent — missing files
// are not an error.
func (w *WAL) Ack(batchID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	safeName := filepath.Base(batchID)
	path := filepath.Join(w.dir, safeName+".wal")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing WAL entry: %w", err)
	}
	return fsyncDir(w.dir)
}

// Pending returns all unacknowledged finalized (.wal) entries, sorted by
// timestamp. *.open files are not included.
func (w *WAL) Pending() ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, err := w.listWALFilesLocked()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})
	return entries, nil
}

// Count returns the number of pending finalized (.wal) entries.
func (w *WAL) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, _ := w.listWALFilesLocked()
	return len(files)
}

// PendingBytes returns the total on-disk size of pending finalized entries.
func (w *WAL) PendingBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, _ := w.listWALFilesLocked()
	var total int64
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			total += info.Size()
		}
	}
	return total
}

func (w *WAL) listWALFilesLocked() ([]string, error) {
	dirEntries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("reading WAL directory: %w", err)
	}
	var files []string
	for _, e := range dirEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wal") {
			files = append(files, filepath.Join(w.dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// enforceLimitsLocked applies (in order) the TTL, the max-entries, and the
// max-size policies. Caller must hold w.mu.
func (w *WAL) enforceLimitsLocked() {
	files, _ := w.listWALFilesLocked()

	// 1. TTL — drop anything older than maxAge by mtime.
	cutoff := time.Now().Add(-w.maxAge)
	kept := files[:0]
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil && info.ModTime().Before(cutoff) {
			os.Remove(f)
			continue
		}
		kept = append(kept, f)
	}
	files = kept

	// 2. Max entries — drop oldest first.
	for len(files) >= w.maxEntries && len(files) > 0 {
		os.Remove(files[0])
		files = files[1:]
	}

	// 3. Max bytes — drop oldest first until under cap.
	maxBytes := int64(w.maxSizeMB) * 1024 * 1024
	var total int64
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			total += info.Size()
		}
	}
	for total > maxBytes && len(files) > 0 {
		if info, err := os.Stat(files[0]); err == nil {
			total -= info.Size()
		}
		os.Remove(files[0])
		files = files[1:]
	}
}
```

- [ ] **Step 4: Run all WAL tests**

```
go test ./internal/wal/ -v
```

Expected: all existing tests + new tests PASS. (`TestNew_DefaultLimits` will need updating — the previous defaults are gone. Edit it inline to assert the new defaults: `maxSizeMB == 1024`, `maxEntries == 2000`. Or delete it and rely on `TestNew_NewDefaults` from this task.)

- [ ] **Step 5: Update or remove `TestNew_DefaultLimits`**

In `internal/wal/wal_test.go`, delete the body of `TestNew_DefaultLimits` (it's superseded by `TestNew_NewDefaults`). Re-run:

```
go test ./internal/wal/ -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```
git add internal/wal/wal.go internal/wal/wal_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: atomic writes, 7-day TTL, bump limits to 2000/1GB"
```

---

## Task 3: OpenBatch type — Open + meta line write

**Files:**
- Create: `internal/wal/openbatch.go`
- Create: `internal/wal/openbatch_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package wal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBatch_CreatesOpenFileWithMeta(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob, err := w.OpenBatch(BatchMeta{
		BatchID:   "b_1000_ag",
		AgentID:   "ag",
		Epoch:     2,
		StartedAt: 1000,
	})
	if err != nil {
		t.Fatalf("OpenBatch: %v", err)
	}
	defer ob.Close()

	path := filepath.Join(w.Dir(), "b_1000_ag.open")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("no first line: %v", scanner.Err())
	}
	var line struct {
		Meta *BatchMeta `json:"meta"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
		t.Fatalf("first line not JSON: %v", err)
	}
	if line.Meta == nil || line.Meta.BatchID != "b_1000_ag" {
		t.Errorf("meta = %+v, want batch_id=b_1000_ag", line.Meta)
	}
}

func TestOpenBatch_RejectsUnsafeBatchID(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	_, err := w.OpenBatch(BatchMeta{BatchID: "../escape", AgentID: "ag", Epoch: 1})
	if err == nil {
		t.Error("expected error for path-traversal batch_id")
	}
}

func TestOpenBatch_DuplicateOpenFails(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	meta := BatchMeta{BatchID: "b1", AgentID: "ag", Epoch: 1}
	ob1, err := w.OpenBatch(meta)
	if err != nil {
		t.Fatalf("first OpenBatch: %v", err)
	}
	defer ob1.Close()
	if _, err := w.OpenBatch(meta); err == nil {
		t.Error("expected error opening same batch_id twice")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test ./internal/wal/ -run TestOpenBatch -v
```

Expected: FAIL — `undefined: BatchMeta`, `OpenBatch undefined`.

- [ ] **Step 3: Implement Open + meta**

Write `internal/wal/openbatch.go`:

```go
package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// BatchMeta is the first JSON line of every .open file. Recovery uses it to
// reconstruct the wal.Entry that wraps the appended payload entries.
type BatchMeta struct {
	BatchID   string `json:"batch_id"`
	AgentID   string `json:"agent_id"`
	Epoch     int    `json:"epoch"`
	StartedAt int64  `json:"started_at"`
}

// OpenBatch is an in-progress NDJSON batch file. Each call to Append appends
// one CRC-tagged entry line and fsyncs. Finalize atomically renames .open ->
// .wal. The zero value is unusable; obtain one via WAL.OpenBatch.
//
// Concurrency: Append may be called from multiple goroutines but is
// serialized internally via mu. Close/Finalize must not race with Append.
type OpenBatch struct {
	wal  *WAL
	meta BatchMeta
	path string // <dir>/<batch_id>.open

	mu     sync.Mutex
	file   *os.File
	closed bool
	count  int // number of payload entries appended (excludes meta)
}

func safeBatchName(batchID string) (string, error) {
	name := filepath.Base(batchID)
	if name == "." || name == "/" || name == "" || name == ".." {
		return "", fmt.Errorf("invalid batch_id: %q", batchID)
	}
	for _, r := range batchID {
		if r == '/' || r == '\\' || r == 0 {
			return "", fmt.Errorf("invalid batch_id: %q", batchID)
		}
	}
	return name, nil
}

// OpenBatch creates a new in-progress batch file and writes the meta line.
// The returned OpenBatch must be Finalize'd or Close'd by the caller.
func (w *WAL) OpenBatch(meta BatchMeta) (*OpenBatch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.enforceLimitsLocked()

	name, err := safeBatchName(meta.BatchID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(w.dir, name+".open")

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create open-batch file: %w", err)
	}

	metaLine, err := json.Marshal(struct {
		Meta BatchMeta `json:"meta"`
	}{Meta: meta})
	if err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("marshal meta: %w", err)
	}
	metaLine = append(metaLine, '\n')
	if _, err := f.Write(metaLine); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write meta: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("fsync meta: %w", err)
	}
	if err := fsyncDir(w.dir); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("fsync dir: %w", err)
	}

	return &OpenBatch{
		wal:  w,
		meta: meta,
		path: path,
		file: f,
	}, nil
}

// Close releases the file handle and removes the .open file if no payload
// entries were appended. Safe to call multiple times.
func (ob *OpenBatch) Close() error {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return nil
	}
	ob.closed = true
	closeErr := ob.file.Close()
	if ob.count == 0 {
		// Empty batch — leave nothing on disk.
		os.Remove(ob.path)
		fsyncDir(filepath.Dir(ob.path))
	}
	return closeErr
}

// Count returns the number of payload entries appended (excludes meta).
func (ob *OpenBatch) Count() int {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	return ob.count
}

// Meta returns a copy of the batch metadata.
func (ob *OpenBatch) Meta() BatchMeta {
	return ob.meta
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test ./internal/wal/ -run TestOpenBatch -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add internal/wal/openbatch.go internal/wal/openbatch_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: add OpenBatch type with meta-line initialization"
```

---

## Task 4: OpenBatch.Append with CRC32C

**Files:**
- Modify: `internal/wal/openbatch.go`
- Modify: `internal/wal/openbatch_test.go`

- [ ] **Step 1: Add the failing test**

Append to `internal/wal/openbatch_test.go`:

```go
func TestOpenBatch_AppendPersistsAndCRCs(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	ob, err := w.OpenBatch(BatchMeta{BatchID: "b1", AgentID: "ag", Epoch: 1, StartedAt: 100})
	if err != nil {
		t.Fatalf("OpenBatch: %v", err)
	}
	defer ob.Close()

	for i, ts := range []int64{110, 120, 130} {
		if err := ob.Append(EntryRecord{
			Epoch:      1,
			Timestamp:  ts,
			EncPayload: fmt.Sprintf("ct-%d", i),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if ob.Count() != 3 {
		t.Errorf("Count = %d, want 3", ob.Count())
	}

	// Inspect raw file content.
	raw, err := os.ReadFile(filepath.Join(w.Dir(), "b1.open"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 4 { // 1 meta + 3 entries
		t.Fatalf("got %d lines, want 4: %q", len(lines), lines)
	}
	for i, line := range lines[1:] {
		var rec EntryRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d not JSON: %v", i, err)
		}
		if rec.CRC == 0 {
			t.Errorf("line %d has zero CRC", i)
		}
	}
}
```

Add `"strings"` and `"fmt"` to the test file imports if not present.

- [ ] **Step 2: Run test to verify it fails**

```
go test ./internal/wal/ -run TestOpenBatch_AppendPersistsAndCRCs -v
```

Expected: FAIL — `EntryRecord undefined`, `Append undefined`.

- [ ] **Step 3: Implement Append + EntryRecord**

Append to `internal/wal/openbatch.go`:

```go
import (
	// add to existing imports
	"hash/crc32"
)

// EntryRecord is one payload line in an .open or recovered .wal file. The CRC
// is computed over the JSON encoding of the same struct with CRC=0 (so a
// reader can recompute and compare). All fields except CRC are required.
type EntryRecord struct {
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
	CRC        uint32 `json:"crc"`
}

// crcTable uses Castagnoli (the same polynomial as ext4 / btrfs / Snappy).
// Faster than IEEE on modern CPUs and adequate for torn-write detection.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

func computeCRC(rec EntryRecord) (uint32, []byte, error) {
	rec.CRC = 0
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, nil, err
	}
	return crc32.Checksum(data, crcTable), data, nil
}

// Append serializes rec, computes its CRC, writes it as a single NDJSON line,
// and fsyncs. Safe for concurrent calls from multiple goroutines on the same
// OpenBatch (rare but supported).
func (ob *OpenBatch) Append(rec EntryRecord) error {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return fmt.Errorf("openbatch: closed")
	}

	crc, _, err := computeCRC(rec)
	if err != nil {
		return fmt.Errorf("compute crc: %w", err)
	}
	rec.CRC = crc

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	line = append(line, '\n')

	if _, err := ob.file.Write(line); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}
	if err := ob.file.Sync(); err != nil {
		return fmt.Errorf("fsync entry: %w", err)
	}
	ob.count++
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test ./internal/wal/ -run TestOpenBatch -v
```

Expected: PASS for all OpenBatch tests.

- [ ] **Step 5: Commit**

```
git add internal/wal/openbatch.go internal/wal/openbatch_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: OpenBatch.Append writes CRC-tagged NDJSON lines"
```

---

## Task 5: OpenBatch.Finalize — atomic rename to .wal

**Files:**
- Modify: `internal/wal/openbatch.go`
- Modify: `internal/wal/openbatch_test.go`

- [ ] **Step 1: Add failing tests**

Append to `internal/wal/openbatch_test.go`:

```go
func TestFinalize_RenamesAndReturnsEntry(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	ob, _ := w.OpenBatch(BatchMeta{BatchID: "b1", AgentID: "ag", Epoch: 2, StartedAt: 500})
	for _, ts := range []int64{510, 520} {
		ob.Append(EntryRecord{Epoch: 2, Timestamp: ts, EncPayload: "x"})
	}

	entry, err := ob.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if entry.BatchID != "b1" || entry.AgentID != "ag" || entry.Epoch != 2 {
		t.Errorf("entry meta wrong: %+v", entry)
	}
	if entry.Timestamp != 500 {
		t.Errorf("entry.Timestamp = %d, want 500 (StartedAt)", entry.Timestamp)
	}

	// .open should be gone, .wal should exist.
	if _, err := os.Stat(filepath.Join(w.Dir(), "b1.open")); !os.IsNotExist(err) {
		t.Error(".open file still present after Finalize")
	}
	if _, err := os.Stat(filepath.Join(w.Dir(), "b1.wal")); err != nil {
		t.Errorf(".wal file not created: %v", err)
	}

	// EncPayload should be a JSON array of payload strings (not the raw NDJSON).
	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 2 {
		t.Errorf("got %d payloads, want 2", len(payloads))
	}
}

func TestFinalize_EmptyBatchRemovesFile(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	ob, _ := w.OpenBatch(BatchMeta{BatchID: "b1", AgentID: "ag", Epoch: 1, StartedAt: 100})

	_, err := ob.Finalize()
	if err != ErrEmptyBatch {
		t.Errorf("Finalize empty batch err = %v, want ErrEmptyBatch", err)
	}
	if _, err := os.Stat(filepath.Join(w.Dir(), "b1.open")); !os.IsNotExist(err) {
		t.Error(".open file still present after empty Finalize")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test ./internal/wal/ -run 'TestFinalize' -v
```

Expected: FAIL — `Finalize undefined`, `ErrEmptyBatch undefined`.

- [ ] **Step 3: Implement Finalize**

Append to `internal/wal/openbatch.go`:

```go
import (
	// add to existing imports
	"errors"
	"strings"
	"bufio"
)

// ErrEmptyBatch is returned by Finalize when no payload entries were appended.
// The .open file is removed and the caller should not send any message.
var ErrEmptyBatch = errors.New("openbatch: no entries appended")

// Finalize closes the .open file, renames it to .wal atomically, and returns a
// wal.Entry suitable for sending as a batch / wal_sync / flush message. The
// returned EncPayload is a JSON array of the appended encrypted payload strings,
// matching the format the scheduler already serializes for transport.
func (ob *OpenBatch) Finalize() (Entry, error) {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return Entry{}, fmt.Errorf("openbatch: closed")
	}
	if ob.count == 0 {
		ob.closed = true
		ob.file.Close()
		os.Remove(ob.path)
		fsyncDir(filepath.Dir(ob.path))
		return Entry{}, ErrEmptyBatch
	}

	if err := ob.file.Sync(); err != nil {
		return Entry{}, fmt.Errorf("fsync open file: %w", err)
	}
	if err := ob.file.Close(); err != nil {
		return Entry{}, fmt.Errorf("close open file: %w", err)
	}
	ob.closed = true

	// Read back the payload strings to build the wal.Entry.EncPayload JSON.
	payloads, err := readOpenFilePayloads(ob.path)
	if err != nil {
		return Entry{}, fmt.Errorf("read open file: %w", err)
	}

	wrapped, err := json.Marshal(payloads)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal payloads: %w", err)
	}

	finalPath := strings.TrimSuffix(ob.path, ".open") + ".wal"
	if err := os.Rename(ob.path, finalPath); err != nil {
		return Entry{}, fmt.Errorf("rename to .wal: %w", err)
	}
	if err := fsyncDir(filepath.Dir(finalPath)); err != nil {
		return Entry{}, fmt.Errorf("fsync dir: %w", err)
	}

	return Entry{
		BatchID:    ob.meta.BatchID,
		AgentID:    ob.meta.AgentID,
		Epoch:      ob.meta.Epoch,
		Timestamp:  ob.meta.StartedAt,
		EncPayload: string(wrapped),
	}, nil
}

// readOpenFilePayloads reads an .open or finalized .wal NDJSON file (with meta
// line + payload lines) and returns the EncPayload strings in file order.
// Lines that fail JSON parse or CRC validation are dropped (used for both
// finalize round-trip and crash recovery).
func readOpenFilePayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // up to 4 MB per line
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip meta
		}
		var rec EntryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			// Torn final line — stop here, what we have is what we keep.
			break
		}
		want, _, err := computeCRC(rec)
		if err != nil || want != rec.CRC {
			break
		}
		payloads = append(payloads, rec.EncPayload)
	}
	if err := scanner.Err(); err != nil {
		return payloads, err
	}
	return payloads, nil
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/wal/ -v
```

Expected: PASS for all WAL tests.

- [ ] **Step 5: Commit**

```
git add internal/wal/openbatch.go internal/wal/openbatch_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: OpenBatch.Finalize renames .open to .wal and returns Entry"
```

---

## Task 6: WAL recovery — RecoverOrphans

**Files:**
- Create: `internal/wal/recovery.go`
- Create: `internal/wal/recovery_test.go`

- [ ] **Step 1: Write failing tests**

```go
package wal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// helper: build a .open file with the given meta and entries (correct CRCs).
func writeOpenFile(t *testing.T, dir, batchID string, agentID string, epoch int, startedAt int64, payloads []string, tornLast bool) {
	t.Helper()
	path := filepath.Join(dir, batchID+".open")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	metaLine, _ := json.Marshal(struct {
		Meta BatchMeta `json:"meta"`
	}{Meta: BatchMeta{BatchID: batchID, AgentID: agentID, Epoch: epoch, StartedAt: startedAt}})
	f.Write(append(metaLine, '\n'))

	for i, p := range payloads {
		rec := EntryRecord{Epoch: epoch, Timestamp: startedAt + int64(i), EncPayload: p}
		crc, _, _ := computeCRC(rec)
		rec.CRC = crc
		line, _ := json.Marshal(rec)
		if tornLast && i == len(payloads)-1 {
			// Truncate the line halfway to simulate torn write.
			f.Write(line[:len(line)/2])
			break
		}
		f.Write(append(line, '\n'))
	}
}

func TestRecoverOrphans_FinalizesValidOpenFile(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, []string{"p1", "p2"}, false)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if pending[0].BatchID != "b1" {
		t.Errorf("BatchID = %q, want b1", pending[0].BatchID)
	}
	var payloads []string
	if err := json.Unmarshal([]byte(pending[0].EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 2 {
		t.Errorf("payloads = %d, want 2", len(payloads))
	}
}

func TestRecoverOrphans_DropsTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, []string{"p1", "p2", "p3"}, true)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	var payloads []string
	json.Unmarshal([]byte(pending[0].EncPayload), &payloads)
	if len(payloads) != 2 {
		t.Errorf("payloads = %d, want 2 (torn final dropped)", len(payloads))
	}
}

func TestRecoverOrphans_DropsEmptyOpenFile(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, nil, false)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	if w.Count() != 0 {
		t.Errorf("Count = %d, want 0 (empty .open dropped)", w.Count())
	}
	if _, err := os.Stat(filepath.Join(dir, "b1.open")); !os.IsNotExist(err) {
		t.Error(".open file should have been removed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test ./internal/wal/ -run TestRecoverOrphans -v
```

Expected: FAIL — `RecoverOrphans undefined`.

- [ ] **Step 3: Implement RecoverOrphans**

Write `internal/wal/recovery.go`:

```go
package wal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// RecoverOrphans scans the WAL directory for in-progress (.open) files left
// over from an unclean shutdown, validates each line via CRC (dropping the
// final torn line if any), and either:
//   - finalizes the file by renaming .open -> .wal (so the existing wal_sync
//     path picks it up), or
//   - removes the file if no valid payload entries remain.
//
// Safe to call once on startup before the scheduler enters its run loop.
func (w *WAL) RecoverOrphans() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	dirEntries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range dirEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".open") {
			continue
		}
		path := filepath.Join(w.dir, e.Name())
		if err := w.recoverOneLocked(path); err != nil {
			log.Printf("[wal] recover %s: %v", e.Name(), err)
		}
	}
	return nil
}

func (w *WAL) recoverOneLocked(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var meta BatchMeta
	gotMeta := false
	var payloads []string
	for scanner.Scan() {
		if !gotMeta {
			var line struct {
				Meta BatchMeta `json:"meta"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil || line.Meta.BatchID == "" {
				f.Close()
				os.Remove(path)
				log.Printf("[wal] recover: %s missing/invalid meta, removed", filepath.Base(path))
				return nil
			}
			meta = line.Meta
			gotMeta = true
			continue
		}
		var rec EntryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			break
		}
		want, _, err := computeCRC(rec)
		if err != nil || want != rec.CRC {
			break
		}
		payloads = append(payloads, rec.EncPayload)
	}
	f.Close()

	if !gotMeta || len(payloads) == 0 {
		os.Remove(path)
		log.Printf("[wal] recover: %s had no valid entries, removed", filepath.Base(path))
		return nil
	}

	wrapped, err := json.Marshal(payloads)
	if err != nil {
		return fmt.Errorf("marshal payloads: %w", err)
	}
	entry := Entry{
		BatchID:    meta.BatchID,
		AgentID:    meta.AgentID,
		Epoch:      meta.Epoch,
		Timestamp:  meta.StartedAt,
		EncPayload: string(wrapped),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	finalPath := strings.TrimSuffix(path, ".open") + ".wal"
	if err := atomicReplace(finalPath, data, 0600); err != nil {
		return fmt.Errorf("atomicReplace: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove .open: %w", err)
	}
	if err := fsyncDir(w.dir); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	log.Printf("[wal] recovered %s with %d entries", meta.BatchID, len(payloads))
	return nil
}
```

- [ ] **Step 4: Run all WAL tests**

```
go test ./internal/wal/ -v
```

Expected: PASS for all WAL tests.

- [ ] **Step 5: Commit**

```
git add internal/wal/recovery.go internal/wal/recovery_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "wal: RecoverOrphans for crash-interrupted .open files"
```

---

## Task 7: Scheduler — replace batchBuf with OpenBatch

**Files:**
- Modify: `internal/scheduler/scheduler.go`
- Modify: `internal/scheduler/scheduler_test.go`

- [ ] **Step 1: Add failing test**

Append to `internal/scheduler/scheduler_test.go` (if there are no existing tests, create the file with a `package scheduler` header). Skip the test if `package scheduler_test` already in use — adapt to that style.

```go
func TestScheduler_AppendsToOpenBatchOnIdleTick(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.New(dir, 10, 100)
	enc := newTestEncryptor(t)
	conn := newFakeConn()
	orch := newFakeOrch(/* one snapshot */)

	s := New("ag", 1, enc, orch, conn, w)

	// Simulate one collected snapshot via the public bufferSnapshot path.
	s.bufferSnapshot(&Snapshot{Timestamp: 100, Metrics: nil})

	// Expect a .open file to exist with one payload line.
	files, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(files) != 1 {
		t.Fatalf(".open files = %d, want 1", len(files))
	}

	// Drive a batch boundary manually by calling sendBatch().
	s.sendBatch()

	// Now there should be a .wal file (until ack) and no .open.
	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 0 {
		t.Errorf(".open files after sendBatch = %d, want 0", len(openFiles))
	}
	walFiles, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(walFiles) != 1 {
		t.Errorf(".wal files after sendBatch = %d, want 1", len(walFiles))
	}
	if got := len(conn.sent); got != 1 {
		t.Errorf("sent messages = %d, want 1 (the batch)", got)
	}
}
```

If helpers `newTestEncryptor`, `newFakeConn`, `newFakeOrch` don't exist, factor them out from any existing scheduler test or copy minimal versions from `internal/scheduler/scheduler_test.go`. (Run `grep -n 'newFakeConn\|newFakeOrch\|newTestEncryptor' internal/scheduler/scheduler_test.go` first to see what's already there.)

- [ ] **Step 2: Run test to verify it fails**

```
go test ./internal/scheduler/ -run TestScheduler_AppendsToOpenBatchOnIdleTick -v
```

Expected: FAIL — `bufferSnapshot` still uses in-memory slice; no .open file appears.

- [ ] **Step 3: Refactor scheduler**

Apply these surgical changes to `internal/scheduler/scheduler.go`:

3a. Remove the `batchMu` and `batchBuf` fields from the `Scheduler` struct, replacing them with a single OpenBatch reference:

```go
type Scheduler struct {
	agentID   string
	epoch     int
	encryptor *crypto.Encryptor
	orch      *collector.Orchestrator
	conn      *transport.Connection
	wal       *wal.WAL

	mu   sync.RWMutex
	mode Mode

	// In-progress batch, opened lazily on first idle-tick collect of a window.
	openMu    sync.Mutex
	openBatch *wal.OpenBatch
	openID    string

	paceChanged chan struct{}
	logManager  LogBufferProvider
}
```

3b. Replace `bufferSnapshot` with an `OpenBatch.Append`-driven version:

```go
func (s *Scheduler) bufferSnapshot(snap *Snapshot) {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	plaintext, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[scheduler] marshal snapshot error: %v", err)
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Printf("[scheduler] encrypt snapshot error: %v", err)
		return
	}

	s.openMu.Lock()
	defer s.openMu.Unlock()

	if s.openBatch == nil {
		batchID := fmt.Sprintf("b_%d_%s", time.Now().Unix(), s.agentID)
		ob, err := s.wal.OpenBatch(wal.BatchMeta{
			BatchID:   batchID,
			AgentID:   s.agentID,
			Epoch:     epoch,
			StartedAt: snap.Timestamp,
		})
		if err != nil {
			log.Printf("[scheduler] OpenBatch error: %v", err)
			return
		}
		s.openBatch = ob
		s.openID = batchID
	}

	if err := s.openBatch.Append(wal.EntryRecord{
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	}); err != nil {
		log.Printf("[scheduler] OpenBatch.Append error: %v", err)
	}
}
```

3c. Replace `sendBatch` to finalize the open batch and send the resulting Entry:

```go
func (s *Scheduler) sendBatch() {
	s.openMu.Lock()
	ob := s.openBatch
	s.openBatch = nil
	s.openID = ""
	s.openMu.Unlock()

	if ob == nil {
		return
	}

	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[scheduler] Finalize error: %v", err)
		return
	}

	// Reconstruct BatchEntry list from the JSON payload array for the message.
	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		log.Printf("[scheduler] decode payloads error: %v", err)
		return
	}
	entries := make([]protocol.BatchEntry, len(payloads))
	for i, p := range payloads {
		entries[i] = protocol.BatchEntry{
			Epoch:      entry.Epoch,
			Timestamp:  entry.Timestamp + int64(i*10), // approximate per-tick spacing
			EncPayload: p,
		}
	}

	if err := s.conn.Send(protocol.BatchMessage{
		Type:    "batch",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] batch send error: %v (data in WAL)", err)
	} else {
		log.Printf("[scheduler] batch sent: %s (%d entries)", entry.BatchID, len(entries))
	}
}
```

> **Note:** the per-entry timestamp loss above is acceptable because batch entries are timestamped at decryption time on the dashboard via the encrypted payload (`Snapshot.Timestamp`), not via the outer `BatchEntry.Timestamp`. If a downstream consumer needs precise per-entry timestamps before decryption, change `EntryRecord` to carry a separate `OuterTimestamp` field and pass it through. Verified: `app.blind.watch/lib/agents/queries.ts` uses the decrypted `Snapshot.Timestamp` for plotting.

3d. Replace `flush()` similarly — finalize then `SendSync` with `flush_` batch ID:

```go
func (s *Scheduler) flush() {
	s.openMu.Lock()
	ob := s.openBatch
	s.openBatch = nil
	s.openID = ""
	s.openMu.Unlock()

	if ob == nil {
		return
	}

	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[scheduler] flush finalize error: %v", err)
		return
	}

	// Rename the .wal to a flush_ prefix so the server knows it's a graceful flush.
	// (Optional — the server treats batch and flush identically except for the prefix.)

	var payloads []string
	json.Unmarshal([]byte(entry.EncPayload), &payloads)
	entries := make([]protocol.BatchEntry, len(payloads))
	for i, p := range payloads {
		entries[i] = protocol.BatchEntry{
			Epoch: entry.Epoch, Timestamp: entry.Timestamp + int64(i*10), EncPayload: p,
		}
	}

	if err := s.conn.SendSync(protocol.FlushMessage{
		Type:    "flush",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] flush send error: %v (data in WAL)", err)
	}
}
```

3e. Replace `sendReplay()` to read the in-progress OpenBatch payloads (without finalizing):

```go
func (s *Scheduler) sendReplay() {
	s.openMu.Lock()
	ob := s.openBatch
	openID := s.openID
	s.openMu.Unlock()
	if ob == nil {
		return
	}
	// Read back the on-disk .open file — it's already encrypted.
	path := filepath.Join(s.wal.Dir(), openID+".open")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	var entries []protocol.BatchEntry
	for scanner.Scan() {
		if first { first = false; continue }
		var rec wal.EntryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil { break }
		entries = append(entries, protocol.BatchEntry{
			Epoch: rec.Epoch, Timestamp: rec.Timestamp, EncPayload: rec.EncPayload,
		})
	}
	if len(entries) == 0 {
		return
	}
	s.mu.RLock()
	epoch := s.epoch
	s.mu.RUnlock()
	s.conn.Send(protocol.ReplayMessage{Type: "replay", Epoch: epoch, Entries: entries})
}
```

Add new imports to `scheduler.go`: `"bufio"`, `"os"`, `"path/filepath"`. Remove the now-unused `encryptSnapshots` function and the `batchMu`/`batchBuf` field references.

3f. In `syncWAL()`, call `RecoverOrphans()` before the existing pending scan:

```go
func (s *Scheduler) syncWAL() {
	if err := s.wal.RecoverOrphans(); err != nil {
		log.Printf("[scheduler] WAL recovery error: %v", err)
	}
	entries, err := s.wal.Pending()
	// ... rest unchanged
}
```

- [ ] **Step 4: Run scheduler tests**

```
go test ./internal/scheduler/ -v
```

Expected: PASS, including new test. Other existing scheduler tests may need updating where they touched `batchBuf` directly — fix any compile errors by switching to the new public surface (`bufferSnapshot`, `sendBatch`).

- [ ] **Step 5: Commit**

```
git add internal/scheduler/scheduler.go internal/scheduler/scheduler_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "scheduler: persist each snapshot via OpenBatch; recover orphans on boot"
```

---

## Task 8: Transport — WS ping/pong + read deadline

**Files:**
- Modify: `internal/transport/ws.go`
- Modify: `internal/transport/ws_test.go`

- [ ] **Step 1: Add failing test**

Append to `internal/transport/ws_test.go`:

```go
func TestConnection_DetectsHalfOpen(t *testing.T) {
	// Server that accepts the WS handshake but never reads or writes.
	// (Doesn't respond to pings.)
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Send the connected message so our gate passes.
		c.WriteJSON(map[string]any{"type": "connected", "pace": map[string]int{"interval_ms": 0, "collect_ms": 10000}})
		// Then pretend to be alive but never read anything.
		select {}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn := NewConnection(wsURL, "tok", "ag", "test")
	conn.SetPingInterval(200 * time.Millisecond)
	conn.SetReadDeadline(600 * time.Millisecond)

	connectedCh := make(chan struct{}, 1)
	conn.OnConnected(func(protocol.PaceConfig) { connectedCh <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go conn.Run(ctx)

	// Wait for first connect.
	select {
	case <-connectedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("never connected")
	}

	// Within ~ReadDeadline + small slack, conn.IsConnected should flip false.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !conn.IsConnected() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected disconnect detection within 2s, IsConnected still true")
}
```

Add imports: `"net/http"`, `"net/http/httptest"`, `"strings"`, `"github.com/gorilla/websocket"`, `"github.com/watchblind/agent/internal/protocol"` if missing.

- [ ] **Step 2: Run test to verify it fails**

```
go test ./internal/transport/ -run TestConnection_DetectsHalfOpen -v -timeout 30s
```

Expected: FAIL — no SetPingInterval / SetReadDeadline methods, or test times out because half-open isn't detected.

- [ ] **Step 3: Implement ping/read deadline**

In `internal/transport/ws.go`:

3a. Add fields and configuration setters to `Connection`:

```go
type Connection struct {
	// ...existing fields...
	pingInterval time.Duration
	readDeadline time.Duration
}

const (
	defaultPingInterval = 15 * time.Second
	defaultReadDeadline = 45 * time.Second
)

func (c *Connection) SetPingInterval(d time.Duration) { c.pingInterval = d }
func (c *Connection) SetReadDeadline(d time.Duration) { c.readDeadline = d }
```

In `NewConnection`, set defaults:

```go
return &Connection{
	// ...existing init...
	pingInterval: defaultPingInterval,
	readDeadline: defaultReadDeadline,
}
```

3b. After successful dial in `connect`, register pong handler and initial read deadline:

```go
conn.SetReadDeadline(time.Now().Add(c.readDeadline))
conn.SetPongHandler(func(string) error {
	return conn.SetReadDeadline(time.Now().Add(c.readDeadline))
})
```

3c. Start a ping goroutine alongside the write pump:

```go
go c.writePump(ctx)
go c.pingLoop(ctx, conn)
```

3d. Implement `pingLoop`:

```go
func (c *Connection) pingLoop(ctx context.Context, conn *websocket.Conn) {
	if c.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(c.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-t.C:
			c.connMu.Lock()
			cur := c.conn
			c.connMu.Unlock()
			if cur != conn {
				return // we've reconnected; this loop is for the old conn
			}
			deadline := time.Now().Add(5 * time.Second)
			if err := cur.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				return
			}
		}
	}
}
```

3e. Refresh the read deadline on every received message in `readLoop`:

After the existing `_, data, err := conn.ReadMessage()` line, on success refresh the deadline:

```go
conn.SetReadDeadline(time.Now().Add(c.readDeadline))
```

- [ ] **Step 4: Run test to verify it passes**

```
go test ./internal/transport/ -run TestConnection_DetectsHalfOpen -v -timeout 30s
```

Expected: PASS within ~1 s.

- [ ] **Step 5: Commit**

```
git add internal/transport/ws.go internal/transport/ws_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "transport: WS ping every 15s + 45s read deadline detect half-open"
```

---

## Task 9: Transport — connected-message gate, sendCh drain, log throttling

**Files:**
- Modify: `internal/transport/ws.go`
- Modify: `internal/transport/ws_test.go`

- [ ] **Step 1: Add failing tests**

Append to `internal/transport/ws_test.go`:

```go
func TestConnection_NotConnectedUntilConnectedMessage(t *testing.T) {
	// Server accepts the WS but never sends a "connected" message.
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := upgrader.Upgrade(w, r, nil)
		defer c.Close()
		// Sit silent for the duration of the test.
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn := NewConnection(wsURL, "tok", "ag", "test")
	conn.SetReadDeadline(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go conn.Run(ctx)

	time.Sleep(500 * time.Millisecond)
	if conn.IsConnected() {
		t.Error("IsConnected = true before connected message received")
	}
}

func TestConnection_DrainsSendChOnDisconnect(t *testing.T) {
	conn := NewConnection("ws://127.0.0.1:0", "tok", "ag", "test")
	// Pre-fill sendCh.
	for i := 0; i < 5; i++ {
		conn.sendCh <- sendItem{data: []byte("x"), category: "batch"}
	}
	conn.drainSendCh()
	if got := len(conn.sendCh); got != 0 {
		t.Errorf("sendCh len after drain = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test ./internal/transport/ -run 'TestConnection_NotConnectedUntilConnectedMessage|TestConnection_DrainsSendChOnDisconnect' -v
```

Expected: FAIL — `connected` flips true on TCP dial; `drainSendCh` undefined.

- [ ] **Step 3: Implement the gate, drain, log throttling**

In `internal/transport/ws.go`:

3a. In `connect`, do **not** set `c.connected.Store(true)`. Move that to the `connected` message handler in `handleMessage`:

```go
case "connected":
	var msg protocol.ConnectedMessage
	if json.Unmarshal(data, &msg) == nil {
		c.connected.Store(true)
		if c.onConnected != nil {
			c.onConnected(msg.Pace)
		}
	}
```

3b. Add `drainSendCh`:

```go
func (c *Connection) drainSendCh() {
	for {
		select {
		case <-c.sendCh:
		default:
			return
		}
	}
}
```

Call `c.drainSendCh()` in `Run` immediately after `c.readLoop` returns and before resetting `c.connected`:

```go
c.readLoop(ctx)
c.connected.Store(false)
c.drainSendCh()
log.Printf("[ws] disconnected, reconnecting...")
```

3c. Add log throttling — track last failure log time and emit at most once per minute when an attempt fails consecutively:

```go
type Connection struct {
	// existing fields...
	lastFailLog time.Time
}

// In Run, after err := c.connect(ctx):
if err != nil {
	now := time.Now()
	if attempt == 0 || now.Sub(c.lastFailLog) >= time.Minute {
		log.Printf("[ws] connection failed (attempt %d): %v, retrying in %v", attempt+1, err, backoff(attempt))
		c.lastFailLog = now
	}
	// ... rest unchanged
}
```

And on successful reconnect after a failure, log a one-line summary:

```go
// After connect succeeds:
attempt = 0
if !c.lastFailLog.IsZero() {
	log.Printf("[ws] reconnected")
	c.lastFailLog = time.Time{}
}
```

> **Note:** the authoritative "X pending WAL batches" line is logged by the scheduler inside `syncWAL` as it iterates pending entries. The transport-level reconnect log only marks the recovery point; it deliberately does not count WAL files since the transport layer doesn't hold a WAL reference.

- [ ] **Step 4: Run tests to verify they pass**

```
go test ./internal/transport/ -v -timeout 30s
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add internal/transport/ws.go internal/transport/ws_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "transport: connected-message gate, drain sendCh on disconnect, throttle failure logs"
```

---

## Task 10: Logtail — migrate idle batch to OpenBatch

**Files:**
- Modify: `internal/logtail/manager.go`
- Modify: `internal/logtail/manager_test.go` (create if absent)

- [ ] **Step 1: Add failing test**

Create `internal/logtail/manager_test.go` (or append):

```go
package logtail

import (
	"path/filepath"
	"testing"

	"github.com/watchblind/agent/internal/wal"
)

func TestManager_AppendsLogEntryToOpenBatch(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.New(dir, 10, 100)

	m := newTestManager(t, w) // see helper below
	m.handleLogEntry(LogEntry{Timestamp: 100, Message: "hello", Source: "syslog"})

	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf(".open files = %d, want 1", len(openFiles))
	}
}
```

Add a `newTestManager` helper that constructs a `Manager` with a fake encryptor and connection — copy from any existing test pattern in the repo (`internal/wal/wal_test.go` makeEntry style, or `scheduler_test.go` patterns).

- [ ] **Step 2: Run test to verify it fails**

```
go test ./internal/logtail/ -run TestManager_AppendsLogEntryToOpenBatch -v
```

Expected: FAIL — `handleLogEntry` undefined or no .open file produced.

- [ ] **Step 3: Refactor logtail**

In `internal/logtail/manager.go`:

3a. Replace the `batch []LogEntry` field and its `batchMu` with an OpenBatch reference:

```go
openMu    sync.Mutex
openBatch *wal.OpenBatch
openID    string
```

3b. Extract the per-entry logic from the `m.entries` case in `Run` into `handleLogEntry`:

```go
func (m *Manager) handleLogEntry(entry LogEntry) {
	m.mu.RLock()
	enc := m.encryptor
	epoch := m.epoch
	m.mu.RUnlock()
	if enc == nil {
		return
	}
	plaintext, err := json.Marshal(entry)
	if err != nil {
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return
	}

	m.openMu.Lock()
	defer m.openMu.Unlock()

	if m.openBatch == nil {
		batchID := fmt.Sprintf("lb_%d_%s", time.Now().Unix(), m.agentID)
		ob, err := m.walLog.OpenBatch(wal.BatchMeta{
			BatchID: batchID, AgentID: m.agentID, Epoch: epoch, StartedAt: entry.Timestamp,
		})
		if err != nil {
			log.Printf("[logtail] OpenBatch error: %v", err)
			return
		}
		m.openBatch = ob
		m.openID = batchID
	}
	if err := m.openBatch.Append(wal.EntryRecord{
		Epoch: epoch, Timestamp: entry.Timestamp, EncPayload: encrypted,
	}); err != nil {
		log.Printf("[logtail] OpenBatch.Append error: %v", err)
	}

	m.liveMu.RLock()
	isLive := m.live
	m.liveMu.RUnlock()
	if isLive {
		m.SendLive(entry)
	}
}
```

3c. Replace `sendBatch` with a finalize-then-send variant:

```go
func (m *Manager) flushOpenBatch() {
	m.openMu.Lock()
	ob := m.openBatch
	m.openBatch = nil
	m.openID = ""
	m.openMu.Unlock()
	if ob == nil {
		return
	}
	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[logtail] Finalize error: %v", err)
		return
	}
	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		log.Printf("[logtail] decode payloads error: %v", err)
		return
	}
	protoEntries := make([]protocol.LogBatchEntry, len(payloads))
	for i, p := range payloads {
		protoEntries[i] = protocol.LogBatchEntry{
			Timestamp: entry.Timestamp + int64(i), EncPayload: p,
		}
	}
	if err := m.conn.Send(protocol.LogBatchMessage{
		Type: "log_batch", BatchID: entry.BatchID, Epoch: entry.Epoch, Entries: protoEntries,
	}); err != nil {
		log.Printf("[logtail] send error: %v (data in WAL)", err)
	}
}
```

3d. Update `Run` to call `m.handleLogEntry(entry)` in the `<-m.entries` arm and `m.flushOpenBatch()` in the `<-batchTimer.C`, `<-m.flushCh`, and shutdown arms. Drop the early `MaxBatchSize` flush — OpenBatch handles each entry individually now and there is no in-memory buildup. (Disk size is bounded by WAL limits, not memory.)

3e. Update `BufferedEntries` (used for live replay): read the in-progress `.open` file similar to scheduler `sendReplay`. Reuse the same scanner pattern.

- [ ] **Step 4: Run tests**

```
go test ./internal/logtail/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add internal/logtail/manager.go internal/logtail/manager_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "logtail: persist each log entry via OpenBatch (crash-safe)"
```

---

## Task 11: Dashboard — surface WAL counters

**Files:**
- Modify: `internal/dashboard/dashboard.go`

- [ ] **Step 1: Plumb the WAL into Dashboard**

Add a parameter and field:

```go
type Dashboard struct {
	// ...existing fields...
	wal       *wal.WAL
	lastAckTS atomic.Int64
}

func New(
	snapCh <-chan collector.Snapshot,
	alertCh <-chan alert.AlertEvent,
	alertState *alert.StateTracker,
	snd *sender.MockSender,
	procCol *collector.ProcessCollector,
	w *wal.WAL,
) *Dashboard {
	return &Dashboard{
		snapCh: snapCh, alertCh: alertCh, alertState: alertState,
		sender: snd, procCol: procCol, wal: w,
	}
}

// NoteAck is called from the scheduler ack callback to refresh the timestamp.
func (d *Dashboard) NoteAck() { d.lastAckTS.Store(time.Now().Unix()) }
```

- [ ] **Step 2: Render counters in the status bar**

In `updateMetrics`, replace the status bar text:

```go
files := d.wal.Count()
bytes := d.wal.PendingBytes()
last := d.lastAckTS.Load()
since := "never"
if last > 0 {
	since = fmt.Sprintf("%ds", time.Now().Unix()-last)
}
d.statusBar.SetText(fmt.Sprintf(
	"[yellow]blind.watch agent[white] | [green]%d[white] metrics | WAL [green]%d[white] files / [green]%s[white] | last ack [green]%s[white] | %s | [green]q[white]=quit",
	len(metrics), files, formatBytes(float64(bytes)), since, snap.Timestamp.Format("15:04:05"),
))
```

Add `"github.com/watchblind/agent/internal/wal"` import and `"sync/atomic"`.

- [ ] **Step 3: Update the agent main wiring**

Find the dashboard construction site (likely `cmd/agent/main.go` — check `grep -rn "dashboard.New" cmd/`) and pass the WAL through. Wire `dashboard.NoteAck()` into the existing scheduler ack callback (the place that calls `s.AckBatch`).

- [ ] **Step 4: Run all tests + manual smoke**

```
go test ./... -count=1
go build ./...
```

Expected: build succeeds; tests pass.

- [ ] **Step 5: Commit**

```
git add internal/dashboard/dashboard.go cmd/agent/main.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "dashboard: show WAL pending files/bytes and time since last ack"
```

---

## Task 12: Integration tests — half-open + crash mid-window

**Files:**
- Create: `internal/scheduler/scheduler_recovery_test.go`

- [ ] **Step 1: Write the integration test**

```go
package scheduler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/watchblind/agent/internal/wal"
)

// TestCrashMidWindow_RecoversAllSnapshots simulates appending several snapshots
// to an open batch, then "crashing" (dropping the scheduler reference without
// finalizing), then booting fresh and verifying RecoverOrphans + Pending picks
// up exactly those snapshots.
func TestCrashMidWindow_RecoversAllSnapshots(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.New(dir, 10, 100)
	enc := newTestEncryptor(t)
	conn := newFakeConn()
	orch := newFakeOrch()

	s1 := New("ag", 1, enc, orch, conn, w)
	for _, ts := range []int64{100, 110, 120, 130} {
		s1.bufferSnapshot(&Snapshot{Timestamp: ts})
	}
	// Drop the scheduler — simulates crash before sendBatch fires.
	s1 = nil

	// New WAL on the same dir; recover orphans.
	w2, _ := wal.New(dir, 10, 100)
	if err := w2.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w2.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1 batch", len(pending))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(files) != 1 {
		t.Errorf("wal files = %d, want 1", len(files))
	}
}

// TestCrashMidWindow_TornFinalLineDropped corrupts the last line of the .open
// file and verifies the surviving entries still recover.
func TestCrashMidWindow_TornFinalLineDropped(t *testing.T) {
	dir := t.TempDir()
	w, _ := wal.New(dir, 10, 100)
	enc := newTestEncryptor(t)
	conn := newFakeConn()
	orch := newFakeOrch()
	s := New("ag", 1, enc, orch, conn, w)
	for _, ts := range []int64{100, 110, 120, 130} {
		s.bufferSnapshot(&Snapshot{Timestamp: ts})
	}
	// Find the .open file and truncate the last byte to simulate torn write.
	files, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(files) != 1 {
		t.Fatalf(".open files = %d, want 1", len(files))
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := os.Truncate(files[0], info.Size()-1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	w2, _ := wal.New(dir, 10, 100)
	if err := w2.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w2.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	// Decode the wrapped JSON payload array and assert exactly 3 entries
	// survived (the last one was torn by the truncate).
	var payloads []string
	if err := json.Unmarshal([]byte(pending[0].EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 3 {
		t.Errorf("payloads = %d, want 3 (last torn line dropped)", len(payloads))
	}
}
```

> Add `"encoding/json"` to the imports for the second test.

- [ ] **Step 2: Run tests**

```
go test ./internal/scheduler/ -run 'TestCrashMidWindow' -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```
git add internal/scheduler/scheduler_recovery_test.go
git -c user.name="0xKismetDev" -c user.email="131729061+0xKismetDev@users.noreply.github.com" \
    commit -m "scheduler: integration tests for crash-mid-window recovery"
```

---

## Final verification

- [ ] Run the full test suite:

```
cd /Users/tom/Documents/watchblind/agent.blind.watch
go test ./... -count=1 -race
```

Expected: PASS.

- [ ] Build the binary to confirm no compile errors anywhere:

```
go build ./...
```

Expected: success.

- [ ] Show the commit list to the user before they choose to push:

```
git log --oneline origin/main..HEAD
```

Expected: 12 commits, one per task.

- [ ] **Do NOT push.** Ask the user whether to push to `origin/main` and confirm watchblind credentials before any `git push`.
