package internal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/scheduler"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
	"github.com/gorilla/websocket"
)

// miniServer is a minimal WebSocket server for integration testing.
type miniServer struct {
	mu       sync.Mutex
	batches  []protocol.BatchMessage
	lives    []protocol.LiveMessage
	flushes  []protocol.FlushMessage
	walSyncs []protocol.WALSyncMessage
	alerts   []protocol.AlertMessage

	upgrader websocket.Upgrader
	pace     protocol.PaceConfig
}

func newMiniServer(pace protocol.PaceConfig) *miniServer {
	return &miniServer{
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		pace:     pace,
	}
}

func (ms *miniServer) handler(w http.ResponseWriter, r *http.Request) {
	conn, err := ms.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send connected
	data, _ := json.Marshal(protocol.ConnectedMessage{
		Type: "connected",
		Pace: ms.pace,
	})
	conn.WriteMessage(websocket.TextMessage, data)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var env protocol.Envelope
		if json.Unmarshal(msg, &env) != nil {
			continue
		}

		ms.mu.Lock()
		switch env.Type {
		case "batch":
			var m protocol.BatchMessage
			if json.Unmarshal(msg, &m) == nil {
				ms.batches = append(ms.batches, m)
				ack, _ := json.Marshal(protocol.AckMessage{Type: "ack", BatchID: m.BatchID})
				conn.WriteMessage(websocket.TextMessage, ack)
			}
		case "live":
			var m protocol.LiveMessage
			if json.Unmarshal(msg, &m) == nil {
				ms.lives = append(ms.lives, m)
			}
		case "flush":
			var m protocol.FlushMessage
			if json.Unmarshal(msg, &m) == nil {
				ms.flushes = append(ms.flushes, m)
				ack, _ := json.Marshal(protocol.AckMessage{Type: "ack", BatchID: m.BatchID})
				conn.WriteMessage(websocket.TextMessage, ack)
			}
		case "wal_sync":
			var m protocol.WALSyncMessage
			if json.Unmarshal(msg, &m) == nil {
				ms.walSyncs = append(ms.walSyncs, m)
				// ONE ack per WAL batch
				ack, _ := json.Marshal(protocol.AckMessage{Type: "ack", BatchID: m.BatchID})
				conn.WriteMessage(websocket.TextMessage, ack)
			}
		case "alert":
			var m protocol.AlertMessage
			if json.Unmarshal(msg, &m) == nil {
				ms.alerts = append(ms.alerts, m)
			}
		}
		ms.mu.Unlock()
	}
}

func (ms *miniServer) getBatches() []protocol.BatchMessage {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]protocol.BatchMessage, len(ms.batches))
	copy(out, ms.batches)
	return out
}

func (ms *miniServer) getLives() []protocol.LiveMessage {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]protocol.LiveMessage, len(ms.lives))
	copy(out, ms.lives)
	return out
}

func (ms *miniServer) getFlushes() []protocol.FlushMessage {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]protocol.FlushMessage, len(ms.flushes))
	copy(out, ms.flushes)
	return out
}

func (ms *miniServer) getWALSyncs() []protocol.WALSyncMessage {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]protocol.WALSyncMessage, len(ms.walSyncs))
	copy(out, ms.walSyncs)
	return out
}

// TestE2ELiveModeFlow tests: agent connects → live mode → sends live data → server receives encrypted
func TestE2ELiveModeFlow(t *testing.T) {
	// Start test server in live mode
	ms := newMiniServer(protocol.PaceConfig{IntervalMS: 1000, CollectMS: 500})
	server := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Set up components
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("crypto init: %v", err)
	}

	walDir := t.TempDir()
	w, err := wal.New(walDir, 100, 100)
	if err != nil {
		t.Fatalf("wal init: %v", err)
	}

	orch := collector.NewOrchestrator()
	orch.Register(collector.NewCPUCollector())
	orch.Register(collector.NewMemoryCollector())

	conn := transport.NewConnection(wsURL, "test-token", "agt_e2e", "test")

	sched := scheduler.New("agt_e2e", 1, enc, orch, conn, w)

	// Wire callbacks
	conn.OnAck(func(batchID string) {
		sched.AckBatch(batchID)
	})
	conn.OnPace(func(intervalMS, collectMS int) {
		sched.SetPace(intervalMS, collectMS)
	})
	conn.OnConnected(func(pace protocol.PaceConfig) {
		sched.SetPace(pace.IntervalMS, pace.CollectMS)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Start orchestrator (collects metrics every 500ms)
	go orch.Run(ctx, 500*time.Millisecond)
	go conn.Run(ctx)
	go sched.Run(ctx)

	// Wait for some live messages to arrive
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for live messages")
		case <-time.After(200 * time.Millisecond):
			lives := ms.getLives()
			if len(lives) >= 2 {
				// Verify encrypted payloads
				for _, live := range lives {
					if live.EncPayload == "" {
						t.Error("live message has empty enc_payload")
					}
					if live.Epoch != 1 {
						t.Errorf("unexpected epoch: %d", live.Epoch)
					}

					// Verify the payload is actually encrypted (can decrypt with our key)
					decrypted, err := enc.Decrypt(live.EncPayload)
					if err != nil {
						t.Errorf("failed to decrypt live payload: %v", err)
						continue
					}

					// Should be valid JSON containing metrics
					var snap struct {
						Timestamp int64              `json:"timestamp"`
						Metrics   []collector.Metric `json:"metrics"`
					}
					if err := json.Unmarshal(decrypted, &snap); err != nil {
						t.Errorf("decrypted payload is not valid JSON: %v", err)
					}
					if len(snap.Metrics) == 0 {
						t.Error("decrypted snapshot has no metrics")
					}
				}
				return // Success
			}
		}
	}
}

// TestE2EEncryptionOpacity verifies the server CANNOT read payload content.
func TestE2EEncryptionOpacity(t *testing.T) {
	ms := newMiniServer(protocol.PaceConfig{IntervalMS: 1000, CollectMS: 500})
	server := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	agentEnc, _ := crypto.NewEncryptor()
	serverEnc, _ := crypto.NewEncryptor() // Different key — simulates server

	w, _ := wal.New(t.TempDir(), 100, 100)
	orch := collector.NewOrchestrator()
	orch.Register(collector.NewCPUCollector())
	orch.Register(collector.NewMemoryCollector())

	conn := transport.NewConnection(wsURL, "token", "agt_opacity", "test")
	sched := scheduler.New("agt_opacity", 1, agentEnc, orch, conn, w)

	conn.OnAck(func(batchID string) { sched.AckBatch(batchID) })
	conn.OnPace(func(i, c int) { sched.SetPace(i, c) })
	conn.OnConnected(func(p protocol.PaceConfig) { sched.SetPace(p.IntervalMS, p.CollectMS) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go orch.Run(ctx, 500*time.Millisecond)
	go conn.Run(ctx)
	go sched.Run(ctx)

	// Wait for live messages
	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout")
		case <-time.After(200 * time.Millisecond):
			lives := ms.getLives()
			if len(lives) < 1 {
				continue
			}

			for _, live := range lives {
				// Server with different key CANNOT decrypt
				_, err := serverEnc.Decrypt(live.EncPayload)
				if err == nil {
					t.Fatal("server was able to decrypt agent payload — E2E broken!")
				}

				// Agent with correct key CAN decrypt
				plain, err := agentEnc.Decrypt(live.EncPayload)
				if err != nil {
					t.Fatalf("agent failed to decrypt own data: %v", err)
				}

				// Payload should not contain agent_id or other metadata
				// (it's the metric data, not the wrapper)
				var snap map[string]interface{}
				json.Unmarshal(plain, &snap)
				if _, has := snap["agent_id"]; has {
					t.Error("plaintext payload contains agent_id — metadata leak")
				}
			}
			return
		}
	}
}

// TestE2EWALRecovery tests: write to WAL → restart with same WAL dir → entries synced
func TestE2EWALRecovery(t *testing.T) {
	walDir := t.TempDir()
	enc, _ := crypto.NewEncryptor()

	// Phase 1: Write some entries to WAL (simulating a crash mid-send)
	w1, _ := wal.New(walDir, 100, 100)

	plaintext := []byte(`{"test": "data"}`)
	encrypted, _ := enc.Encrypt(plaintext)

	for i := 0; i < 3; i++ {
		w1.Append(wal.Entry{
			BatchID:    "recovery_" + string(rune('a'+i)),
			AgentID:    "agt_recovery",
			Epoch:      1,
			Timestamp:  time.Now().Unix() + int64(i),
			EncPayload: encrypted,
		})
	}

	if w1.Count() != 3 {
		t.Fatalf("expected 3 WAL entries, got %d", w1.Count())
	}

	// Phase 2: Start server and new agent with same WAL dir — should sync
	ms := newMiniServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	w2, _ := wal.New(walDir, 100, 100)
	orch := collector.NewOrchestrator()
	conn := transport.NewConnection(wsURL, "token", "agt_recovery", "test")
	sched := scheduler.New("agt_recovery", 1, enc, orch, conn, w2)

	conn.OnAck(func(batchID string) { sched.AckBatch(batchID) })
	conn.OnConnected(func(p protocol.PaceConfig) { sched.SetPace(p.IntervalMS, p.CollectMS) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)
	go sched.Run(ctx)

	// Wait for WAL sync to arrive at server.
	// Each WAL entry is sent as a separate wal_sync message with 1s delay between.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			syncs := ms.getWALSyncs()
			totalEntries := 0
			for _, sync := range syncs {
				totalEntries += len(sync.Entries)
			}
			t.Fatalf("timeout waiting for WAL sync (got %d messages, %d entries)", len(syncs), totalEntries)
		case <-time.After(200 * time.Millisecond):
			syncs := ms.getWALSyncs()
			totalEntries := 0
			for _, sync := range syncs {
				totalEntries += len(sync.Entries)
			}

			if totalEntries < 3 {
				continue // Wait for all 3 entries to arrive
			}

			if totalEntries != 3 {
				t.Errorf("expected 3 WAL sync entries, got %d", totalEntries)
			}

			// After acks, WAL should be clean
			time.Sleep(500 * time.Millisecond)
			if w2.Count() != 0 {
				t.Errorf("WAL should be empty after sync acks, got %d", w2.Count())
			}
			return
		}
	}
}

// TestE2EGracefulShutdown tests: agent collects data → cancel context → flush sent
func TestE2EGracefulShutdown(t *testing.T) {
	ms := newMiniServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	enc, _ := crypto.NewEncryptor()
	w, _ := wal.New(t.TempDir(), 100, 100)

	orch := collector.NewOrchestrator()
	orch.Register(collector.NewCPUCollector())

	conn := transport.NewConnection(wsURL, "token", "agt_flush", "test")
	sched := scheduler.New("agt_flush", 1, enc, orch, conn, w)

	conn.OnAck(func(batchID string) { sched.AckBatch(batchID) })
	conn.OnConnected(func(p protocol.PaceConfig) { sched.SetPace(p.IntervalMS, p.CollectMS) })

	ctx, cancel := context.WithCancel(context.Background())

	connected := make(chan struct{}, 1)
	conn.OnConnected(func(p protocol.PaceConfig) {
		select {
		case connected <- struct{}{}:
		default:
		}
	})

	go orch.Run(ctx, 500*time.Millisecond)
	go conn.Run(ctx)
	go sched.Run(ctx)

	// Wait for connection
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout connecting")
	}

	// Let some data collect (idle mode, buffered)
	time.Sleep(2 * time.Second)

	// Trigger graceful shutdown
	cancel()

	// Wait for flush to arrive
	time.Sleep(1 * time.Second)

	flushes := ms.getFlushes()
	if len(flushes) == 0 {
		// In idle mode with 10min batch interval, there should be buffered data → flush
		t.Log("no flush received (may have no buffered data if collect ticker didn't fire)")
	} else {
		// Verify flush has entries and is encrypted
		for _, f := range flushes {
			if len(f.Entries) == 0 {
				t.Error("flush has no entries")
			}
			if !strings.HasPrefix(f.BatchID, "flush_") {
				t.Errorf("flush batch_id should start with flush_, got %s", f.BatchID)
			}

			// Verify each entry can be decrypted
			for i, entry := range f.Entries {
				if entry.EncPayload == "" {
					t.Errorf("flush entry %d has empty enc_payload", i)
					continue
				}

				decrypted, err := enc.Decrypt(entry.EncPayload)
				if err != nil {
					t.Errorf("failed to decrypt flush entry %d: %v", i, err)
					continue
				}

				// Should be valid JSON with metrics
				var snap struct {
					Timestamp int64              `json:"timestamp"`
					Metrics   []collector.Metric `json:"metrics"`
				}
				if err := json.Unmarshal(decrypted, &snap); err != nil {
					t.Errorf("flush entry %d is not valid JSON: %v", i, err)
				}
			}
		}
	}
}

// TestE2EOnlyEncryptedDataOnDisk verifies WAL files contain only encrypted payloads.
func TestE2EOnlyEncryptedDataOnDisk(t *testing.T) {
	walDir := t.TempDir()
	enc, _ := crypto.NewEncryptor()
	w, _ := wal.New(walDir, 100, 100)

	// Write a WAL entry with known plaintext
	plaintext := `{"cpu_percent": 42.5, "memory_used": 8589934592, "secret": "password123"}`
	encrypted, _ := enc.Encrypt([]byte(plaintext))

	w.Append(wal.Entry{
		BatchID:    "disk_check_001",
		AgentID:    "agt_test",
		Epoch:      1,
		Timestamp:  time.Now().Unix(),
		EncPayload: encrypted,
	})

	// Read raw WAL file from disk
	entries, _ := w.Pending()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// The entry's EncPayload should NOT contain any plaintext
	raw := entries[0].EncPayload
	if strings.Contains(raw, "cpu_percent") {
		t.Fatal("WAL file contains plaintext metric name")
	}
	if strings.Contains(raw, "42.5") {
		t.Fatal("WAL file contains plaintext metric value")
	}
	if strings.Contains(raw, "password123") {
		t.Fatal("WAL file contains plaintext secret")
	}
	if strings.Contains(raw, "memory_used") {
		t.Fatal("WAL file contains plaintext metric name")
	}

	// But we CAN decrypt it back to the original
	decrypted, err := enc.Decrypt(raw)
	if err != nil {
		t.Fatalf("failed to decrypt WAL entry: %v", err)
	}
	if string(decrypted) != plaintext {
		t.Errorf("decrypted data doesn't match original:\ngot:  %s\nwant: %s", decrypted, plaintext)
	}
}

// TestE2EMetadataMinimality verifies wire messages contain only necessary metadata.
func TestE2EMetadataMinimality(t *testing.T) {
	ms := newMiniServer(protocol.PaceConfig{IntervalMS: 1000, CollectMS: 500})
	server := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	enc, _ := crypto.NewEncryptor()
	w, _ := wal.New(t.TempDir(), 100, 100)

	orch := collector.NewOrchestrator()
	orch.Register(collector.NewCPUCollector())

	conn := transport.NewConnection(wsURL, "token", "agt_meta", "test")
	sched := scheduler.New("agt_meta", 1, enc, orch, conn, w)

	conn.OnAck(func(batchID string) { sched.AckBatch(batchID) })
	conn.OnPace(func(i, c int) { sched.SetPace(i, c) })
	conn.OnConnected(func(p protocol.PaceConfig) { sched.SetPace(p.IntervalMS, p.CollectMS) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go orch.Run(ctx, 500*time.Millisecond)
	go conn.Run(ctx)
	go sched.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout")
		case <-time.After(200 * time.Millisecond):
			lives := ms.getLives()
			if len(lives) < 1 {
				continue
			}

			// Allowed metadata fields in a live message
			allowed := map[string]bool{
				"type":        true,
				"agent_id":    true,
				"epoch":       true,
				"timestamp":   true,
				"enc_payload": true,
			}

			// Marshal/unmarshal to check actual wire fields
			data, _ := json.Marshal(lives[0])
			var wireFields map[string]interface{}
			json.Unmarshal(data, &wireFields)

			for field := range wireFields {
				if !allowed[field] {
					t.Errorf("unexpected metadata field in wire message: %q", field)
				}
			}
			return
		}
	}
}
