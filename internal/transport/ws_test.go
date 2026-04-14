package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/gorilla/websocket"
)

// testServer is a minimal WebSocket server for testing the Connection.
type testServer struct {
	mu       sync.Mutex
	conns    []*websocket.Conn
	received []json.RawMessage
	upgrader websocket.Upgrader
	pace     protocol.PaceConfig
	autoAck  bool
}

func newTestServer(pace protocol.PaceConfig) *testServer {
	return &testServer{
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		pace:     pace,
		autoAck:  true,
	}
}

func (ts *testServer) handler(w http.ResponseWriter, r *http.Request) {
	// Validate auth
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := ts.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	ts.mu.Lock()
	ts.conns = append(ts.conns, conn)
	ts.mu.Unlock()

	// Send connected message
	data, _ := json.Marshal(protocol.ConnectedMessage{
		Type: "connected",
		Pace: ts.pace,
	})
	conn.WriteMessage(websocket.TextMessage, data)

	// Read loop
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		ts.mu.Lock()
		ts.received = append(ts.received, json.RawMessage(msg))
		ts.mu.Unlock()

		// Auto-ack batches and flushes
		if ts.autoAck {
			var env protocol.Envelope
			if json.Unmarshal(msg, &env) == nil {
				switch env.Type {
				case "batch", "flush":
					var batch struct {
						BatchID string `json:"batch_id"`
					}
					if json.Unmarshal(msg, &batch) == nil {
						ack, _ := json.Marshal(protocol.AckMessage{
							Type:    "ack",
							BatchID: batch.BatchID,
						})
						conn.WriteMessage(websocket.TextMessage, ack)
					}
				}
			}
		}
	}
}

func (ts *testServer) getReceived() []json.RawMessage {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]json.RawMessage, len(ts.received))
	copy(out, ts.received)
	return out
}

func (ts *testServer) sendToAll(msg interface{}) {
	data, _ := json.Marshal(msg)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, c := range ts.conns {
		c.WriteMessage(websocket.TextMessage, data)
	}
}

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestConnectionConnects(t *testing.T) {
	ts := newTestServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connected := make(chan protocol.PaceConfig, 1)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connected <- pace
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go conn.Run(ctx)

	select {
	case pace := <-connected:
		if pace.IntervalMS != 0 || pace.CollectMS != 10000 {
			t.Errorf("unexpected pace: %+v", pace)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for connection")
	}

	if !conn.IsConnected() {
		t.Error("expected IsConnected() to be true")
	}
}

func TestConnectionSendAndReceiveAck(t *testing.T) {
	ts := newTestServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connected := make(chan struct{}, 1)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connected <- struct{}{}
	})

	acked := make(chan string, 1)
	conn.OnAck(func(batchID string) {
		acked <- batchID
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)

	<-connected

	// Send a batch message
	msg := protocol.BatchMessage{
		Type:    "batch",
		BatchID: "test_batch_001",
		Epoch:   1,
		Entries: []protocol.BatchEntry{{
			Epoch:      1,
			Timestamp:  time.Now().Unix(),
			EncPayload: "encrypted_data_here",
		}},
	}

	if err := conn.Send(msg); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case batchID := <-acked:
		if batchID != "test_batch_001" {
			t.Errorf("expected batch ID test_batch_001, got %s", batchID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ack")
	}
}

func TestConnectionPaceCallback(t *testing.T) {
	ts := newTestServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connected := make(chan struct{}, 1)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connected <- struct{}{}
	})

	paced := make(chan [2]int, 1)
	conn.OnPace(func(intervalMS, collectMS int) {
		paced <- [2]int{intervalMS, collectMS}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)

	<-connected

	// Server pushes pace change
	ts.sendToAll(protocol.PaceMessage{
		Type:       "pace",
		IntervalMS: 1000,
		CollectMS:  1000,
	})

	select {
	case p := <-paced:
		if p[0] != 1000 || p[1] != 1000 {
			t.Errorf("unexpected pace: interval=%d collect=%d", p[0], p[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for pace callback")
	}
}

func TestConnectionReconnects(t *testing.T) {
	connectCount := 0
	var mu sync.Mutex

	ts := newTestServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connectCount++
		count := connectCount
		mu.Unlock()

		if count == 1 {
			// First connection: accept then immediately close
			conn, err := ts.upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			data, _ := json.Marshal(protocol.ConnectedMessage{
				Type: "connected",
				Pace: protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000},
			})
			conn.WriteMessage(websocket.TextMessage, data)
			time.Sleep(100 * time.Millisecond)
			conn.Close()
			return
		}
		// Second connection: normal
		ts.handler(w, r)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connectEvents := make(chan struct{}, 5)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connectEvents <- struct{}{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)

	// Should get at least 2 connect events (initial + reconnect)
	for i := 0; i < 2; i++ {
		select {
		case <-connectEvents:
		case <-time.After(4 * time.Second):
			t.Fatalf("timeout waiting for connect event %d", i+1)
		}
	}
}

func TestConnectionSendBufferFull(t *testing.T) {
	// Don't start a server — connection won't be established
	conn := NewConnection("ws://localhost:0/nope", "token", "agt_test", "test")

	// Fill the send buffer (256 capacity)
	for i := 0; i < 256; i++ {
		conn.sendCh <- sendItem{data: []byte("test"), category: "other"}
	}

	// Next send should return error (buffer full)
	err := conn.Send(map[string]string{"type": "test"})
	if err == nil {
		t.Error("expected error when send buffer is full")
	}
}

func TestConnectionLiveMessages(t *testing.T) {
	ts := newTestServer(protocol.PaceConfig{IntervalMS: 1000, CollectMS: 1000})
	server := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connected := make(chan struct{}, 1)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connected <- struct{}{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)
	<-connected

	// Send multiple live messages
	for i := 0; i < 3; i++ {
		msg := protocol.LiveMessage{
			Type:       "live",
				Epoch:      1,
			Timestamp:  time.Now().Unix(),
			EncPayload: "enc_live_data",
		}
		if err := conn.Send(msg); err != nil {
			t.Fatalf("Send live %d failed: %v", i, err)
		}
	}

	// Wait for messages to arrive
	time.Sleep(500 * time.Millisecond)

	received := ts.getReceived()
	liveCount := 0
	for _, raw := range received {
		var env protocol.Envelope
		if json.Unmarshal(raw, &env) == nil && env.Type == "live" {
			liveCount++
		}
	}

	if liveCount != 3 {
		t.Errorf("expected 3 live messages, got %d", liveCount)
	}
}

func TestConnection_DetectsHalfOpen(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.WriteJSON(map[string]any{"type": "connected", "pace": map[string]int{"interval_ms": 0, "collect_ms": 10000}})
		select {} // accept but never pong/read
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn := NewConnection(wsURL, "tok", "ag", "test")
	conn.SetPingInterval(200 * time.Millisecond)
	conn.SetReadDeadline(600 * time.Millisecond)

	connectedCh := make(chan struct{}, 1)
	conn.OnConnected(func(protocol.PaceConfig) {
		select {
		case connectedCh <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go conn.Run(ctx)

	select {
	case <-connectedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("never connected")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !conn.IsConnected() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected disconnect detection within 2s, IsConnected still true")
}

func TestConnection_NotConnectedUntilConnectedMessage(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := upgrader.Upgrade(w, r, nil)
		defer c.Close()
		time.Sleep(2 * time.Second) // accept WS, never send connected
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
	for i := 0; i < 5; i++ {
		conn.sendCh <- sendItem{data: []byte("x"), category: "batch"}
	}
	conn.drainSendCh()
	if got := len(conn.sendCh); got != 0 {
		t.Errorf("sendCh len after drain = %d, want 0", got)
	}
}

func TestConnectionPayloadOpacity(t *testing.T) {
	// Verify that the server only sees encrypted payloads, never plaintext
	ts := newTestServer(protocol.PaceConfig{IntervalMS: 0, CollectMS: 10000})
	server := httptest.NewServer(http.HandlerFunc(ts.handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/agent/stream"
	conn := NewConnection(wsURL, "test-token", "agt_test", "test")

	connected := make(chan struct{}, 1)
	conn.OnConnected(func(pace protocol.PaceConfig) {
		connected <- struct{}{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go conn.Run(ctx)
	<-connected

	// Send a batch with an "encrypted" payload
	msg := protocol.BatchMessage{
		Type:    "batch",
		BatchID: "opacity_test",
		Epoch:   1,
		Entries: []protocol.BatchEntry{{
			Epoch:      1,
			Timestamp:  time.Now().Unix(),
			EncPayload: "base64_encrypted_blob_that_server_cannot_read",
		}},
	}
	conn.Send(msg)

	time.Sleep(500 * time.Millisecond)

	received := ts.getReceived()
	for _, raw := range received {
		var env protocol.Envelope
		if json.Unmarshal(raw, &env) != nil || env.Type != "batch" {
			continue
		}

		var batch protocol.BatchMessage
		if json.Unmarshal(raw, &batch) != nil {
			t.Fatal("failed to unmarshal batch")
		}

		// Server sees entries with enc_payload but can't derive metrics from it
		if len(batch.Entries) == 0 || batch.Entries[0].EncPayload != "base64_encrypted_blob_that_server_cannot_read" {
			t.Error("payload was modified in transit")
		}

		// Verify only expected fields are present (no plaintext metrics)
		var rawMap map[string]interface{}
		json.Unmarshal(raw, &rawMap)
		for key := range rawMap {
			switch key {
			case "type", "batch_id", "agent_id", "epoch", "entries":
				// Expected metadata fields
			default:
				t.Errorf("unexpected field in batch message: %s (potential metadata leak)", key)
			}
		}
	}
}
