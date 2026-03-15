package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/watchblind/agent/internal/protocol"
	"github.com/gorilla/websocket"
)

// MockAPI simulates the Auth Gateway Worker + OrgDO for local development.
// It validates tokens, accepts agent WebSocket connections, sends acks,
// and can simulate live mode (pace changes) and config pushes.

type AgentMeta struct {
	OrgID   string   `json:"org_id"`
	AgentID string   `json:"agent_id"`
	Scopes  []string `json:"scopes"`
	Tier    string   `json:"tier"`
}

type StoredBatch struct {
	AgentID    string `json:"agent_id"`
	BatchID    string `json:"batch_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"` // opaque encrypted blob — server cannot read
	ReceivedAt int64  `json:"received_at"`
	Type       string `json:"type"` // batch, live, flush, wal_sync
}

// ProvisionedAgent stores provisioning data for an agent.
type ProvisionedAgent struct {
	AgentID              string `json:"agent_id"`
	OrgID                string `json:"org_id"`
	Name                 string `json:"name"`
	TokenHash            string `json:"token_hash"`
	ProvSecretHash       string `json:"provisioning_secret_hash"`
	WrappedDEKProvision  string `json:"wrapped_dek_provision"`
	WrappedDEKAgent      string `json:"wrapped_dek_agent"`
	AgentPublicKey       string `json:"agent_public_key"`
	Epoch                int    `json:"epoch"`
	ProvisioningConsumed bool   `json:"provisioning_consumed"`
}

type Server struct {
	tokens map[string]AgentMeta // token_hash → agent meta

	mu                sync.RWMutex
	agents            map[string]*websocket.Conn    // agent_id → ws
	viewers           map[string]*websocket.Conn    // viewer_id → ws
	batches           []StoredBatch
	provisionedAgents map[string]*ProvisionedAgent  // agent_id → provisioning data
	liveMode          bool
	messageLog        []string // for debugging

	upgrader websocket.Upgrader
}

func NewServer() *Server {
	// Pre-configure a test token
	token := "bw_test_token_for_local_development_0123456789abcdef0123456789abcdef"
	tokenHash := sha256Sum(token)

	return &Server{
		tokens: map[string]AgentMeta{
			tokenHash: {
				OrgID:   "org_dev",
				AgentID: "agt_dev_local",
				Scopes:  []string{"agent:stream", "metrics:write", "logs:write"},
				Tier:    "pro",
			},
		},
		agents:            make(map[string]*websocket.Conn),
		viewers:           make(map[string]*websocket.Conn),
		provisionedAgents: make(map[string]*ProvisionedAgent),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *Server) handleAgentStream(w http.ResponseWriter, r *http.Request) {
	// Auth Gateway: validate token
	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token = token[len("Bearer "):]
	tokenHash := sha256Sum(token)

	meta, ok := s.tokens[tokenHash]
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[mockapi] upgrade error: %v", err)
		return
	}

	s.mu.Lock()
	s.agents[meta.AgentID] = conn
	hasViewers := len(s.viewers) > 0
	s.mu.Unlock()

	log.Printf("[mockapi] agent connected: %s (org=%s)", meta.AgentID, meta.OrgID)

	// Send connected message with pace
	pace := protocol.PaceConfig{
		IntervalMS: 0,
		CollectMS:  10000,
	}
	if hasViewers || s.liveMode {
		pace.IntervalMS = 1000
		pace.CollectMS = 1000
	}
	sendJSON(conn, protocol.ConnectedMessage{
		Type: "connected",
		Pace: pace,
	})

	// Read loop
	s.agentReadLoop(conn, meta)

	// Cleanup on disconnect
	s.mu.Lock()
	delete(s.agents, meta.AgentID)
	s.mu.Unlock()
	log.Printf("[mockapi] agent disconnected: %s", meta.AgentID)
}

func (s *Server) agentReadLoop(conn *websocket.Conn, meta AgentMeta) {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var env protocol.Envelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}

		s.logMessage(fmt.Sprintf("[%s] recv %s from %s", time.Now().Format("15:04:05"), env.Type, meta.AgentID))

		switch env.Type {
		case "batch":
			var msg protocol.BatchMessage
			if json.Unmarshal(data, &msg) == nil {
				s.handleBatch(conn, meta, msg)
			}

		case "live":
			var msg protocol.LiveMessage
			if json.Unmarshal(data, &msg) == nil {
				s.handleLive(meta, msg)
			}

		case "flush":
			var msg protocol.FlushMessage
			if json.Unmarshal(data, &msg) == nil {
				s.handleFlush(conn, meta, msg)
			}

		case "wal_sync":
			var msg protocol.WALSyncMessage
			if json.Unmarshal(data, &msg) == nil {
				s.handleWALSync(conn, meta, msg)
			}

		case "alert":
			var msg protocol.AlertMessage
			if json.Unmarshal(data, &msg) == nil {
				s.handleAlert(meta, msg)
			}
		}
	}
}

func (s *Server) handleBatch(conn *websocket.Conn, meta AgentMeta, msg protocol.BatchMessage) {
	// agent_id comes from the authenticated connection, NOT the message.
	// This prevents agent_id spoofing — the server tags it.
	agentID := meta.AgentID

	// Store the encrypted blob — we CANNOT read the content (E2E)
	s.mu.Lock()
	s.batches = append(s.batches, StoredBatch{
		AgentID:    agentID,
		BatchID:    msg.BatchID,
		Epoch:      msg.Epoch,
		Timestamp:  msg.Timestamp,
		EncPayload: msg.EncPayload,
		ReceivedAt: time.Now().Unix(),
		Type:       "batch",
	})
	batchCount := len(s.batches)
	s.mu.Unlock()

	log.Printf("[mockapi] stored batch %s (epoch=%d, payload=%d bytes, total_batches=%d)",
		msg.BatchID, msg.Epoch, len(msg.EncPayload), batchCount)

	// Broadcast to viewers if any (encrypted — viewers decrypt client-side)
	s.broadcastToViewers(agentID, msg.Epoch, msg.Timestamp, msg.EncPayload)

	// Ack — agent will delete from WAL
	sendJSON(conn, protocol.AckMessage{
		Type:    "ack",
		BatchID: msg.BatchID,
	})
}

func (s *Server) handleLive(meta AgentMeta, msg protocol.LiveMessage) {
	agentID := meta.AgentID

	s.mu.Lock()
	s.batches = append(s.batches, StoredBatch{
		AgentID:    agentID,
		BatchID:    fmt.Sprintf("live_%d_%s", msg.Timestamp, agentID),
		Epoch:      msg.Epoch,
		Timestamp:  msg.Timestamp,
		EncPayload: msg.EncPayload,
		ReceivedAt: time.Now().Unix(),
		Type:       "live",
	})
	s.mu.Unlock()

	s.broadcastToViewers(agentID, msg.Epoch, msg.Timestamp, msg.EncPayload)
}

func (s *Server) handleFlush(conn *websocket.Conn, meta AgentMeta, msg protocol.FlushMessage) {
	s.mu.Lock()
	s.batches = append(s.batches, StoredBatch{
		AgentID:    meta.AgentID,
		BatchID:    msg.BatchID,
		Epoch:      msg.Epoch,
		Timestamp:  msg.Timestamp,
		EncPayload: msg.EncPayload,
		ReceivedAt: time.Now().Unix(),
		Type:       "flush",
	})
	s.mu.Unlock()

	log.Printf("[mockapi] stored flush %s", msg.BatchID)

	sendJSON(conn, protocol.AckMessage{
		Type:    "ack",
		BatchID: msg.BatchID,
	})
}

func (s *Server) handleWALSync(conn *websocket.Conn, meta AgentMeta, msg protocol.WALSyncMessage) {
	log.Printf("[mockapi] WAL sync: %d entries from %s", len(msg.Entries), meta.AgentID)

	for _, entry := range msg.Entries {
		s.mu.Lock()
		s.batches = append(s.batches, StoredBatch{
			AgentID:    meta.AgentID,
			BatchID:    entry.BatchID,
			Epoch:      entry.Epoch,
			Timestamp:  entry.Timestamp,
			EncPayload: entry.EncPayload,
			ReceivedAt: time.Now().Unix(),
			Type:       "wal_sync",
		})
		s.mu.Unlock()

		// Ack each entry so agent cleans up its WAL
		sendJSON(conn, protocol.AckMessage{
			Type:    "ack",
			BatchID: entry.BatchID,
		})
	}
}

func (s *Server) handleAlert(meta AgentMeta, msg protocol.AlertMessage) {
	status := "FIRING"
	if msg.Recovered {
		status = "RECOVERED"
	}
	log.Printf("[mockapi] alert from %s: %s (encrypted notification: %d bytes)",
		meta.AgentID, status, len(msg.EncNotification))
}

// broadcastToViewers sends encrypted data to all connected dashboard viewers.
func (s *Server) broadcastToViewers(agentID string, epoch int, timestamp int64, encPayload string) {
	s.mu.RLock()
	viewers := make(map[string]*websocket.Conn)
	for k, v := range s.viewers {
		viewers[k] = v
	}
	s.mu.RUnlock()

	if len(viewers) == 0 {
		return
	}

	msg := map[string]interface{}{
		"type":        "metric",
		"agent_id":    agentID,
		"epoch":       epoch,
		"timestamp":   timestamp,
		"enc_payload": encPayload,
	}

	for _, ws := range viewers {
		sendJSON(ws, msg)
	}
}

// --- Control endpoints (for testing) ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]string, 0, len(s.agents))
	for id := range s.agents {
		agents = append(agents, id)
	}

	status := map[string]interface{}{
		"connected_agents": agents,
		"viewer_count":     len(s.viewers),
		"batches_stored":   len(s.batches),
		"live_mode":        s.liveMode,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleBatches(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.batches)
}

func (s *Server) handleSetLive(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.liveMode = true
	agents := make(map[string]*websocket.Conn)
	for k, v := range s.agents {
		agents[k] = v
	}
	s.mu.Unlock()

	// Tell all agents to go live
	pace := protocol.PaceMessage{
		Type:       "pace",
		IntervalMS: 1000,
		CollectMS:  1000,
	}
	for _, conn := range agents {
		sendJSON(conn, pace)
	}

	log.Printf("[mockapi] live mode activated for %d agents", len(agents))
	w.Write([]byte(`{"status":"live mode activated"}`))
}

func (s *Server) handleSetIdle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.liveMode = false
	agents := make(map[string]*websocket.Conn)
	for k, v := range s.agents {
		agents[k] = v
	}
	s.mu.Unlock()

	pace := protocol.PaceMessage{
		Type:       "pace",
		IntervalMS: 0,
		CollectMS:  10000,
	}
	for _, conn := range agents {
		sendJSON(conn, pace)
	}

	log.Printf("[mockapi] idle mode activated for %d agents", len(agents))
	w.Write([]byte(`{"status":"idle mode activated"}`))
}

func (s *Server) handlePushConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EncConfig string `json:"enc_config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if body.EncConfig == "" {
		http.Error(w, "enc_config is required (config must be E2E encrypted by the browser)", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	agents := make(map[string]*websocket.Conn)
	for k, v := range s.agents {
		agents[k] = v
	}
	s.mu.RUnlock()

	msg := protocol.ConfigMessage{
		Type:      "config",
		EncConfig: body.EncConfig,
	}
	for _, conn := range agents {
		sendJSON(conn, msg)
	}

	log.Printf("[mockapi] pushed encrypted config to %d agents", len(agents))
	w.Write([]byte(`{"status":"encrypted config pushed"}`))
}

func (s *Server) handleMessageLog(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.messageLog)
}

func (s *Server) logMessage(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messageLog = append(s.messageLog, msg)
	if len(s.messageLog) > 1000 {
		s.messageLog = s.messageLog[len(s.messageLog)-1000:]
	}
}

// --- Provisioning endpoints ---

// handleCreateAgent simulates the dashboard registering a new agent.
// Called by cmd/provision to set up agent credentials and wrapped DEK.
func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID            string `json:"agent_id"`
		OrgID              string `json:"org_id"`
		Name               string `json:"name"`
		Token              string `json:"token"`
		TokenHash          string `json:"token_hash"`
		ProvSecretHash     string `json:"provisioning_secret_hash"`
		WrappedDEKProvision string `json:"wrapped_dek_provision"`
		Epoch              int    `json:"epoch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	// Register the token so the agent can authenticate
	s.tokens[req.TokenHash] = AgentMeta{
		OrgID:   req.OrgID,
		AgentID: req.AgentID,
		Scopes:  []string{"agent:stream", "metrics:write", "logs:write"},
		Tier:    "pro",
	}

	// Store provisioning data
	s.provisionedAgents[req.AgentID] = &ProvisionedAgent{
		AgentID:             req.AgentID,
		OrgID:               req.OrgID,
		Name:                req.Name,
		TokenHash:           req.TokenHash,
		ProvSecretHash:      req.ProvSecretHash,
		WrappedDEKProvision: req.WrappedDEKProvision,
		Epoch:               req.Epoch,
	}
	s.mu.Unlock()

	log.Printf("[mockapi] agent created: %s (org=%s, name=%s)", req.AgentID, req.OrgID, req.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": req.AgentID,
		"status":   "created",
	})
}

// handleProvision handles the agent's first-boot provisioning call.
// Agent sends agent_secret + public key, server returns wrapped DEK.
func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth via bearer token
	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token = token[len("Bearer "):]
	tokenHash := sha256Sum(token)

	meta, ok := s.tokens[tokenHash]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		AgentSecret    string `json:"agent_secret"`
		AgentPublicKey string `json:"agent_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	prov, exists := s.provisionedAgents[meta.AgentID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	if prov.ProvisioningConsumed {
		s.mu.Unlock()
		http.Error(w, "provisioning already consumed", http.StatusForbidden)
		return
	}

	wrappedDEK := prov.WrappedDEKProvision
	epoch := prov.Epoch
	s.mu.Unlock()

	log.Printf("[mockapi] provisioning agent %s (public_key=%s...)", meta.AgentID, req.AgentPublicKey[:20])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"wrapped_dek_provision": wrappedDEK,
		"epoch":                epoch,
	})
}

// handleUploadDEK handles the agent uploading its re-wrapped DEK after provisioning.
func (s *Server) handleUploadDEK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token = token[len("Bearer "):]
	tokenHash := sha256Sum(token)

	meta, ok := s.tokens[tokenHash]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		WrappedDEKAgent string `json:"wrapped_dek_agent"`
		AgentPublicKey  string `json:"agent_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	prov, exists := s.provisionedAgents[meta.AgentID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	prov.WrappedDEKAgent = req.WrappedDEKAgent
	prov.AgentPublicKey = req.AgentPublicKey
	prov.ProvisioningConsumed = true
	s.mu.Unlock()

	log.Printf("[mockapi] agent %s provisioning completed (DEK re-wrapped)", meta.AgentID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "provisioning_complete",
	})
}

// handleGetAgentDEK returns the wrapped DEK for a provisioned agent (subsequent boots).
func (s *Server) handleGetAgentDEK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token = token[len("Bearer "):]
	tokenHash := sha256Sum(token)

	meta, ok := s.tokens[tokenHash]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	prov, exists := s.provisionedAgents[meta.AgentID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	wrappedDEK := prov.WrappedDEKAgent
	if wrappedDEK == "" {
		// Not yet provisioned — return provision DEK
		wrappedDEK = prov.WrappedDEKProvision
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"wrapped_dek": wrappedDEK,
		"epoch":       prov.Epoch,
	})
}

// handleWhoami returns agent identity from token.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token = token[len("Bearer "):]
	tokenHash := sha256Sum(token)

	meta, ok := s.tokens[tokenHash]
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	prov := s.provisionedAgents[meta.AgentID]
	s.mu.RUnlock()

	name := ""
	if prov != nil {
		name = prov.Name
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": meta.AgentID,
		"org_id":   meta.OrgID,
		"name":     name,
	})
}

func sendJSON(conn *websocket.Conn, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	conn.WriteMessage(websocket.TextMessage, data)
}

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func main() {
	addr := flag.String("addr", ":9800", "listen address")
	flag.Parse()

	srv := NewServer()

	// Agent WebSocket endpoint (matches spec: /v1/agent/stream)
	http.HandleFunc("/v1/agent/stream", srv.handleAgentStream)

	// Provisioning endpoints (spec: provisioning-protocol.md)
	http.HandleFunc("/v1/agents", srv.handleCreateAgent)
	http.HandleFunc("/v1/agent/whoami", srv.handleWhoami)
	http.HandleFunc("/v1/agent/provision", srv.handleProvision)
	http.HandleFunc("/v1/agent/dek", srv.handleUploadDEK)
	http.HandleFunc("/v1/keys/agent-dek", srv.handleGetAgentDEK)

	// Control/debug endpoints
	http.HandleFunc("/status", srv.handleStatus)
	http.HandleFunc("/batches", srv.handleBatches)
	http.HandleFunc("/control/live", srv.handleSetLive)
	http.HandleFunc("/control/idle", srv.handleSetIdle)
	http.HandleFunc("/control/config", srv.handlePushConfig)
	http.HandleFunc("/messages", srv.handleMessageLog)

	fmt.Fprintf(os.Stdout, "blind.watch mock API starting on %s\n", *addr)
	fmt.Fprintf(os.Stdout, "  WebSocket:  ws://localhost%s/v1/agent/stream\n", *addr)
	fmt.Fprintf(os.Stdout, "  Provision:  go run ./cmd/provision --api http://localhost%s\n", *addr)
	fmt.Fprintf(os.Stdout, "  Status:     http://localhost%s/status\n", *addr)
	fmt.Fprintf(os.Stdout, "  Batches:    http://localhost%s/batches\n", *addr)
	fmt.Fprintf(os.Stdout, "  Go Live:    curl -X POST http://localhost%s/control/live\n", *addr)
	fmt.Fprintf(os.Stdout, "  Go Idle:    curl -X POST http://localhost%s/control/idle\n", *addr)
	fmt.Fprintf(os.Stdout, "\n  Static token: bw_test_token_for_local_development_0123456789abcdef0123456789abcdef\n")

	log.Fatal(http.ListenAndServe(*addr, nil))
}
