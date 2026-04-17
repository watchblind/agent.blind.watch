package protocol

// --- Agent → Server ---
// Note: agent_id is NOT included in agent→server messages.
// The server knows the agent's identity from the authenticated WebSocket
// connection (token → agent_id mapping). This prevents agent_id spoofing.

// BatchMessage sends a 10-minute batch of individually-encrypted snapshots.
// ONE message per batch window, ONE batch_id, ONE ack for the whole batch.
type BatchMessage struct {
	Type    string       `json:"type"` // "batch"
	BatchID string       `json:"batch_id"`
	Epoch   int          `json:"epoch"`
	Entries []BatchEntry `json:"entries"`
}

// BatchEntry is a single encrypted snapshot within a batch.
type BatchEntry struct {
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

// ReplayMessage is sent on live mode activation with retained last batch
// (if within 90s) plus the current in-progress batch buffer.
type ReplayMessage struct {
	Type    string       `json:"type"` // "replay"
	Epoch   int          `json:"epoch"`
	Entries []BatchEntry `json:"entries"`
}

// LiveMessage sends a single encrypted snapshot (metrics + processes) each second.
type LiveMessage struct {
	Type       string `json:"type"` // "live"
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

// FlushMessage is sent on graceful shutdown with any buffered snapshots.
// Same entries-array format as BatchMessage.
type FlushMessage struct {
	Type    string       `json:"type"` // "flush"
	BatchID string       `json:"batch_id"`
	Epoch   int          `json:"epoch"`
	Entries []BatchEntry `json:"entries"`
}

// WALSyncMessage re-sends a full batch from WAL on startup.
// Each WAL file stores one complete batch that can be resent as-is.
type WALSyncMessage struct {
	Type    string       `json:"type"` // "wal_sync"
	BatchID string       `json:"batch_id"`
	Entries []BatchEntry `json:"entries"`
}

type AlertMessage struct {
	Type            string `json:"type"` // "alert"
	Epoch           int    `json:"epoch"`
	TriggeredAt     int64  `json:"triggered_at"`
	Recovered       bool   `json:"recovered"`
	EncNotification string `json:"enc_notification"`
}

// --- Server → Agent ---

type PaceConfig struct {
	IntervalMS int `json:"interval_ms"` // 0 = default batch mode
	CollectMS  int `json:"collect_ms"`  // collection interval in ms
}

type ConnectedMessage struct {
	Type string     `json:"type"` // "connected"
	Pace PaceConfig `json:"pace"`
}

type AckMessage struct {
	Type    string `json:"type"` // "ack"
	BatchID string `json:"batch_id"`
}

type PaceMessage struct {
	Type       string `json:"type"` // "pace"
	IntervalMS int    `json:"interval_ms"`
	CollectMS  int    `json:"collect_ms"`
}

type ConfigMessage struct {
	Type      string `json:"type"` // "config"
	EncConfig string `json:"enc_config"`
}

type DEKRotatedMessage struct {
	Type     string `json:"type"` // "dek_rotated"
	NewEpoch int    `json:"new_epoch"`
}

type DisconnectMessage struct {
	Type   string `json:"type"` // "disconnect"
	Reason string `json:"reason"`
}

type ErrorMessage struct {
	Type       string `json:"type"` // "error"
	Code       string `json:"code"`
	Category   string `json:"category,omitempty"`   // rate-limit category: "live", "batch", "wal", "other"
	RetryAfter int    `json:"retry_after,omitempty"`
}

// --- Log messages ---

type LogBatchEntry struct {
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

type LogBatchMessage struct {
	Type    string          `json:"type"` // "log_batch"
	BatchID string          `json:"batch_id"`
	Epoch   int             `json:"epoch"`
	Entries []LogBatchEntry `json:"entries"`
}

type LiveLogMessage struct {
	Type       string `json:"type"` // "live_log"
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

// --- Update messages ---

// UpdateAvailableMessage is sent by the server to trigger an agent self-update.
type UpdateAvailableMessage struct {
	Type    string `json:"type"`    // "update_available"
	Version string `json:"version"` // target version e.g. "0.3.0"
}

// VersionReportMessage is sent by the agent on connect with its encrypted version.
type VersionReportMessage struct {
	Type       string `json:"type"`        // "version_report"
	Epoch      int    `json:"epoch"`
	EncPayload string `json:"enc_payload"` // encrypted JSON: {"version":"0.3.0"}
}

// UpdateStatusMessage reports update progress from agent to server.
type UpdateStatusMessage struct {
	Type   string  `json:"type"`             // "update_status"
	Status string  `json:"status"`           // "downloading" | "staged" | "failed"
	Error  *string `json:"error,omitempty"`
}

// --- Re-provisioning ---

// ProvisionRevokedMessage is sent by the server when the agent's credentials
// have been invalidated (re-provisioned or deleted from the dashboard).
// On receipt the agent should shut down gracefully — any reconnect will fail
// auth since the token has already been deleted.
// See docs/components/agent-lifecycle.md §8.4 in the blind.watch repo.
type ProvisionRevokedMessage struct {
	Type   string `json:"type"`   // "provision_revoked"
	Reason string `json:"reason"` // "reprovisioned" | "deleted"
}

// Envelope is used for initial JSON parsing to determine message type.
type Envelope struct {
	Type string `json:"type"`
}

// PathsPreviewRequest is the server -> agent request carrying a directory path
// to enumerate. Plaintext; the path itself is not a secret.
type PathsPreviewRequest struct {
	Type      string `json:"type"`       // always "paths_preview_request"
	RequestID string `json:"request_id"`
	Path      string `json:"path"`
}

// PathsPreviewResponse is the agent -> server reply with the encrypted Listing.
type PathsPreviewResponse struct {
	Type       string `json:"type"`        // always "paths_preview_response"
	RequestID  string `json:"request_id"`
	Epoch      int    `json:"epoch"`
	EncListing string `json:"enc_listing"` // base64 AES-GCM of pathbrowser.Listing JSON
}
