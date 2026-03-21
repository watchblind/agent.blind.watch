package protocol

// --- Agent → Server ---
// Note: agent_id is NOT included in agent→server messages.
// The server knows the agent's identity from the authenticated WebSocket
// connection (token → agent_id mapping). This prevents agent_id spoofing.

type BatchMessage struct {
	Type       string `json:"type"` // "batch"
	BatchID    string `json:"batch_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload,omitempty"` // legacy single-blob (unused, kept for compat)
	Entries    []BatchEntry `json:"entries,omitempty"`    // per-snapshot encrypted entries
}

// BatchEntry is a single encrypted snapshot within a batch.
type BatchEntry struct {
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

type LiveMessage struct {
	Type       string `json:"type"` // "live"
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

type WALSyncMessage struct {
	Type    string         `json:"type"` // "wal_sync"
	Entries []WALSyncEntry `json:"entries"`
}

type WALSyncEntry struct {
	BatchID    string `json:"batch_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

type FlushMessage struct {
	Type       string       `json:"type"` // "flush"
	BatchID    string       `json:"batch_id"`
	Epoch      int          `json:"epoch"`
	Timestamp  int64        `json:"timestamp"`
	EncPayload string       `json:"enc_payload,omitempty"` // legacy single-blob (unused)
	Entries    []BatchEntry `json:"entries,omitempty"`      // per-snapshot encrypted entries
}

type LiveProcMessage struct {
	Type       string `json:"type"` // "live_proc"
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

type BatchProcMessage struct {
	Type       string `json:"type"` // "batch_proc"
	BatchID    string `json:"batch_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload,omitempty"` // legacy single-blob (unused)
	Entries    []BatchEntry `json:"entries,omitempty"`    // per-snapshot encrypted entries
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

// Envelope is used for initial JSON parsing to determine message type.
type Envelope struct {
	Type string `json:"type"`
}
