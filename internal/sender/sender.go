package sender

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/crypto"
)

type SendLog struct {
	Timestamp   time.Time `json:"timestamp"`
	PayloadSize int       `json:"payload_size"`
	Endpoint    string    `json:"endpoint"`
	Encrypted   string    `json:"encrypted_preview"` // first 64 chars
}

type MockSender struct {
	encryptor *crypto.Encryptor
	endpoint  string
	mu        sync.RWMutex
	logs      []SendLog
}

func NewMockSender(enc *crypto.Encryptor, endpoint string) *MockSender {
	return &MockSender{
		encryptor: enc,
		endpoint:  endpoint,
	}
}

func (s *MockSender) Send(snap collector.Snapshot) error {
	payload, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}

	encrypted, err := s.encryptor.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	preview := encrypted
	if len(preview) > 64 {
		preview = preview[:64] + "..."
	}

	log := SendLog{
		Timestamp:   time.Now(),
		PayloadSize: len(encrypted),
		Endpoint:    s.endpoint,
		Encrypted:   preview,
	}

	s.mu.Lock()
	s.logs = append(s.logs, log)
	// Keep last 100 logs
	if len(s.logs) > 100 {
		s.logs = s.logs[len(s.logs)-100:]
	}
	s.mu.Unlock()

	return nil
}

func (s *MockSender) RecentLogs(n int) []SendLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.logs) {
		n = len(s.logs)
	}
	result := make([]SendLog, n)
	copy(result, s.logs[len(s.logs)-n:])
	return result
}
