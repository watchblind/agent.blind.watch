package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Encryptor handles AES-256-GCM encryption with deterministic nonces per spec.
type Encryptor struct {
	aead       cipher.AEAD
	dek        []byte // retained so we can zero it on shutdown
	clientHash [4]byte
	agentID    string
	nonce      *NonceManager
}

// NonceManager handles persistent nonce state to prevent nonce reuse across restarts.
type NonceManager struct {
	mu            sync.Mutex
	counter       uint32
	lastTimestamp uint32
	persistPath   string // empty = in-memory only (tests)
}

// nonceState is the on-disk format for nonce persistence.
type nonceState struct {
	Counter       uint32 `json:"counter"`
	LastTimestamp uint32 `json:"last_timestamp"`
}

// newNonceManager creates a nonce manager. If persistPath is empty, nonces are
// in-memory only (suitable for tests). Otherwise state is loaded from disk.
func newNonceManager(persistPath string) (*NonceManager, error) {
	nm := &NonceManager{persistPath: persistPath}

	if persistPath == "" {
		return nm, nil
	}

	data, err := os.ReadFile(persistPath)
	if os.IsNotExist(err) {
		return nm, nil
	} else if err != nil {
		return nil, fmt.Errorf("reading nonce state: %w", err)
	}

	var state nonceState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing nonce state: %w", err)
	}

	nm.counter = state.Counter
	nm.lastTimestamp = state.LastTimestamp
	return nm, nil
}

// next returns the next nonce counter value. If persistence is configured,
// the state is written to disk BEFORE returning (crash-safe).
func (nm *NonceManager) next() (uint32, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	now := uint32(time.Now().Unix())

	if now != nm.lastTimestamp {
		nm.counter = 0
		nm.lastTimestamp = now
	}

	nm.counter++

	if nm.persistPath != "" {
		if err := nm.persist(); err != nil {
			return 0, fmt.Errorf("persisting nonce state: %w", err)
		}
	}

	return nm.counter, nil
}

func (nm *NonceManager) persist() error {
	state := nonceState{
		Counter:      nm.counter,
		LastTimestamp: nm.lastTimestamp,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	tmpPath := nm.persistPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	f, err := os.Open(tmpPath)
	if err == nil {
		f.Sync()
		f.Close()
	}

	return os.Rename(tmpPath, nm.persistPath)
}

// NewEncryptor creates an encryptor with a random DEK and in-memory nonces.
// For tests only — production code should use NewEncryptorWithConfig.
func NewEncryptor() (*Encryptor, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}
	return NewEncryptorWithKey(dek)
}

// NewEncryptorWithKey creates an encryptor with the given DEK and in-memory nonces.
// client_hash defaults to a random value. For tests or legacy use.
func NewEncryptorWithKey(dek []byte) (*Encryptor, error) {
	aead, err := makeAEAD(dek)
	if err != nil {
		return nil, err
	}

	var clientHash [4]byte
	rand.Read(clientHash[:])

	nm, _ := newNonceManager("")

	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &Encryptor{
		aead:       aead,
		dek:        dekCopy,
		clientHash: clientHash,
		agentID:    "",
		nonce:      nm,
	}, nil
}

// NewEncryptorWithConfig creates a production encryptor with:
//   - client_hash derived from agentID (SHA-256(agent_id)[0:4])
//   - AAD = agent_id||timestamp on every encrypt/decrypt
//   - persistent nonce counter in dataDir/nonce_state.json
func NewEncryptorWithConfig(dek []byte, agentID string, dataDir string) (*Encryptor, error) {
	aead, err := makeAEAD(dek)
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256([]byte(agentID))
	var clientHash [4]byte
	copy(clientHash[:], h[:4])

	persistPath := filepath.Join(dataDir, "nonce_state.json")
	nm, err := newNonceManager(persistPath)
	if err != nil {
		return nil, fmt.Errorf("initializing nonce manager: %w", err)
	}

	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &Encryptor{
		aead:       aead,
		dek:        dekCopy,
		clientHash: clientHash,
		agentID:    agentID,
		nonce:      nm,
	}, nil
}

func makeAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	return aead, nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Nonce format: client_hash(4) || timestamp(4) || counter(4)
// AAD: agent_id||timestamp (binds ciphertext to agent and time)
// Wire format: base64(nonce || ciphertext || auth_tag)
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	nonce, err := e.makeNonce()
	if err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	aad := e.buildAAD(nonce)
	ciphertext := e.aead.Seal(nil, nonce, plaintext, aad)

	wire := make([]byte, len(nonce)+len(ciphertext))
	copy(wire, nonce)
	copy(wire[len(nonce):], ciphertext)

	return base64.StdEncoding.EncodeToString(wire), nil
}

// Decrypt decrypts a wire-format payload.
// AAD is reconstructed from the agentID + timestamp embedded in the nonce.
func (e *Encryptor) Decrypt(encoded string) ([]byte, error) {
	wire, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	nonceSize := e.aead.NonceSize()
	if len(wire) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := wire[:nonceSize]
	ciphertext := wire[nonceSize:]

	aad := e.buildAAD(nonce)
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// NonceSize returns the nonce size used by the AEAD.
func (e *Encryptor) NonceSize() int {
	return e.aead.NonceSize()
}

// ZeroDEK overwrites the Encryptor's internal DEK buffer with zeros.
// Must be called on graceful shutdown and on SIGTERM/SIGINT per spec.
func (e *Encryptor) ZeroDEK() {
	for i := range e.dek {
		e.dek[i] = 0
	}
}

// buildAAD constructs associated data from agentID and the timestamp in the nonce.
// Format: "agentID||timestamp". This binds ciphertext to both the agent identity
// and time — tampering with either causes decryption to fail.
func (e *Encryptor) buildAAD(nonce []byte) []byte {
	timestamp := binary.BigEndian.Uint32(nonce[4:8])
	return []byte(fmt.Sprintf("%s||%d", e.agentID, timestamp))
}

func (e *Encryptor) makeNonce() ([]byte, error) {
	counter, err := e.nonce.next()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	copy(nonce[0:4], e.clientHash[:])
	binary.BigEndian.PutUint32(nonce[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(nonce[8:12], counter)
	return nonce, nil
}
