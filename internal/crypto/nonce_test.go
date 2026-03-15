package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClientHashDerivedFromAgentID(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	dir := t.TempDir()
	enc, err := NewEncryptorWithConfig(dek, "agt_test_123", dir)
	if err != nil {
		t.Fatalf("NewEncryptorWithConfig: %v", err)
	}

	// client_hash should be SHA-256("agt_test_123")[0:4]
	expected := sha256.Sum256([]byte("agt_test_123"))
	if enc.clientHash != [4]byte(expected[:4]) {
		t.Fatalf("client_hash mismatch: got %x, want %x", enc.clientHash, expected[:4])
	}
}

func TestDifferentAgentIDsDifferentClientHash(t *testing.T) {
	dek := make([]byte, 32)

	dir := t.TempDir()
	enc1, _ := NewEncryptorWithConfig(dek, "agt_aaa", filepath.Join(dir, "a"))
	enc2, _ := NewEncryptorWithConfig(dek, "agt_bbb", filepath.Join(dir, "b"))

	if enc1.clientHash == enc2.clientHash {
		t.Fatal("different agent IDs should produce different client hashes")
	}
}

func TestNonceCounterPersistence(t *testing.T) {
	dir := t.TempDir()
	dek := make([]byte, 32)

	// First encryptor — encrypt a few times
	enc1, err := NewEncryptorWithConfig(dek, "agt_persist", dir)
	if err != nil {
		t.Fatalf("NewEncryptorWithConfig: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := enc1.Encrypt([]byte("data")); err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
	}

	// Read persisted state
	stateFile := filepath.Join(dir, "nonce_state.json")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("nonce_state.json should exist: %v", err)
	}

	var state nonceState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("parse nonce state: %v", err)
	}

	if state.Counter < 5 {
		t.Fatalf("expected counter >= 5 after 5 encryptions, got %d", state.Counter)
	}

	// Second encryptor — should resume from persisted counter
	enc2, err := NewEncryptorWithConfig(dek, "agt_persist", dir)
	if err != nil {
		t.Fatalf("NewEncryptorWithConfig (reload): %v", err)
	}

	// Encrypt once more
	if _, err := enc2.Encrypt([]byte("data")); err != nil {
		t.Fatalf("Encrypt after reload: %v", err)
	}

	// Counter should be higher than before
	data2, _ := os.ReadFile(stateFile)
	var state2 nonceState
	json.Unmarshal(data2, &state2)

	if state2.Counter <= state.Counter {
		t.Fatalf("counter should increase after reload: was %d, now %d", state.Counter, state2.Counter)
	}
}

func TestNonceUniquenessAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	dek := make([]byte, 32)

	// Collect nonces from first "session"
	enc1, _ := NewEncryptorWithConfig(dek, "agt_restart", dir)
	nonces1 := collectNonces(t, enc1, 3)

	// Simulate restart — new encryptor with same dir
	enc2, _ := NewEncryptorWithConfig(dek, "agt_restart", dir)
	nonces2 := collectNonces(t, enc2, 3)

	// No nonce from session 2 should match session 1
	// (counter bytes at positions 8-11 should differ)
	for _, n1 := range nonces1 {
		for _, n2 := range nonces2 {
			c1 := binary.BigEndian.Uint32(n1[8:12])
			c2 := binary.BigEndian.Uint32(n2[8:12])
			if c1 == c2 {
				t.Fatalf("nonce counter collision across restart: both have counter=%d", c1)
			}
		}
	}
}

func TestNonceStateFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dek := make([]byte, 32)

	enc, _ := NewEncryptorWithConfig(dek, "agt_perms", dir)
	enc.Encrypt([]byte("trigger persist"))

	stateFile := filepath.Join(dir, "nonce_state.json")
	info, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("stat nonce_state.json: %v", err)
	}

	perms := info.Mode().Perm()
	if perms != 0600 {
		t.Fatalf("nonce_state.json has permissions %o, want 0600", perms)
	}
}

func TestNonceManagerInMemoryForTests(t *testing.T) {
	// NewEncryptor (no config) should work without any disk persistence
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	// Should encrypt fine without any data dir
	ct, err := enc.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "test" {
		t.Fatalf("roundtrip failed: got %q", pt)
	}
}

func collectNonces(t *testing.T, enc *Encryptor, count int) [][]byte {
	t.Helper()
	var nonces [][]byte
	for i := 0; i < count; i++ {
		n, err := enc.makeNonce()
		if err != nil {
			t.Fatalf("makeNonce: %v", err)
		}
		nonces = append(nonces, n)
	}
	return nonces
}
