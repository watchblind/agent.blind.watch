package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Private and public should be 32 bytes and different
	if kp.Private == [32]byte{} {
		t.Fatal("private key is zero")
	}
	if kp.Public == [32]byte{} {
		t.Fatal("public key is zero")
	}
	if kp.Private == kp.Public {
		t.Fatal("private and public keys should differ")
	}
}

func TestGenerateKeypairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeypair()
	kp2, _ := GenerateKeypair()

	if kp1.Private == kp2.Private {
		t.Fatal("two keypairs should have different private keys")
	}
	if kp1.Public == kp2.Public {
		t.Fatal("two keypairs should have different public keys")
	}
}

func TestLoadKeypair(t *testing.T) {
	kp1, _ := GenerateKeypair()

	kp2, err := LoadKeypair(kp1.Private[:])
	if err != nil {
		t.Fatalf("LoadKeypair: %v", err)
	}

	if kp1.Public != kp2.Public {
		t.Fatal("loading same private key should produce same public key")
	}
}

func TestLoadKeypairBadLength(t *testing.T) {
	_, err := LoadKeypair([]byte("too short"))
	if err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestDeriveKey(t *testing.T) {
	secret := []byte("test-provisioning-secret")

	key1, err := DeriveKey(secret, "agent-id-1", "provision-key")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	// Same inputs → same output (deterministic)
	key2, _ := DeriveKey(secret, "agent-id-1", "provision-key")
	if !bytes.Equal(key1, key2) {
		t.Fatal("same inputs should produce same key")
	}

	// Different salt → different key
	key3, _ := DeriveKey(secret, "agent-id-2", "provision-key")
	if bytes.Equal(key1, key3) {
		t.Fatal("different salts should produce different keys")
	}

	// Different info → different key
	key4, _ := DeriveKey(secret, "agent-id-1", "agent-secret")
	if bytes.Equal(key1, key4) {
		t.Fatal("different info strings should produce different keys")
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	// Generate a DEK
	dek := make([]byte, 32)
	rand.Read(dek)

	// Generate a wrapping key
	wrappingKey := make([]byte, 32)
	rand.Read(wrappingKey)

	// Wrap
	wrapped, err := WrapKey(dek, wrappingKey)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	// Unwrap
	unwrapped, err := UnwrapKey(wrapped, wrappingKey)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Fatal("unwrapped key should match original DEK")
	}
}

func TestWrapUnwrapWrongKey(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	wrappingKey := make([]byte, 32)
	rand.Read(wrappingKey)

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	wrapped, _ := WrapKey(dek, wrappingKey)

	_, err := UnwrapKey(wrapped, wrongKey)
	if err == nil {
		t.Fatal("unwrap with wrong key should fail")
	}
}

func TestProvisioningFlowRoundtrip(t *testing.T) {
	// Simulate the full provisioning flow per spec:
	//
	// Browser:
	//   1. Generate DEK
	//   2. Generate provisioning_secret
	//   3. Derive provision_key = HKDF(prov_secret, agent_id, "provision-key")
	//   4. Wrap DEK with provision_key
	//
	// Agent first boot:
	//   5. Derive provision_key from same provisioning_secret
	//   6. Unwrap DEK
	//   7. Derive agent_secret = HKDF(prov_secret, agent_id, "agent-secret")
	//   8. Derive agent_key = HKDF(agent_secret, agent_id, "agent-key")
	//   9. Re-wrap DEK with agent_key
	//
	// Agent subsequent boot:
	//   10. Derive agent_key from stored agent_secret
	//   11. Unwrap DEK from stored wrapped_dek_agent

	agentID := "agt_test_provisioning"

	// --- Browser side ---
	originalDEK := make([]byte, 32)
	rand.Read(originalDEK)

	provSecret := make([]byte, 32)
	rand.Read(provSecret)

	provisionKey, _ := DeriveKey(provSecret, agentID, "provision-key")
	wrappedDEKProvision, _ := WrapKey(originalDEK, provisionKey)

	// --- Agent first boot ---
	// Agent has provSecret from install command
	agentProvisionKey, _ := DeriveKey(provSecret, agentID, "provision-key")

	// Agent unwraps DEK
	unwrappedDEK, err := UnwrapKey(wrappedDEKProvision, agentProvisionKey)
	if err != nil {
		t.Fatalf("agent failed to unwrap DEK: %v", err)
	}
	if !bytes.Equal(originalDEK, unwrappedDEK) {
		t.Fatal("agent's unwrapped DEK doesn't match browser's original")
	}

	// Agent derives agent_secret (stored to disk)
	agentSecret, _ := DeriveKey(provSecret, agentID, "agent-secret")

	// Agent derives agent_key from agent_secret
	agentKey, _ := DeriveKey(agentSecret, agentID, "agent-key")

	// Agent re-wraps DEK with agent_key
	wrappedDEKAgent, _ := WrapKey(unwrappedDEK, agentKey)

	// --- Agent subsequent boot ---
	// Agent reads agent_secret from disk, derives agent_key
	agentKey2, _ := DeriveKey(agentSecret, agentID, "agent-key")

	// Agent unwraps DEK
	finalDEK, err := UnwrapKey(wrappedDEKAgent, agentKey2)
	if err != nil {
		t.Fatalf("subsequent boot failed to unwrap DEK: %v", err)
	}
	if !bytes.Equal(originalDEK, finalDEK) {
		t.Fatal("subsequent boot DEK doesn't match original")
	}

	// Verify: agent can encrypt/decrypt with the recovered DEK
	enc, err := NewEncryptorWithKey(finalDEK)
	if err != nil {
		t.Fatalf("creating encryptor with recovered DEK: %v", err)
	}

	plaintext := []byte(`{"cpu_percent": 42.5, "memory_used": 8589934592}`)
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt with recovered DEK: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt with recovered DEK: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("roundtrip with recovered DEK failed")
	}
}

func TestForwardSecrecy(t *testing.T) {
	// Verify: agent_secret cannot be used to recover provisioning_secret
	// (HKDF is one-way — this is a property test, not a proof)

	provSecret := make([]byte, 32)
	rand.Read(provSecret)

	agentSecret, _ := DeriveKey(provSecret, "agt_test", "agent-secret")
	provisionKey, _ := DeriveKey(provSecret, "agt_test", "provision-key")

	// agent_secret and provision_key should be completely different
	if bytes.Equal(agentSecret, provisionKey) {
		t.Fatal("agent_secret and provision_key should be different")
	}

	// Neither should equal the original secret
	if bytes.Equal(agentSecret, provSecret) {
		t.Fatal("agent_secret should differ from provisioning_secret")
	}
	if bytes.Equal(provisionKey, provSecret) {
		t.Fatal("provision_key should differ from provisioning_secret")
	}
}
