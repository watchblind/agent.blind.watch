package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := []byte("hello, world")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestRoundtripPayloads(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x42}},
		{"short text", []byte("hi")},
		{"json-like", []byte(`{"action":"heartbeat","ts":1234567890}`)},
		{"binary with nulls", []byte{0, 1, 2, 0, 255, 254, 0}},
		{"large 64KB", make([]byte, 64*1024)},
	}

	// Fill the large payload with non-trivial data.
	for i := range cases[len(cases)-1].data {
		cases[len(cases)-1].data[i] = byte(i % 251)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := enc.Encrypt(tc.data)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			got, err := enc.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if len(got) != len(tc.data) {
				t.Fatalf("length mismatch: got %d, want %d", len(got), len(tc.data))
			}
			for i := range tc.data {
				if got[i] != tc.data[i] {
					t.Fatalf("byte mismatch at index %d: got 0x%02x, want 0x%02x", i, got[i], tc.data[i])
				}
			}
		})
	}
}

func TestNonceUniqueness(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := []byte("same input every time")
	seen := make(map[string]bool)

	const iterations = 100
	for i := 0; i < iterations; i++ {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt iteration %d: %v", i, err)
		}

		if seen[ct] {
			t.Fatalf("duplicate ciphertext at iteration %d", i)
		}
		seen[ct] = true
	}
}

func TestTamperedCiphertext(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	ct, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wire, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// Flip a byte in the ciphertext portion (after the 12-byte nonce).
	wire[len(wire)-1] ^= 0xFF

	tampered := base64.StdEncoding.EncodeToString(wire)
	_, err = enc.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestTamperedNonce(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	ct, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wire, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// Flip a byte in the nonce portion.
	wire[0] ^= 0xFF

	tampered := base64.StdEncoding.EncodeToString(wire)
	_, err = enc.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected decryption to fail on tampered nonce")
	}
}

func TestBase64WireFormat(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	ct, err := enc.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Must be valid standard base64.
	wire, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("output is not valid base64: %v", err)
	}

	// Wire = nonce(12) + ciphertext(len(plaintext)) + GCM tag(16).
	nonceSize := enc.NonceSize()
	expectedMin := nonceSize + 16 // at minimum: nonce + tag (empty plaintext)
	if len(wire) < expectedMin {
		t.Fatalf("wire too short: got %d bytes, want at least %d", len(wire), expectedMin)
	}

	// For "test" (4 bytes), wire should be exactly nonce + 4 + 16.
	expectedLen := nonceSize + 4 + 16
	if len(wire) != expectedLen {
		t.Fatalf("wire length: got %d, want %d", len(wire), expectedLen)
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	_, err = enc.Decrypt("not!valid!base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecryptTooShort(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	// Encode fewer bytes than the nonce size.
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	_, err = enc.Decrypt(short)
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than nonce")
	}
}

func TestDifferentKeysCannotDecrypt(t *testing.T) {
	enc1, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor 1: %v", err)
	}

	enc2, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor 2: %v", err)
	}

	ct, err := enc1.Encrypt([]byte("for enc1 only"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = enc2.Decrypt(ct)
	if err == nil {
		t.Fatal("expected decryption to fail with a different key")
	}
}

func TestNewEncryptorWithKeyBadLength(t *testing.T) {
	_, err := NewEncryptorWithKey([]byte("too-short"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestNewEncryptorWithKeyRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	enc1, err := NewEncryptorWithKey(key)
	if err != nil {
		t.Fatalf("NewEncryptorWithKey 1: %v", err)
	}

	enc2, err := NewEncryptorWithKey(key)
	if err != nil {
		t.Fatalf("NewEncryptorWithKey 2: %v", err)
	}

	ct, err := enc1.Encrypt([]byte("shared key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := enc2.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt with same key: %v", err)
	}

	if string(got) != "shared key" {
		t.Errorf("got %q, want %q", got, "shared key")
	}
}

func TestEncryptDoesNotLeakPlaintext(t *testing.T) {
	enc, err := NewEncryptor()
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	secret := "do-not-leak-this-string"
	ct, err := enc.Encrypt([]byte(secret))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The base64-encoded ciphertext should not contain the plaintext.
	if strings.Contains(ct, secret) {
		t.Fatal("ciphertext contains plaintext")
	}

	// Nor should the raw wire bytes.
	wire, _ := base64.StdEncoding.DecodeString(ct)
	if strings.Contains(string(wire), secret) {
		t.Fatal("raw wire contains plaintext")
	}
}
