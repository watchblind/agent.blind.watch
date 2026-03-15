// Package provision handles the agent's first-boot provisioning and
// subsequent-boot DEK recovery. It implements the client side of the
// provisioning protocol defined in provisioning-protocol.md.
package provision

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watchblind/agent/internal/crypto"
)

// httpClient is used for all provisioning and DEK HTTP calls.
// It enforces a 30-second timeout and TLS 1.2 minimum.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

// requireHTTPS returns an error if the API URL uses plaintext HTTP.
// Only http://localhost and http://127.0.0.1 are permitted (for development).
func requireHTTPS(apiURL string) error {
	if strings.HasPrefix(apiURL, "https://") {
		return nil
	}
	if strings.HasPrefix(apiURL, "http://localhost") ||
		strings.HasPrefix(apiURL, "http://127.0.0.1") ||
		strings.HasPrefix(apiURL, "http://[::1]") {
		return nil
	}
	if strings.HasPrefix(apiURL, "http://") {
		return fmt.Errorf("plaintext HTTP is not allowed for remote hosts (use https://): %s", apiURL)
	}
	return nil
}

// State holds the persistent agent state written to disk after provisioning.
// This replaces the TOML config file — the agent derives everything it needs
// from this state + the server's config push over WebSocket.
type State struct {
	AgentID     string `json:"agent_id"`
	OrgID       string `json:"org_id"`
	Token       string `json:"token"`
	APIURL      string `json:"api_url"`
	AgentSecret string `json:"agent_secret"` // base64-encoded 32-byte HKDF output
	Epoch       int    `json:"epoch"`
}

// ProvisionInput holds the values needed for first-boot provisioning,
// typically from environment variables or a provision file.
type ProvisionInput struct {
	Token              string
	ProvisioningSecret string
	APIURL             string
	AgentID            string // optional — fetched from /v1/agent/whoami if empty
}

// LoadInputFromEnv reads provisioning input from environment variables.
func LoadInputFromEnv() (*ProvisionInput, error) {
	token := os.Getenv("BW_TOKEN")
	secret := os.Getenv("BW_SECRET")
	apiURL := os.Getenv("BW_API_URL")
	agentID := os.Getenv("BW_AGENT_ID")

	if token == "" || secret == "" || apiURL == "" {
		return nil, fmt.Errorf("BW_TOKEN, BW_SECRET, and BW_API_URL must be set")
	}

	return &ProvisionInput{
		Token:              token,
		ProvisioningSecret: secret,
		APIURL:             apiURL,
		AgentID:            agentID,
	}, nil
}

// LoadInputFromFile reads provisioning input from a JSON file
// (written by cmd/provision for testing).
func LoadInputFromFile(path string) (*ProvisionInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading provision file: %w", err)
	}

	var f struct {
		AgentID            string `json:"agent_id"`
		OrgID              string `json:"org_id"`
		Token              string `json:"token"`
		ProvisioningSecret string `json:"provisioning_secret"`
		APIURL             string `json:"api_url"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing provision file: %w", err)
	}

	return &ProvisionInput{
		Token:              f.Token,
		ProvisioningSecret: f.ProvisioningSecret,
		APIURL:             f.APIURL,
		AgentID:            f.AgentID,
	}, nil
}

// FirstBoot performs the full first-boot provisioning flow:
//  1. Fetch agent identity (whoami)
//  2. Generate X25519 keypair
//  3. Derive agent_secret from provisioning secret
//  4. Fetch wrapped DEK from server
//  5. Unwrap DEK using provisioning secret
//  6. Re-wrap DEK with agent_secret
//  7. Upload re-wrapped DEK + public key
//  8. Save state + private key to dataDir
//  9. Return the raw DEK for immediate use
func FirstBoot(input *ProvisionInput, dataDir string) (dek []byte, state *State, err error) {
	if err := requireHTTPS(input.APIURL); err != nil {
		return nil, nil, err
	}

	// Step 1: Resolve agent identity
	agentID := input.AgentID
	orgID := ""
	if agentID == "" {
		agentID, orgID, err = whoami(input.APIURL, input.Token)
		if err != nil {
			return nil, nil, fmt.Errorf("whoami: %w", err)
		}
	}

	fmt.Printf("[provision] agent_id: %s\n", agentID)

	// Step 2: Generate X25519 keypair
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("generating keypair: %w", err)
	}
	fmt.Println("[provision] generated X25519 keypair")

	// Step 3: Derive agent_secret from provisioning_secret
	agentSecret, err := crypto.DeriveKey(
		[]byte(input.ProvisioningSecret), agentID, "agent-secret",
	)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving agent_secret: %w", err)
	}

	// Step 4: Call POST /v1/agent/provision → get wrapped_dek_provision
	wrappedDEKProv, epoch, err := fetchProvisionDEK(
		input.APIURL, input.Token,
		base64.StdEncoding.EncodeToString(agentSecret),
		base64.StdEncoding.EncodeToString(kp.Public[:]),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching provision DEK: %w", err)
	}
	fmt.Printf("[provision] received wrapped DEK (epoch=%d)\n", epoch)

	// Step 5: Derive provision_key and unwrap DEK
	provisionKey, err := crypto.DeriveKey(
		[]byte(input.ProvisioningSecret), agentID, "provision-key",
	)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving provision_key: %w", err)
	}

	dek, err = crypto.UnwrapKey(wrappedDEKProv, provisionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrapping DEK: %w", err)
	}
	fmt.Println("[provision] unwrapped DEK successfully")

	// Step 6: Derive agent_key and re-wrap DEK
	agentKey, err := crypto.DeriveKey(agentSecret, agentID, "agent-key")
	if err != nil {
		return nil, nil, fmt.Errorf("deriving agent_key: %w", err)
	}

	wrappedDEKAgent, err := crypto.WrapKey(dek, agentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("re-wrapping DEK: %w", err)
	}

	// Step 7: Upload re-wrapped DEK
	err = uploadDEK(
		input.APIURL, input.Token,
		wrappedDEKAgent,
		base64.StdEncoding.EncodeToString(kp.Public[:]),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("uploading DEK: %w", err)
	}
	fmt.Println("[provision] uploaded re-wrapped DEK to server")

	// Step 8: Save state to disk
	state = &State{
		AgentID:     agentID,
		OrgID:       orgID,
		Token:       input.Token,
		APIURL:      input.APIURL,
		AgentSecret: base64.StdEncoding.EncodeToString(agentSecret),
		Epoch:       epoch,
	}

	if err := saveState(dataDir, state, kp.Private[:]); err != nil {
		return nil, nil, fmt.Errorf("saving state: %w", err)
	}
	fmt.Printf("[provision] state saved to %s\n", dataDir)

	// Provisioning secret is NOT saved — it's gone after this function returns
	return dek, state, nil
}

// SubsequentBoot loads saved state and recovers the DEK from the server.
func SubsequentBoot(dataDir string) (dek []byte, state *State, err error) {
	// Load saved state (need api_url to check HTTPS before any network call)
	state, err = LoadState(dataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("loading state: %w", err)
	}

	if err := requireHTTPS(state.APIURL); err != nil {
		return nil, nil, err
	}

	// Decode agent_secret
	agentSecret, err := base64.StdEncoding.DecodeString(state.AgentSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding agent_secret: %w", err)
	}

	// Derive agent_key
	agentKey, err := crypto.DeriveKey(agentSecret, state.AgentID, "agent-key")
	if err != nil {
		return nil, nil, fmt.Errorf("deriving agent_key: %w", err)
	}

	// Fetch wrapped DEK from server
	wrappedDEK, epoch, err := FetchAgentDEK(state.APIURL, state.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching agent DEK: %w", err)
	}

	// Unwrap DEK
	dek, err = crypto.UnwrapKey(wrappedDEK, agentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrapping DEK: %w", err)
	}

	state.Epoch = epoch
	return dek, state, nil
}

// IsProvisioned checks if the agent has already been provisioned
// by looking for the state file in dataDir.
func IsProvisioned(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, "state.json"))
	return err == nil
}

// --- HTTP helpers ---

func whoami(apiURL, token string) (agentID, orgID string, err error) {
	req, _ := http.NewRequest("GET", apiURL+"/v1/agent/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("whoami returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AgentID string `json:"agent_id"`
		OrgID   string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}
	return result.AgentID, result.OrgID, nil
}

func fetchProvisionDEK(apiURL, token, agentSecret, agentPubKey string) (wrappedDEK string, epoch int, err error) {
	body, _ := json.Marshal(map[string]string{
		"agent_secret":    agentSecret,
		"agent_public_key": agentPubKey,
	})

	req, _ := http.NewRequest("POST", apiURL+"/v1/agent/provision", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("provision returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		WrappedDEKProvision string `json:"wrapped_dek_provision"`
		Epoch               int    `json:"epoch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	return result.WrappedDEKProvision, result.Epoch, nil
}

func uploadDEK(apiURL, token, wrappedDEKAgent, agentPubKey string) error {
	body, _ := json.Marshal(map[string]string{
		"wrapped_dek_agent": wrappedDEKAgent,
		"agent_public_key":  agentPubKey,
	})

	req, _ := http.NewRequest("PUT", apiURL+"/v1/agent/dek", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload DEK returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func FetchAgentDEK(apiURL, token string) (wrappedDEK string, epoch int, err error) {
	if err := requireHTTPS(apiURL); err != nil {
		return "", 0, err
	}

	req, _ := http.NewRequest("GET", apiURL+"/v1/keys/agent-dek", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("fetch DEK returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		WrappedDEK string `json:"wrapped_dek"`
		Epoch      int    `json:"epoch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	return result.WrappedDEK, result.Epoch, nil
}

// --- Disk persistence ---

func saveState(dataDir string, state *State, privateKey []byte) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	// Write state file
	stateJSON, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	statePath := filepath.Join(dataDir, "state.json")
	if err := os.WriteFile(statePath, stateJSON, 0600); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}

	// Write private key separately (tighter permissions)
	keyPath := filepath.Join(dataDir, "agent-key")
	if err := os.WriteFile(keyPath, privateKey, 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	return nil
}

func LoadState(dataDir string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return nil, err
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}
