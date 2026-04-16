// provision simulates the dashboard/browser creating a new agent.
//
// It performs the browser-side of the provisioning flow:
//  1. Generate a random DEK for the agent
//  2. Generate a random provisioning secret
//  3. Derive provision_key via HKDF
//  4. Wrap DEK with provision_key
//  5. Generate an agent token
//  6. Register everything with the mock API
//  7. Print the install command the user would copy
//
// Usage:
//
//	go run ./cmd/provision --api http://localhost:9800 --agent-name my-server
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/watchblind/agent/internal/crypto"
)

func main() {
	apiURL := flag.String("api", "http://localhost:9800", "mock API URL")
	agentName := flag.String("agent-name", "dev-server-01", "display name for the agent")
	flag.Parse()

	fmt.Println("blind.watch provisioning simulator")
	fmt.Println("  Simulates: dashboard creating a new agent")
	fmt.Printf("  API: %s\n\n", *apiURL)

	// Step 1: Generate random DEK (32 bytes)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		log.Fatalf("generating DEK: %v", err)
	}
	fmt.Printf("[browser] Generated DEK: %s...\n", hex.EncodeToString(dek)[:16])

	// Step 2: Generate provisioning secret (32 bytes)
	provSecretBytes := make([]byte, 32)
	if _, err := rand.Read(provSecretBytes); err != nil {
		log.Fatalf("generating provisioning secret: %v", err)
	}
	provisioningSecret := "prov_" + base64.RawURLEncoding.EncodeToString(provSecretBytes)
	fmt.Printf("[browser] Generated provisioning secret: %s...\n", provisioningSecret[:20])

	// Step 3: Generate agent token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Fatalf("generating token: %v", err)
	}
	agentToken := "bw_" + base64.RawURLEncoding.EncodeToString(tokenBytes)
	fmt.Printf("[browser] Generated agent token: %s...\n", agentToken[:20])

	// Step 4: Generate agent ID
	agentIDBytes := make([]byte, 8)
	rand.Read(agentIDBytes)
	agentID := "agt_" + hex.EncodeToString(agentIDBytes)
	orgID := "org_dev"
	fmt.Printf("[browser] Agent ID: %s\n", agentID)

	// Step 5: Derive provision_key from provisioning_secret via HKDF
	provisionKey, err := crypto.DeriveKey([]byte(provisioningSecret), agentID, "provision-key")
	if err != nil {
		log.Fatalf("deriving provision key: %v", err)
	}
	fmt.Printf("[browser] Derived provision_key via HKDF(secret, agent_id, \"provision-key\")\n")

	// Step 6: Wrap DEK with provision_key
	wrappedDEK, err := crypto.WrapKey(dek, provisionKey)
	if err != nil {
		log.Fatalf("wrapping DEK: %v", err)
	}
	fmt.Printf("[browser] Wrapped DEK: %s...\n", wrappedDEK[:20])

	// Step 7: Register with mock API
	tokenHash := sha256Hex(agentToken)
	provSecretHash := sha256Hex(provisioningSecret)

	reqBody := map[string]interface{}{
		"agent_id":                 agentID,
		"org_id":                   orgID,
		"name":                     *agentName,
		"token":                    agentToken,
		"token_hash":               tokenHash,
		"provisioning_secret_hash": provSecretHash,
		"wrapped_dek_provision":    wrappedDEK,
		"epoch":                    1,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(*apiURL+"/v1/agents", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("registering agent: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errMsg json.RawMessage
		json.NewDecoder(resp.Body).Decode(&errMsg)
		log.Fatalf("registration failed (%d): %s", resp.StatusCode, errMsg)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("\n[server] Agent registered successfully\n")
	fmt.Printf("[server] Response: %v\n", result)

	// Step 8: Print install command
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("INSTALL COMMAND (copy and run on target server):")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\nexport BW_TOKEN=%s\n", agentToken)
	fmt.Printf("export BW_SECRET=%s\n", provisioningSecret)
	fmt.Printf("export BW_API_URL=%s\n", *apiURL)
	fmt.Printf("export BW_AGENT_ID=%s\n", agentID)
	fmt.Println("blindwatch-agent --first-boot")
	fmt.Println()

	// Step 9: Also write a provisioning file for easy testing
	provFile := map[string]string{
		"agent_id":            agentID,
		"org_id":              orgID,
		"token":               agentToken,
		"provisioning_secret": provisioningSecret,
		"api_url":             *apiURL,
	}
	provJSON, _ := json.MarshalIndent(provFile, "", "  ")
	provPath := filepath.Join(os.TempDir(), fmt.Sprintf("blindwatch-provision-%s.json", agentID))
	if err := os.WriteFile(provPath, provJSON, 0600); err != nil {
		log.Printf("warning: could not write provision file: %v", err)
	} else {
		fmt.Printf("Provision file written to: %s\n", provPath)
		fmt.Printf("  Use: go run ./cmd/agent --first-boot --provision-file %s\n", provPath)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
