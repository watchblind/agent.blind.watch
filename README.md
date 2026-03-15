# blind.watch agent

End-to-end encrypted monitoring agent. Collects system metrics, encrypts them client-side with AES-256-GCM, and transmits only ciphertext to the server. The server never sees plaintext data.

## How it works

The agent collects CPU, memory, disk, network, GPU, and process metrics at configurable intervals. Every payload is encrypted with a per-agent Data Encryption Key (DEK) before leaving the machine. The server stores opaque blobs it cannot decrypt — only authorized users with access to the wrapped DEK can read the data in the browser.

```
Agent                          Server                      Browser
  |                              |                            |
  | AES-256-GCM(metrics, DEK)    |                            |
  |----------------------------->|  stores encrypted blob     |
  |                              |                            |
  |                              |  wrapped_dek (per-user)    |
  |                              |--------------------------->|
  |                              |                            | unwraps DEK
  |                              |                            | decrypts metrics
```

## Quickstart

### First boot (provisioned)

```bash
export BW_TOKEN=bw_...
export BW_SECRET=prov_...
export BW_API_URL=https://api.blind.watch
blindwatch-agent --first-boot
```

The provisioning secret is used once to derive encryption keys, then discarded. Subsequent boots recover the DEK from the server automatically:

```bash
blindwatch-agent
```

### Install script

```bash
curl -fsSL https://install.blind.watch/agent.sh | sh -s -- \
  --token bw_... \
  --secret prov_... \
  --api https://api.blind.watch
```

This installs the binary, provisions the agent, and creates a systemd service.

## Security model

| Property | Mechanism |
|---|---|
| Payload encryption | AES-256-GCM, 256-bit DEK |
| Key derivation | HKDF-SHA256 with domain separation |
| Nonce scheme | `client_hash(4) \|\| timestamp(4) \|\| counter(4)`, persisted to disk |
| AAD binding | `agent_id\|\|timestamp` prevents cross-agent replay |
| Key wrapping | AES-256-GCM with derived wrapping keys |
| Provisioning | Single-use secret, two-stage HKDF derivation |
| TLS | Enforced for remote hosts, TLS 1.2 minimum |
| Memory | DEK zeroed after init, core dumps disabled, 50 MB limit |

### What the server sees

| Visible (metadata) | Invisible (encrypted) |
|---|---|
| Agent ID, timestamps, epoch | CPU, memory, disk, network, GPU metrics |
| Batch IDs | Process list (PID, name, cmdline, user) |
| Connection status | Alert rule definitions and notifications |
| | Config (alert rules pushed E2E encrypted) |

## Architecture

```
cmd/
  agent/          CLI entry point
  mockapi/        Local development server
  provision/      Simulates browser-side agent creation

internal/
  crypto/         AES-256-GCM encryption, HKDF, X25519, nonce management
  provision/      First-boot and subsequent-boot key recovery
  transport/      WebSocket client with reconnection and rate limiting
  scheduler/      Metric batching, live/idle mode, WAL integration
  collector/      CPU, memory, disk, network, GPU, process collectors
  alert/          Threshold evaluation with firing/recovery state machine
  wal/            Write-ahead log for guaranteed delivery
  protocol/       Wire format definitions
  config/         TOML config parsing and validation
  dashboard/      Terminal UI (optional)
```

## Building

```bash
go build -o blindwatch-agent ./cmd/agent
```

## Testing

```bash
go test ./...
```

## Local development

Start the mock API server:

```bash
go run ./cmd/mockapi
```

Create a test agent:

```bash
go run ./cmd/provision --api http://localhost:9800
```

Run the agent with the output credentials:

```bash
export BW_TOKEN=bw_...
export BW_SECRET=prov_...
export BW_API_URL=http://localhost:9800
export BW_AGENT_ID=agt_...
go run ./cmd/agent --first-boot --data-dir /tmp/bw-test
```

## Releases

Binaries are built with [GoReleaser](https://goreleaser.com/) on tagged releases via GitHub Actions. Supported platforms: Linux (amd64, arm64), Windows (amd64, arm64).

## License

AGPL-3.0
