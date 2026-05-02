package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/watchblind/agent/internal/alert"
	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/config"
	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/dashboard"
	"github.com/watchblind/agent/internal/logtail"
	"github.com/watchblind/agent/internal/pathbrowser"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/provision"
	"github.com/watchblind/agent/internal/scheduler"
	"github.com/watchblind/agent/internal/sdnotify"
	"github.com/watchblind/agent/internal/sender"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/updater"
	"github.com/watchblind/agent/internal/wal"
)

// Set by goreleaser via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// runAgent runs the agent until stopCh is closed. It is invoked by the
// platform-specific entry point in entry.go (console mode + signal handling)
// and by the Windows SCM handler in service_windows.go (service mode).
func runAgent(stopCh <-chan struct{}) {
	// --- Memory and security limits ---
	debug.SetMemoryLimit(50 * 1024 * 1024) // 50 MB GOMEMLIMIT per spec
	// Core dump disabling is in security_linux.go (build-tagged)

	// --- Flags ---
	showVersion := flag.Bool("version", false, "print version and exit")
	firstBoot := flag.Bool("first-boot", false, "run first-boot provisioning (requires BW_TOKEN, BW_SECRET, BW_API_URL env vars)")
	provisionFile := flag.String("provision-file", "", "path to provision JSON file (alternative to env vars)")
	dataDir := flag.String("data-dir", "/var/lib/blindwatch", "directory for agent state and keys")
	walDir := flag.String("wal-dir", "", "WAL directory (defaults to <data-dir>/wal)")
	dashboardMode := flag.Bool("dashboard", false, "enable terminal dashboard")

	// Legacy flags for backward compatibility with config file
	configPath := flag.String("config", "", "path to config file (legacy mode, skips provisioning)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("blindwatch-agent %s (commit=%s, built=%s)\n", version, commit, date)
		os.Exit(0)
	}

	if *walDir == "" {
		*walDir = *dataDir + "/wal"
	}

	var (
		dek     []byte
		agentID string
		apiURL  string
		token   string
		epoch   int
		rules   []config.AlertRule
	)

	// --- Boot mode selection ---
	if *configPath != "" {
		// Legacy mode: load from config file (for backward compat / dashboard dev)
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		agentID = cfg.AgentID
		apiURL = cfg.APIURL
		token = cfg.Token
		epoch = 1
		rules = cfg.Alerts.Rules

		// Legacy: random DEK (no provisioning)
		dek = make([]byte, 32)
		rand.Read(dek)
		fmt.Println("  crypto:   AES-256-GCM (random DEK — legacy mode)")

	} else if *firstBoot {
		// First boot: provisioning flow
		var input *provision.ProvisionInput
		var err error

		if *provisionFile != "" {
			input, err = provision.LoadInputFromFile(*provisionFile)
		} else {
			input, err = provision.LoadInputFromEnv()
		}
		if err != nil {
			log.Fatalf("Provisioning input: %v", err)
		}

		fmt.Printf("blind.watch agent %s — first boot provisioning\n", version)

		var state *provision.State
		dek, state, err = provision.FirstBoot(input, *dataDir)
		if err != nil {
			log.Fatalf("First boot failed: %v", err)
		}

		agentID = state.AgentID
		apiURL = state.APIURL
		token = state.Token
		epoch = state.Epoch

		fmt.Println("[provision] first boot complete — provisioning secret discarded")
		fmt.Printf("  agent_id: %s\n", agentID)
		fmt.Printf("  api_url:  %s\n", apiURL)
		fmt.Printf("  epoch:    %d\n", epoch)
		return

	} else if provision.IsProvisioned(*dataDir) {
		// Subsequent boot: recover DEK from server
		fmt.Printf("blind.watch agent %s starting\n", version)

		var state *provision.State
		var err error
		dek, state, err = provision.SubsequentBoot(*dataDir)
		if err != nil {
			log.Fatalf("DEK recovery failed: %v", err)
		}

		agentID = state.AgentID
		apiURL = state.APIURL
		token = state.Token
		epoch = state.Epoch

		fmt.Println("  crypto:   AES-256-GCM (DEK recovered from server)")

	} else {
		fmt.Fprintf(os.Stderr, "Error: agent is not provisioned.\n\n")
		fmt.Fprintf(os.Stderr, "First boot:\n")
		fmt.Fprintf(os.Stderr, "  export BW_TOKEN=bw_...\n")
		fmt.Fprintf(os.Stderr, "  export BW_SECRET=prov_...\n")
		fmt.Fprintf(os.Stderr, "  export BW_API_URL=https://api.blind.watch\n")
		fmt.Fprintf(os.Stderr, "  blindwatch-agent --first-boot\n\n")
		fmt.Fprintf(os.Stderr, "Or with provision file:\n")
		fmt.Fprintf(os.Stderr, "  blindwatch-agent --first-boot --provision-file /path/to/provision.json\n\n")
		fmt.Fprintf(os.Stderr, "Legacy mode (no provisioning):\n")
		fmt.Fprintf(os.Stderr, "  blindwatch-agent --config /path/to/config.toml\n")
		os.Exit(1)
	}

	// --- Common startup ---
	fmt.Printf("  agent_id: %s\n", agentID)
	fmt.Printf("  api_url:  %s\n", apiURL)
	fmt.Printf("  epoch:    %d\n", epoch)

	// Create encryptor with the provisioned DEK.
	// Uses agent_id for client_hash, AAD, and persists nonce counter to dataDir.
	enc, err := crypto.NewEncryptorWithConfig(dek, agentID, *dataDir)
	if err != nil {
		log.Fatalf("Failed to init encryption: %v", err)
	}
	// Zero the DEK slice — only the Encryptor holds it now
	for i := range dek {
		dek[i] = 0
	}

	// Initialize WAL
	w, err := wal.New(*walDir, 500, 1000)
	if err != nil {
		log.Fatalf("Failed to init WAL: %v", err)
	}
	fmt.Printf("  wal_dir:  %s\n", *walDir)

	// Initialize collectors
	orch := collector.NewOrchestrator()
	orch.Register(collector.NewCPUCollector())
	orch.Register(collector.NewMemoryCollector())
	orch.Register(collector.NewDiskCollector())
	orch.Register(collector.NewNetworkCollector())
	orch.Register(collector.NewGPUCollector())
	procCol := collector.NewProcessCollector(50)
	orch.Register(procCol)

	// Initialize alert evaluator
	eval := alert.NewEvaluator(rules)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build WebSocket URL
	wsURL := buildWSURL(apiURL) + "/v1/agent/stream"
	fmt.Printf("  ws_url:   %s\n", wsURL)

	// Initialize WebSocket connection (now includes version header)
	conn := transport.NewConnection(wsURL, token, agentID, version)

	// Initialize scheduler
	sched := scheduler.New(agentID, epoch, enc, orch, conn, w)

	// Initialize log manager
	logMgr, err := logtail.NewManager(agentID, *dataDir, enc, epoch, conn, w)
	if err != nil {
		log.Fatalf("Failed to init log manager: %v", err)
	}

	// Wire log manager into scheduler for live mode control and replay
	sched.SetLogManager(logMgr)

	// Wire callbacks — dash may be nil when --dashboard=false, set after construction
	var dash *dashboard.Dashboard
	conn.OnAck(func(batchID string) {
		sched.AckBatch(batchID)
		if dash != nil {
			dash.NoteAck()
		}
	})

	conn.OnPace(func(intervalMS, collectMS int) {
		sched.SetPace(intervalMS, collectMS)
	})

	// Auto-update poller context — cancelled and recreated on config change
	var autoUpdateCancel context.CancelFunc

	// Forward declaration so OnConfig (which spawns the auto-update poller)
	// and OnUpdateAvailable can both invoke the same flush+trigger flow.
	var runUpdate func(targetVersion string)

	// Config push from server — decrypt E2E encrypted config, then apply
	conn.OnConfig(func(encConfig string) {
		log.Printf("[agent] received encrypted config (%d bytes)", len(encConfig))

		if encConfig == "" {
			log.Printf("[agent] empty enc_config, ignoring")
			return
		}

		// Decrypt using current encryptor (tracks DEK rotations)
		currentEnc, _ := sched.EncryptorAndEpoch()
		plaintext, err := currentEnc.Decrypt(encConfig)
		if err != nil {
			log.Printf("[agent] failed to decrypt config: %v", err)
			return
		}

		var cfg struct {
			Alerts struct {
				Rules []config.AlertRule `json:"rules"`
			} `json:"alerts"`
			Collection struct {
				IntervalSeconds int `json:"interval_seconds"`
			} `json:"collection"`
			LogSources  []logtail.LogSourceConfig `json:"log_sources"`
			AutoUpdate  *bool                     `json:"auto_update,omitempty"`
		}
		if err := json.Unmarshal(plaintext, &cfg); err != nil {
			log.Printf("[agent] failed to parse decrypted config: %v", err)
			return
		}

		if len(cfg.Alerts.Rules) > 0 {
			if err := config.ValidateRules(cfg.Alerts.Rules); err != nil {
				log.Printf("[agent] rejected invalid config: %v", err)
				return
			}
			eval.UpdateRules(cfg.Alerts.Rules)
			log.Printf("[agent] updated %d alert rules from server", len(cfg.Alerts.Rules))
		}

		if cfg.LogSources != nil {
			logMgr.UpdateConfig(cfg.LogSources)
			log.Printf("[agent] updated %d log sources from server", len(cfg.LogSources))
		}

		// Push the user-chosen collection interval through to the scheduler
		// so dashboard "Save & Push" actually re-paces sampling without
		// waiting for a reconnect/connected message. SetPace expects ms;
		// the wire format is seconds. SetPace also re-derives the live
		// interval, so the second arg matches idle.
		if cfg.Collection.IntervalSeconds > 0 {
			ms := cfg.Collection.IntervalSeconds * 1000
			sched.SetPace(ms, ms)
			log.Printf("[agent] collection interval updated: %ds", cfg.Collection.IntervalSeconds)
		}

		// Manage auto-update poller based on config
		if cfg.AutoUpdate != nil {
			// Cancel existing poller if running
			if autoUpdateCancel != nil {
				autoUpdateCancel()
				autoUpdateCancel = nil
			}

			if *cfg.AutoUpdate {
				autoCtx, cancelFn := context.WithCancel(ctx)
				autoUpdateCancel = cancelFn
				go updater.StartAutoUpdatePoller(autoCtx, version, runUpdate)
				log.Printf("[agent] auto-update enabled")
			} else {
				log.Printf("[agent] auto-update disabled")
			}
		}
	})

	conn.OnConnected(func(pace protocol.PaceConfig) {
		log.Printf("[agent] connected to server (pace: interval=%dms collect=%dms)",
			pace.IntervalMS, pace.CollectMS)
		sched.SetPace(pace.IntervalMS, pace.CollectMS)

		// Send encrypted version report so dashboard can display it
		currentEnc, currentEpoch := sched.EncryptorAndEpoch()
		if currentEnc != nil {
			versionJSON, _ := json.Marshal(map[string]string{"version": version})
			encVersion, err := currentEnc.Encrypt(versionJSON)
			if err == nil {
				conn.Send(protocol.VersionReportMessage{
					Type:       "version_report",
					Epoch:      currentEpoch,
					EncPayload: encVersion,
				})
			}
		}
	})

	conn.OnDisconnect(func(reason string) {
		log.Printf("[agent] disconnected by server: %s", reason)
	})

	// runUpdate flushes everything we have buffered locally to the backend
	// before handing off to the upgrade unit (which kills this process). The
	// flush is bounded to a few seconds — a hung backend must not be able to
	// block an update indefinitely. Shared between dashboard-triggered and
	// auto-update paths so both report `syncing` and avoid a 10-minute gap.
	runUpdate = func(targetVersion string) {
		conn.Send(protocol.UpdateStatusMessage{
			Type:   "update_status",
			Status: "syncing",
		})
		sched.FlushNow()
		logMgr.FlushAndWait()
		conn.Drain(3 * time.Second)
		updater.TriggerUpdate(conn, targetVersion)
	}

	conn.OnUpdateAvailable(func(targetVersion string) {
		log.Printf("[agent] update requested: %s -> %s", version, targetVersion)
		go runUpdate(targetVersion)
	})

	// Dashboard-triggered re-provisioning (or deletion) — credentials
	// invalidated. Any reconnect will 401, so exit gracefully; the operator
	// will reinstall with the new one-liner on the replacement host.
	conn.OnProvisionRevoked(func(reason string) {
		log.Printf("[agent] provisioning revoked (%s): shutting down", reason)
		cancel()
	})

	// DEK rotation — server pushes new epoch, agent fetches and swaps
	conn.OnDEKRotated(func(newEpoch int) {
		log.Printf("[agent] DEK rotation event: new epoch %d", newEpoch)

		state, err := provision.LoadState(*dataDir)
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to load state: %v", err)
			return
		}

		agentSecret, err := base64.StdEncoding.DecodeString(state.AgentSecret)
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to decode agent_secret: %v", err)
			return
		}

		agentKey, err := crypto.DeriveKey(agentSecret, state.AgentID, "agent-key")
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to derive agent_key: %v", err)
			return
		}

		wrappedDEK, _, err := provision.FetchAgentDEK(state.APIURL, state.Token)
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to fetch new DEK: %v", err)
			return
		}

		newDEK, err := crypto.UnwrapKey(wrappedDEK, agentKey)
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to unwrap new DEK: %v", err)
			return
		}

		newEnc, err := crypto.NewEncryptorWithConfig(newDEK, state.AgentID, *dataDir)
		if err != nil {
			log.Printf("[agent] DEK rotation: failed to create encryptor: %v", err)
			return
		}

		// Zero the new DEK from local memory
		for i := range newDEK {
			newDEK[i] = 0
		}

		// Zero the old encryptor's DEK before replacing it
		oldEnc, _ := sched.EncryptorAndEpoch()
		oldEnc.ZeroDEK()

		sched.SetEncryptor(newEnc, newEpoch)
		logMgr.SetEncryptor(newEnc, newEpoch)
		log.Printf("[agent] DEK rotation complete: now using epoch %d", newEpoch)
	})

	conn.OnPathsPreview(func(req protocol.PathsPreviewRequest) {
		listing := pathbrowser.ListDir(req.Path)
		plain, _ := json.Marshal(listing)
		enc, epoch := sched.EncryptorAndEpoch()
		if enc == nil {
			log.Printf("[paths] no encryptor, dropping preview response")
			return
		}
		encListing, err := enc.Encrypt(plain)
		if err != nil {
			log.Printf("[paths] encrypt error: %v", err)
			return
		}
		_ = conn.Send(protocol.PathsPreviewResponse{
			Type:       "paths_preview_response",
			RequestID:  req.RequestID,
			Epoch:      epoch,
			EncListing: encListing,
		})
	})

	// Default collection interval (overridden by server pace)
	interval := 10 * time.Second

	// Alert evaluation on each snapshot
	go func() {
		sub := orch.Subscribe()
		for snap := range sub {
			eval.Evaluate(snap)
		}
	}()

	// Alert event forwarding over WebSocket. The notification payload is
	// E2E encrypted with the agent's DEK — only the dashboard can decrypt
	// it. Include enough structured detail (rule name, metric, operator,
	// threshold, observed value, duration, agent hostname) for the
	// dashboard's notification panel + alert history rows to render real
	// names and values without leaking anything to the server.
	go func() {
		hostname, _ := os.Hostname()
		for event := range eval.Events() {
			fmt.Printf("[ALERT] %s: %s\n", event.Type, event.Message)

			notifPayload, _ := json.Marshal(map[string]interface{}{
				"rule_id":          event.RuleID,
				"rule_name":        event.RuleName,
				"metric":           event.Metric,
				"operator":         event.Operator,
				"threshold":        event.Threshold,
				"value":            event.Value,
				"duration_seconds": event.DurationSeconds,
				"agent_hostname":   hostname,
				"triggered_at":     event.Time.Unix(),
				"recovered":        event.Type == "recovered",
				"message":          event.Message,
			})

			// Use current encryptor/epoch from scheduler (tracks DEK rotations)
			currentEnc, currentEpoch := sched.EncryptorAndEpoch()
			encNotif, err := currentEnc.Encrypt(notifPayload)
			if err != nil {
				continue
			}

			conn.Send(protocol.AlertMessage{
				Type:            "alert",
				Epoch:           currentEpoch,
				TriggeredAt:     event.Time.Unix(),
				Recovered:       event.Type == "recovered",
				EncNotification: encNotif,
			})
		}
	}()

	if *dashboardMode {
		snapCh := orch.Subscribe()
		alertCh := eval.Events()
		snd := sender.NewMockSender(enc, apiURL+"/v1/ingest")

		go func() {
			sub := orch.Subscribe()
			for snap := range sub {
				snd.Send(snap)
			}
		}()

		go orch.Run(ctx, interval)
		go conn.Run(ctx)
		go sched.Run(ctx)
		go logMgr.Run(ctx)

		dash = dashboard.New(snapCh, alertCh, eval.States(), snd, procCol, w)
		if err := dash.Run(); err != nil {
			log.Fatalf("Dashboard error: %v", err)
		}
		cancel()

		// Zero the DEK from the current encryptor per spec
		currentEnc, _ := sched.EncryptorAndEpoch()
		currentEnc.ZeroDEK()
	} else {
		go orch.Run(ctx, interval)
		go conn.Run(ctx)
		go sched.Run(ctx)
		go logMgr.Run(ctx)

		// systemd watchdog: send READY and periodic WATCHDOG pings
		sdnotify.Ready()
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					sdnotify.Watchdog()
				}
			}
		}()

		fmt.Printf("\nAgent running (WebSocket mode).\n")
		fmt.Printf("  WAL entries: %d pending\n", w.Count())
		<-stopCh
		fmt.Println("\nShutting down gracefully...")
		cancel()

		// Zero the DEK from the current encryptor per spec
		currentEnc, _ := sched.EncryptorAndEpoch()
		currentEnc.ZeroDEK()

		time.Sleep(500 * time.Millisecond)
	}
}

func buildWSURL(apiURL string) string {
	url := apiURL
	if strings.HasPrefix(url, "https://") {
		url = "wss://" + strings.TrimPrefix(url, "https://")
	} else if strings.HasPrefix(url, "http://") {
		url = "ws://" + strings.TrimPrefix(url, "http://")
	} else {
		// Default to secure WebSocket for unknown schemes
		url = "wss://" + url
	}
	return url
}
