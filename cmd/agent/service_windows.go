//go:build windows

package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "BlindwatchAgent"

// runAsService returns true when the binary is launched by the Windows
// Service Control Manager. In that case it dispatches to the SCM and
// blocks until the service stops, so the caller must return immediately.
func runAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("svc.IsWindowsService: %v", err)
	}
	if !isService {
		return false
	}

	redirectServiceLog()

	if err := svc.Run(serviceName, &bwService{}); err != nil {
		log.Fatalf("svc.Run: %v", err)
	}
	return true
}

// redirectServiceLog points stdout/stderr and the default logger at
// <data-dir>\agent.log so output isn't lost. SCM doesn't capture stdout.
func redirectServiceLog() {
	dataDir := peekDataDirFlag()
	if dataDir == "" {
		dataDir = `C:\ProgramData\blindwatch`
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "agent.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	os.Stdout = f
	os.Stderr = f
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.LUTC)
}

// peekDataDirFlag does a non-destructive scan of os.Args for --data-dir
// before flag.Parse runs in runAgent. Returns "" if not present.
func peekDataDirFlag() string {
	for i, a := range os.Args[1:] {
		if a == "--data-dir" || a == "-data-dir" {
			if i+2 < len(os.Args) {
				return os.Args[i+2]
			}
		}
		if v, ok := stripPrefix(a, "--data-dir="); ok {
			return v
		}
		if v, ok := stripPrefix(a, "-data-dir="); ok {
			return v
		}
	}
	return ""
}

func stripPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

type bwService struct{}

func (s *bwService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	// Reset flag.CommandLine so runAgent's flag.Parse can run cleanly when
	// SCM passes service-name as args[0].
	if len(args) > 0 {
		flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	}

	stopCh := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[service] runAgent panicked: %v", rec)
			}
		}()
		runAgent(stopCh)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepts}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				log.Printf("[service] unexpected control: %d", c.Cmd)
			}
		case <-done:
			// runAgent exited on its own (e.g. fatal error). Report stop.
			status <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	}

	status <- svc.Status{State: svc.StopPending}
	close(stopCh)

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		log.Printf("[service] runAgent did not exit within 15s, forcing")
	}

	status <- svc.Status{State: svc.Stopped}
	return false, 0
}
