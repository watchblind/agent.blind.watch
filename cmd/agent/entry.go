package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if runAsService() {
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stopCh := make(chan struct{})
	go func() {
		<-sigCh
		close(stopCh)
	}()

	runAgent(stopCh)
}
