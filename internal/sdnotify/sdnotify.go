package sdnotify

import (
	"net"
	"os"
)

// Notify sends a message to systemd via the NOTIFY_SOCKET.
// No-op if NOTIFY_SOCKET is not set (i.e. not running under systemd).
func Notify(state string) error {
	socketAddr := os.Getenv("NOTIFY_SOCKET")
	if socketAddr == "" {
		return nil
	}

	conn, err := net.Dial("unixgram", socketAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(state))
	return err
}

// Ready sends READY=1 to systemd.
func Ready() error {
	return Notify("READY=1")
}

// Watchdog sends WATCHDOG=1 to systemd.
func Watchdog() error {
	return Notify("WATCHDOG=1")
}
