//go:build !linux && !windows

package pathbrowser

// Development fallback (macOS and other unixes) so the package compiles and
// tests run locally. The agent only ships for linux and windows; those
// allowlists live in roots_linux.go / roots_windows.go. The /private/*
// variants exist because macOS resolves /tmp, /etc and /var through the
// /private prefix during filepath.EvalSymlinks.
var allowedRoots = []string{
	"/var/log",
	"/var/lib",
	"/home",
	"/opt",
	"/etc",
	"/tmp",
	"/private/tmp",
	"/private/etc",
	"/private/var/log",
	"/private/var/lib",
}

// Denylisted substrings — same policy as linux.
var deniedContains = []string{"/proc", "/sys", "/dev", "/root"}
