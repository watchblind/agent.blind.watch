//go:build linux

package pathbrowser

// Allowlist of permitted root prefixes. A resolved path must lie under one of
// these after filepath.EvalSymlinks to be enumerable.
var allowedRoots = []string{
	"/var/log",
	"/var/lib",
	"/home",
	"/opt",
	"/etc",
	"/tmp",
}

// Denylisted substrings — even within allowed roots, paths containing any of
// these are refused (handles edge cases like bind mounts from /proc).
var deniedContains = []string{"/proc", "/sys", "/dev", "/root"}
