package pathbrowser

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Entry struct {
	Name     string `json:"name"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Mtime    int64  `json:"mtime"`
	Readable bool   `json:"readable"`
}

type Listing struct {
	Path      string  `json:"path"`
	Parent    string  `json:"parent"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
	Error     string  `json:"error,omitempty"`
}

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

const maxEntries = 500
const maxPathLen = 1024

func ListDir(path string) Listing {
	out := Listing{Path: path}

	if len(path) == 0 || len(path) > maxPathLen {
		out.Error = "invalid path length"
		return out
	}
	if strings.ContainsRune(path, '\x00') {
		out.Error = "invalid path (null byte)"
		return out
	}
	if !filepath.IsAbs(path) {
		out.Error = "path must be absolute"
		return out
	}
	clean := filepath.Clean(path)

	// Resolve symlinks so /var/log/link-to-/etc/shadow is detected.
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		// Non-existent paths still go through the allowlist check below so we
		// return a consistent "denied" error rather than leaking existence.
		resolved = clean
	}

	if !underAllowedRoot(resolved) {
		out.Error = "path not in allowed roots"
		return out
	}
	for _, deny := range deniedContains {
		if strings.Contains(resolved, deny) {
			out.Error = "path is denied"
			return out
		}
	}

	info, err := os.Stat(resolved)
	if err != nil {
		out.Error = fmt.Sprintf("stat: %v", err)
		return out
	}
	if !info.IsDir() {
		out.Error = "not a directory"
		return out
	}

	dirEntries, err := os.ReadDir(resolved)
	if err != nil {
		out.Error = fmt.Sprintf("read: %v", err)
		return out
	}

	// Lexicographic sort for deterministic output + truncation.
	sort.Slice(dirEntries, func(i, j int) bool { return dirEntries[i].Name() < dirEntries[j].Name() })

	if len(dirEntries) > maxEntries {
		out.Truncated = true
		dirEntries = dirEntries[:maxEntries]
	}

	out.Entries = make([]Entry, 0, len(dirEntries))
	for _, de := range dirEntries {
		full := filepath.Join(resolved, de.Name())
		e := Entry{Name: de.Name(), IsDir: de.IsDir(), Readable: true}
		if fi, err := os.Stat(full); err == nil {
			e.Size = fi.Size()
			e.Mtime = fi.ModTime().Unix()
		} else {
			e.Readable = false
		}
		out.Entries = append(out.Entries, e)
	}

	out.Path = resolved
	parent := filepath.Dir(resolved)
	if underAllowedRoot(parent) && parent != resolved {
		out.Parent = parent
	}
	return out
}

func underAllowedRoot(p string) bool {
	for _, root := range allowedRoots {
		if p == root || strings.HasPrefix(p, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
