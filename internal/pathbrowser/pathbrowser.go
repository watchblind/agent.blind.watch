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
	// Symlink metadata for the spec browse_response translation
	// (internal/browse). Additive so the legacy paths_preview JSON shape is
	// unchanged for existing dashboards.
	Symlink   bool `json:"symlink,omitempty"`    // entry is a symbolic link
	TargetDir bool `json:"target_dir,omitempty"` // symlink target is a directory
}

type Listing struct {
	Path      string  `json:"path"`
	Parent    string  `json:"parent"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
	Error     string  `json:"error,omitempty"`
}

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
	if isDenied(resolved) {
		out.Error = "path is denied"
		return out
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
		e.Symlink = de.Type()&os.ModeSymlink != 0

		if e.Symlink {
			// A symlink inside an allowed root can still point outside it
			// (e.g. /var/log/x -> /root/secret). Stat'ing straight through
			// it would leak the target's real size/mtime, so resolve the
			// target first and only report metadata when the RESOLVED path
			// passes the same allowedRoots/deniedContains check as the
			// requested directory itself. A denied target still leaves the
			// entry listed (by name, as a symlink) — just with no
			// size/mtime/target_dir — whereas a genuinely broken symlink
			// (target doesn't exist) keeps the legacy Readable=false
			// behavior so translate.go continues to omit it.
			target, err := filepath.EvalSymlinks(full)
			if err != nil {
				e.Readable = false
			} else if underAllowedRoot(target) && !isDenied(target) {
				if fi, statErr := os.Stat(target); statErr == nil {
					e.Size = fi.Size()
					e.Mtime = fi.ModTime().Unix()
					e.TargetDir = fi.IsDir()
				} else {
					e.Readable = false
				}
			}
		} else if fi, err := os.Stat(full); err == nil {
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

func isDenied(p string) bool {
	for _, deny := range deniedContains {
		if strings.Contains(p, deny) {
			return true
		}
	}
	return false
}
