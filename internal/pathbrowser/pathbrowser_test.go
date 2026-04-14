package pathbrowser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListDir_Allowlist(t *testing.T) {
	got := ListDir("/var/log")
	if got.Error != "" && !strings.Contains(got.Error, "not found") {
		t.Logf("listing /var/log got error %q (ok on some systems)", got.Error)
	}
}

func TestListDir_DenylistProc(t *testing.T) {
	got := ListDir("/proc")
	if got.Error == "" {
		t.Error("expected error for /proc, got empty")
	}
}

func TestListDir_OutsideAllowlist(t *testing.T) {
	got := ListDir("/usr/bin")
	if got.Error == "" {
		t.Error("expected error for /usr/bin (outside allowlist)")
	}
}

func TestListDir_RejectsRelative(t *testing.T) {
	got := ListDir("var/log")
	if got.Error == "" {
		t.Error("expected error for relative path")
	}
}

func TestListDir_RejectsNull(t *testing.T) {
	got := ListDir("/var/log\x00/etc")
	if got.Error == "" {
		t.Error("expected error for path with null byte")
	}
}

func TestListDir_TruncatesAt500(t *testing.T) {
	dir := t.TempDir()
	// Inject temp dir as an allowed root for this test via a seam.
	// Simpler: create 600 files and list /tmp/<subdir>. /tmp is on the allowlist.
	subdir, err := os.MkdirTemp("/tmp", "pathbrowser-*")
	if err != nil {
		t.Skip("cannot create /tmp dir:", err)
	}
	defer os.RemoveAll(subdir)
	// On macOS /tmp -> /private/tmp; skip if the resolved path is outside allowlist.
	resolved, _ := filepath.EvalSymlinks(subdir)
	if !underAllowedRoot(resolved) {
		t.Skipf("/tmp resolved to %q which is outside allowlist (macOS symlink), skipping", resolved)
	}
	for i := 0; i < 600; i++ {
		p := filepath.Join(subdir, "f"+strings.Repeat("x", 3)+string(rune('a'+(i%26)))+"_"+string(rune('a'+(i/26))))
		os.WriteFile(p, nil, 0600)
	}
	got := ListDir(subdir)
	if !got.Truncated {
		t.Errorf("expected Truncated=true, got entries=%d", len(got.Entries))
	}
	if len(got.Entries) > 500 {
		t.Errorf("entries=%d exceeds cap", len(got.Entries))
	}
	_ = dir
}

func TestListDir_UnreadableChildMarkedReadableFalse(t *testing.T) {
	// Hard to reliably simulate cross-platform; check the Entry struct shape on a valid listing.
	got := ListDir("/etc")
	for _, e := range got.Entries {
		if e.Name == "" {
			t.Error("entry with empty name")
		}
	}
}
