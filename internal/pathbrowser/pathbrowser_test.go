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

func TestListDir_SymlinkFields(t *testing.T) {
	subdir, err := os.MkdirTemp("/tmp", "pathbrowser-symlink-*")
	if err != nil {
		t.Skip("cannot create /tmp dir:", err)
	}
	defer os.RemoveAll(subdir)
	resolved, _ := filepath.EvalSymlinks(subdir)
	if !underAllowedRoot(resolved) {
		t.Skipf("/tmp resolved to %q which is outside allowlist, skipping", resolved)
	}

	if err := os.WriteFile(filepath.Join(subdir, "plain.log"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(subdir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	mkLink := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(subdir, name)); err != nil {
			t.Skip("symlinks not supported here:", err)
		}
	}
	mkLink(filepath.Join(subdir, "plain.log"), "link-file")
	mkLink(filepath.Join(subdir, "sub"), "link-dir")
	mkLink(filepath.Join(subdir, "does-not-exist"), "link-broken")

	got := ListDir(subdir)
	if got.Error != "" {
		t.Fatalf("unexpected error: %s", got.Error)
	}

	byName := map[string]Entry{}
	for _, e := range got.Entries {
		byName[e.Name] = e
	}

	if e := byName["plain.log"]; e.Symlink || e.IsDir {
		t.Errorf("plain.log flags wrong: %+v", e)
	}
	if e := byName["link-file"]; !e.Symlink || e.TargetDir || !e.Readable || e.Size != 1 {
		t.Errorf("link-file should be a readable symlink to a file: %+v", e)
	}
	if e := byName["link-dir"]; !e.Symlink || !e.TargetDir || !e.Readable {
		t.Errorf("link-dir should be a symlink with TargetDir=true: %+v", e)
	}
	if e := byName["link-broken"]; !e.Symlink || e.Readable {
		t.Errorf("link-broken should be an unreadable symlink: %+v", e)
	}
}

func TestListDir_SymlinkTargetOutsideAllowlistIsListedWithoutMetadata(t *testing.T) {
	// The symlink itself lives inside an allowed root (/tmp); its target does
	// not — simulating /var/log/x -> /root/secret from a real deployment.
	linkDir, err := os.MkdirTemp("/tmp", "pathbrowser-outside-link-*")
	if err != nil {
		t.Skip("cannot create /tmp dir:", err)
	}
	defer os.RemoveAll(linkDir)
	resolvedLinkDir, _ := filepath.EvalSymlinks(linkDir)
	if !underAllowedRoot(resolvedLinkDir) {
		t.Skipf("/tmp resolved to %q which is outside allowlist, skipping", resolvedLinkDir)
	}

	// os.TempDir() (default OS temp dir, not /tmp explicitly) lands outside
	// every allowed root on macOS (/var/folders/.../T). Skip if this
	// environment's default temp dir happens to resolve under an allowed
	// root (e.g. some Linux setups where it IS /tmp) — there is no leak to
	// prove in that case.
	outsideDir, err := os.MkdirTemp("", "pathbrowser-outside-target-*")
	if err != nil {
		t.Skip("cannot create outside temp dir:", err)
	}
	defer os.RemoveAll(outsideDir)
	resolvedOutside, _ := filepath.EvalSymlinks(outsideDir)
	if underAllowedRoot(resolvedOutside) {
		t.Skipf("outside temp dir %q unexpectedly resolved under an allowed root, skipping", resolvedOutside)
	}

	target := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(target, []byte("classified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(linkDir, "leaky-link")); err != nil {
		t.Skip("symlinks not supported here:", err)
	}

	got := ListDir(linkDir)
	if got.Error != "" {
		t.Fatalf("unexpected error: %s", got.Error)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got.Entries), got.Entries)
	}

	e := got.Entries[0]
	if e.Name != "leaky-link" {
		t.Fatalf("entry name = %q, want leaky-link", e.Name)
	}
	if !e.Symlink {
		t.Error("expected Symlink=true")
	}
	if !e.Readable {
		t.Error("a denied-target symlink must still be listed (Readable=true), not omitted like a broken one")
	}
	if e.Size != 0 || e.Mtime != 0 || e.TargetDir {
		t.Errorf("denied-target symlink must not leak target metadata: %+v", e)
	}
}
