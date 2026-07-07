package browse

import (
	"testing"

	"github.com/watchblind/agent/internal/pathbrowser"
)

func TestTranslateListing_MapsShapes(t *testing.T) {
	l := pathbrowser.Listing{
		Path:      "/var/log/nginx",
		Truncated: true,
		Entries: []pathbrowser.Entry{
			{Name: "access.log", IsDir: false, Size: 1234, Mtime: 1700000000, Readable: true},
			{Name: "archive", IsDir: true, Size: 4096, Mtime: 1700000001, Readable: true},
			{Name: "current", Symlink: true, TargetDir: false, Size: 55, Mtime: 1700000002, Readable: true},
			{Name: "linked-dir", Symlink: true, TargetDir: true, Size: 4096, Mtime: 1700000003, Readable: true},
			{Name: "dangling", Symlink: true, Readable: false}, // broken symlink — omitted
		},
	}

	got := TranslateListing(l)

	if got.Path != "/var/log/nginx" {
		t.Errorf("Path = %q", got.Path)
	}
	if !got.Truncated {
		t.Error("Truncated flag lost in translation")
	}
	if got.Error != nil {
		t.Errorf("unexpected error: %v", *got.Error)
	}

	// Broken symlink omitted; dirs (and symlink-to-dir) first, alphabetical.
	wantOrder := []string{"archive", "linked-dir", "access.log", "current"}
	if len(got.Entries) != len(wantOrder) {
		t.Fatalf("got %d entries %+v, want %d", len(got.Entries), got.Entries, len(wantOrder))
	}
	for i, want := range wantOrder {
		if got.Entries[i].Name != want {
			t.Errorf("Entries[%d].Name = %q, want %q", i, got.Entries[i].Name, want)
		}
	}

	byName := map[string]DirEntry{}
	for _, e := range got.Entries {
		byName[e.Name] = e
	}

	if e := byName["access.log"]; e.Type != "file" || e.Size == nil || *e.Size != 1234 || e.Modified == nil || *e.Modified != 1700000000 {
		t.Errorf("file entry wrong: %+v", e)
	}
	if e := byName["archive"]; e.Type != "dir" || e.Size != nil || e.Modified != nil {
		t.Errorf("dir entry must have null size/modified: %+v", e)
	}
	if e := byName["current"]; e.Type != "symlink" || e.Size == nil || *e.Size != 55 {
		t.Errorf("symlink-to-file entry wrong: %+v", e)
	}
	if e := byName["linked-dir"]; e.Type != "symlink" || e.Size != nil || e.Modified != nil {
		t.Errorf("symlink-to-dir entry must have null size/modified: %+v", e)
	}
}

func TestTranslateListing_Error(t *testing.T) {
	got := TranslateListing(pathbrowser.Listing{Path: "/proc", Error: "path is denied"})
	if got.Error == nil || *got.Error != "path is denied" {
		t.Fatalf("Error = %v, want \"path is denied\"", got.Error)
	}
	if len(got.Entries) != 0 {
		t.Errorf("error listing should carry no entries, got %+v", got.Entries)
	}
}

func TestTranslateListing_UnreadableFileHasNulls(t *testing.T) {
	got := TranslateListing(pathbrowser.Listing{
		Path:    "/var/log",
		Entries: []pathbrowser.Entry{{Name: "secret.log", Readable: false}},
	})
	if len(got.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(got.Entries))
	}
	e := got.Entries[0]
	if e.Type != "file" || e.Size != nil || e.Modified != nil {
		t.Errorf("unreadable file should be a file with null size/modified: %+v", e)
	}
}
