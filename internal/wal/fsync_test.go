package wal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndSync_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := writeAndSync(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("writeAndSync: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("contents = %q, want %q", string(got), "hello")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
}

func TestAtomicReplace_OverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := atomicReplace(path, []byte("new"), 0600); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("contents = %q, want %q", string(got), "new")
	}
}

func TestAtomicReplace_NoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := atomicReplace(path, []byte("x"), 0600); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (no temp leftover)", len(entries))
	}
}

func TestFsyncDir_OK(t *testing.T) {
	dir := t.TempDir()
	if err := fsyncDir(dir); err != nil {
		t.Errorf("fsyncDir: %v", err)
	}
}

func TestFsyncDir_NonExistent(t *testing.T) {
	err := fsyncDir(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Error("expected error for non-existent dir")
	}
}
