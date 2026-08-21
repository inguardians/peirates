package peirates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemHelpers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "example.txt")
	if err := os.WriteFile(file, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := displayFile(file); err != nil {
		t.Fatal(err)
	}
	if err := listDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := displayFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing file error")
	}
	if err := listDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing dir error")
	}
}

func TestChangeAndGetCurrentDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	dir := t.TempDir()
	if err := changeDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := getCurrentDirectory(); err != nil || got != dir {
		t.Fatalf("cwd = %q, %v", got, err)
	}
	if err := changeDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing dir error")
	}
}
