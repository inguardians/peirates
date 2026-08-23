package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHelpers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "example.txt")
	if err := os.WriteFile(file, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DisplayFile(file); err != nil {
		t.Fatal(err)
	}
	if err := ListDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := DisplayFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing file error")
	}
	if err := ListDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing directory error")
	}
}

func TestChangeAndCurrentDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	dir := t.TempDir()
	if err := ChangeDirectory(dir); err != nil {
		t.Fatal(err)
	}
	got, err := CurrentDirectory()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || got != resolved {
		t.Fatalf("cwd = %q, want %q (resolve error: %v)", got, resolved, err)
	}
	if err := ChangeDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing directory error")
	}
}
