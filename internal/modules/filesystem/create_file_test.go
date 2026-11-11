package filesystem

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateFileBeforeContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pasted.txt")
	err := CreateFile(path, func(file io.Writer) error {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("before contents: size=%d mode=%v", info.Size(), info.Mode())
		}
		_, err = io.WriteString(file, "pasted text\n")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "pasted text\n" {
		t.Fatalf("contents=%q error=%v", content, err)
	}
}

func TestCreateFileRejectsExistingPathsBeforeContents(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(existing, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, dir, link, filepath.Join(dir, "missing", "file")} {
		err := CreateFile(path, func(io.Writer) error {
			t.Fatal("requested contents for an invalid path")
			return nil
		})
		if err == nil {
			t.Fatalf("expected creation failure for %s", path)
		}
	}
	content, err := os.ReadFile(existing)
	if err != nil || string(content) != "keep" {
		t.Fatalf("existing file changed: %q, %v", content, err)
	}
}

func TestCreateFileReportsContentFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial")
	wantErr := errors.New("input failed")
	err := CreateFile(path, func(file io.Writer) error {
		if _, err := io.WriteString(file, "partial"); err != nil {
			t.Fatal(err)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v, want %v", err, wantErr)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "partial" {
		t.Fatalf("contents=%q error=%v", content, err)
	}
}
