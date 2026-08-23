package ui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputToUserWritesRequestedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.log")
	OutputToUser("test output\n", true, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "test output\n" {
		t.Fatalf("log contents = %q", data)
	}
}

func TestOutputToUserAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.log")
	OutputToUser("first", true, path)
	OutputToUser("second", true, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "firstsecond" {
		t.Fatalf("log contents = %q", data)
	}
}
