package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisplayJSONFile(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"nested object", `{"z":[1,{"ok":true}],"a":null}`, "{\n  \"z\": [\n    1,\n    {\n      \"ok\": true\n    }\n  ],\n  \"a\": null\n}\n", false},
		{"array", `[1,2]`, "[\n  1,\n  2\n]\n", false},
		{"large number", `9007199254740993`, "9007199254740993\n", false},
		{"number notation", `1.2300e+20`, "1.2300e+20\n", false},
		{"string", `"hello"`, "\"hello\"\n", false},
		{"null", `null`, "null\n", false},
		{"empty", "", "", true},
		{"malformed", `{"value":}`, "", true},
		{"multiple values", `{} {}`, "", true},
		{"trailing garbage", `{} invalid`, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(tt.input), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := os.CreateTemp(t.TempDir(), "stdout")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			original := os.Stdout
			os.Stdout = output
			defer func() { os.Stdout = original }()
			err = DisplayJSONFile(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DisplayJSONFile() error = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "failed formatting JSON") {
				t.Fatalf("unexpected error: %v", err)
			}
			got, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDisplayJSONFileReadErrors(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Join(dir, "missing.json")} {
		if err := DisplayJSONFile(path); err == nil {
			t.Errorf("DisplayJSONFile(%q) should fail", path)
		}
	}
}

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
