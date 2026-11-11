package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type createFilePromptWriter struct {
	bytes.Buffer
	t    *testing.T
	path string
}

func (out *createFilePromptWriter) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("Paste file contents")) {
		info, err := os.Stat(out.path)
		if err != nil {
			out.t.Fatalf("file must exist before content prompt: %v", err)
		}
		if info.Size() != 0 {
			out.t.Fatalf("file size before content prompt=%d, want 0", info.Size())
		}
	}
	return out.Buffer.Write(data)
}

func TestRequestCreateFile(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
		promptPath        bool
	}{
		{"multiline", "first\n\n\t  indented  \nEOF\nnext command\n", "first\n\n\t  indented  \n", false},
		{"prompted path", "hello\nEOF\nnext command\n", "hello\n", true},
		{"empty", "EOF\nnext command\n", "", false},
		{"long line", strings.Repeat("x", 100000) + "\nEOF\nnext command\n", strings.Repeat("x", 100000) + "\n", false},
		{"end of input", "last line without newline", "last line without newline", false},
		{"CRLF", "hello\r\nEOF\r\nnext command\n", "hello\r\n", false},
		{"delimiter must be exact", " EOF\nEOF \nEOF\nnext command\n", " EOF\nEOF \n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pasted file.txt")
			command := fmt.Sprintf("create-file %q", path)
			input := test.input
			if test.promptPath {
				command = "create-file"
				input = path + "\n" + input
			}
			reader := strings.NewReader(input)
			out := &createFilePromptWriter{t: t, path: path}
			if err := requestCreateFile(command, reader, out); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != test.want {
				t.Fatalf("unexpected content (length %d, want %d), error=%v", len(content), len(test.want), err)
			}
			if strings.Contains(test.input, "next command") {
				rest, err := io.ReadAll(reader)
				if err != nil || string(rest) != "next command\n" {
					t.Fatalf("remaining input=%q error=%v", rest, err)
				}
			}
			if !strings.Contains(out.String(), "[+] Created file: "+path) {
				t.Fatalf("missing success message: %s", out.String())
			}
		})
	}
}

func TestRequestCreateFileInvalidPathDoesNotPromptForContents(t *testing.T) {
	dir := t.TempDir()
	for _, command := range []string{
		"create-file ''", "create-file 'unterminated", "create-file one two",
		fmt.Sprintf("create-file %q", dir),
		fmt.Sprintf("create-file %q", filepath.Join(dir, "missing", "file")),
	} {
		var out bytes.Buffer
		input := strings.NewReader("untouched\nEOF\n")
		if err := requestCreateFile(command, input, &out); err == nil {
			t.Errorf("%s: expected error", command)
		}
		if input.Len() != len("untouched\nEOF\n") || strings.Contains(out.String(), "Paste file contents") {
			t.Errorf("%s: requested contents before validating path", command)
		}
	}
}

type createFileErrorReader struct{}

func (createFileErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("input failure")
}

func TestRequestCreateFileInputFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	var out bytes.Buffer
	err := requestCreateFile(fmt.Sprintf("create-file %q", path), createFileErrorReader{}, &out)
	if err == nil || !strings.Contains(err.Error(), "input failure") {
		t.Fatalf("expected input failure, got %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != 0 {
		t.Fatalf("expected empty file after input failure: %v", err)
	}
	if strings.Contains(out.String(), "[+] Created file") {
		t.Fatal("reported success on input failure")
	}
}

func TestMainCreateFileFromMFlag(t *testing.T) {
	for _, promptPath := range []bool{false, true} {
		t.Run(fmt.Sprint(promptPath), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pasted file.txt")
			command := fmt.Sprintf("create-file %q", path)
			input := "first\n\n  second\nEOF\n"
			if promptPath {
				command = "create-file"
				input = path + "\n" + input
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
			cmd.Env = append(os.Environ(), "PEIRATES_MAIN_MODULE_HELPER=1", "PEIRATES_TEST_MODULE="+command)
			cmd.Stdin = strings.NewReader(input)
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "[+] Created file: "+path) {
				t.Fatalf("Main -m failed: %v\n%s", err, output)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != "first\n\n  second\n" {
				t.Fatalf("contents=%q error=%v", content, err)
			}
		})
	}
}
