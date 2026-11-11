package app

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/inguardians/peirates/internal/modules/filesystem"
)

func handleCreateFile(command string, stdin io.Reader, stdout io.Writer) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != "create-file" {
		return false
	}
	if err := requestCreateFile(command, stdin, stdout); err != nil {
		fmt.Fprintf(stdout, "[-] create-file: %v\n", err)
	}
	return true
}

func requestCreateFile(command string, stdin io.Reader, stdout io.Writer) error {
	args, err := parseCommandArgs(command)
	if err != nil {
		return err
	}
	if len(args) > 2 {
		return fmt.Errorf("usage: create-file [path] (quote paths containing spaces)")
	}
	// Do not consume bytes belonging to the next menu command after EOF.
	reader := bufio.NewReader(&singleByteReader{reader: stdin})
	var path string
	if len(args) == 2 {
		path = args[1]
	} else {
		if _, err := fmt.Fprint(stdout, "File path: "); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading file path: %w", err)
		}
		path = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("file path is required")
	}
	if err := filesystem.CreateFile(path, func(file io.Writer) error {
		if _, err := fmt.Fprintln(stdout, "Paste file contents. Finish with EOF on a line by itself (or end of input):"); err != nil {
			return err
		}
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil && readErr != io.EOF {
				return fmt.Errorf("reading file contents: %w", readErr)
			}
			if strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r") == "EOF" {
				return nil
			}
			if _, err := io.WriteString(file, line); err != nil {
				return err
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "[+] Created file: %s\n", path)
	return err
}
