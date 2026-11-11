// Package filesystem provides local filesystem operations used by Peirates.
package filesystem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// CreateFile creates an empty file before calling writeContents with its open
// handle. Existing paths (including symlinks) are rejected. On failure, the
// empty or partially written file remains so the caller can inspect it.
func CreateFile(path string, writeContents func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed creating file: %w", err)
	}
	writeErr := writeContents(file)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("failed writing or closing file: %w", err)
	}
	return nil
}

// DisplayFile prints the contents of the file at filePath.
func DisplayFile(filePath string) error {
	return displayFile(filePath, false)
}

// DisplayJSONFile prints the file's JSON contents with two-space indentation.
func DisplayJSONFile(filePath string) error {
	return displayFile(filePath, true)
}

func displayFile(filePath string, prettyJSON bool) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	defer file.Close()

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading file: %w", err)
	}
	if prettyJSON {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, content, "", "  "); err != nil {
			return fmt.Errorf("failed formatting JSON: %w", err)
		}
		content = formatted.Bytes()
	}
	fmt.Println(string(content))
	return nil
}

// ListDirectory prints the names of entries in the directory at dirPath.
func ListDirectory(dirPath string) error {
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("failed opening directory: %w", err)
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		return fmt.Errorf("failed reading directory: %w", err)
	}
	for _, file := range files {
		fmt.Println(file.Name())
	}
	return nil
}

// ChangeDirectory changes the current working directory to dirPath.
func ChangeDirectory(dirPath string) error {
	if err := os.Chdir(dirPath); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	return nil
}

// CurrentDirectory returns the current working directory.
func CurrentDirectory() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}
	return cwd, nil
}
