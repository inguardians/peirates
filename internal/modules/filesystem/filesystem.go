// Package filesystem provides local filesystem operations used by Peirates.
package filesystem

import (
	"fmt"
	"os"
)

// DisplayFile prints the contents of the file at filePath.
func DisplayFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	defer file.Close()

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading file: %w", err)
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
