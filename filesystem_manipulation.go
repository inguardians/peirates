package peirates

import (
	"fmt"
	"os"
)

func displayFile(filePath string) error {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	defer file.Close()

	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading file: %w", err)
	}

	// Print the content of the file
	fmt.Println(string(content))
	return nil
}

func listDirectory(dirPath string) error {
	// Open the directory
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("failed opening directory: %w", err)
	}
	defer dir.Close()

	// Read the directory contents
	files, err := dir.Readdir(-1)
	if err != nil {
		return fmt.Errorf("failed reading directory: %w", err)
	}

	// Print the names of the files and directories
	for _, file := range files {
		fmt.Println(file.Name())
	}
	return nil
}

func changeDirectory(dirPath string) error {
	if err := os.Chdir(dirPath); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	return nil
}

func getCurrentDirectory() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}
	return cwd, nil
}
