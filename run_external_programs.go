package peirates

import (
	"fmt"
	"os"
	"os/exec"
)

func runBash() error {

	err := runExtProgram("/bin/bash")
	if err != nil {
		fmt.Printf("Error running shell: %v\n", err)
	}

	return err
}

func runSH() error {

	err := runExtProgram("/bin/sh")
	if err != nil {
		fmt.Printf("Error running shell: %v\n", err)
	}

	return err
}

func runExtProgram(program string) error {

	cmd := exec.Command(program)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
