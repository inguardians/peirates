// Package shell runs local programs with the process standard streams.
package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Runner runs local programs using configurable standard streams.
type Runner struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// NewRunner returns a Runner connected to the current process standard streams.
func NewRunner() Runner {
	return Runner{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

// Run executes program with the runner's configured standard streams.
func (r Runner) Run(program string) error {
	cmd := exec.Command(program)
	cmd.Stdin = r.Stdin
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	return cmd.Run()
}

// Bash starts the Bash shell.
func (r Runner) Bash() error {
	err := r.Run("/bin/bash")
	if err != nil {
		fmt.Fprintf(r.Stdout, "Error running shell: %v\n", err)
	}
	return err
}

// SH starts the Bourne shell.
func (r Runner) SH() error {
	err := r.Run("/bin/sh")
	if err != nil {
		fmt.Fprintf(r.Stdout, "Error running shell: %v\n", err)
	}
	return err
}
