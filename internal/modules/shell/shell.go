// Package shell runs local programs with the process standard streams.
package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

type Runner struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func NewRunner() Runner {
	return Runner{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

func (r Runner) Run(program string) error {
	cmd := exec.Command(program)
	cmd.Stdin = r.Stdin
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	return cmd.Run()
}

func (r Runner) Bash() error {
	err := r.Run("/bin/bash")
	if err != nil {
		fmt.Fprintf(r.Stdout, "Error running shell: %v\n", err)
	}
	return err
}

func (r Runner) SH() error {
	err := r.Run("/bin/sh")
	if err != nil {
		fmt.Fprintf(r.Stdout, "Error running shell: %v\n", err)
	}
	return err
}
