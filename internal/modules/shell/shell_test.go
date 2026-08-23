package shell

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestRun(t *testing.T) {
	program, err := exec.LookPath("echo")
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	runner := Runner{Stdout: &stdout, Stderr: &stdout}
	if err := runner.Run(program); err != nil {
		t.Fatalf("Run(%s): %v", program, err)
	}
	if err := runner.Run("/definitely/not/a/program"); err == nil {
		t.Fatal("Run succeeded for a missing program")
	}
}
