package peirates

import (
	"os/exec"
	"testing"
)

func TestRunExtProgram(t *testing.T) {
	program, err := exec.LookPath("echo")
	if err != nil {
		t.Fatal(err)
	}
	if err := runExtProgram(program); err != nil {
		t.Fatalf("runExtProgram(%s): %v", program, err)
	}
	if err := runExtProgram("/definitely/not/a/program"); err == nil {
		t.Fatal("runExtProgram succeeded for a missing program")
	}
}
