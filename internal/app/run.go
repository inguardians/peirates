package app

import (
	"os"
	"path/filepath"

	"github.com/inguardians/peirates/internal/modules/hostpid"
)

// Entrypoints contains the process modes selected by RunArgs.
type Entrypoints struct {
	Peirates      func()
	Kubectl       func()
	HostPIDWorker func([]string)
}

// Run starts Peirates using the current process arguments.
func Run() {
	RunArgs(os.Args, Entrypoints{
		Peirates: Main,
		Kubectl:  ExecKubectlAndExit,
		HostPIDWorker: func(args []string) {
			os.Exit(hostpid.RunWorker(args, os.Stdin, os.Stdout, os.Stderr))
		},
	})
}

// RunArgs preserves the historical argv routing for normal and kubectl modes.
func RunArgs(args []string, entrypoints Entrypoints) {
	if len(args) == 0 {
		args = []string{"peirates"}
	}
	os.Args = args
	if len(os.Args) > 1 && os.Args[1] == hostpid.WorkerArgument {
		entrypoints.HostPIDWorker(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--kubectl" {
		os.Args = append([]string{"kubectl"}, os.Args[2:]...)
		entrypoints.Kubectl()
		return
	}
	if filepath.Base(os.Args[0]) == "kubectl" {
		entrypoints.Kubectl()
		return
	}
	entrypoints.Peirates()
}
