package main

import (
	"os"
	"path/filepath"

	"github.com/inguardians/peirates"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--kubectl" {
		os.Args = append([]string{"kubectl"}, os.Args[2:]...)
		peirates.ExecKubectlAndExit()
	} else if filepath.Base(os.Args[0]) == "kubectl" {
		peirates.ExecKubectlAndExit()
	} else {
		peirates.Main()
	}
}
