package main

import (
	"os"
	"path/filepath"

	"github.com/inguardians/peirates"
)

func main() {
	// if len(os.Args) > 1 && os.Args[1] == "--kubectl" {
	// 	os.Args = append(os.Args[0:1], os.Args[2:]...)
	if filepath.Base(os.Args[0]) == "kubectl" {
		peirates.ExecKubectlAndExit()
	} else {
		peirates.PeiratesMain()
	}
}
