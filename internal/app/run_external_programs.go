package app

import "github.com/inguardians/peirates/internal/modules/shell"

func runBash() error                     { return shell.NewRunner().Bash() }
func runSH() error                       { return shell.NewRunner().SH() }
func runExtProgram(program string) error { return shell.NewRunner().Run(program) }
