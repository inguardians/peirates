// Package hostpid implements the privileged hostPID node-shell capability.
package hostpid

import "errors"

// WorkerArgument selects the isolated hostPID worker process. It is an
// internal process mode, not a supported user-facing command-line option.
const WorkerArgument = "--internal-hostpid-worker"

const outputPrefix = "[hostpid-breakout]"

// ErrUnsupported is returned on operating systems without Linux namespaces.
var ErrUnsupported = errors.New("hostPID breakout is supported only on Linux")

func shellEnvironment(term string) []string {
	environment := []string{
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PS1=[peirates-host]# ",
	}
	if term != "" {
		environment = append(environment, "TERM="+term)
	}
	return environment
}
