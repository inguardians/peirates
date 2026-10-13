package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/inguardians/peirates/internal/modules/kubectlcani"
)

var launchKubectlCanI = kubectlcani.Run

// handleKubectlCanI accepts both the bare usage request and an authorization
// query. Arguments are plain whitespace-separated words, never shell input.
func handleKubectlCanI(input string, session *Session, out io.Writer) bool {
	arguments := strings.Fields(input)
	if len(arguments) == 0 || arguments[0] != "kubectl-can-i" {
		return false
	}
	accounts := append([]ServiceAccount(nil), session.ServiceAccounts...)
	certificates := append([]ClientCertificateKeyPair(nil), session.ClientCertificates...)
	if err := launchKubectlCanI(session.Connection, accounts, certificates, arguments[1:], out); err != nil {
		fmt.Fprintf(out, "[kubectl-can-i] %v\n", err)
	}
	return true
}
