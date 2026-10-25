// Package kubectlcani checks an action using each stored Kubernetes credential.
package kubectlcani

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
	"github.com/spf13/pflag"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const usage = "usage: kubectl-can-i [-n namespace | -A] [--subresource name] VERB RESOURCE[/NAME] (or /nonresource-url)"

type identity struct {
	labels []string
	cfg    model.ServerInfo
}

// Run executes embedded kubectl auth can-i for every stored identity, also
// including active credentials when absent from the store. It never changes the
// active session. Only successful authorization checks are reported as permitted.
func Run(base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair, args []string, out io.Writer) error {
	return run(base, accounts, certs, args, out, kube.NewClient().RunCommand)
}

func run(base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair, args []string, out io.Writer, runner kube.CommandRunner) error {
	if out == nil || runner == nil {
		return errors.New("kubectl-can-i requires output and a command runner")
	}
	checkArgs, err := parseArgs(args)
	if err != nil {
		return err
	}
	ids := identities(base, accounts, certs)
	if len(ids) == 0 {
		_, err = fmt.Fprintln(out, "No configured identities to check")
		return err
	}
	permitted, denied, failed := 0, 0, 0
	for _, id := range ids {
		allowed, checkErr := check(id.cfg, checkArgs, runner)
		for _, label := range id.labels {
			switch {
			case checkErr != nil:
				failed++
				_, err = fmt.Fprintf(out, "[-] Check failed: %s (%s)\n", label, checkErr)
			case allowed:
				permitted++
				_, err = fmt.Fprintf(out, "[+] Permitted: %s\n", label)
			default:
				denied++
			}
			if err != nil {
				return err
			}
		}
	}
	if _, err = fmt.Fprintf(out, "Authorization checks: %d permitted, %d denied, %d failed\n", permitted, denied, failed); err != nil {
		return err
	}
	if failed != 0 {
		return fmt.Errorf("authorization checks failed for %d identities; their permissions are unknown", failed)
	}
	return nil
}

func parseArgs(args []string) ([]string, error) {
	flags := pflag.NewFlagSet("kubectl-can-i", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	namespace := flags.StringP("namespace", "n", "", "namespace")
	allNamespaces := flags.BoolP("all-namespaces", "A", false, "all namespaces")
	subresource := flags.String("subresource", "", "subresource")
	if err := flags.Parse(args); err != nil {
		return nil, errors.New("invalid or unsupported arguments; " + usage)
	}
	positional := flags.Args()
	if len(positional) != 2 || strings.TrimSpace(positional[0]) == "" || strings.TrimSpace(positional[1]) == "" || strings.HasPrefix(positional[0], "-") || strings.HasPrefix(positional[1], "-") {
		return nil, errors.New(usage)
	}
	if flags.Changed("namespace") && (strings.TrimSpace(*namespace) == "" || *allNamespaces) {
		return nil, errors.New("specify a nonempty namespace or all namespaces; " + usage)
	}
	if flags.Changed("subresource") && (strings.TrimSpace(*subresource) == "" || strings.HasPrefix(positional[1], "/")) {
		return nil, errors.New("subresource requires a nonempty name and a resource; " + usage)
	}
	result := []string{"auth", "can-i", positional[0], positional[1]}
	if flags.Changed("namespace") {
		result = append(result, "--namespace="+*namespace)
	}
	if *allNamespaces {
		result = append(result, "--all-namespaces")
	}
	if flags.Changed("subresource") {
		result = append(result, "--subresource="+*subresource)
	}
	return result, nil
}

func identities(base model.ServerInfo, accounts []model.ServiceAccount, certs []model.ClientCertificateKeyPair) []identity {
	var ids []identity
	seen := make(map[model.ServerInfo]int)
	add := func(kind, name string, cfg model.ServerInfo, active bool) {
		// Labels and the session preflight toggle do not affect authentication.
		cfg.TokenName, cfg.ClientCertName, cfg.UseAuthCanI = "", "", false
		if cfg.Namespace == "" {
			cfg.Namespace = "default"
		}
		label := kind + " " + strconv.Quote(name)
		if index, ok := seen[cfg]; ok {
			if active {
				return
			}
			for _, existing := range ids[index].labels {
				if existing == label {
					return
				}
			}
			ids[index].labels = append(ids[index].labels, label)
			return
		}
		seen[cfg] = len(ids)
		ids = append(ids, identity{labels: []string{label}, cfg: cfg})
	}
	for i, account := range accounts {
		cfg := base
		cfg.ActiveTokenKind, cfg.ActiveTokenExpiresAt = "", time.Time{}
		cfg.Token = account.Token
		cfg.ClientCertData, cfg.ClientKeyData = "", ""
		name := account.Name
		if name == "" {
			name = "#" + strconv.Itoa(i+1)
		}
		add("service account", name, cfg, false)
	}
	for i, cert := range certs {
		cfg := base
		cfg.ActiveTokenKind, cfg.ActiveTokenExpiresAt = "", time.Time{}
		cfg.Token = ""
		cfg.ClientCertData, cfg.ClientKeyData = cert.ClientCertificateData, cert.ClientKeyData
		if cert.APIServer != "" {
			cfg.APIServer = cert.APIServer
		}
		if cert.CACert != "" {
			cfg.CACertData, cfg.CAPath = cert.CACert, ""
		}
		name := cert.Name
		if name == "" {
			name = "#" + strconv.Itoa(i+1)
		}
		add("certificate", name, cfg, false)
	}
	if base.Token != "" {
		cfg := base
		cfg.ClientCertData, cfg.ClientKeyData = "", ""
		name := base.TokenName
		if name == "" {
			name = "active"
		}
		kind := "service account"
		if cfg.ActiveTokenKind != "" {
			kind = "node token"
		}
		add(kind, name, cfg, true)
	}
	if base.ClientCertData != "" || base.ClientKeyData != "" {
		cfg := base
		cfg.Token = ""
		name := base.ClientCertName
		if name == "" {
			name = "active"
		}
		add("certificate", name, cfg, true)
	}
	return ids
}

func check(cfg model.ServerInfo, args []string, runner kube.CommandRunner) (bool, error) {
	if err := kube.CheckActiveToken(cfg); err != nil {
		return false, err
	}
	if cfg.APIServer == "" {
		return false, errors.New("API server is not configured")
	}
	if cfg.Token == "" && (cfg.ClientCertData == "" || cfg.ClientKeyData == "") {
		return false, errors.New("credential is incomplete")
	}
	cluster := &clientcmdapi.Cluster{Server: cfg.APIServer, InsecureSkipTLSVerify: cfg.IgnoreTLS}
	if !cfg.IgnoreTLS {
		cluster.CertificateAuthorityData = []byte(cfg.CACertData)
		if len(cluster.CertificateAuthorityData) == 0 && cfg.CAPath != "" {
			var err error
			cluster.CertificateAuthorityData, err = os.ReadFile(cfg.CAPath)
			if err != nil {
				return false, errors.New("could not read certificate authority")
			}
		}
		if len(cluster.CertificateAuthorityData) == 0 {
			return false, errors.New("certificate authority is not configured")
		}
	}
	config := clientcmdapi.NewConfig()
	config.Clusters["target"] = cluster
	config.AuthInfos["identity"] = &clientcmdapi.AuthInfo{Token: cfg.Token, ClientCertificateData: []byte(cfg.ClientCertData), ClientKeyData: []byte(cfg.ClientKeyData)}
	config.Contexts["check"] = &clientcmdapi.Context{Cluster: "target", AuthInfo: "identity", Namespace: cfg.Namespace}
	config.CurrentContext = "check"
	contents, err := clientcmd.Write(*config)
	if err != nil {
		return false, errors.New("could not encode isolated kubeconfig")
	}
	dir, err := os.MkdirTemp("", "peirates-can-i-")
	if err != nil {
		return false, errors.New("could not create isolated kubeconfig directory")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	configPath := filepath.Join(dir, "config")
	if err = os.WriteFile(configPath, contents, 0600); err != nil {
		return false, errors.New("could not write isolated kubeconfig")
	}
	command := []string{"--kubeconfig=" + configPath, "--cache-dir=" + filepath.Join(dir, "cache"), "--request-timeout=10s"}
	command = append(command, args...)
	var stdout, stderr bytes.Buffer
	err = runner(strings.NewReader(""), &stdout, &stderr, command...)
	// The shared embedded runner combines streams. Kubectl prints its decision
	// last, after discovery warnings; never interpret arbitrary success text.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	decision := strings.TrimSpace(lines[len(lines)-1])
	if err == nil && decision == "yes" {
		return true, nil
	}
	var exitError interface{ ExitCode() int }
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 && (decision == "no" || strings.HasPrefix(decision, "no - ")) {
		return false, nil
	}
	// Kubectl errors can embed the server URL or credentials. Do not propagate
	// captured streams or the runner error to the terminal.
	return false, errors.New("authorization check failed")
}
