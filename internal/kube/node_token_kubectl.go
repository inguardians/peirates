package kube

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// runWithNodeToken keeps the generated credential out of argv and isolates it
// from the operator's ambient kubeconfig, client certificates, and exec plugins.
func (c *Client) runWithNodeToken(cfg ServerInfo, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if _, err := nodeTokenEndpoint(cfg.APIServer); err != nil {
		return err
	}
	for _, arg := range args {
		if arg == "--" {
			break // Remaining values belong to an exec command, not kubectl.
		}
		name := strings.SplitN(arg, "=", 2)[0]
		switch name {
		case "--kubeconfig", "--server", "-s", "--token", "--client-certificate", "--client-key", "--certificate-authority", "--insecure-skip-tls-verify", "--tls-server-name", "--context", "--cluster", "--user", "--username", "--password", "--as", "--as-group", "--as-uid":
			return errors.New("active node token does not allow kubectl target or identity overrides; switch identity first")
		}
		if strings.HasPrefix(arg, "-s") && !strings.HasPrefix(arg, "--") {
			return errors.New("active node token does not allow a kubectl server override")
		}
	}
	ca := []byte(cfg.CACertData)
	if len(ca) == 0 && cfg.CAPath != "" {
		var err error
		ca, err = os.ReadFile(cfg.CAPath)
		if err != nil {
			return errors.New("cannot read active node token CA")
		}
	}
	if !cfg.IgnoreTLS {
		if _, err := nodeTokenCAs(ca); err != nil {
			return err
		}
	}
	config := clientcmdapi.NewConfig()
	config.Clusters["target"] = &clientcmdapi.Cluster{Server: cfg.APIServer, CertificateAuthorityData: ca, InsecureSkipTLSVerify: cfg.IgnoreTLS}
	if cfg.IgnoreTLS {
		config.Clusters["target"].CertificateAuthorityData = nil
	}
	config.AuthInfos["node"] = &clientcmdapi.AuthInfo{Token: cfg.Token}
	config.Contexts["node"] = &clientcmdapi.Context{Cluster: "target", AuthInfo: "node", Namespace: cfg.Namespace}
	config.CurrentContext = "node"
	contents, err := clientcmd.Write(*config)
	if err != nil {
		return errors.New("cannot encode isolated node kubeconfig")
	}
	dir, err := os.MkdirTemp("", "peirates-node-token-")
	if err != nil {
		return errors.New("cannot create isolated node kubeconfig directory")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		return errors.New("cannot write isolated node kubeconfig")
	}
	runner := c.RunCommand
	if runner == nil {
		runner = runCommand
	}
	command := []string{"--kubeconfig=" + path, "--cache-dir=" + filepath.Join(dir, "cache")}
	return runner(stdin, stdout, stderr, append(command, args...)...)
}
