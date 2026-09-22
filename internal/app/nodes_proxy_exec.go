package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
	"github.com/inguardians/peirates/internal/modules/nodesproxyexec"
)

var launchNodesProxyExec = func(connection ServerInfo, accounts []ServiceAccount) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return launchNodesProxyExecWithStreams(ctx, connection, accounts, os.Stdin, os.Stdout, os.Stderr, os.Getenv)
}

var newNodesProxyAccessReviewer = func() nodesproxyexec.AccessReviewer {
	return nodesProxyAccessReviewer{client: &kube.Client{}}
}

var newNodesProxyKubeletFactory = func(origin string, tlsOptions kube.KubeletTLSOptions) nodesproxyexec.KubeletFactory {
	return nodesProxyKubeletFactory{options: kube.KubeletClientOptions{Origin: origin, TLS: tlsOptions}}
}

type nodesProxyAccessReviewer struct{ client *kube.Client }

func (reviewer nodesProxyAccessReviewer) ReviewAccess(ctx context.Context, connection model.ServerInfo, request nodesproxyexec.AccessRequest) (bool, error) {
	return reviewer.client.AuthCanIResource(ctx, connection, kube.ResourceAttributes{
		Resource:    "nodes",
		Subresource: "proxy",
		Verb:        request.Verb,
		Name:        request.NodeName,
	})
}

type nodesProxyKubeletFactory struct{ options kube.KubeletClientOptions }

func (factory nodesProxyKubeletFactory) NewKubelet(_ context.Context, connection model.ServerInfo) (nodesproxyexec.Kubelet, error) {
	options := factory.options
	options.BearerToken = connection.Token
	client, err := kube.NewKubeletClient(options)
	if err != nil {
		return nil, err
	}
	return nodesProxyKubelet{client: client}, nil
}

type nodesProxyKubelet struct{ client *kube.KubeletClient }

func (client nodesProxyKubelet) Probe(ctx context.Context) error { return client.client.Probe(ctx) }

func (client nodesProxyKubelet) ListRunningContainers(ctx context.Context) ([]nodesproxyexec.Target, error) {
	containers, err := client.client.ListRunningContainers(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]nodesproxyexec.Target, 0, len(containers))
	for _, container := range containers {
		targets = append(targets, nodesproxyexec.Target{
			NodeName:      container.NodeName,
			Namespace:     container.Namespace,
			PodName:       container.PodName,
			ContainerName: container.ContainerName,
			ContainerKind: nodesproxyexec.ContainerKind(container.Kind),
		})
	}
	return targets, nil
}

func (client nodesProxyKubelet) Exec(ctx context.Context, target nodesproxyexec.Target, argv []string, stdout, stderr io.Writer) (nodesproxyexec.ExecStatus, error) {
	status, err := client.client.Exec(ctx, kube.KubeletContainer{
		NodeName:      target.NodeName,
		Namespace:     target.Namespace,
		PodName:       target.PodName,
		ContainerName: target.ContainerName,
		Kind:          kube.KubeletContainerKind(target.ContainerKind),
	}, argv, stdout, stderr)
	return nodesproxyexec.ExecStatus{ExitCode: status.ExitCode, Protocol: status.Protocol, Complete: status.Protocol != "" && status.ExitCode >= 0}, err
}

func launchNodesProxyExecWithStreams(ctx context.Context, connection ServerInfo, accounts []ServiceAccount, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	if len(accounts) == 0 {
		return nodesproxyexec.ErrNoCredentials
	}
	if ctx == nil {
		return errors.New("nodes/proxy execution context is nil")
	}
	reader := bufio.NewReader(stdin)

	defaultNode := strings.TrimSpace(getenv("NODE_NAME"))
	if sanitizeNodesProxyDisplay(defaultNode) != defaultNode {
		defaultNode = ""
	}
	nodePrompt := "Kubernetes node name: "
	if defaultNode != "" {
		nodePrompt = fmt.Sprintf("Kubernetes node name [%s]: ", defaultNode)
	}
	node, err := readNodesProxyLine(reader, stdout, nodePrompt)
	if err != nil {
		return cancellationError("node name", err)
	}
	if node == "" {
		node = defaultNode
	}

	reviewsEnabled := connection.UseAuthCanI
	scan, err := nodesproxyexec.ReviewCredentials(ctx, connection, append([]ServiceAccount(nil), accounts...), node, newNodesProxyAccessReviewer(), reviewsEnabled)
	if err != nil {
		return fmt.Errorf("review stored tokens: %w", err)
	}
	renderCredentialScan(stdout, node, scan)
	if !hasSelectableCredential(scan, reviewsEnabled) {
		return errors.New("no stored token is eligible for direct kubelet access")
	}

	indexLine, err := readNodesProxyLine(reader, stdout, "Stored token index: ")
	if err != nil {
		return cancellationError("stored token selection", err)
	}
	index, err := strconv.Atoi(indexLine)
	if err != nil {
		return errors.New("stored token index must be an original numeric index")
	}
	allowUnchecked := false
	if credentialState(scan, index) == nodesproxyexec.AccessUnchecked {
		fmt.Fprintln(stderr, "WARNING: authorization reviews are disabled; this token's nodes/proxy permission is unproven.")
		ack := fmt.Sprintf("USE-UNCHECKED-TOKEN-%d", index)
		line, readErr := readNodesProxyLine(reader, stdout, "Type "+ack+" to continue: ")
		if readErr != nil || line != ack {
			return errors.New("unchecked credential selection cancelled")
		}
		allowUnchecked = true
	}
	selected, err := scan.Select(index, allowUnchecked)
	if err != nil {
		return fmt.Errorf("select stored token: %w", err)
	}

	origin, err := readNodesProxyLine(reader, stdout, "Kubelet HTTPS origin: ")
	if err != nil {
		return cancellationError("kubelet origin", err)
	}
	tlsOptions, tlsLabel, err := readKubeletTLSOptions(reader, stdout, stderr, connection)
	if err != nil {
		return err
	}
	factory := newNodesProxyKubeletFactory(origin, tlsOptions)
	prepared, probe, err := nodesproxyexec.Prepare(ctx, selected, node, factory)
	if err != nil {
		fmt.Fprintf(stdout, "Result classification: %s\n", probe.Classification)
		return err
	}
	if len(probe.Containers) == 0 {
		fmt.Fprintf(stdout, "Result classification: %s\n", probe.Classification)
		return errors.New("direct kubelet returned no running containers on the selected node")
	}

	fmt.Fprintln(stdout, "Running kubelet containers:")
	for targetIndex, target := range probe.Containers {
		fmt.Fprintf(stdout, "[%d] %s/%s/%s kind=%s node=%s\n", targetIndex, target.Namespace, target.PodName, target.ContainerName, target.ContainerKind, target.NodeName)
	}
	targetLine, err := readNodesProxyLine(reader, stdout, "Running container index: ")
	if err != nil {
		return cancellationError("running container selection", err)
	}
	targetIndex, err := strconv.Atoi(targetLine)
	if err != nil || targetIndex < 0 || targetIndex >= len(probe.Containers) {
		return errors.New("running container index was not offered")
	}
	target := probe.Containers[targetIndex]

	commandLine, err := readNodesProxyLine(reader, stdout, "Command [id]: ")
	if err != nil {
		return cancellationError("command", err)
	}
	if commandLine == "" {
		commandLine = "id"
	}
	argv, err := parseNodesProxyCommand(commandLine)
	if err != nil {
		return fmt.Errorf("invalid command line: %w", err)
	}
	encodedArgv, _ := json.Marshal(argv)

	allowed, denied, reviewErrors, unchecked := credentialCounts(scan)
	fmt.Fprintf(stdout, "Node: %s\n", node)
	fmt.Fprintf(stdout, "Stored tokens reviewed: %d (allowed=%d denied=%d error=%d unchecked=%d)\n", len(scan.Credentials), allowed, denied, reviewErrors, unchecked)
	fmt.Fprintf(stdout, "Selected token: [%d] %s\n", selected.Credential.Credential.Index, selected.Credential.Credential.Name)
	fmt.Fprintf(stdout, "Kubelet: %s\n", origin)
	fmt.Fprintf(stdout, "get nodes/proxy: %s\n", selected.Credential.GetProxy)
	fmt.Fprintf(stdout, "create nodes/proxy: %s\n", selected.Credential.CreateProxy)
	fmt.Fprintf(stdout, "Kubelet TLS: %s\n", tlsLabel)
	fmt.Fprintf(stdout, "Direct /pods: authorized; %d running containers found\n", len(probe.Containers))
	fmt.Fprintf(stdout, "Target: %s/%s/%s\n", target.Namespace, target.PodName, target.ContainerName)
	fmt.Fprintf(stdout, "Argv: %s\n", encodedArgv)

	result, execErr := prepared.Execute(ctx, nodesproxyexec.Options{Target: target, Argv: argv})
	renderNodesProxyExecResult(stdout, result)
	if execErr != nil {
		return execErr
	}
	return nil
}

func parseNodesProxyCommand(commandLine string) ([]string, error) {
	var argv []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false

	flush := func() {
		argv = append(argv, current.String())
		current.Reset()
		tokenStarted = false
	}

	for _, character := range commandLine {
		if escaped {
			current.WriteRune(character)
			escaped = false
			tokenStarted = true
			continue
		}
		if quote != 0 {
			switch {
			case character == quote:
				quote = 0
			case quote == '"' && character == '\\':
				escaped = true
			default:
				current.WriteRune(character)
			}
			continue
		}

		switch {
		case unicode.IsSpace(character):
			if tokenStarted {
				flush()
			}
		case character == '\'' || character == '"':
			quote = character
			tokenStarted = true
		case character == '\\':
			escaped = true
			tokenStarted = true
		default:
			current.WriteRune(character)
			tokenStarted = true
		}
	}
	if escaped {
		return nil, errors.New("trailing escape")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if tokenStarted {
		flush()
	}
	if len(argv) == 0 {
		return nil, errors.New("command is empty")
	}
	return argv, nil
}

func readKubeletTLSOptions(reader *bufio.Reader, stdout, _ io.Writer, connection ServerInfo) (kube.KubeletTLSOptions, string, error) {
	caPathDefault := connection.CAPath
	if sanitizeNodesProxyDisplay(caPathDefault) != caPathDefault {
		caPathDefault = ""
	}
	const defaultMode = "insecure"
	prompt := "Kubelet TLS mode [ca-data/ca-file/insecure] [insecure]: "
	mode, err := readNodesProxyLine(reader, stdout, prompt)
	if err != nil {
		return kube.KubeletTLSOptions{}, "", cancellationError("kubelet TLS mode", err)
	}
	if mode == "" {
		mode = defaultMode
	}
	options := kube.KubeletTLSOptions{}
	switch mode {
	case "ca-data":
		if connection.CACertData == "" {
			return options, "", errors.New("active connection has no CA data for kubelet TLS")
		}
		options.CAData = []byte(connection.CACertData)
	case "ca-file":
		prompt := "Kubelet CA file: "
		if caPathDefault != "" {
			prompt = fmt.Sprintf("Kubelet CA file [%s]: ", caPathDefault)
		}
		path, readErr := readNodesProxyLine(reader, stdout, prompt)
		if readErr != nil {
			return options, "", cancellationError("kubelet CA file", readErr)
		}
		if path == "" {
			path = caPathDefault
		}
		if path == "" {
			return options, "", errors.New("kubelet CA file is required")
		}
		options.CAFile = path
	case "insecure":
		options.Insecure = true
		return options, "insecure", nil
	default:
		return options, "", errors.New("kubelet TLS mode must be ca-data, ca-file, or insecure")
	}
	serverName, err := readNodesProxyLine(reader, stdout, "Kubelet TLS server name [certificate default]: ")
	if err != nil {
		return options, "", cancellationError("kubelet TLS server name", err)
	}
	options.ServerName = serverName
	return options, "verified", nil
}

func readNodesProxyLine(reader *bufio.Reader, stdout io.Writer, prompt string) (string, error) {
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func sanitizeNodesProxyDisplay(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, value)
}

func cancellationError(field string, err error) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("nodes/proxy execution cancelled while reading %s", field)
	}
	return fmt.Errorf("read %s: %w", field, err)
}

func renderCredentialScan(stdout io.Writer, node string, scan nodesproxyexec.CredentialScan) {
	fmt.Fprintf(stdout, "Stored token RBAC results for node %s:\n", node)
	for _, result := range scan.Credentials {
		fmt.Fprintf(stdout, "[%d] name=%q method=%q get nodes/proxy=%s create nodes/proxy=%s", result.Credential.Index, result.Credential.Name, result.Credential.DiscoveryMethod, result.GetProxy, result.CreateProxy)
		if result.GetError != "" {
			fmt.Fprintf(stdout, " get-error=%q", result.GetError)
		}
		if result.CreateError != "" {
			fmt.Fprintf(stdout, " create-error=%q", result.CreateError)
		}
		fmt.Fprintln(stdout)
	}
}

func hasSelectableCredential(scan nodesproxyexec.CredentialScan, reviewsEnabled bool) bool {
	for _, result := range scan.Credentials {
		if result.GetProxy == nodesproxyexec.AccessAllowed || (!reviewsEnabled && result.GetProxy == nodesproxyexec.AccessUnchecked) {
			return true
		}
	}
	return false
}

func credentialState(scan nodesproxyexec.CredentialScan, index int) nodesproxyexec.AccessState {
	for _, result := range scan.Credentials {
		if result.Credential.Index == index {
			return result.GetProxy
		}
	}
	return ""
}

func credentialCounts(scan nodesproxyexec.CredentialScan) (allowed, denied, reviewErrors, unchecked int) {
	for _, result := range scan.Credentials {
		switch result.GetProxy {
		case nodesproxyexec.AccessAllowed:
			allowed++
		case nodesproxyexec.AccessDenied:
			denied++
		case nodesproxyexec.AccessError:
			reviewErrors++
		case nodesproxyexec.AccessUnchecked:
			unchecked++
		}
	}
	return
}

func renderNodesProxyExecResult(stdout io.Writer, result nodesproxyexec.ExecResult) {
	fmt.Fprintf(stdout, "Negotiated WebSocket protocol: %s\n", result.Protocol)
	fmt.Fprintf(stdout, "Remote exit code: %d\n", result.ExitCode)
	fmt.Fprintln(stdout, "Stdout:")
	_, _ = stdout.Write(result.Stdout)
	if len(result.Stdout) > 0 && result.Stdout[len(result.Stdout)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Stderr:")
	_, _ = stdout.Write(result.Stderr)
	if len(result.Stderr) > 0 && result.Stderr[len(result.Stderr)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "Result classification: %s\n", result.Classification)
	fmt.Fprintln(stdout, "Container execution does not by itself prove compromise of the Kubernetes node or physical host.")
}
