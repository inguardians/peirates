package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	remotecommandconstants "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
)

const (
	// DefaultKubeletReadTimeout bounds direct kubelet read-only requests.
	DefaultKubeletReadTimeout = 10 * time.Second
	// DefaultKubeletCommandTimeout bounds one direct kubelet exec session.
	DefaultKubeletCommandTimeout = 30 * time.Second
	// DefaultKubeletPodResponseLimit bounds the kubelet /pods response.
	DefaultKubeletPodResponseLimit int64 = 8 << 20
	// DefaultKubeletOutputLimit bounds stdout and stderr together.
	DefaultKubeletOutputLimit int64 = 1 << 20
	// DefaultKubeletErrorDetailLimit bounds retained server error details.
	DefaultKubeletErrorDetailLimit int64 = 4 << 10
	// MaxKubeletCommandArgs bounds the number of argv entries sent to kubelet.
	MaxKubeletCommandArgs = 256
	// MaxKubeletCommandBytes bounds the aggregate number of argv bytes.
	MaxKubeletCommandBytes = 64 << 10
)

var (
	// ErrKubeletPodResponseTooLarge identifies an oversized /pods response.
	ErrKubeletPodResponseTooLarge = errors.New("kubelet pods response exceeds configured limit")
	// ErrKubeletOutputLimit identifies command output that reached the combined bound.
	ErrKubeletOutputLimit = errors.New("kubelet command output exceeds configured limit")
)

// KubeletTLSOptions describes TLS settings used only for the direct kubelet.
// It is intentionally separate from ServerInfo because API server and kubelet
// serving certificates can use different authorities and names.
type KubeletTLSOptions struct {
	CAData     []byte
	CAFile     string
	ServerName string
	Insecure   bool
}

// KubeletClientOptions configures one selected stored token for one direct
// kubelet origin. Zero bounds and timeouts select the documented defaults.
type KubeletClientOptions struct {
	Origin           string
	BearerToken      string
	TLS              KubeletTLSOptions
	ReadTimeout      time.Duration
	CommandTimeout   time.Duration
	PodResponseLimit int64
	OutputLimit      int64
	ErrorDetailLimit int64
}

// KubeletContainerKind identifies which pod container collection owns a
// running status.
type KubeletContainerKind string

const (
	KubeletContainerRegular   KubeletContainerKind = "regular"
	KubeletContainerInit      KubeletContainerKind = "init"
	KubeletContainerEphemeral KubeletContainerKind = "ephemeral"
)

// KubeletContainer is a running target reported by the selected kubelet.
type KubeletContainer struct {
	NodeName      string
	Namespace     string
	PodName       string
	ContainerName string
	Kind          KubeletContainerKind
}

// KubeletExecStatus describes a completed remote command. ExitCode is -1
// until a completion status is known.
type KubeletExecStatus struct {
	ExitCode int
	Protocol string
}

// KubeletHTTPStatusError describes a bounded, sanitized non-success response.
type KubeletHTTPStatusError struct {
	StatusCode      int
	Status          string
	Detail          string
	DetailTruncated bool
}

func (e *KubeletHTTPStatusError) Error() string {
	message := fmt.Sprintf("kubelet returned %s", e.Status)
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	if e.DetailTruncated {
		message += " (detail truncated)"
	}
	return message
}

type kubeletStreamExecutor interface {
	StreamWithContext(context.Context, remotecommand.StreamOptions) error
}

type kubeletExecutorFactory func(*rest.Config, string, string, ...string) (kubeletStreamExecutor, func() string, error)

// KubeletClient performs bounded, GET-only requests against one direct
// kubelet origin with one selected bearer token.
type KubeletClient struct {
	origin           *url.URL
	token            string
	restConfig       *rest.Config
	httpClient       *http.Client
	readTimeout      time.Duration
	commandTimeout   time.Duration
	podResponseLimit int64
	outputLimit      int64
	errorDetailLimit int64
	newExecutor      kubeletExecutorFactory
}

// NewKubeletClient validates options and constructs a direct kubelet client.
func NewKubeletClient(options KubeletClientOptions) (*KubeletClient, error) {
	origin, err := parseKubeletOrigin(options.Origin)
	if err != nil {
		return nil, err
	}
	if options.BearerToken == "" {
		return nil, errors.New("kubelet bearer token is empty")
	}
	if strings.TrimSpace(options.BearerToken) != options.BearerToken || strings.ContainsAny(options.BearerToken, "\r\n") {
		return nil, errors.New("kubelet bearer token contains whitespace")
	}

	readTimeout, err := positiveDurationOrDefault("read", options.ReadTimeout, DefaultKubeletReadTimeout)
	if err != nil {
		return nil, err
	}
	commandTimeout, err := positiveDurationOrDefault("command", options.CommandTimeout, DefaultKubeletCommandTimeout)
	if err != nil {
		return nil, err
	}
	podLimit, err := positiveLimitOrDefault("pods response", options.PodResponseLimit, DefaultKubeletPodResponseLimit)
	if err != nil {
		return nil, err
	}
	outputLimit, err := positiveLimitOrDefault("command output", options.OutputLimit, DefaultKubeletOutputLimit)
	if err != nil {
		return nil, err
	}
	errorLimit, err := positiveLimitOrDefault("error detail", options.ErrorDetailLimit, DefaultKubeletErrorDetailLimit)
	if err != nil {
		return nil, err
	}

	config := &rest.Config{
		Host:        origin.String(),
		BearerToken: options.BearerToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   options.TLS.Insecure, // #nosec G402 -- set only by the explicit kubelet-specific operator choice.
			ServerName: options.TLS.ServerName,
			CAFile:     options.TLS.CAFile,
			CAData:     append([]byte(nil), options.TLS.CAData...),
			NextProtos: []string{"http/1.1"},
		},
	}
	transport, err := rest.TransportFor(config)
	if err != nil {
		return nil, fmt.Errorf("configure kubelet transport: %w", err)
	}

	return &KubeletClient{
		origin:           origin,
		token:            options.BearerToken,
		restConfig:       config,
		httpClient:       &http.Client{Transport: transport, CheckRedirect: rejectKubeletRedirect},
		readTimeout:      readTimeout,
		commandTimeout:   commandTimeout,
		podResponseLimit: podLimit,
		outputLimit:      outputLimit,
		errorDetailLimit: errorLimit,
		newExecutor:      newKubeletWebSocketExecutor,
	}, nil
}

// Probe verifies that the selected credential and TLS configuration can read
// and decode the direct kubelet /pods endpoint.
func (c *KubeletClient) Probe(ctx context.Context) error {
	_, err := c.listPods(ctx)
	return err
}

// ListRunningContainers returns regular, init, and ephemeral containers whose
// current status is running.
func (c *KubeletClient) ListRunningContainers(ctx context.Context) ([]KubeletContainer, error) {
	pods, err := c.listPods(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]KubeletContainer, 0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		targets = appendRunningStatuses(targets, pod, pod.Status.ContainerStatuses, KubeletContainerRegular)
		targets = appendRunningStatuses(targets, pod, pod.Status.InitContainerStatuses, KubeletContainerInit)
		targets = appendRunningStatuses(targets, pod, pod.Status.EphemeralContainerStatuses, KubeletContainerEphemeral)
	}
	sort.Slice(targets, func(i, j int) bool {
		left, right := targets[i], targets[j]
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.PodName != right.PodName {
			return left.PodName < right.PodName
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.ContainerName < right.ContainerName
	})
	return targets, nil
}

// Exec runs one non-interactive command over a WebSocket HTTP GET. It never
// retries with POST or SPDY.
func (c *KubeletClient) Exec(ctx context.Context, target KubeletContainer, argv []string, stdout, stderr io.Writer) (KubeletExecStatus, error) {
	status := KubeletExecStatus{ExitCode: -1}
	if ctx == nil {
		return status, errors.New("kubelet exec context is nil")
	}
	if err := validateKubeletTarget(target); err != nil {
		return status, err
	}
	if err := validateKubeletArgv(argv); err != nil {
		return status, err
	}
	if stdout == nil || stderr == nil {
		return status, errors.New("kubelet exec requires stdout and stderr writers")
	}

	execURL := *c.origin
	execURL.Path = "/exec/" + target.Namespace + "/" + target.PodName + "/" + target.ContainerName
	values := make(url.Values, len(argv)+4)
	values.Set("input", "0")
	values.Set("output", "1")
	values.Set("error", "1")
	values.Set("tty", "0")
	for _, argument := range argv {
		values.Add("command", argument)
	}
	execURL.RawQuery = values.Encode()

	executor, negotiatedProtocol, err := c.newExecutor(
		c.restConfig,
		http.MethodGet,
		execURL.String(),
		remotecommandconstants.StreamProtocolV5Name,
		remotecommandconstants.StreamProtocolV4Name,
		remotecommandconstants.StreamProtocolV3Name,
		remotecommandconstants.StreamProtocolV2Name,
		remotecommandconstants.StreamProtocolV1Name,
	)
	if err != nil {
		return status, sanitizeKubeletError("create kubelet WebSocket executor", err, c.token, c.errorDetailLimit)
	}

	execContext, cancel := context.WithTimeout(ctx, c.commandTimeout)
	defer cancel()
	budget := &combinedOutputBudget{remaining: c.outputLimit, cancel: cancel}
	err = executor.StreamWithContext(execContext, remotecommand.StreamOptions{
		Stdout: budget.writer(stdout),
		Stderr: budget.writer(stderr),
		Tty:    false,
	})
	status.Protocol = negotiatedProtocol()
	if budget.wasExceeded() {
		return status, ErrKubeletOutputLimit
	}
	if err == nil {
		if status.Protocol == "" {
			return status, errors.New("kubelet WebSocket completed without a negotiated protocol")
		}
		status.ExitCode = 0
		return status, nil
	}
	var exitError utilexec.ExitError
	if errors.As(err, &exitError) && exitError.Exited() {
		if status.Protocol == "" {
			return status, errors.New("kubelet WebSocket returned an exit status without a negotiated protocol")
		}
		status.ExitCode = exitError.ExitStatus()
		return status, nil
	}
	if execContext.Err() != nil {
		return status, execContext.Err()
	}
	return status, sanitizeKubeletError("execute kubelet WebSocket command", err, c.token, c.errorDetailLimit)
}

func (c *KubeletClient) listPods(ctx context.Context) (*corev1.PodList, error) {
	if ctx == nil {
		return nil, errors.New("kubelet pods context is nil")
	}
	requestContext, cancel := context.WithTimeout(ctx, c.readTimeout)
	defer cancel()
	defer c.httpClient.CloseIdleConnections()
	requestURL := *c.origin
	requestURL.Path = "/pods"
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build kubelet pods request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.httpClient.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return nil, requestContext.Err()
		}
		return nil, sanitizeKubeletError("perform kubelet pods request", err, c.token, c.errorDetailLimit)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, kubeletStatusError(response, c.errorDetailLimit, c.token)
	}
	body, err := readBounded(response.Body, c.podResponseLimit)
	if err != nil {
		if errors.Is(err, ErrRawResponseTooLarge) {
			return nil, ErrKubeletPodResponseTooLarge
		}
		return nil, fmt.Errorf("read kubelet pods response: %w", err)
	}
	var pods corev1.PodList
	if err := json.Unmarshal(body, &pods); err != nil {
		return nil, fmt.Errorf("decode kubelet pods response: %w", err)
	}
	return &pods, nil
}

func appendRunningStatuses(targets []KubeletContainer, pod *corev1.Pod, statuses []corev1.ContainerStatus, kind KubeletContainerKind) []KubeletContainer {
	for i := range statuses {
		if statuses[i].State.Running == nil {
			continue
		}
		targets = append(targets, KubeletContainer{
			NodeName:      pod.Spec.NodeName,
			Namespace:     pod.Namespace,
			PodName:       pod.Name,
			ContainerName: statuses[i].Name,
			Kind:          kind,
		})
	}
	return targets
}

func parseKubeletOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse kubelet origin: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("kubelet origin must use https")
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("kubelet origin must contain only an HTTPS host and explicit port")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("kubelet origin must not contain a path")
	}
	if parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("kubelet origin must not contain an escaped path, query, or fragment")
	}
	port := parsed.Port()
	if port == "" {
		return nil, errors.New("kubelet origin requires an explicit port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, errors.New("kubelet origin port must be between 1 and 65535")
	}
	parsed.Path = ""
	return parsed, nil
}

func positiveDurationOrDefault(name string, value, defaultValue time.Duration) (time.Duration, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < 0 {
		return 0, fmt.Errorf("kubelet %s timeout must be positive", name)
	}
	return value, nil
}

func positiveLimitOrDefault(name string, value, defaultValue int64) (int64, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < 0 || value == math.MaxInt64 {
		return 0, fmt.Errorf("kubelet %s limit must be positive and bounded", name)
	}
	return value, nil
}

func rejectKubeletRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func kubeletStatusError(response *http.Response, limit int64, token string) error {
	detail, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil {
		return fmt.Errorf("read kubelet error response: %w", readErr)
	}
	truncated := int64(len(detail)) > limit
	if truncated {
		detail = detail[:limit]
	}
	sanitized, sanitizedTruncated := sanitizeErrorDetail(detail, token, limit)
	return &KubeletHTTPStatusError{
		StatusCode:      response.StatusCode,
		Status:          fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)),
		Detail:          sanitized,
		DetailTruncated: truncated || sanitizedTruncated,
	}
}

func validateKubeletTarget(target KubeletContainer) error {
	components := []struct {
		name  string
		value string
	}{
		{name: "node", value: target.NodeName},
		{name: "namespace", value: target.Namespace},
		{name: "pod", value: target.PodName},
		{name: "container", value: target.ContainerName},
	}
	for _, component := range components {
		if component.value == "" || strings.ContainsAny(component.value, "/\x00") {
			return fmt.Errorf("kubelet target %s must be non-empty and contain no slash or NUL", component.name)
		}
	}
	switch target.Kind {
	case KubeletContainerRegular, KubeletContainerInit, KubeletContainerEphemeral:
	default:
		return errors.New("kubelet target container kind is invalid")
	}
	return nil
}

func validateKubeletArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("kubelet command argv is empty")
	}
	if len(argv) > MaxKubeletCommandArgs {
		return fmt.Errorf("kubelet command has more than %d arguments", MaxKubeletCommandArgs)
	}
	var total int64
	for _, argument := range argv {
		if strings.ContainsRune(argument, '\x00') {
			return errors.New("kubelet command argument contains NUL")
		}
		total += int64(len(argument))
		if total > MaxKubeletCommandBytes {
			return fmt.Errorf("kubelet command arguments exceed %d bytes", MaxKubeletCommandBytes)
		}
	}
	return nil
}

func newKubeletWebSocketExecutor(config *rest.Config, method, requestURL string, protocols ...string) (kubeletStreamExecutor, func() string, error) {
	capture := &protocolCapture{}
	copyConfig := rest.CopyConfig(config)
	copyConfig.Wrap(func(roundTripper http.RoundTripper) http.RoundTripper {
		return captureRoundTripper{base: roundTripper, capture: capture}
	})
	executor, err := remotecommand.NewWebSocketExecutorForProtocols(copyConfig, method, requestURL, protocols...)
	return executor, capture.get, err
}

type protocolCapture struct {
	mu       sync.Mutex
	protocol string
}

func (c *protocolCapture) set(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.protocol = protocol
}

func (c *protocolCapture) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.protocol
}

type captureRoundTripper struct {
	base    http.RoundTripper
	capture *protocolCapture
}

func (r captureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if response != nil {
		r.capture.set(response.Header.Get("Sec-WebSocket-Protocol"))
	}
	return response, err
}

type combinedOutputBudget struct {
	mu        sync.Mutex
	remaining int64
	cancel    context.CancelFunc
	exceeded  bool
}

func (b *combinedOutputBudget) writer(destination io.Writer) io.Writer {
	return outputBudgetWriter{budget: b, destination: destination}
}

func (b *combinedOutputBudget) wasExceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

type outputBudgetWriter struct {
	budget      *combinedOutputBudget
	destination io.Writer
}

func (w outputBudgetWriter) Write(content []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	if w.budget.exceeded {
		return 0, ErrKubeletOutputLimit
	}
	allowed := int64(len(content))
	if allowed > w.budget.remaining {
		allowed = w.budget.remaining
	}
	written := 0
	var err error
	if allowed > 0 {
		written, err = w.destination.Write(content[:allowed])
		w.budget.remaining -= int64(written)
	}
	if err != nil {
		return written, err
	}
	if written != int(allowed) {
		return written, io.ErrShortWrite
	}
	if allowed < int64(len(content)) {
		w.budget.exceeded = true
		w.budget.cancel()
		return written, ErrKubeletOutputLimit
	}
	return written, nil
}

func sanitizeKubeletError(prefix string, err error, token string, limit int64) error {
	message, _ := sanitizeErrorDetail([]byte(err.Error()), token, limit)
	if message == "" {
		message = "request failed"
	}
	return fmt.Errorf("%s: %s", prefix, message)
}
