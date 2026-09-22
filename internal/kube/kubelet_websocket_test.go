package kube

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 is required by the WebSocket handshake in this test.
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	remotecommandconstants "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
)

func TestNewKubeletClientValidatesAndDefaultsOptions(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		token  string
		ok     bool
	}{
		{name: "valid DNS", origin: "https://worker.example:10250", token: "token", ok: true},
		{name: "valid IPv6", origin: "https://[2001:db8::1]:10250/", token: "token", ok: true},
		{name: "http", origin: "http://worker.example:10250", token: "token"},
		{name: "missing port", origin: "https://worker.example", token: "token"},
		{name: "userinfo", origin: "https://user@worker.example:10250", token: "token"},
		{name: "path", origin: "https://worker.example:10250/pods", token: "token"},
		{name: "query", origin: "https://worker.example:10250/?x=1", token: "token"},
		{name: "fragment", origin: "https://worker.example:10250/#x", token: "token"},
		{name: "empty token", origin: "https://worker.example:10250"},
		{name: "token newline", origin: "https://worker.example:10250", token: "token\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewKubeletClient(KubeletClientOptions{Origin: test.origin, BearerToken: test.token})
			if (err == nil) != test.ok {
				t.Fatalf("NewKubeletClient() error = %v, want success %v", err, test.ok)
			}
			if !test.ok {
				return
			}
			if client.readTimeout != DefaultKubeletReadTimeout || client.commandTimeout != DefaultKubeletCommandTimeout || client.podResponseLimit != DefaultKubeletPodResponseLimit || client.outputLimit != DefaultKubeletOutputLimit || client.errorDetailLimit != DefaultKubeletErrorDetailLimit {
				t.Fatalf("defaults not applied: %#v", client)
			}
			if client.origin.Path != "" || client.origin.RawQuery != "" {
				t.Fatalf("origin not normalized: %q", client.origin.String())
			}
		})
	}

	invalidOptions := []KubeletClientOptions{
		{Origin: "https://worker.example:10250", BearerToken: "token", ReadTimeout: -1},
		{Origin: "https://worker.example:10250", BearerToken: "token", CommandTimeout: -1},
		{Origin: "https://worker.example:10250", BearerToken: "token", PodResponseLimit: -1},
		{Origin: "https://worker.example:10250", BearerToken: "token", OutputLimit: -1},
		{Origin: "https://worker.example:10250", BearerToken: "token", ErrorDetailLimit: -1},
	}
	for _, options := range invalidOptions {
		if _, err := NewKubeletClient(options); err == nil {
			t.Fatalf("NewKubeletClient(%#v) unexpectedly succeeded", options)
		}
	}
}

func TestNewKubeletClientKeepsTLSSeparate(t *testing.T) {
	caData := []byte("not parsed until transport construction")
	_, err := NewKubeletClient(KubeletClientOptions{
		Origin:      "https://worker.example:10250",
		BearerToken: "token",
		TLS:         KubeletTLSOptions{CAData: caData, ServerName: "kubelet.internal"},
	})
	if err == nil {
		t.Fatal("invalid kubelet CA unexpectedly succeeded")
	}

	client, err := NewKubeletClient(KubeletClientOptions{
		Origin:      "https://worker.example:10250",
		BearerToken: "token",
		TLS:         KubeletTLSOptions{Insecure: true, ServerName: "kubelet.internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !client.restConfig.TLSClientConfig.Insecure || client.restConfig.TLSClientConfig.ServerName != "kubelet.internal" {
		t.Fatalf("TLS config = %#v", client.restConfig.TLSClientConfig)
	}
	if got := client.restConfig.TLSClientConfig.NextProtos; !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("NextProtos = %#v", got)
	}
}

func TestKubeletClientVerifiedTLSAndBearerAuthentication(t *testing.T) {
	caData, serverCertificate, _, _ := makeMutualTLSCertificates(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.TLS == nil || request.TLS.Version < tls.VersionTLS12 {
				t.Errorf("TLS version = %#v", request.TLS)
			}
			if request.URL.Path != "/pods" || request.Header.Get("Authorization") != "Bearer selected-token" {
				t.Errorf("request path = %q, Authorization = %q", request.URL.Path, request.Header.Get("Authorization"))
			}
			_, _ = writer.Write([]byte(`{"apiVersion":"v1","kind":"PodList","items":[]}`))
		})},
		TLS: &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12},
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewKubeletClient(KubeletClientOptions{
		Origin:      server.URL,
		BearerToken: "selected-token",
		TLS:         KubeletTLSOptions{CAData: []byte(caData)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListRunningContainers(context.Background()); err != nil {
		t.Fatalf("verified request failed: %v", err)
	}

	untrusted, err := NewKubeletClient(KubeletClientOptions{Origin: server.URL, BearerToken: "selected-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.ListRunningContainers(context.Background()); err == nil {
		t.Fatal("untrusted kubelet certificate unexpectedly succeeded")
	}
}

func TestListRunningContainersIsBoundedFilteredAndSorted(t *testing.T) {
	client := newTestKubeletClient(t)
	pods := corev1.PodList{Items: []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "worker-a"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "z", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
					{Name: "stopped", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}},
				},
				InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
				EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "ns"},
			Spec:       corev1.PodSpec{NodeName: "worker-a"},
			Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
		},
	}}
	body, err := json.Marshal(pods)
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/pods" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer selected-token" {
			t.Fatalf("Authorization = %q", got)
		}
		return response(http.StatusOK, body), nil
	})

	targets, err := client.ListRunningContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []KubeletContainer{
		{NodeName: "worker-a", Namespace: "ns", PodName: "pod-a", ContainerName: "app", Kind: KubeletContainerRegular},
		{NodeName: "worker-a", Namespace: "ns", PodName: "pod-b", ContainerName: "debug", Kind: KubeletContainerEphemeral},
		{NodeName: "worker-a", Namespace: "ns", PodName: "pod-b", ContainerName: "init", Kind: KubeletContainerInit},
		{NodeName: "worker-a", Namespace: "ns", PodName: "pod-b", ContainerName: "z", Kind: KubeletContainerRegular},
	}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets = %#v, want %#v", targets, want)
	}
	if err := client.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	client.podResponseLimit = int64(len(body) - 1)
	if _, err := client.ListRunningContainers(context.Background()); !errors.Is(err, ErrKubeletPodResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestListRunningContainersRejectsRedirectAndSanitizesErrors(t *testing.T) {
	client := newTestKubeletClient(t)
	token := client.token
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, []byte("denied for "+token+"\x00")), nil
	})
	_, err := client.ListRunningContainers(context.Background())
	var statusError *KubeletHTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusForbidden {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), token) || strings.ContainsRune(err.Error(), '\x00') {
		t.Fatalf("error leaked token or control characters: %q", err)
	}

	redirectResponse := response(http.StatusFound, nil)
	redirectResponse.Header.Set("Location", "https://other.example:10250/pods")
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return redirectResponse, nil })
	_, err = client.ListRunningContainers(context.Background())
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusFound {
		t.Fatalf("redirect error = %#v", err)
	}
	if got := rejectKubeletRedirect(nil, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy = %v", got)
	}

	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport reflected " + token)
	})
	_, err = client.ListRunningContainers(context.Background())
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("transport error leaked token: %q", err)
	}
}

func TestKubeletExecUsesGETStructuredURLAndProtocols(t *testing.T) {
	client := newTestKubeletClient(t)
	var calls int
	client.newExecutor = func(config *rest.Config, method, requestURL string, protocols ...string) (kubeletStreamExecutor, func() string, error) {
		calls++
		if config.BearerToken != "selected-token" {
			t.Fatalf("BearerToken = %q", config.BearerToken)
		}
		if method != http.MethodGet {
			t.Fatalf("method = %q, want GET", method)
		}
		parsed, err := url.Parse(requestURL)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Path != "/exec/ns/pod/container" {
			t.Fatalf("path = %q", parsed.Path)
		}
		if got := parsed.Query()["command"]; !reflect.DeepEqual(got, []string{"/bin/sh", "-c", "printf alpha & beta"}) {
			t.Fatalf("command query = %#v", got)
		}
		for name, want := range map[string]string{"input": "0", "output": "1", "error": "1", "tty": "0"} {
			if got := parsed.Query().Get(name); got != want {
				t.Fatalf("query %s = %q, want %q", name, got, want)
			}
		}
		wantProtocols := []string{
			remotecommandconstants.StreamProtocolV5Name,
			remotecommandconstants.StreamProtocolV4Name,
			remotecommandconstants.StreamProtocolV3Name,
			remotecommandconstants.StreamProtocolV2Name,
			remotecommandconstants.StreamProtocolV1Name,
		}
		if !reflect.DeepEqual(protocols, wantProtocols) {
			t.Fatalf("protocols = %#v", protocols)
		}
		return streamExecutorFunc(func(_ context.Context, options remotecommand.StreamOptions) error {
			if options.Stdin != nil || options.Tty || options.Stdout == nil || options.Stderr == nil {
				t.Fatalf("stream options = %#v", options)
			}
			_, _ = options.Stdout.Write([]byte("out"))
			_, _ = options.Stderr.Write([]byte("err"))
			return nil
		}), func() string { return remotecommandconstants.StreamProtocolV5Name }, nil
	}
	var stdout, stderr bytes.Buffer
	status, err := client.Exec(context.Background(), testKubeletTarget(), []string{"/bin/sh", "-c", "printf alpha & beta"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || status.ExitCode != 0 || status.Protocol != remotecommandconstants.StreamProtocolV5Name || stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("calls = %d, status = %#v, stdout = %q, stderr = %q", calls, status, stdout.String(), stderr.String())
	}
}

func TestKubeletExecNegotiatesRealGETWebSocket(t *testing.T) {
	caData, serverCertificate, _, _ := makeMutualTLSCertificates(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != "/exec/ns/pod/container" {
				t.Errorf("request = %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("Authorization") != "Bearer selected-token" {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			if got := request.URL.Query()["command"]; !reflect.DeepEqual(got, []string{"id"}) {
				t.Errorf("command query = %#v", got)
			}
			connection, buffered, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer connection.Close()
			acceptInput := request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
			acceptHash := sha1.Sum([]byte(acceptInput)) // #nosec G401 -- required by RFC 6455.
			_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n", base64.StdEncoding.EncodeToString(acceptHash[:]), remotecommandconstants.StreamProtocolV5Name)
			writeTestWebSocketFrame(t, buffered, 0x82, append([]byte{1}, []byte("out")...))
			writeTestWebSocketFrame(t, buffered, 0x82, append([]byte{2}, []byte("err")...))
			writeTestWebSocketFrame(t, buffered, 0x82, append([]byte{3}, []byte(`{"status":"Success"}`)...))
			writeTestWebSocketFrame(t, buffered, 0x88, []byte{0x03, 0xe8})
			if err := buffered.Flush(); err != nil {
				t.Errorf("flush websocket frames: %v", err)
			}
		})},
		TLS: &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12},
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewKubeletClient(KubeletClientOptions{
		Origin:      server.URL,
		BearerToken: "selected-token",
		TLS:         KubeletTLSOptions{CAData: []byte(caData)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status, err := client.Exec(context.Background(), testKubeletTarget(), []string{"id"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if status.ExitCode != 0 || status.Protocol != remotecommandconstants.StreamProtocolV5Name || stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("status = %#v, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
}

func TestKubeletExecExitOutputTimeoutAndSanitizedErrors(t *testing.T) {
	t.Run("exit status", func(t *testing.T) {
		client := newTestKubeletClient(t)
		client.newExecutor = executorFactoryForTest(func(context.Context, remotecommand.StreamOptions) error {
			return utilexec.CodeExitError{Err: errors.New("exit 17"), Code: 17}
		}, remotecommandconstants.StreamProtocolV4Name)
		status, err := client.Exec(context.Background(), testKubeletTarget(), []string{"false"}, io.Discard, io.Discard)
		if err != nil || status.ExitCode != 17 || status.Protocol != remotecommandconstants.StreamProtocolV4Name {
			t.Fatalf("status = %#v, err = %v", status, err)
		}
	})

	t.Run("combined output limit", func(t *testing.T) {
		client := newTestKubeletClient(t)
		client.outputLimit = 5
		client.newExecutor = executorFactoryForTest(func(_ context.Context, options remotecommand.StreamOptions) error {
			_, _ = options.Stdout.Write([]byte("1234"))
			_, err := options.Stderr.Write([]byte("5678"))
			return err
		}, remotecommandconstants.StreamProtocolV5Name)
		var stdout, stderr bytes.Buffer
		_, err := client.Exec(context.Background(), testKubeletTarget(), []string{"id"}, &stdout, &stderr)
		if !errors.Is(err, ErrKubeletOutputLimit) || stdout.String() != "1234" || stderr.String() != "5" {
			t.Fatalf("stdout = %q, stderr = %q, err = %v", stdout.String(), stderr.String(), err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		client := newTestKubeletClient(t)
		client.commandTimeout = time.Millisecond
		client.newExecutor = executorFactoryForTest(func(ctx context.Context, _ remotecommand.StreamOptions) error {
			<-ctx.Done()
			return ctx.Err()
		}, "")
		_, err := client.Exec(context.Background(), testKubeletTarget(), []string{"id"}, io.Discard, io.Discard)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("sanitize handshake error", func(t *testing.T) {
		client := newTestKubeletClient(t)
		token := client.token
		client.newExecutor = func(*rest.Config, string, string, ...string) (kubeletStreamExecutor, func() string, error) {
			return nil, func() string { return "" }, errors.New("server reflected " + token + "\x00")
		}
		_, err := client.Exec(context.Background(), testKubeletTarget(), []string{"id"}, io.Discard, io.Discard)
		if err == nil || strings.Contains(err.Error(), token) || strings.ContainsRune(err.Error(), '\x00') {
			t.Fatalf("error was not sanitized: %q", err)
		}
	})
}

func TestKubeletExecValidatesTargetArgvAndCompletion(t *testing.T) {
	client := newTestKubeletClient(t)
	client.newExecutor = executorFactoryForTest(func(context.Context, remotecommand.StreamOptions) error { return nil }, "")
	tests := []struct {
		name   string
		target KubeletContainer
		argv   []string
		stdout io.Writer
		stderr io.Writer
	}{
		{name: "empty node", target: KubeletContainer{Namespace: "ns", PodName: "pod", ContainerName: "container"}, argv: []string{"id"}, stdout: io.Discard, stderr: io.Discard},
		{name: "slash", target: KubeletContainer{NodeName: "node", Namespace: "ns/x", PodName: "pod", ContainerName: "container"}, argv: []string{"id"}, stdout: io.Discard, stderr: io.Discard},
		{name: "invalid kind", target: KubeletContainer{NodeName: "node", Namespace: "ns", PodName: "pod", ContainerName: "container"}, argv: []string{"id"}, stdout: io.Discard, stderr: io.Discard},
		{name: "empty argv", target: testKubeletTarget(), stdout: io.Discard, stderr: io.Discard},
		{name: "NUL argv", target: testKubeletTarget(), argv: []string{"a\x00b"}, stdout: io.Discard, stderr: io.Discard},
		{name: "nil stdout", target: testKubeletTarget(), argv: []string{"id"}, stderr: io.Discard},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Exec(context.Background(), test.target, test.argv, test.stdout, test.stderr); err == nil {
				t.Fatal("Exec() unexpectedly succeeded")
			}
		})
	}
	if _, err := client.Exec(context.Background(), testKubeletTarget(), []string{"id"}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "without a negotiated protocol") {
		t.Fatalf("missing protocol error = %v", err)
	}
}

func TestResourceAttributesNameJSON(t *testing.T) {
	withName, err := json.Marshal(ResourceAttributes{Verb: "get", Resource: "nodes", Subresource: "proxy", Name: "worker-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(withName, []byte(`"name":"worker-a"`)) {
		t.Fatalf("resource attributes = %s", withName)
	}
	withoutName, err := json.Marshal(ResourceAttributes{Verb: "get", Resource: "pods"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(withoutName, []byte(`"name"`)) {
		t.Fatalf("empty name was serialized: %s", withoutName)
	}
}

func newTestKubeletClient(t *testing.T) *KubeletClient {
	t.Helper()
	client, err := NewKubeletClient(KubeletClientOptions{
		Origin:      "https://worker.example:10250",
		BearerToken: "selected-token",
		TLS:         KubeletTLSOptions{Insecure: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testKubeletTarget() KubeletContainer {
	return KubeletContainer{NodeName: "worker-a", Namespace: "ns", PodName: "pod", ContainerName: "container", Kind: KubeletContainerRegular}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(statusCode int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

type streamExecutorFunc func(context.Context, remotecommand.StreamOptions) error

func (f streamExecutorFunc) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	return f(ctx, options)
}

func executorFactoryForTest(stream streamExecutorFunc, protocol string) kubeletExecutorFactory {
	return func(*rest.Config, string, string, ...string) (kubeletStreamExecutor, func() string, error) {
		return stream, func() string { return protocol }, nil
	}
}

func writeTestWebSocketFrame(t *testing.T, destination io.Writer, opcode byte, payload []byte) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatalf("test websocket payload too large: %d", len(payload))
	}
	if _, err := destination.Write(append([]byte{opcode, byte(len(payload))}, payload...)); err != nil {
		t.Fatalf("write websocket frame: %v", err)
	}
}
