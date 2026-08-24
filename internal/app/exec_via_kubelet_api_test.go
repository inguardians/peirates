package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestRunningPodContainers(t *testing.T) {
	const podsJSON = `{
		"items": [
			{
				"metadata": {"name": "pod-a", "namespace": "namespace-a"},
				"status": {"containerStatuses": [
					{"name": "app", "state": {"running": {}}},
					{"name": "pause", "state": {"running": {}}},
					{"name": "stopped", "state": {}}
				]}
			},
			{
				"metadata": {"name": "pod-b", "namespace": "namespace-b"},
				"status": {"containerStatuses": [
					{"name": "sidecar", "state": {"running": {}}}
				]}
			}
		]
	}`

	var podDetails PodDetails
	if err := json.Unmarshal([]byte(podsJSON), &podDetails); err != nil {
		t.Fatalf("unmarshal pod fixture: %v", err)
	}

	want := []PodNamespaceContainerTuple{
		{PodName: "pod-a", PodNamespace: "namespace-a", ContainerName: "app"},
		{PodName: "pod-b", PodNamespace: "namespace-b", ContainerName: "sidecar"},
	}
	if got := runningPodContainers(podDetails); !reflect.DeepEqual(got, want) {
		t.Fatalf("runningPodContainers() = %#v, want %#v", got, want)
	}
}

func TestExecuteKubeletCommandEncodesArgvAndReturnsOutput(t *testing.T) {
	var gotCommand []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "" {
			t.Errorf("Content-Type = %q, want empty", got)
		}
		gotCommand = r.URL.Query()["cmd"]
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("request body = %q, want empty", body)
		}
		_, _ = w.Write([]byte("command output"))
	}))
	defer server.Close()

	output, err := executeKubeletCommand(server.URL, "cat", "/var/run/secrets/token")
	if err != nil {
		t.Fatalf("executeKubeletCommand() error = %v", err)
	}
	if output != "command output" {
		t.Fatalf("executeKubeletCommand() output = %q, want %q", output, "command output")
	}
	wantCommand := []string{"cat", "/var/run/secrets/token"}
	if !reflect.DeepEqual(gotCommand, wantCommand) {
		t.Fatalf("encoded cmd values = %#v, want %#v", gotCommand, wantCommand)
	}
}

func TestExecuteKubeletCommandReturnsHTTPError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "exec failed", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := executeKubeletCommand(server.URL, "printf", "marker")
	if err == nil {
		t.Fatal("executeKubeletCommand() error = nil, want HTTP status error")
	}
	if !strings.Contains(err.Error(), "500 Internal Server Error") {
		t.Fatalf("executeKubeletCommand() error = %q, want status", err)
	}
	if !strings.Contains(err.Error(), `"exec failed"`) {
		t.Fatalf("executeKubeletCommand() error = %q, want quoted response body", err)
	}
}

func TestExecuteKubeletCommandBoundsAndNormalizesHTTPErrorBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("first line\n\tsecond line " + strings.Repeat("x", 6000)))
	}))
	defer server.Close()

	_, err := executeKubeletCommand(server.URL, "false")
	if err == nil {
		t.Fatal("executeKubeletCommand() error = nil, want HTTP status error")
	}
	errorText := err.Error()
	if !strings.Contains(errorText, `"first line second line `) {
		t.Fatalf("executeKubeletCommand() error = %q, want normalized response body", err)
	}
	if !strings.Contains(errorText, "…") {
		t.Fatalf("executeKubeletCommand() error = %q, want truncation marker", err)
	}
	if len([]rune(errorText)) > 600 {
		t.Fatalf("executeKubeletCommand() error has %d runes, want bounded diagnostic", len([]rune(errorText)))
	}
}

func TestExecuteKubeletCommandReturnsRequestError(t *testing.T) {
	_, err := executeKubeletCommand("://bad-url", "printf", "marker")
	if err == nil {
		t.Fatal("executeKubeletCommand() error = nil, want request construction error")
	}
}
