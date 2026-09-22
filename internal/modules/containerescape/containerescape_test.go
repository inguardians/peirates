package containerescape

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeOptions(t *testing.T) {
	explicit := []string{"/test.sock"}
	options := normalizeOptions(Options{DockerSockets: explicit})
	explicit[0] = "/changed.sock"
	if options.DockerSockets[0] != "/test.sock" {
		t.Fatal("normalizeOptions retained caller-owned slice")
	}
	if options.DockerTimeout != defaultDockerTimeout || options.DockerMaxResponseSize != defaultDockerMaxBytes {
		t.Fatalf("defaults = %#v", options)
	}
	custom := normalizeOptions(Options{DockerTimeout: 3 * time.Second, DockerMaxResponseSize: 123})
	if custom.DockerTimeout != 3*time.Second || custom.DockerMaxResponseSize != 123 {
		t.Fatalf("custom options = %#v", custom)
	}
}

func TestUnsupportedFindingsAreComplete(t *testing.T) {
	findings := unsupportedFindings()
	if len(findings) != 7 {
		t.Fatalf("finding count = %d", len(findings))
	}
	wantOrder := []string{
		TechniqueHostPID,
		TechniqueHostRoot,
		TechniqueHostLogSymlinkRead,
		TechniqueDockerSocket,
		TechniqueCgroupRelease,
		TechniqueCorePattern,
		TechniqueHostPIDPtrace,
	}
	gotOrder := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Technique == "" || finding.Summary == "" || finding.Status != "unsupported" {
			t.Fatalf("finding = %#v", finding)
		}
		gotOrder = append(gotOrder, finding.Technique)
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("technique order = %#v, want %#v", gotOrder, wantOrder)
	}
}
