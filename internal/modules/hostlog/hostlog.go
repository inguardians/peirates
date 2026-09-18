// Package hostlog implements a bounded single-file read through a writable
// host /var/log mount and an injected kubelet log fetcher.
package hostlog

import (
	"context"
	"errors"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

const Technique = "hostlog-symlink-read"

// ErrUnsupported is returned when the host-log primitive is unavailable on
// the current operating system.
var ErrUnsupported = errors.New("host-log symlink read is supported only on Linux")

// Fetcher verifies and reads from a kubelet-compatible log endpoint. Paths
// passed to Read are slash-separated components relative to kubelet /logs/.
type Fetcher interface {
	Probe(context.Context) error
	Read(context.Context, string) ([]byte, error)
}

// Options describes one explicit host-file read. RunID is an optional
// deterministic test seam; production callers should leave it empty.
type Options struct {
	MountPoint string
	TargetPath string
	RunID      string
	Fetcher    Fetcher
}

// Result contains the exact response and the paths used for one completed
// read. Content is returned only after the temporary symlink is removed.
type Result struct {
	MountPoint             string
	HostLogRoot            string
	HostPathOriginUnproven bool
	LogPath                string
	Content                []byte
}

// Probe performs a strictly read-only local prerequisite assessment.
func Probe(ctx context.Context) ([]escapeutil.Finding, error) {
	return probePlatform(ctx)
}

// ReadFile reads one explicitly selected absolute host path and removes its
// temporary symlink before returning any content.
func ReadFile(ctx context.Context, options Options) (Result, error) {
	return readFilePlatform(ctx, options)
}
