// Package containerescape performs a strictly read-only assessment of local
// container escape prerequisites.
package containerescape

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

const (
	TechniqueHostPID            = "hostpid-breakout"
	TechniqueHostRoot           = "hostroot-breakout"
	TechniqueHostLogSymlinkRead = "hostlog-symlink-read"
	TechniqueDockerSocket       = "docker-socket-breakout"
	TechniqueCgroupRelease      = "cgroup-release-agent-breakout"
	TechniqueCorePattern        = "hostproc-core-pattern-breakout"
	TechniqueHostPIDPtrace      = "hostpid-ptrace-breakout"
)

const (
	defaultDockerTimeout  = 2 * time.Second
	defaultDockerMaxBytes = int64(64 * 1024)
)

// Options configures bounded read-only assessment. DockerSockets adds
// explicitly requested absolute Unix socket paths; it does not disable the
// conventional and DOCKER_HOST candidates.
type Options struct {
	DockerSockets         []string
	DockerTimeout         time.Duration
	DockerMaxResponseSize int64
}

func normalizeOptions(options Options) Options {
	options.DockerSockets = append([]string(nil), options.DockerSockets...)
	if options.DockerTimeout <= 0 {
		options.DockerTimeout = defaultDockerTimeout
	}
	if options.DockerMaxResponseSize <= 0 {
		options.DockerMaxResponseSize = defaultDockerMaxBytes
	}
	return options
}

// Scan performs the default read-only assessment.
func Scan(ctx context.Context) ([]escapeutil.Finding, error) {
	return ScanWithOptions(ctx, Options{})
}

// ScanWithOptions performs the read-only assessment with explicit bounds.
func ScanWithOptions(ctx context.Context, options Options) ([]escapeutil.Finding, error) {
	return scanPlatform(ctx, normalizeOptions(options))
}

// Run prints a deterministic, concise assessment suitable for menu and direct
// command invocation.
func Run(ctx context.Context, output io.Writer) error {
	findings, err := Scan(ctx)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Container escape assessment (read-only; findings are not proof of escape):"); err != nil {
		return fmt.Errorf("write container escape scan heading: %w", err)
	}
	for _, finding := range findings {
		if err := escapeutil.ValidateFinding(finding); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "[%s] %s: %s\n", finding.Status, finding.Technique, finding.Summary); err != nil {
			return fmt.Errorf("write %s finding: %w", finding.Technique, err)
		}
		for _, evidence := range finding.Evidence {
			if _, err := fmt.Fprintf(output, "  - %s\n", evidence); err != nil {
				return fmt.Errorf("write %s evidence: %w", finding.Technique, err)
			}
		}
	}
	return nil
}

func unsupportedFindings() []escapeutil.Finding {
	result := make([]escapeutil.Finding, 0, 7)
	for _, technique := range []string{
		TechniqueHostPID,
		TechniqueHostRoot,
		TechniqueHostLogSymlinkRead,
		TechniqueDockerSocket,
		TechniqueCgroupRelease,
		TechniqueCorePattern,
		TechniqueHostPIDPtrace,
	} {
		result = append(result, escapeutil.Finding{
			Technique: technique,
			Status:    escapeutil.StatusUnsupported,
			Summary:   escapeutil.ErrUnsupported.Error(),
		})
	}
	return result
}
