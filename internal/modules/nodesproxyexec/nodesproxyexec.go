// Package nodesproxyexec implements the bounded capability logic for direct
// kubelet command execution authorized by Kubernetes nodes/proxy access.
// Network transports and operator interaction are injected by callers.
package nodesproxyexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/inguardians/peirates/internal/model"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// MaxReviewConcurrency is the hard ceiling for concurrent access reviews.
	MaxReviewConcurrency = 4
	// DefaultCommandTimeout bounds one confirmed remote command.
	DefaultCommandTimeout = 30 * time.Second
	// DefaultOutputLimit is shared by stdout and stderr.
	DefaultOutputLimit int64 = 1 << 20
	// MaxArgumentCount bounds remote command argument count.
	MaxArgumentCount = 128
	// MaxArgumentBytes bounds the aggregate byte length of remote command argv.
	MaxArgumentBytes = 32 << 10

	maxMetadataBytes = 256
	maxErrorBytes    = 4 << 10
)

// AccessState is the outcome of one access review.
type AccessState string

const (
	AccessAllowed   AccessState = "allowed"
	AccessDenied    AccessState = "denied"
	AccessError     AccessState = "error"
	AccessUnchecked AccessState = "unchecked"
)

// Classification is the conservative conclusion supported by collected
// authorization and execution evidence.
type Classification string

const (
	ClassificationConfirmedGetOnlyExec        Classification = "confirmed-get-only-exec"
	ClassificationBroadProxyAccess            Classification = "broad-proxy-access"
	ClassificationExecutionConfirmedUnchecked Classification = "execution-confirmed-authz-unchecked"
	ClassificationPermissionCandidate         Classification = "permission-candidate"
	ClassificationNotExploitableFromHere      Classification = "not-exploitable-from-here"
)

// ContainerKind identifies the Kubernetes container-status collection that
// supplied a running target.
type ContainerKind string

const (
	ContainerRegular   ContainerKind = "regular"
	ContainerInit      ContainerKind = "init"
	ContainerEphemeral ContainerKind = "ephemeral"
)

var (
	ErrNoCredentials       = errors.New("no stored service-account tokens")
	ErrInvalidNode         = errors.New("invalid Kubernetes node name")
	ErrInvalidSelection    = errors.New("credential selection is not eligible")
	ErrInvalidTarget       = errors.New("container target is invalid")
	ErrTargetNotOffered    = errors.New("container target was not in the prepared target list")
	ErrTargetNoLongerRuns  = errors.New("container target is no longer running on the selected node")
	ErrInvalidArguments    = errors.New("command arguments are invalid")
	ErrOutputLimitExceeded = errors.New("combined command output limit exceeded")
	ErrExecutionIncomplete = errors.New("remote command did not return a completed status")
)

// AccessRequest describes one node-scoped nodes/proxy access review.
type AccessRequest struct {
	Verb     string
	NodeName string
}

// AccessReviewer performs one SelfSubjectAccessReview using the supplied
// private connection copy. Implementations must not retain the connection.
type AccessReviewer interface {
	ReviewAccess(context.Context, model.ServerInfo, AccessRequest) (bool, error)
}

// CredentialRef contains display-safe metadata and an opaque original index.
type CredentialRef struct {
	Index           int
	Name            string
	DiscoveryMethod string
	Kind            string
}

// CredentialAccess contains the access state for one original stored entry.
// It intentionally contains no credential value, prefix, or digest.
type CredentialAccess struct {
	Credential  CredentialRef
	GetProxy    AccessState
	CreateProxy AccessState
	GetError    string
	CreateError string
}

// CredentialScan contains ordered display results. Private connection copies
// are retained only so a later explicit selection cannot be influenced by
// mutation of the caller's live session.
type CredentialScan struct {
	Credentials []CredentialAccess
	selectEntry func(int, bool) (SelectedCredential, error)
}

type scanEntry struct {
	access     CredentialAccess
	connection model.ServerInfo
}

// SelectedCredential is an explicit immutable selection. Only display-safe
// access metadata is exported; the private connection is passed directly to
// an injected factory when preparing kubelet access.
type SelectedCredential struct {
	Credential CredentialAccess
	newKubelet func(context.Context, KubeletFactory) (Kubelet, error)
	redact     func(string, error) error
	canonical  func() CredentialAccess
}

// Target identifies one currently running container.
type Target struct {
	NodeName      string
	Namespace     string
	PodName       string
	ContainerName string
	ContainerKind ContainerKind
}

// ExecStatus describes a completed remote-command protocol result.
type ExecStatus struct {
	ExitCode int
	Protocol string
	Complete bool
}

// Kubelet is the direct, authenticated transport seam.
type Kubelet interface {
	Probe(context.Context) error
	ListRunningContainers(context.Context) ([]Target, error)
	Exec(context.Context, Target, []string, io.Writer, io.Writer) (ExecStatus, error)
}

// KubeletFactory binds an explicitly selected private credential to caller-
// supplied endpoint and TLS settings.
type KubeletFactory interface {
	NewKubelet(context.Context, model.ServerInfo) (Kubelet, error)
}

// ProbeResult is the safe result of direct reachability and target discovery.
type ProbeResult struct {
	Credential     CredentialAccess
	Containers     []Target
	Classification Classification
}

// Options configures one bounded non-interactive command.
type Options struct {
	Target         Target
	Argv           []string
	CommandTimeout time.Duration
	OutputLimit    int64
}

// ExecResult contains bounded output and execution evidence.
type ExecResult struct {
	Stdout         []byte
	Stderr         []byte
	ExitCode       int
	Protocol       string
	Classification Classification
}

// Prepared retains a private selected client and the exact target inventory
// displayed to the operator. It is safe for one Execute call at a time.
type Prepared struct {
	credential CredentialAccess
	node       string
	kubelet    Kubelet
	offered    map[targetIdentity]struct{}
	redact     func(string, error) error
}

type targetIdentity struct {
	namespace string
	pod       string
	container string
	kind      ContainerKind
}

// ReviewCredentials takes an immutable snapshot of every stored token and
// reviews unique token values with no more than four concurrent workers.
// Returned display results always retain original stored order.
func ReviewCredentials(ctx context.Context, base model.ServerInfo, stored []model.ServiceAccount, node string, reviewer AccessReviewer, reviewsEnabled bool) (CredentialScan, error) {
	if err := validateNode(node); err != nil {
		return CredentialScan{}, err
	}
	if len(stored) == 0 {
		return CredentialScan{}, ErrNoCredentials
	}
	if reviewsEnabled && reviewer == nil {
		return CredentialScan{}, errors.New("access reviewer is required")
	}

	scan := CredentialScan{
		Credentials: make([]CredentialAccess, len(stored)),
	}
	entries := make([]scanEntry, len(stored))
	type tokenGroup struct {
		token   string
		indexes []int
	}
	groups := make([]tokenGroup, 0, len(stored))
	groupByDigest := make(map[[sha256.Size]byte]int, len(stored))
	for index, account := range stored {
		ref := CredentialRef{
			Index:           index,
			Name:            sanitizeText(account.Name, maxMetadataBytes),
			DiscoveryMethod: sanitizeText(account.DiscoveryMethod, maxMetadataBytes),
			Kind:            "service-account-token",
		}
		access := CredentialAccess{Credential: ref, GetProxy: AccessUnchecked, CreateProxy: AccessUnchecked}
		connection := base
		connection.Token = account.Token
		connection.TokenName = account.Name
		connection.ClientCertData = ""
		connection.ClientKeyData = ""
		connection.ClientCertName = ""
		connection.UseAuthCanI = true
		scan.Credentials[index] = access
		entries[index] = scanEntry{access: access, connection: connection}

		digest := sha256.Sum256([]byte(account.Token))
		if groupIndex, ok := groupByDigest[digest]; ok {
			groups[groupIndex].indexes = append(groups[groupIndex].indexes, index)
			continue
		}
		groupByDigest[digest] = len(groups)
		groups = append(groups, tokenGroup{token: account.Token, indexes: []int{index}})
	}

	if !reviewsEnabled {
		scan.selectEntry = selectionFunc(entries)
		return scan, nil
	}

	type outcome struct {
		getState    AccessState
		createState AccessState
		getError    string
		createError string
	}
	outcomes := make([]outcome, len(groups))
	for i := range outcomes {
		outcomes[i] = outcome{getState: AccessUnchecked, createState: AccessUnchecked}
	}

	workerCount := MaxReviewConcurrency
	if len(groups) < workerCount {
		workerCount = len(groups)
	}
	var nextMu sync.Mutex
	next := 0
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				nextMu.Lock()
				if next >= len(groups) {
					nextMu.Unlock()
					return
				}
				groupIndex := next
				next++
				nextMu.Unlock()
				if ctx.Err() != nil {
					return
				}

				group := groups[groupIndex]
				connection := entries[group.indexes[0]].connection
				allowed, err := reviewer.ReviewAccess(ctx, connection, AccessRequest{Verb: "get", NodeName: node})
				if err != nil {
					outcomes[groupIndex].getState = AccessError
					outcomes[groupIndex].getError = sanitizeCredentialError(err, group.token)
					continue
				}
				if !allowed {
					outcomes[groupIndex].getState = AccessDenied
					continue
				}
				outcomes[groupIndex].getState = AccessAllowed
				allowed, err = reviewer.ReviewAccess(ctx, connection, AccessRequest{Verb: "create", NodeName: node})
				if err != nil {
					outcomes[groupIndex].createState = AccessError
					outcomes[groupIndex].createError = sanitizeCredentialError(err, group.token)
					continue
				}
				if allowed {
					outcomes[groupIndex].createState = AccessAllowed
				} else {
					outcomes[groupIndex].createState = AccessDenied
				}
			}
		}()
	}
	workers.Wait()

	for groupIndex, group := range groups {
		result := outcomes[groupIndex]
		for _, index := range group.indexes {
			access := scan.Credentials[index]
			access.GetProxy = result.getState
			access.CreateProxy = result.createState
			access.GetError = result.getError
			access.CreateError = result.createError
			scan.Credentials[index] = access
			entries[index].access = access
		}
	}
	scan.selectEntry = selectionFunc(entries)
	if err := ctx.Err(); err != nil {
		return scan, err
	}
	return scan, nil
}

// Select resolves an original stored index. Unchecked selection is rejected
// unless the caller has separately warned the operator and opts in.
func (scan CredentialScan) Select(index int, allowUnchecked bool) (SelectedCredential, error) {
	if scan.selectEntry == nil {
		return SelectedCredential{}, ErrInvalidSelection
	}
	return scan.selectEntry(index, allowUnchecked)
}

func selectionFunc(entries []scanEntry) func(int, bool) (SelectedCredential, error) {
	// Copy both the slice and every value so the closure is an immutable
	// module-start snapshot independent of the caller and scan display fields.
	snapshot := append([]scanEntry(nil), entries...)
	return func(index int, allowUnchecked bool) (SelectedCredential, error) {
		if index < 0 || index >= len(snapshot) {
			return SelectedCredential{}, ErrInvalidSelection
		}
		entry := snapshot[index]
		if entry.access.GetProxy != AccessAllowed && !(allowUnchecked && entry.access.GetProxy == AccessUnchecked) {
			return SelectedCredential{}, ErrInvalidSelection
		}
		connection := entry.connection
		redact := func(stage string, err error) error {
			return safeStageError(stage, err, connection.Token)
		}
		return SelectedCredential{
			Credential: entry.access,
			newKubelet: func(ctx context.Context, factory KubeletFactory) (Kubelet, error) {
				kubelet, err := factory.NewKubelet(ctx, connection)
				if err != nil {
					return nil, redact("construct direct kubelet client", err)
				}
				return kubelet, nil
			},
			redact:    redact,
			canonical: func() CredentialAccess { return entry.access },
		}, nil
	}
}

// Prepare binds the selected private credential, verifies direct kubelet
// reachability, and returns a deterministic list of valid targets on the node.
func Prepare(ctx context.Context, selected SelectedCredential, node string, factory KubeletFactory) (*Prepared, ProbeResult, error) {
	result := ProbeResult{Credential: selected.Credential, Classification: ClassificationNotExploitableFromHere}
	if err := validateNode(node); err != nil {
		return nil, result, err
	}
	if selected.canonical == nil {
		return nil, result, ErrInvalidSelection
	}
	access := selected.canonical()
	result.Credential = access
	if access.GetProxy != AccessAllowed && access.GetProxy != AccessUnchecked {
		return nil, result, ErrInvalidSelection
	}
	if factory == nil {
		return nil, result, errors.New("kubelet factory is required")
	}
	if selected.newKubelet == nil || selected.redact == nil {
		return nil, result, ErrInvalidSelection
	}
	kubelet, err := selected.newKubelet(ctx, factory)
	if err != nil {
		return nil, result, err
	}
	if kubelet == nil {
		return nil, result, errors.New("kubelet factory returned a nil client")
	}
	if err := kubelet.Probe(ctx); err != nil {
		return nil, result, selected.redact("probe direct kubelet", err)
	}
	targets, err := kubelet.ListRunningContainers(ctx)
	if err != nil {
		return nil, result, selected.redact("list running kubelet containers", err)
	}
	targets = normalizeTargets(targets, node)
	result.Containers = append([]Target(nil), targets...)
	result.Classification = ClassificationPermissionCandidate
	offered := make(map[targetIdentity]struct{}, len(targets))
	for _, target := range targets {
		offered[identityOf(target)] = struct{}{}
	}
	prepared := &Prepared{
		credential: access,
		node:       node,
		kubelet:    kubelet,
		offered:    offered,
		redact:     selected.redact,
	}
	return prepared, result, nil
}

// Execute revalidates the selected target against a fresh running-container
// inventory, then performs one time- and output-bounded command.
func (prepared *Prepared) Execute(ctx context.Context, options Options) (ExecResult, error) {
	result := ExecResult{ExitCode: -1, Classification: ClassificationNotExploitableFromHere}
	if prepared == nil || prepared.kubelet == nil {
		return result, errors.New("nodes/proxy execution was not prepared")
	}
	if err := validateTarget(options.Target); err != nil || options.Target.NodeName != prepared.node {
		return result, ErrInvalidTarget
	}
	if _, ok := prepared.offered[identityOf(options.Target)]; !ok {
		return result, ErrTargetNotOffered
	}
	argv, err := normalizeArgv(options.Argv)
	if err != nil {
		return result, err
	}
	timeout := options.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	limit := options.OutputLimit
	if limit <= 0 {
		limit = DefaultOutputLimit
	}

	fresh, err := prepared.kubelet.ListRunningContainers(ctx)
	if err != nil {
		return result, prepared.redact("revalidate running kubelet containers", err)
	}
	found := false
	for _, candidate := range fresh {
		if validateTarget(candidate) == nil && candidate.NodeName == prepared.node && identityOf(candidate) == identityOf(options.Target) {
			found = true
			break
		}
	}
	if !found {
		return result, ErrTargetNoLongerRuns
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := newCombinedOutput(limit, cancel)
	status, execErr := prepared.kubelet.Exec(execCtx, options.Target, argv, output.stdoutWriter(), output.stderrWriter())
	result.Stdout, result.Stderr = output.bytes()
	result.ExitCode = status.ExitCode
	result.Protocol = sanitizeText(status.Protocol, maxMetadataBytes)
	if output.overflowed() {
		return result, ErrOutputLimitExceeded
	}
	if execCtx.Err() != nil {
		return result, execCtx.Err()
	}
	if !status.Complete {
		if execErr != nil {
			return result, prepared.redact("execute direct kubelet command", execErr)
		}
		return result, ErrExecutionIncomplete
	}
	result.Classification = successClassification(prepared.credential)
	if execErr != nil {
		return result, prepared.redact("remote command completed with an error", execErr)
	}
	return result, nil
}

func successClassification(access CredentialAccess) Classification {
	if access.GetProxy == AccessUnchecked {
		return ClassificationExecutionConfirmedUnchecked
	}
	if access.GetProxy == AccessAllowed && access.CreateProxy == AccessDenied {
		return ClassificationConfirmedGetOnlyExec
	}
	if access.GetProxy == AccessAllowed && access.CreateProxy == AccessAllowed {
		return ClassificationBroadProxyAccess
	}
	// A failed negative control cannot support a GET-only or broad-access
	// conclusion, even after execution. Preserve the conservative candidate
	// label instead of inventing authorization evidence.
	return ClassificationPermissionCandidate
}

func validateNode(node string) error {
	if node == "" || len(validation.IsDNS1123Subdomain(node)) != 0 {
		return ErrInvalidNode
	}
	return nil
}

func validateTarget(target Target) error {
	for _, value := range []string{target.NodeName, target.Namespace, target.PodName, target.ContainerName} {
		if value == "" || strings.ContainsAny(value, "/\x00") {
			return ErrInvalidTarget
		}
	}
	switch target.ContainerKind {
	case ContainerRegular, ContainerInit, ContainerEphemeral:
		return nil
	default:
		return ErrInvalidTarget
	}
}

func normalizeArgv(argv []string) ([]string, error) {
	if len(argv) == 0 || len(argv) > MaxArgumentCount {
		return nil, ErrInvalidArguments
	}
	total := 0
	result := append([]string(nil), argv...)
	for _, arg := range result {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, ErrInvalidArguments
		}
		total += len(arg)
		if total > MaxArgumentBytes {
			return nil, ErrInvalidArguments
		}
	}
	return result, nil
}

func normalizeTargets(targets []Target, node string) []Target {
	result := make([]Target, 0, len(targets))
	seen := make(map[targetIdentity]struct{}, len(targets))
	for _, target := range targets {
		if validateTarget(target) != nil || target.NodeName != node {
			continue
		}
		identity := identityOf(target)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		result = append(result, target)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.PodName != right.PodName {
			return left.PodName < right.PodName
		}
		if containerKindRank(left.ContainerKind) != containerKindRank(right.ContainerKind) {
			return containerKindRank(left.ContainerKind) < containerKindRank(right.ContainerKind)
		}
		return left.ContainerName < right.ContainerName
	})
	return result
}

func containerKindRank(kind ContainerKind) int {
	switch kind {
	case ContainerRegular:
		return 0
	case ContainerInit:
		return 1
	default:
		return 2
	}
}

func identityOf(target Target) targetIdentity {
	return targetIdentity{
		namespace: target.Namespace,
		pod:       target.PodName,
		container: target.ContainerName,
		kind:      target.ContainerKind,
	}
}

func sanitizeCredentialError(err error, token string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if token != "" {
		message = strings.ReplaceAll(message, token, "[redacted credential]")
	}
	return sanitizeText(message, maxErrorBytes)
}

func safeStageError(stage string, err error, token string) error {
	if err == nil {
		return nil
	}
	return errors.New(stage + ": " + sanitizeCredentialError(err, token))
}

func sanitizeText(value string, maxBytes int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, value)
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

type combinedOutput struct {
	mu        sync.Mutex
	remaining int64
	overflow  bool
	cancel    context.CancelFunc
	stdout    bytes.Buffer
	stderr    bytes.Buffer
}

type combinedWriter struct {
	output *combinedOutput
	stderr bool
}

func newCombinedOutput(limit int64, cancel context.CancelFunc) *combinedOutput {
	return &combinedOutput{remaining: limit, cancel: cancel}
}

func (output *combinedOutput) stdoutWriter() io.Writer { return combinedWriter{output: output} }
func (output *combinedOutput) stderrWriter() io.Writer {
	return combinedWriter{output: output, stderr: true}
}

func (writer combinedWriter) Write(data []byte) (int, error) {
	output := writer.output
	output.mu.Lock()
	defer output.mu.Unlock()
	if int64(len(data)) <= output.remaining {
		output.remaining -= int64(len(data))
		if writer.stderr {
			return output.stderr.Write(data)
		}
		return output.stdout.Write(data)
	}
	written := int(output.remaining)
	if written > 0 {
		if writer.stderr {
			_, _ = output.stderr.Write(data[:written])
		} else {
			_, _ = output.stdout.Write(data[:written])
		}
	}
	output.remaining = 0
	output.overflow = true
	output.cancel()
	return written, ErrOutputLimitExceeded
}

func (output *combinedOutput) bytes() ([]byte, []byte) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.stdout.Bytes()...), append([]byte(nil), output.stderr.Bytes()...)
}

func (output *combinedOutput) overflowed() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.overflow
}
