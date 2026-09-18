//go:build linux

package hostlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

type testHostLogSystem struct {
	realHostLogSystem
	mountInfo           []byte
	pathKindOverrides   map[string]pathKind
	accessPathOverrides map[string]error
	openPathOverrides   map[string]string
	accessErr           error
	directoryAccessErr  error
	unlinkErr           error
	randomByte          byte
	shortRandom         bool
}

func (system *testHostLogSystem) readFile(name string) ([]byte, error) {
	if name != procSelfMountInfo {
		return nil, fmt.Errorf("unexpected read: %s", name)
	}
	return append([]byte(nil), system.mountInfo...), nil
}

func (system *testHostLogSystem) accessPath(name string) error {
	if err, exists := system.accessPathOverrides[name]; exists {
		return err
	}
	if system.accessErr != nil {
		return system.accessErr
	}
	return system.realHostLogSystem.accessPath(name)
}

func (system *testHostLogSystem) pathKind(name string) (pathKind, error) {
	if kind, exists := system.pathKindOverrides[name]; exists {
		return kind, nil
	}
	return system.realHostLogSystem.pathKind(name)
}

func (system *testHostLogSystem) openDirectoryNoFollow(name string) (*os.File, escapeutil.FileIdentity, error) {
	if replacement, exists := system.openPathOverrides[name]; exists {
		return system.realHostLogSystem.openDirectoryNoFollow(replacement)
	}
	return system.realHostLogSystem.openDirectoryNoFollow(name)
}

func (system *testHostLogSystem) accessDirectory(directory *os.File) error {
	if system.directoryAccessErr != nil {
		return system.directoryAccessErr
	}
	return system.realHostLogSystem.accessDirectory(directory)
}

func (system *testHostLogSystem) unlinkAt(directory *os.File, name string) error {
	if system.unlinkErr != nil {
		return system.unlinkErr
	}
	return system.realHostLogSystem.unlinkAt(directory, name)
}

func (system *testHostLogSystem) randomBytes(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = system.randomByte
	}
	if system.shortRandom {
		return len(buffer) - 1, nil
	}
	return len(buffer), nil
}

type testFetcher struct {
	probeErr   error
	readErr    error
	content    []byte
	probeCalls int
	readCalls  int
	readPath   string
	onProbe    func()
	onRead     func(string)
}

func (fetcher *testFetcher) Probe(context.Context) error {
	fetcher.probeCalls++
	if fetcher.onProbe != nil {
		fetcher.onProbe()
	}
	return fetcher.probeErr
}

func (fetcher *testFetcher) Read(_ context.Context, logPath string) ([]byte, error) {
	fetcher.readCalls++
	fetcher.readPath = logPath
	if fetcher.onRead != nil {
		fetcher.onRead(logPath)
	}
	return append([]byte(nil), fetcher.content...), fetcher.readErr
}

func testMountInfo(root, mountPoint, options string) []byte {
	return []byte(fmt.Sprintf("41 1 0:40 %s %s %s - overlay overlay rw\n", root, mountPoint, options))
}

func TestProbeWithSystemFindsWritableHostLogMountWithoutMutation(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw,nosuid")}

	findings, err := probeWithSystem(context.Background(), system)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Technique != Technique || findings[0].Status != escapeutil.StatusCandidate {
		t.Fatalf("findings = %#v", findings)
	}
	if err := escapeutil.ValidateFinding(findings[0]); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(mountPoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only probe created entries: %#v", entries)
	}
}

func TestProbeWithSystemBlocksInaccessibleMount(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{
		mountInfo: testMountInfo("/var/log", mountPoint, "rw"),
		accessErr: errors.New("permission denied"),
	}
	findings, err := probeWithSystem(context.Background(), system)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Status != escapeutil.StatusBlocked {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestProbeWithSystemReportsExactDestinationFallbackAsUnproven(t *testing.T) {
	system := &testHostLogSystem{
		mountInfo:           testMountInfo("/", "/var/log", "rw,nosuid"),
		pathKindOverrides:   map[string]pathKind{"/var/log": pathDirectory},
		accessPathOverrides: map[string]error{"/var/log": nil},
	}

	findings, err := probeWithSystem(context.Background(), system)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Status != escapeutil.StatusCandidate {
		t.Fatalf("findings = %#v", findings)
	}
	evidence := strings.Join(findings[0].Evidence, "\n")
	for _, expected := range []string{"/var/log", "mountinfo did not retain a /var/log root", "hostPath origin is unproven", "kubelet path is /logs/"} {
		if !strings.Contains(evidence, expected) {
			t.Fatalf("evidence = %q, want %q", evidence, expected)
		}
	}
}

func TestReadFileWithSystemUsesNestedURLPrefixAndCleansUp(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("a", 24)
	linkName := linkNamePrefix + runID
	target := "/etc/hostname"
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log/pods", mountPoint, "rw")}
	fetcher := &testFetcher{content: []byte("exact response\x00bytes")}
	fetcher.onProbe = func() {
		if _, err := os.Lstat(filepath.Join(mountPoint, linkName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary link existed during endpoint preflight: %v", err)
		}
	}
	fetcher.onRead = func(logPath string) {
		if logPath != "pods/"+linkName {
			t.Fatalf("log path = %q", logPath)
		}
		gotTarget, err := os.Readlink(filepath.Join(mountPoint, linkName))
		if err != nil {
			t.Fatal(err)
		}
		if gotTarget != target {
			t.Fatalf("symlink target = %q, want %q", gotTarget, target)
		}
	}

	result, err := readFileWithSystem(context.Background(), Options{
		TargetPath: target,
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err != nil {
		t.Fatal(err)
	}
	if result.MountPoint != mountPoint || result.HostLogRoot != "/var/log/pods" ||
		result.LogPath != "pods/"+linkName || string(result.Content) != "exact response\x00bytes" {
		t.Fatalf("result = %#v", result)
	}
	if fetcher.probeCalls != 1 || fetcher.readCalls != 1 {
		t.Fatalf("fetcher calls = probe %d, read %d", fetcher.probeCalls, fetcher.readCalls)
	}
	if _, err := os.Lstat(filepath.Join(mountPoint, linkName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary link remained after success: %v", err)
	}
}

func TestReadFileWithSystemPreservesUnprovenFallbackOrigin(t *testing.T) {
	mountedDirectory := t.TempDir()
	runID := strings.Repeat("9", 24)
	linkName := linkNamePrefix + runID
	target := "/etc/hostname"
	system := &testHostLogSystem{
		mountInfo:           testMountInfo("/", "/var/log", "rw"),
		pathKindOverrides:   map[string]pathKind{"/var/log": pathDirectory},
		accessPathOverrides: map[string]error{"/var/log": nil},
		openPathOverrides:   map[string]string{"/var/log": mountedDirectory},
	}
	fetcher := &testFetcher{content: []byte("fallback response")}
	fetcher.onRead = func(logPath string) {
		if logPath != linkName {
			t.Fatalf("log path = %q, want %q", logPath, linkName)
		}
		gotTarget, err := os.Readlink(filepath.Join(mountedDirectory, linkName))
		if err != nil {
			t.Fatal(err)
		}
		if gotTarget != target {
			t.Fatalf("symlink target = %q, want %q", gotTarget, target)
		}
	}

	result, err := readFileWithSystem(context.Background(), Options{
		MountPoint: "/var/log",
		TargetPath: target,
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err != nil {
		t.Fatal(err)
	}
	if result.MountPoint != "/var/log" || result.HostLogRoot != "/var/log" ||
		!result.HostPathOriginUnproven || result.LogPath != linkName {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(mountedDirectory, linkName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary fallback link remained after success: %v", err)
	}
}

func TestReadFileWithSystemProbeFailureDoesNotMutate(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	fetcher := &testFetcher{probeErr: errors.New("forbidden")}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      strings.Repeat("b", 24),
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "before filesystem mutation") {
		t.Fatalf("error = %v", err)
	}
	entries, readErr := os.ReadDir(mountPoint)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 || fetcher.readCalls != 0 {
		t.Fatalf("probe failure mutated mount or read content: entries=%#v reads=%d", entries, fetcher.readCalls)
	}
}

func TestReadFileWithSystemFetchFailureCleansUp(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("c", 24)
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	fetcher := &testFetcher{readErr: errors.New("upstream failed")}

	_, err := readFileWithSystem(context.Background(), Options{
		MountPoint: mountPoint,
		TargetPath: "/etc/passwd",
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "upstream failed") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(mountPoint, linkNamePrefix+runID)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary link remained after fetch failure: %v", statErr)
	}
}

func TestReadFileWithSystemContextCancellationCleansUp(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("d", 24)
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	ctx, cancel := context.WithCancel(context.Background())
	fetcher := &testFetcher{}
	fetcher.onRead = func(string) {
		cancel()
		fetcher.readErr = ctx.Err()
	}

	_, err := readFileWithSystem(ctx, Options{
		TargetPath: "/etc/passwd",
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if _, statErr := os.Lstat(filepath.Join(mountPoint, linkNamePrefix+runID)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary link remained after cancellation: %v", statErr)
	}
}

func TestReadFileWithSystemRefusesExistingEntry(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("e", 24)
	linkPath := filepath.Join(mountPoint, linkNamePrefix+runID)
	if err := os.WriteFile(linkPath, []byte("owned by someone else"), 0o600); err != nil {
		t.Fatal(err)
	}
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	fetcher := &testFetcher{}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v", err)
	}
	content, readErr := os.ReadFile(linkPath)
	if readErr != nil || string(content) != "owned by someone else" {
		t.Fatalf("existing entry was modified: content=%q err=%v", content, readErr)
	}
	if fetcher.readCalls != 0 {
		t.Fatalf("read called after collision: %d", fetcher.readCalls)
	}
}

func TestReadFileWithSystemReportsFetchAndCleanupFailures(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("f", 24)
	linkPath := filepath.Join(mountPoint, linkNamePrefix+runID)
	system := &testHostLogSystem{
		mountInfo: testMountInfo("/var/log", mountPoint, "rw"),
		unlinkErr: errors.New("unlink failed"),
	}
	fetcher := &testFetcher{readErr: errors.New("fetch failed")}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "cleanup temporary host-log symlink") ||
		!strings.Contains(err.Error(), linkPath) || !strings.Contains(err.Error(), "unlink failed") ||
		!strings.Contains(err.Error(), "fetch failed") {
		t.Fatalf("combined error = %v", err)
	}
	if _, statErr := os.Lstat(linkPath); statErr != nil {
		t.Fatalf("expected failed cleanup to leave link for inspection: %v", statErr)
	}
	if removeErr := os.Remove(linkPath); removeErr != nil {
		t.Fatal(removeErr)
	}
}

func TestReadFileWithSystemRefusesToRemoveReplacedEntry(t *testing.T) {
	mountPoint := t.TempDir()
	runID := strings.Repeat("1", 24)
	linkPath := filepath.Join(mountPoint, linkNamePrefix+runID)
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	fetcher := &testFetcher{content: []byte("must not be returned")}
	fetcher.onRead = func(string) {
		if err := os.Remove(linkPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(linkPath, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	result, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      runID,
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("error = %v", err)
	}
	if len(result.Content) != 0 {
		t.Fatalf("content returned after cleanup failure: %q", result.Content)
	}
	content, readErr := os.ReadFile(linkPath)
	if readErr != nil || string(content) != "replacement" {
		t.Fatalf("replacement was removed or changed: content=%q err=%v", content, readErr)
	}
}

func TestReadFileWithSystemRechecksMountAfterEndpointProbe(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	fetcher := &testFetcher{}
	fetcher.onProbe = func() {
		system.mountInfo = testMountInfo("/var/log", mountPoint, "ro")
	}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      strings.Repeat("2", 24),
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "recheck host-log mount") {
		t.Fatalf("error = %v", err)
	}
	entries, readErr := os.ReadDir(mountPoint)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("mount change produced filesystem mutation: entries=%#v err=%v", entries, readErr)
	}
}

func TestReadFileWithSystemRejectsDirectoryReplacementAfterEndpointProbe(t *testing.T) {
	mountPoint := t.TempDir()
	replacement := t.TempDir()
	system := &testHostLogSystem{
		mountInfo:         testMountInfo("/var/log", mountPoint, "rw"),
		openPathOverrides: make(map[string]string),
	}
	fetcher := &testFetcher{}
	fetcher.onProbe = func() {
		system.openPathOverrides[mountPoint] = replacement
	}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      strings.Repeat("9", 24),
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "directory identity changed after endpoint preflight") {
		t.Fatalf("error = %v", err)
	}
	if fetcher.readCalls != 0 {
		t.Fatalf("read calls = %d, want 0", fetcher.readCalls)
	}
	for _, directory := range []string{mountPoint, replacement} {
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("directory %s was mutated: entries=%#v err=%v", directory, entries, readErr)
		}
	}
}

func TestReadFileWithSystemRechecksAutoSelectionAmbiguity(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", first, "rw")}
	fetcher := &testFetcher{}
	fetcher.onProbe = func() {
		system.mountInfo = append(system.mountInfo, testMountInfo("/var/log/pods", second, "rw")...)
	}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      strings.Repeat("5", 24),
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "multiple host-log mounts") {
		t.Fatalf("error = %v", err)
	}
	for _, mountPoint := range []string{first, second} {
		entries, readErr := os.ReadDir(mountPoint)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("ambiguity introduced after preflight mutated %s: entries=%#v err=%v", mountPoint, entries, readErr)
		}
	}
}

func TestReadFileWithSystemRejectsAmbiguousAutoSelection(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	mountInfo := append(testMountInfo("/var/log", first, "rw"), testMountInfo("/var/log/pods", second, "rw")...)
	// Mount IDs need not be unique for parsing, and candidate ordering remains
	// deterministic through the shared selector.
	system := &testHostLogSystem{mountInfo: mountInfo}
	fetcher := &testFetcher{}

	_, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		RunID:      strings.Repeat("3", 24),
		Fetcher:    fetcher,
	}, system)
	if err == nil || !strings.Contains(err.Error(), "multiple host-log mounts") {
		t.Fatalf("error = %v", err)
	}
	if fetcher.probeCalls != 0 {
		t.Fatalf("endpoint probe called before resolving ambiguity: %d", fetcher.probeCalls)
	}
}

func TestReadFileWithSystemValidatesPathsAndRunIDBeforeMutation(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{mountInfo: testMountInfo("/var/log", mountPoint, "rw")}
	tests := []struct {
		name    string
		options Options
		want    string
	}{
		{name: "relative target", options: Options{TargetPath: "etc/passwd", RunID: strings.Repeat("4", 24)}, want: "must be absolute"},
		{name: "unclean target", options: Options{TargetPath: "/etc/../passwd", RunID: strings.Repeat("4", 24)}, want: "not normalized"},
		{name: "root target", options: Options{TargetPath: "/", RunID: strings.Repeat("4", 24)}, want: "must not be filesystem root"},
		{name: "relative mount", options: Options{MountPoint: "mnt/logs", TargetPath: "/etc/passwd", RunID: strings.Repeat("4", 24)}, want: "mount point"},
		{name: "invalid run ID", options: Options{TargetPath: "/etc/passwd", RunID: "not-hex"}, want: "run ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher := &testFetcher{}
			test.options.Fetcher = fetcher
			_, err := readFileWithSystem(context.Background(), test.options, system)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			entries, readErr := os.ReadDir(mountPoint)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("invalid input mutated mount: entries=%#v err=%v", entries, readErr)
			}
		})
	}
}

func TestReadFileWithSystemGeneratesDeterministicShapeFromRandomBytes(t *testing.T) {
	mountPoint := t.TempDir()
	system := &testHostLogSystem{
		mountInfo:  testMountInfo("/var/log", mountPoint, "rw"),
		randomByte: 0xab,
	}
	fetcher := &testFetcher{content: []byte("ok")}

	result, err := readFileWithSystem(context.Background(), Options{
		TargetPath: "/etc/passwd",
		Fetcher:    fetcher,
	}, system)
	if err != nil {
		t.Fatal(err)
	}
	want := linkNamePrefix + strings.Repeat("ab", randomRunIDBytes)
	if result.LogPath != want {
		t.Fatalf("generated log path = %q, want %q", result.LogPath, want)
	}
}
