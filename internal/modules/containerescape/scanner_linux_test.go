//go:build linux

package containerescape

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

type fakeScannerSystem struct {
	uid           int
	environment   map[string]string
	files         map[string][]byte
	identities    map[string]escapeutil.FileIdentity
	kinds         map[string]pathKind
	accessible    map[string]bool
	dockerResults map[string]dockerProbeResult
	dockerErrors  map[string]error
	readPaths     []string
	accessPaths   []string
	accessModes   []uint32
	dockerPaths   []string
}

func newFakeScannerSystem() *fakeScannerSystem {
	capabilities := uint64(1)<<uint(unix.CAP_SYS_ADMIN) | uint64(1)<<uint(unix.CAP_SYS_CHROOT) | uint64(1)<<uint(unix.CAP_SYS_PTRACE)
	system := &fakeScannerSystem{
		environment: map[string]string{},
		files: map[string][]byte{
			procSelfStatus: []byte(fmt.Sprintf("Name:\tpeirates\nUid:\t0\t0\t0\t0\nCapEff:\t%016x\n", capabilities)),
			procSelfMountInfo: []byte(
				"1 0 0:1 / / rw - overlay overlay rw,upperdir=/host/upper\n" +
					"2 1 8:1 / /hostroot rw - ext4 /dev/sda1 rw\n" +
					"3 1 0:3 / /proc rw - proc proc rw\n" +
					"4 1 0:4 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
					"5 1 8:2 /var/log /hostlogs rw - ext4 /dev/sdb1 rw\n"),
			procSelfCgroup: []byte("2:memory:/workload\n"),
		},
		identities:    make(map[string]escapeutil.FileIdentity),
		kinds:         map[string]pathKind{"/var/run/docker.sock": pathSocket},
		accessible:    make(map[string]bool),
		dockerResults: map[string]dockerProbeResult{"/var/run/docker.sock": {Version: "test", APIVersion: "1.44", OS: "linux"}},
		dockerErrors:  make(map[string]error),
	}
	for index, namespace := range []string{"pid", "mnt", "user", "net", "ipc", "uts", "cgroup"} {
		identity := escapeutil.FileIdentity{Device: 1, Inode: uint64(index + 10)}
		system.identities["/proc/self/ns/"+namespace] = identity
		system.identities["/proc/1/ns/"+namespace] = identity
	}
	system.identities["/"] = escapeutil.FileIdentity{Device: 1, Inode: 1}
	system.identities["/proc/1/root"] = escapeutil.FileIdentity{Device: 2, Inode: 1}
	system.identities["/hostroot"] = escapeutil.FileIdentity{Device: 3, Inode: 1}
	system.kinds["/hostroot"] = pathDirectory
	system.kinds["/hostlogs"] = pathDirectory
	for _, path := range []string{
		"/proc/1/root/bin/sh",
		"/hostroot/bin/sh",
		"/sys/fs/cgroup/memory/release_agent",
		"/sys/fs/cgroup/memory/workload/notify_on_release",
		"/proc/sys/kernel/core_pattern",
		"/hostlogs",
	} {
		system.accessible[path] = true
	}
	return system
}

func (system *fakeScannerSystem) effectiveUID() int { return system.uid }
func (system *fakeScannerSystem) getenv(name string) string {
	return system.environment[name]
}
func (system *fakeScannerSystem) readFile(path string) ([]byte, error) {
	system.readPaths = append(system.readPaths, path)
	data, ok := system.files[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), data...), nil
}
func (system *fakeScannerSystem) identity(path string) (escapeutil.FileIdentity, error) {
	identity, ok := system.identities[path]
	if !ok {
		return escapeutil.FileIdentity{}, errors.New("not found")
	}
	return identity, nil
}
func (system *fakeScannerSystem) pathKind(path string) (pathKind, error) {
	kind, ok := system.kinds[path]
	if !ok {
		return pathOther, errors.New("not found")
	}
	return kind, nil
}
func (system *fakeScannerSystem) access(path string, mode uint32) error {
	system.accessPaths = append(system.accessPaths, path)
	system.accessModes = append(system.accessModes, mode)
	if system.accessible[path] {
		return nil
	}
	return errors.New("permission denied")
}
func (system *fakeScannerSystem) dockerProbe(_ context.Context, path string, _ Options) (dockerProbeResult, error) {
	system.dockerPaths = append(system.dockerPaths, path)
	if err := system.dockerErrors[path]; err != nil {
		return dockerProbeResult{}, err
	}
	result, ok := system.dockerResults[path]
	if !ok {
		return dockerProbeResult{}, errors.New("not found")
	}
	return result, nil
}

func TestScanWithSystemFindsObservableCandidates(t *testing.T) {
	system := newFakeScannerSystem()
	findings, err := scanWithSystem(context.Background(), normalizeOptions(Options{}), system)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]escapeutil.Status{
		TechniqueHostPID:            escapeutil.StatusAvailable,
		TechniqueHostRoot:           escapeutil.StatusAvailable,
		TechniqueHostLogSymlinkRead: escapeutil.StatusCandidate,
		TechniqueDockerSocket:       escapeutil.StatusCandidate,
		TechniqueCgroupRelease:      escapeutil.StatusCandidate,
		TechniqueCorePattern:        escapeutil.StatusCandidate,
		TechniqueHostPIDPtrace:      escapeutil.StatusCandidate,
	}
	if len(findings) != len(want) {
		t.Fatalf("finding count = %d, want %d: %#v", len(findings), len(want), findings)
	}
	wantOrder := []string{
		TechniqueHostPID,
		TechniqueHostPIDPtrace,
		TechniqueHostRoot,
		TechniqueHostLogSymlinkRead,
		TechniqueDockerSocket,
		TechniqueCgroupRelease,
		TechniqueCorePattern,
	}
	for index, technique := range wantOrder {
		if findings[index].Technique != technique {
			t.Fatalf("finding %d = %q, want %q", index, findings[index].Technique, technique)
		}
	}
	for _, finding := range findings {
		if err := escapeutil.ValidateFinding(finding); err != nil {
			t.Fatal(err)
		}
		if finding.Status != want[finding.Technique] {
			t.Errorf("%s status = %s, want %s; summary: %s", finding.Technique, finding.Status, want[finding.Technique], finding.Summary)
		}
	}
	if got := strings.Join(system.readPaths, ","); got != "/proc/self/status,/proc/self/mountinfo,/proc/self/cgroup" {
		t.Fatalf("read paths = %q", got)
	}
	if len(system.dockerPaths) != 1 || system.dockerPaths[0] != "/var/run/docker.sock" {
		t.Fatalf("Docker probe paths = %#v", system.dockerPaths)
	}
}

func TestScanWithSystemFailsClosed(t *testing.T) {
	system := newFakeScannerSystem()
	system.uid = 1000
	system.files[procSelfStatus] = []byte("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n")
	system.files[procSelfMountInfo] = []byte("1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
	system.files[procSelfCgroup] = []byte("0::/workload\n")
	delete(system.kinds, "/var/run/docker.sock")
	delete(system.accessible, "/proc/1/root/bin/sh")
	system.identities["/proc/1/root"] = system.identities["/"]

	findings, err := scanWithSystem(context.Background(), normalizeOptions(Options{}), system)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]escapeutil.Status{
		TechniqueHostPID:            escapeutil.StatusBlocked,
		TechniqueHostRoot:           escapeutil.StatusBlocked,
		TechniqueHostLogSymlinkRead: escapeutil.StatusBlocked,
		TechniqueDockerSocket:       escapeutil.StatusBlocked,
		TechniqueCgroupRelease:      escapeutil.StatusUnsupported,
		TechniqueCorePattern:        escapeutil.StatusBlocked,
		TechniqueHostPIDPtrace:      escapeutil.StatusBlocked,
	}
	for _, finding := range findings {
		if finding.Status != want[finding.Technique] {
			t.Errorf("%s status = %s, want %s; summary: %s", finding.Technique, finding.Status, want[finding.Technique], finding.Summary)
		}
	}
}

func TestHostLogProbeFindsWritableDescendantMountWithoutUIDZero(t *testing.T) {
	system := newFakeScannerSystem()
	system.kinds["/mounted-logs"] = pathDirectory
	system.accessible["/mounted-logs"] = true
	finding := probeHostLog(system, scanFacts{
		effectiveUID: 1000,
		mounts: []escapeutil.Mount{{
			Root:       "/var/log/pods",
			MountPoint: "/mounted-logs",
			Options:    []string{"nosuid", "rw"},
		}},
	})
	if finding.Status != escapeutil.StatusCandidate {
		t.Fatalf("finding = %#v", finding)
	}
	evidence := strings.Join(finding.Evidence, "\n")
	for _, expected := range []string{
		"effective UID is 1000",
		"/mounted-logs",
		"node root /var/log/pods",
		"kubelet /logs/pods/",
		"nodes/proxy authorization",
	} {
		if !strings.Contains(evidence, expected) && !strings.Contains(finding.Summary, expected) {
			t.Errorf("finding does not contain %q: %#v", expected, finding)
		}
	}
	if len(system.readPaths) != 0 || len(system.dockerPaths) != 0 {
		t.Fatalf("host-log probe performed file reads or network probes: reads=%#v docker=%#v", system.readPaths, system.dockerPaths)
	}
	if len(system.accessPaths) != 1 || system.accessPaths[0] != "/mounted-logs" ||
		len(system.accessModes) != 1 || system.accessModes[0] != unix.W_OK|unix.X_OK {
		t.Fatalf("access probes = paths %#v modes %#v", system.accessPaths, system.accessModes)
	}
}

func TestHostLogProbeLabelsExactDestinationFallbackAsUnproven(t *testing.T) {
	system := newFakeScannerSystem()
	system.kinds["/var/log"] = pathDirectory
	system.accessible["/var/log"] = true
	finding := probeHostLog(system, scanFacts{
		effectiveUID: 0,
		mounts: []escapeutil.Mount{{
			Root:       "/var/lib/runtime/volumes/id/_data/log",
			MountPoint: "/var/log",
			Options:    []string{"rw"},
		}},
	})
	if finding.Status != escapeutil.StatusCandidate {
		t.Fatalf("finding = %#v", finding)
	}
	evidence := strings.Join(finding.Evidence, "\n")
	for _, expected := range []string{
		"qualified mount /var/log maps to logical kubelet /logs/",
		"mountinfo did not retain a /var/log root",
		"hostPath origin remains unproven",
	} {
		if !strings.Contains(evidence, expected) {
			t.Errorf("evidence does not contain %q: %s", expected, evidence)
		}
	}
}

func TestHostLogProbeBlocksIncompleteLocalPrerequisites(t *testing.T) {
	tests := []struct {
		name       string
		mounts     []escapeutil.Mount
		kind       *pathKind
		accessible bool
	}{
		{name: "no mount"},
		{name: "read only", mounts: []escapeutil.Mount{{Root: "/var/log", MountPoint: "/mounted-logs", Options: []string{"ro"}}}},
		{name: "missing", mounts: []escapeutil.Mount{{Root: "/var/log", MountPoint: "/mounted-logs", Options: []string{"rw"}}}},
		{name: "regular file", mounts: []escapeutil.Mount{{Root: "/var/log", MountPoint: "/mounted-logs", Options: []string{"rw"}}}, kind: pathKindPointer(pathOther), accessible: true},
		{name: "inaccessible", mounts: []escapeutil.Mount{{Root: "/var/log", MountPoint: "/mounted-logs", Options: []string{"rw"}}}, kind: pathKindPointer(pathDirectory)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakeScannerSystem()
			delete(system.kinds, "/mounted-logs")
			delete(system.accessible, "/mounted-logs")
			if test.kind != nil {
				system.kinds["/mounted-logs"] = *test.kind
			}
			if test.accessible {
				system.accessible["/mounted-logs"] = true
			}
			finding := probeHostLog(system, scanFacts{effectiveUID: 1000, mounts: test.mounts})
			if finding.Status != escapeutil.StatusBlocked {
				t.Fatalf("finding = %#v", finding)
			}
			if !strings.Contains(finding.Summary, "no writable direct mount") {
				t.Fatalf("summary = %q", finding.Summary)
			}
		})
	}
}

func pathKindPointer(kind pathKind) *pathKind { return &kind }

func TestHostPIDPtraceDoesNotRequireSysAdmin(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfStatus] = []byte(fmt.Sprintf(
		"Name:\tpeirates\nUid:\t0\t0\t0\t0\nCapEff:\t%016x\n",
		uint64(1)<<uint(unix.CAP_SYS_PTRACE),
	))
	finding := probeHostPIDPtrace(collectFacts(system))
	if finding.Status != escapeutil.StatusCandidate {
		t.Fatalf("finding = %#v", finding)
	}
	joined := strings.Join(finding.Evidence, "\n")
	if !strings.Contains(joined, "CAP_SYS_PTRACE is effective") || strings.Contains(joined, "CAP_SYS_ADMIN") {
		t.Fatalf("unexpected capability evidence:\n%s", joined)
	}
}

func TestDockerProbeRejectsSymlinkAndNonSocket(t *testing.T) {
	system := newFakeScannerSystem()
	system.environment["DOCKER_HOST"] = "unix:///symlink.sock"
	system.kinds["/symlink.sock"] = pathSymlink
	system.kinds["/run/docker.sock"] = pathOther
	delete(system.kinds, "/var/run/docker.sock")
	finding := probeDocker(context.Background(), system, normalizeOptions(Options{}))
	if finding.Status != escapeutil.StatusBlocked {
		t.Fatalf("status = %s, want blocked", finding.Status)
	}
	if len(system.dockerPaths) != 0 {
		t.Fatalf("probe followed unsafe paths: %#v", system.dockerPaths)
	}
	joined := strings.Join(finding.Evidence, "\n")
	if !strings.Contains(joined, "rejected symlink") || !strings.Contains(joined, "rejected non-socket") {
		t.Fatalf("missing rejection evidence:\n%s", joined)
	}
}

func TestHostRootAmbiguityIsCandidate(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = append(system.files[procSelfMountInfo], []byte("5 1 8:2 / /second rw - ext4 /dev/sdb1 rw\n")...)
	system.identities["/second"] = escapeutil.FileIdentity{Device: 4, Inode: 1}
	system.kinds["/second"] = pathDirectory
	system.accessible["/second/bin/sh"] = true
	facts := collectFacts(system)
	finding := probeHostRoot(system, facts)
	if finding.Status != escapeutil.StatusCandidate || !strings.Contains(finding.Summary, "explicit operator selection") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestHostRootIgnoresQualifiedNestedMounts(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = append(system.files[procSelfMountInfo], []byte(
		"5 2 0:5 / /hostroot/run/container/rootfs rw - overlay overlay rw\n")...)
	system.identities["/hostroot/run/container/rootfs"] = escapeutil.FileIdentity{Device: 5, Inode: 1}
	system.kinds["/hostroot/run/container/rootfs"] = pathDirectory
	system.accessible["/hostroot/run/container/rootfs/bin/sh"] = true

	finding := probeHostRoot(system, collectFacts(system))
	if finding.Status != escapeutil.StatusAvailable ||
		!strings.Contains(finding.Summary, "one distinct mounted host root") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestCgroupReleaseRequiresWritableControlsInSameHierarchy(t *testing.T) {
	system := newFakeScannerSystem()
	system.files[procSelfMountInfo] = []byte(
		"1 0 0:1 / / rw - overlay overlay rw,upperdir=/host/upper\n" +
			"4 1 0:4 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
			"5 1 0:5 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n")
	system.files[procSelfCgroup] = []byte("2:memory:/workload\n3:cpu:/workload\n")
	system.accessible = map[string]bool{
		"/sys/fs/cgroup/memory/release_agent":           true,
		"/sys/fs/cgroup/cpu/workload/notify_on_release": true,
	}

	finding := probeCgroupRelease(system, collectFacts(system))
	if finding.Status != escapeutil.StatusBlocked ||
		!strings.Contains(finding.Summary, "no single cgroup v1 hierarchy") {
		t.Fatalf("finding = %#v", finding)
	}
}

func TestScanHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, err := scanWithSystem(ctx, normalizeOptions(Options{}), newFakeScannerSystem())
	if !errors.Is(err, context.Canceled) || findings != nil {
		t.Fatalf("scanWithSystem() = %#v, %v; want context.Canceled", findings, err)
	}
}
