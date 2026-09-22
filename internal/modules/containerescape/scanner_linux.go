//go:build linux

package containerescape

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

const (
	procSelfStatus    = "/proc/self/status"
	procSelfMountInfo = "/proc/self/mountinfo"
	procSelfCgroup    = "/proc/self/cgroup"
)

type pathKind uint8

const (
	pathOther pathKind = iota
	pathSocket
	pathSymlink
	pathDirectory
)

type scannerSystem interface {
	effectiveUID() int
	getenv(string) string
	readFile(string) ([]byte, error)
	identity(string) (escapeutil.FileIdentity, error)
	pathKind(string) (pathKind, error)
	access(string, uint32) error
	dockerProbe(context.Context, string, Options) (dockerProbeResult, error)
}

type realScannerSystem struct{}

func (realScannerSystem) effectiveUID() int                    { return os.Geteuid() }
func (realScannerSystem) getenv(name string) string            { return os.Getenv(name) }
func (realScannerSystem) readFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (realScannerSystem) identity(path string) (escapeutil.FileIdentity, error) {
	return escapeutil.PathIdentity(path)
}
func (realScannerSystem) pathKind(path string) (pathKind, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return pathOther, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return pathSymlink, nil
	}
	if info.Mode()&os.ModeSocket != 0 {
		return pathSocket, nil
	}
	if info.IsDir() {
		return pathDirectory, nil
	}
	return pathOther, nil
}
func (realScannerSystem) access(path string, mode uint32) error {
	return unix.Faccessat(unix.AT_FDCWD, path, mode, unix.AT_EACCESS)
}
func (realScannerSystem) dockerProbe(ctx context.Context, path string, options Options) (dockerProbeResult, error) {
	return probeDockerSocket(ctx, path, options.DockerTimeout, options.DockerMaxResponseSize)
}

type scanFacts struct {
	effectiveUID int
	capabilities uint64
	statusErr    error
	mounts       []escapeutil.Mount
	mountErr     error
	cgroups      escapeutil.CgroupInfo
	cgroupErr    error
	namespaces   map[string]namespacePair
	root         identityResult
	pidOneRoot   identityResult
}

type identityResult struct {
	identity escapeutil.FileIdentity
	err      error
}

type namespacePair struct {
	current identityResult
	pidOne  identityResult
}

func scanPlatform(ctx context.Context, options Options) ([]escapeutil.Finding, error) {
	return scanWithSystem(ctx, options, realScannerSystem{})
}

func scanWithSystem(ctx context.Context, options Options, system scannerSystem) ([]escapeutil.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	facts := collectFacts(system)
	findings := []escapeutil.Finding{
		probeHostPID(system, facts),
		probeHostPIDPtrace(facts),
		probeHostRoot(system, facts),
		probeHostLog(system, facts),
		probeDocker(ctx, system, options),
		probeCgroupRelease(system, facts),
		probeCorePattern(system, facts),
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func probeHostPIDPtrace(facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueHostPIDPtrace}
	var blockers []string
	if facts.effectiveUID != 0 {
		blockers = append(blockers, "effective UID 0 is absent")
	}
	if facts.statusErr != nil {
		blockers = append(blockers, "effective capabilities could not be read")
	} else {
		if !escapeutil.HasCapability(facts.capabilities, unix.CAP_SYS_PTRACE) {
			blockers = append(blockers, "CAP_SYS_PTRACE is not effective")
		} else {
			finding.Evidence = append(finding.Evidence, "CAP_SYS_PTRACE is effective")
		}
	}
	for _, namespace := range []string{"pid", "user"} {
		pair := facts.namespaces[namespace]
		if pair.current.err != nil || pair.pidOne.err != nil {
			blockers = append(blockers, namespace+" namespace identity could not be inspected")
		} else if !pair.current.identity.Equal(pair.pidOne.identity) {
			blockers = append(blockers, namespace+" namespace differs from visible PID 1")
		} else {
			finding.Evidence = append(finding.Evidence, namespace+" namespace matches visible PID 1")
		}
	}
	finding = finishFinding(finding, blockers,
		"hostPID, compatible user namespace, and ptrace capability prerequisites are present; explicit disposable target selection is still required")
	if len(blockers) == 0 {
		finding.Status = escapeutil.StatusCandidate
	}
	return finding
}

func collectFacts(system scannerSystem) scanFacts {
	facts := scanFacts{
		effectiveUID: system.effectiveUID(),
		namespaces:   make(map[string]namespacePair),
	}
	status, err := system.readFile(procSelfStatus)
	if err != nil {
		facts.statusErr = fmt.Errorf("read process status: %w", err)
	} else {
		facts.capabilities, facts.statusErr = escapeutil.ParseEffectiveCapabilities(status)
		if procUID, uidErr := escapeutil.ParseEffectiveUID(status); uidErr == nil && procUID != facts.effectiveUID {
			facts.statusErr = fmt.Errorf("effective UID differs between process status and system query")
		}
	}
	mountInfo, err := system.readFile(procSelfMountInfo)
	if err != nil {
		facts.mountErr = fmt.Errorf("read mountinfo: %w", err)
	} else {
		facts.mounts, facts.mountErr = escapeutil.ParseMountInfo(mountInfo)
	}
	cgroupData, err := system.readFile(procSelfCgroup)
	if err != nil {
		facts.cgroupErr = fmt.Errorf("read process cgroups: %w", err)
	} else {
		facts.cgroups, facts.cgroupErr = escapeutil.ParseCgroups(cgroupData)
	}
	for _, namespace := range []string{"pid", "mnt", "user", "net", "ipc", "uts", "cgroup"} {
		current, currentErr := system.identity(filepath.Join("/proc/self/ns", namespace))
		pidOne, pidOneErr := system.identity(filepath.Join("/proc/1/ns", namespace))
		facts.namespaces[namespace] = namespacePair{
			current: identityResult{identity: current, err: currentErr},
			pidOne:  identityResult{identity: pidOne, err: pidOneErr},
		}
	}
	facts.root.identity, facts.root.err = system.identity("/")
	facts.pidOneRoot.identity, facts.pidOneRoot.err = system.identity("/proc/1/root")
	return facts
}

func probeHostPID(system scannerSystem, facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueHostPID}
	var blockers []string
	if facts.effectiveUID != 0 {
		blockers = append(blockers, "effective UID 0 is absent")
	}
	if facts.statusErr != nil {
		blockers = append(blockers, "effective capabilities could not be read")
	} else {
		for _, capability := range []struct {
			name string
			bit  int
		}{{"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN}, {"CAP_SYS_CHROOT", unix.CAP_SYS_CHROOT}} {
			if !escapeutil.HasCapability(facts.capabilities, capability.bit) {
				blockers = append(blockers, capability.name+" is not effective")
			}
		}
	}
	for _, namespace := range []string{"pid", "user"} {
		pair := facts.namespaces[namespace]
		if pair.current.err != nil || pair.pidOne.err != nil {
			blockers = append(blockers, namespace+" namespace identity could not be inspected")
		} else if !pair.current.identity.Equal(pair.pidOne.identity) {
			blockers = append(blockers, namespace+" namespace differs from visible PID 1")
		} else {
			finding.Evidence = append(finding.Evidence, namespace+" namespace matches visible PID 1")
		}
	}
	for _, namespace := range []string{"mnt", "net", "ipc", "uts"} {
		pair := facts.namespaces[namespace]
		if pair.current.err != nil || pair.pidOne.err != nil {
			blockers = append(blockers, namespace+" namespace identity could not be inspected")
		}
	}
	inspectedNamespaces := 0
	matchingNamespaces := 0
	for _, namespace := range []string{"pid", "mnt", "user", "net", "ipc", "uts", "cgroup"} {
		pair := facts.namespaces[namespace]
		if pair.current.err != nil || pair.pidOne.err != nil {
			continue
		}
		inspectedNamespaces++
		if pair.current.identity.Equal(pair.pidOne.identity) {
			matchingNamespaces++
		}
	}
	finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d of %d inspected namespace identities match visible PID 1", matchingNamespaces, inspectedNamespaces))
	if facts.root.err != nil || facts.pidOneRoot.err != nil {
		blockers = append(blockers, "filesystem root identities could not be inspected")
	} else if facts.root.identity.Equal(facts.pidOneRoot.identity) {
		blockers = append(blockers, "visible PID 1 has no distinct filesystem root")
	} else {
		finding.Evidence = append(finding.Evidence, "visible PID 1 has a distinct filesystem root")
	}
	if err := system.access("/proc/1/root/bin/sh", unix.X_OK); err != nil {
		blockers = append(blockers, "visible PID 1 root has no executable /bin/sh")
	} else {
		finding.Evidence = append(finding.Evidence, "visible PID 1 root provides executable /bin/sh")
	}
	return finishFinding(finding, blockers, "all observable hostPID breakout prerequisites are present")
}

func probeHostRoot(system scannerSystem, facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueHostRoot}
	var blockers []string
	if facts.effectiveUID != 0 {
		blockers = append(blockers, "effective UID 0 is absent")
	}
	if facts.statusErr != nil || !escapeutil.HasCapability(facts.capabilities, unix.CAP_SYS_CHROOT) {
		blockers = append(blockers, "CAP_SYS_CHROOT is not confirmed effective")
	}
	if facts.mountErr != nil {
		blockers = append(blockers, "mountinfo could not be inspected")
		return finishFinding(finding, blockers, "one distinct mounted host root is available")
	}
	var qualified []string
	for _, candidate := range escapeutil.HostRootCandidates(facts.mounts) {
		kind, kindErr := system.pathKind(candidate)
		if kindErr != nil || kind != pathDirectory {
			continue
		}
		identity, err := system.identity(candidate)
		if err != nil || facts.root.err != nil || identity.Equal(facts.root.identity) {
			continue
		}
		if err := system.access(filepath.Join(candidate, "bin/sh"), unix.X_OK); err != nil {
			continue
		}
		qualified = append(qualified, candidate)
	}
	qualified = escapeutil.OutermostPaths(qualified)
	switch len(qualified) {
	case 0:
		blockers = append(blockers, "no distinct root-mounted filesystem with executable /bin/sh was found")
	case 1:
		finding.Evidence = append(finding.Evidence, "one distinct root-mounted filesystem candidate was found")
	default:
		finding.Status = escapeutil.StatusCandidate
		finding.Summary = "multiple host-root candidates require explicit operator selection"
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d distinct root-mounted filesystem candidates were found", len(qualified)))
		if len(blockers) != 0 {
			finding.Status = escapeutil.StatusBlocked
			finding.Summary = strings.Join(blockers, "; ")
		}
		return finding
	}
	return finishFinding(finding, blockers, "one distinct mounted host root is available")
}

func probeHostLog(system scannerSystem, facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{
		Technique: TechniqueHostLogSymlinkRead,
		Evidence:  []string{fmt.Sprintf("effective UID is %d", facts.effectiveUID)},
	}
	const endpointEvidence = "nodes/proxy authorization and kubelet /logs/ endpoint access were not tested"
	if facts.mountErr != nil {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "mountinfo could not be inspected for a writable host-log mount"
		finding.Evidence = append(finding.Evidence, endpointEvidence)
		return finding
	}

	var qualified []escapeutil.HostLogMount
	for _, candidate := range escapeutil.HostLogCandidates(facts.mounts) {
		kind, err := system.pathKind(candidate.MountPoint)
		if err != nil || kind != pathDirectory {
			continue
		}
		if err := system.access(candidate.MountPoint, unix.W_OK|unix.X_OK); err != nil {
			continue
		}
		qualified = append(qualified, candidate)
	}
	if len(qualified) == 0 {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "no writable direct mount rooted at /var/log with effective write and search access was found"
		finding.Evidence = append(finding.Evidence, endpointEvidence)
		return finding
	}

	finding.Status = escapeutil.StatusCandidate
	if len(qualified) == 1 {
		finding.Summary = "one writable host-log mount is locally usable; nodes/proxy and kubelet /logs/ endpoint access remain unproven"
	} else {
		finding.Summary = "multiple writable host-log mounts require explicit selection; nodes/proxy and kubelet /logs/ endpoint access remain unproven"
	}
	for _, candidate := range qualified {
		endpoint := "/logs/"
		if candidate.URLPrefix != "" {
			endpoint += candidate.URLPrefix + "/"
		}
		if candidate.HostPathOriginUnproven {
			finding.Evidence = append(finding.Evidence, fmt.Sprintf(
				"qualified mount %s maps to logical kubelet %s with rw and effective write/search access; mountinfo did not retain a /var/log root, so hostPath origin remains unproven",
				candidate.MountPoint, endpoint))
			continue
		}
		finding.Evidence = append(finding.Evidence, fmt.Sprintf(
			"qualified mount %s maps node root %s to kubelet %s with rw and effective write/search access",
			candidate.MountPoint, candidate.Root, endpoint))
	}
	finding.Evidence = append(finding.Evidence, endpointEvidence)
	return finding
}

func probeDocker(ctx context.Context, system scannerSystem, options Options) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueDockerSocket}
	paths := escapeutil.DockerSocketPaths(system.getenv("DOCKER_HOST"), options.DockerSockets)
	var sockets, responsive []string
	for _, path := range paths {
		kind, err := system.pathKind(path)
		if err != nil {
			continue
		}
		if kind == pathSymlink {
			finding.Evidence = append(finding.Evidence, fmt.Sprintf("rejected symlink socket candidate %s", path))
			continue
		}
		if kind != pathSocket {
			finding.Evidence = append(finding.Evidence, fmt.Sprintf("rejected non-socket candidate %s", path))
			continue
		}
		sockets = append(sockets, path)
		result, err := system.dockerProbe(ctx, path, options)
		if err != nil {
			finding.Evidence = append(finding.Evidence, fmt.Sprintf("Docker API probe failed for %s", path))
			continue
		}
		responsive = append(responsive, path)
		evidence := fmt.Sprintf("Docker-compatible API responded on %s (API %s)", path, result.APIVersion)
		finding.Evidence = append(finding.Evidence, evidence)
	}
	if len(responsive) != 0 {
		finding.Status = escapeutil.StatusCandidate
		finding.Summary = "a Docker-compatible Unix socket is reachable; an action would still require a suitable local image"
		return finding
	}
	if len(sockets) == 0 {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "no absolute, direct Docker Unix socket was found"
	} else {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "Docker Unix sockets were found but bounded read-only API probes failed"
	}
	return finding
}

func probeCgroupRelease(system scannerSystem, facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueCgroupRelease}
	if facts.cgroupErr != nil || facts.mountErr != nil {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "cgroup topology could not be inspected"
		return finding
	}
	cgroupMounts := escapeutil.MountsByType(facts.mounts, "cgroup")
	if len(cgroupMounts) == 0 {
		finding.Status = escapeutil.StatusUnsupported
		if facts.cgroups.Unified || len(escapeutil.MountsByType(facts.mounts, "cgroup2")) != 0 {
			finding.Summary = "the release_agent technique requires cgroup v1, but only cgroup v2 is active"
		} else {
			finding.Summary = "no cgroup v1 hierarchy is mounted"
		}
		return finding
	}
	var blockers []string
	if facts.effectiveUID != 0 {
		blockers = append(blockers, "effective UID 0 is absent")
	}
	if facts.statusErr != nil || !escapeutil.HasCapability(facts.capabilities, unix.CAP_SYS_ADMIN) {
		blockers = append(blockers, "CAP_SYS_ADMIN is not confirmed effective")
	}
	writableRelease := 0
	writableNotify := 0
	writablePairs := 0
	for _, mount := range cgroupMounts {
		releaseWritable := system.access(filepath.Join(mount.MountPoint, "release_agent"), unix.W_OK) == nil
		if releaseWritable {
			writableRelease++
		}
		notifyWritable := false
		for _, path := range cgroupNotifyPaths(mount, facts.cgroups) {
			if system.access(path, unix.W_OK) == nil {
				writableNotify++
				notifyWritable = true
				break
			}
		}
		if releaseWritable && notifyWritable {
			writablePairs++
		}
	}
	if writableRelease == 0 {
		blockers = append(blockers, "no writable cgroup v1 release_agent was found")
	} else {
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d writable cgroup v1 release_agent file(s) found", writableRelease))
	}
	if writableNotify == 0 {
		blockers = append(blockers, "no writable cgroup v1 notify_on_release was found")
	} else {
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d cgroup v1 hierarchy path(s) allow notify_on_release", writableNotify))
	}
	if writablePairs == 0 {
		blockers = append(blockers, "no single cgroup v1 hierarchy exposes writable release_agent and notify_on_release")
	} else {
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d cgroup v1 hierarchy path(s) expose both writable controls", writablePairs))
	}
	upperDirs := escapeutil.OverlayUpperDirs(facts.mounts)
	if len(upperDirs) == 0 {
		blockers = append(blockers, "no host-visible overlay upperdir could be derived")
	} else {
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d overlay upperdir path candidate(s) derived", len(upperDirs)))
	}
	if len(blockers) != 0 {
		return finishFinding(finding, blockers, "")
	}
	finding.Status = escapeutil.StatusCandidate
	finding.Summary = "observable cgroup v1 release_agent prerequisites are present; mutation is required to prove viability"
	return finding
}

func cgroupNotifyPaths(mount escapeutil.Mount, info escapeutil.CgroupInfo) []string {
	paths := []string{filepath.Join(mount.MountPoint, "notify_on_release")}
	controllers := append([]string(nil), mount.SuperOptions...)
	controllers = append(controllers, strings.Split(filepath.Base(mount.MountPoint), ",")...)
	for _, controller := range controllers {
		groupPath, ok := info.ControllerPath(controller)
		if !ok {
			continue
		}
		relative := strings.TrimPrefix(filepath.Clean(groupPath), string(filepath.Separator))
		if relative == "." || relative == "" {
			continue
		}
		paths = append(paths, filepath.Join(mount.MountPoint, relative, "notify_on_release"))
	}
	return escapeutil.SortedUnique(paths)
}

func probeCorePattern(system scannerSystem, facts scanFacts) escapeutil.Finding {
	finding := escapeutil.Finding{Technique: TechniqueCorePattern}
	if facts.mountErr != nil {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "procfs mounts could not be inspected"
		return finding
	}
	var writableProc int
	for _, mount := range escapeutil.MountsByType(facts.mounts, "proc") {
		if system.access(filepath.Join(mount.MountPoint, "sys/kernel/core_pattern"), unix.W_OK) == nil {
			writableProc++
		}
	}
	var blockers []string
	if writableProc == 0 {
		blockers = append(blockers, "no procfs mount exposes writable core_pattern")
	} else {
		finding.Evidence = append(finding.Evidence, fmt.Sprintf("%d procfs mount(s) expose writable core_pattern", writableProc))
	}
	if len(blockers) != 0 {
		return finishFinding(finding, blockers, "")
	}
	finding.Status = escapeutil.StatusCandidate
	finding.Summary = "a procfs mount exposes writable core_pattern; a temporary kernel-global mutation is required to exercise the action"
	return finding
}

func finishFinding(finding escapeutil.Finding, blockers []string, availableSummary string) escapeutil.Finding {
	if len(blockers) == 0 {
		finding.Status = escapeutil.StatusAvailable
		finding.Summary = availableSummary
		return finding
	}
	sort.Strings(blockers)
	finding.Status = escapeutil.StatusBlocked
	finding.Summary = strings.Join(blockers, "; ")
	return finding
}
