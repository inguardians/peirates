package escapeutil

import (
	"bufio"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Mount is a parsed Linux /proc/*/mountinfo record.
type Mount struct {
	ID             int
	ParentID       int
	MajorMinor     string
	Root           string
	MountPoint     string
	Options        []string
	OptionalFields []string
	FSType         string
	Source         string
	SuperOptions   []string
}

// HostLogMount describes a writable mount that may expose the node's /var/log
// tree. URLPrefix is the slash-separated path below kubelet's /logs/ endpoint.
// HostPathOriginUnproven distinguishes the narrow destination-only fallback
// used when runtime staging obscures the source of a mount placed exactly at
// /var/log.
type HostLogMount struct {
	MountPoint             string
	Root                   string
	URLPrefix              string
	HostPathOriginUnproven bool
}

// ParseMountInfo parses Linux mountinfo and decodes the kernel's octal path
// escapes. Unknown optional fields are retained for forward compatibility.
func ParseMountInfo(data []byte) ([]Mount, error) {
	var mounts []Mount
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return nil, fmt.Errorf("malformed mountinfo line %d", lineNumber)
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil || id < 0 {
			return nil, fmt.Errorf("malformed mount ID on line %d", lineNumber)
		}
		parentID, err := strconv.Atoi(fields[1])
		if err != nil || parentID < 0 {
			return nil, fmt.Errorf("malformed parent mount ID on line %d", lineNumber)
		}
		root, err := unescapeMountField(fields[3])
		if err != nil {
			return nil, fmt.Errorf("decode mount root on line %d: %w", lineNumber, err)
		}
		mountPoint, err := unescapeMountField(fields[4])
		if err != nil {
			return nil, fmt.Errorf("decode mount point on line %d: %w", lineNumber, err)
		}
		source, err := unescapeMountField(fields[separator+2])
		if err != nil {
			return nil, fmt.Errorf("decode mount source on line %d: %w", lineNumber, err)
		}
		superOptions, err := unescapeMountList(fields[separator+3])
		if err != nil {
			return nil, fmt.Errorf("decode super options on line %d: %w", lineNumber, err)
		}
		mounts = append(mounts, Mount{
			ID:             id,
			ParentID:       parentID,
			MajorMinor:     fields[2],
			Root:           root,
			MountPoint:     mountPoint,
			Options:        strings.Split(fields[5], ","),
			OptionalFields: append([]string(nil), fields[6:separator]...),
			FSType:         fields[separator+1],
			Source:         source,
			SuperOptions:   superOptions,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	return mounts, nil
}

func unescapeMountList(value string) ([]string, error) {
	values := strings.Split(value, ",")
	for index, item := range values {
		decoded, err := unescapeMountField(item)
		if err != nil {
			return nil, err
		}
		values[index] = decoded
	}
	return values, nil
}

func unescapeMountField(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("truncated mount escape")
		}
		escape := value[index+1 : index+4]
		var decoded byte
		switch escape {
		case "040":
			decoded = ' '
		case "011":
			decoded = '\t'
		case "012":
			decoded = '\n'
		case "134":
			decoded = '\\'
		default:
			return "", fmt.Errorf("unsupported mount escape \\%s", escape)
		}
		result.WriteByte(decoded)
		index += 3
	}
	return result.String(), nil
}

// HostRootCandidates returns absolute, non-root mount points whose mounted
// subtree starts at filesystem root. Action modules must still qualify each
// candidate and reject ambiguity immediately before mutation.
func HostRootCandidates(mounts []Mount) []string {
	var candidates []string
	for _, mount := range mounts {
		if mount.Root != "/" || mount.MountPoint == "/" || !filepath.IsAbs(mount.MountPoint) {
			continue
		}
		switch mount.FSType {
		case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "tmpfs":
			continue
		}
		candidates = append(candidates, filepath.Clean(mount.MountPoint))
	}
	return SortedUnique(candidates)
}

// HostLogCandidates returns normalized, writable mounts rooted at /var/log or
// one of its true descendants. Kubernetes runtime staging can obscure the bind
// source with a runtime-specific root; in that case only an exact container
// destination of /var/log is accepted, and its hostPath origin remains
// explicitly unproven. Arbitrary destinations and descendant destinations do
// not qualify through this fallback. Action modules must still verify directory
// type and effective write/search access immediately before mutation.
func HostLogCandidates(mounts []Mount) []HostLogMount {
	const hostLogRoot = "/var/log"

	seen := make(map[HostLogMount]struct{})
	var candidates []HostLogMount
	for _, mount := range mounts {
		if !isAbsoluteNormalizedPath(mount.Root) || !isAbsoluteNormalizedPath(mount.MountPoint) ||
			!containsMountOption(mount.Options, "rw") {
			continue
		}

		var candidate HostLogMount
		switch {
		case pathWithin(hostLogRoot, mount.Root):
			prefix := strings.TrimPrefix(mount.Root, hostLogRoot)
			prefix = strings.TrimPrefix(prefix, string(filepath.Separator))
			candidate = HostLogMount{
				MountPoint: mount.MountPoint,
				Root:       mount.Root,
				URLPrefix:  filepath.ToSlash(prefix),
			}
		case mount.MountPoint == hostLogRoot:
			candidate = HostLogMount{
				MountPoint:             mount.MountPoint,
				Root:                   hostLogRoot,
				HostPathOriginUnproven: true,
			}
		default:
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(first, second int) bool {
		if candidates[first].MountPoint != candidates[second].MountPoint {
			return candidates[first].MountPoint < candidates[second].MountPoint
		}
		if candidates[first].Root != candidates[second].Root {
			return candidates[first].Root < candidates[second].Root
		}
		if candidates[first].URLPrefix != candidates[second].URLPrefix {
			return candidates[first].URLPrefix < candidates[second].URLPrefix
		}
		return !candidates[first].HostPathOriginUnproven && candidates[second].HostPathOriginUnproven
	})
	deduplicated := candidates[:0]
	for _, candidate := range candidates {
		if len(deduplicated) > 0 {
			previous := deduplicated[len(deduplicated)-1]
			if previous.MountPoint == candidate.MountPoint && previous.Root == candidate.Root &&
				previous.URLPrefix == candidate.URLPrefix {
				continue
			}
		}
		deduplicated = append(deduplicated, candidate)
	}
	return deduplicated
}

func isAbsoluteNormalizedPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

func pathWithin(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func containsMountOption(options []string, expected string) bool {
	for _, option := range options {
		if option == expected {
			return true
		}
	}
	return false
}

// OutermostPaths removes paths nested beneath another path in the same set.
// This prevents recursive bind-mount children from being counted as separate
// roots when their enclosing mounted filesystem already qualifies.
func OutermostPaths(paths []string) []string {
	ordered := SortedUnique(paths)
	result := make([]string, 0, len(ordered))
	for _, candidate := range ordered {
		nested := false
		for _, parent := range result {
			relative, err := filepath.Rel(parent, candidate)
			if err == nil && relative != "." && relative != ".." &&
				!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			result = append(result, candidate)
		}
	}
	return result
}

// OverlayUpperDirs returns upperdir values derived from overlay mount options.
// These are host-visible path candidates only; their presence is not proof
// that an escape is viable.
func OverlayUpperDirs(mounts []Mount) []string {
	var paths []string
	for _, mount := range mounts {
		if mount.FSType != "overlay" {
			continue
		}
		for _, option := range mount.SuperOptions {
			if strings.HasPrefix(option, "upperdir=") {
				path := strings.TrimPrefix(option, "upperdir=")
				if filepath.IsAbs(path) {
					paths = append(paths, filepath.Clean(path))
				}
			}
		}
	}
	return SortedUnique(paths)
}

// MountsByType returns a copy of mounts with the requested filesystem type.
func MountsByType(mounts []Mount, filesystemType string) []Mount {
	var result []Mount
	for _, mount := range mounts {
		if mount.FSType == filesystemType {
			result = append(result, mount)
		}
	}
	return result
}
