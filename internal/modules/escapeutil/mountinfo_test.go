package escapeutil

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	data := "36 25 0:32 /docker\\040root /host\\040root rw,nosuid shared:7 - ext4 /dev/sda1 rw,relatime\n" +
		"37 25 0:33 / / rw - overlay overlay rw,lowerdir=/lower,upperdir=/host\\134upper,workdir=/work\n"
	mounts, err := ParseMountInfo([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mount count = %d, want 2", len(mounts))
	}
	first := mounts[0]
	if first.ID != 36 || first.ParentID != 25 || first.Root != "/docker root" || first.MountPoint != "/host root" || first.Source != "/dev/sda1" {
		t.Fatalf("first mount = %#v", first)
	}
	if !reflect.DeepEqual(first.OptionalFields, []string{"shared:7"}) {
		t.Fatalf("optional fields = %#v", first.OptionalFields)
	}
	if got := OverlayUpperDirs(mounts); !reflect.DeepEqual(got, []string{"/host\\upper"}) {
		t.Fatalf("OverlayUpperDirs() = %#v", got)
	}
}

func TestParseMountInfoRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "short", line: "1 2 3", want: "malformed mountinfo"},
		{name: "id", line: "x 2 0:1 / / rw - ext4 /dev/a rw", want: "mount ID"},
		{name: "parent", line: "1 x 0:1 / / rw - ext4 /dev/a rw", want: "parent mount ID"},
		{name: "truncated escape", line: "1 2 0:1 / /bad\\ rw - ext4 /dev/a rw", want: "truncated mount escape"},
		{name: "unknown escape", line: "1 2 0:1 / /bad\\777 rw - ext4 /dev/a rw", want: "unsupported mount escape"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMountInfo([]byte(test.line + "\n"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseMountInfo() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMountSelections(t *testing.T) {
	mounts := []Mount{
		{Root: "/", MountPoint: "/", FSType: "overlay", SuperOptions: []string{"upperdir=/host/upper"}},
		{Root: "/", MountPoint: "/host", FSType: "ext4"},
		{Root: "/", MountPoint: "/host", FSType: "ext4"},
		{Root: "/subdir", MountPoint: "/not-root", FSType: "ext4"},
		{Root: "/", MountPoint: "/proc", FSType: "proc"},
		{Root: "/", MountPoint: "relative", FSType: "ext4"},
		{Root: "/", MountPoint: "/overlay", FSType: "overlay", SuperOptions: []string{"upperdir=relative", "upperdir=/host/second"}},
		{Root: "/var/log", MountPoint: "/mnt/logs", Options: []string{"rw", "nosuid"}, FSType: "overlay"},
		{Root: "/var/log/containers", MountPoint: "/mnt/containers", Options: []string{"nodev", "rw"}, FSType: "ext4"},
		{Root: "/var/log", MountPoint: "/mnt/logs", Options: []string{"rw"}, FSType: "overlay"},
		{Root: "/var/log/pods", MountPoint: "/mnt/pods", Options: []string{"ro"}, FSType: "ext4"},
	}
	if got := HostRootCandidates(mounts); !reflect.DeepEqual(got, []string{"/host", "/overlay"}) {
		t.Fatalf("HostRootCandidates() = %#v", got)
	}
	if got := OverlayUpperDirs(mounts); !reflect.DeepEqual(got, []string{"/host/second", "/host/upper"}) {
		t.Fatalf("OverlayUpperDirs() = %#v", got)
	}
	if got := MountsByType(mounts, "proc"); len(got) != 1 || got[0].MountPoint != "/proc" {
		t.Fatalf("MountsByType(proc) = %#v", got)
	}
	wantHostLogs := []HostLogMount{
		{MountPoint: "/mnt/containers", Root: "/var/log/containers", URLPrefix: "containers"},
		{MountPoint: "/mnt/logs", Root: "/var/log", URLPrefix: ""},
	}
	if got := HostLogCandidates(mounts); !reflect.DeepEqual(got, wantHostLogs) {
		t.Fatalf("HostLogCandidates() = %#v, want %#v", got, wantHostLogs)
	}
}

func TestHostLogCandidatesRejectMalformedAndSimilarPaths(t *testing.T) {
	mounts := []Mount{
		{Root: "/var/logger", MountPoint: "/mnt/logger", Options: []string{"rw"}},
		{Root: "/var/log-old", MountPoint: "/mnt/old", Options: []string{"rw"}},
		{Root: "var/log", MountPoint: "/mnt/relative-root", Options: []string{"rw"}},
		{Root: "/var/log/../log", MountPoint: "/mnt/unclean-root", Options: []string{"rw"}},
		{Root: "/var/log", MountPoint: "mnt/relative", Options: []string{"rw"}},
		{Root: "/var/log", MountPoint: "/mnt/logs/.", Options: []string{"rw"}},
		{Root: "/var/log", MountPoint: "/mnt/readonly", Options: []string{"ro"}},
		{Root: "/var/log", MountPoint: "/mnt/not-exact", Options: []string{"rwx"}},
	}
	if got := HostLogCandidates(mounts); len(got) != 0 {
		t.Fatalf("HostLogCandidates() = %#v, want no candidates", got)
	}
}

func TestHostLogCandidatesAcceptsOnlyExactVarLogDestinationFallback(t *testing.T) {
	mounts := []Mount{
		{Root: "/", MountPoint: "/var/log", Options: []string{"rw", "nosuid"}},
		{Root: "/", MountPoint: "/var/log", Options: []string{"rw"}},
		{Root: "/var/lib/runtime/volumes/id/_data/log", MountPoint: "/var/log", Options: []string{"rw"}},
		{Root: "/", MountPoint: "/mnt/node-logs", Options: []string{"rw"}},
		{Root: "/", MountPoint: "/var/log/pods", Options: []string{"rw"}},
		{Root: "/", MountPoint: "/var/log", Options: []string{"ro"}},
		{Root: "/var/log", MountPoint: "/mnt/node-logs", Options: []string{"rw"}},
		{Root: "/var/log", MountPoint: "/var/log", Options: []string{"rw"}},
	}
	want := []HostLogMount{
		{MountPoint: "/mnt/node-logs", Root: "/var/log", URLPrefix: ""},
		{MountPoint: "/var/log", Root: "/var/log", URLPrefix: ""},
	}
	if got := HostLogCandidates(mounts); !reflect.DeepEqual(got, want) {
		t.Fatalf("HostLogCandidates() = %#v, want %#v", got, want)
	}
	readOnly := []Mount{{Root: "/", MountPoint: "/var/log", Options: []string{"ro"}}}
	if got := HostLogCandidates(readOnly); len(got) != 0 {
		t.Fatalf("HostLogCandidates(read-only fallback) = %#v, want no candidates", got)
	}
	fallbackOnly := []Mount{{
		Root:       "/var/lib/runtime/volumes/id/_data/log",
		MountPoint: "/var/log",
		Options:    []string{"rw"},
	}}
	wantFallback := []HostLogMount{{
		MountPoint: "/var/log", Root: "/var/log", HostPathOriginUnproven: true,
	}}
	if got := HostLogCandidates(fallbackOnly); !reflect.DeepEqual(got, wantFallback) {
		t.Fatalf("HostLogCandidates(fallback) = %#v, want %#v", got, wantFallback)
	}
}

func TestOutermostPaths(t *testing.T) {
	paths := []string{
		"/hostroot/run/container/rootfs",
		"/second",
		"/hostroot",
		"/second-nested",
		"/second/var/lib/rootfs",
		"/hostroot",
	}
	want := []string{"/hostroot", "/second", "/second-nested"}
	if got := OutermostPaths(paths); !reflect.DeepEqual(got, want) {
		t.Fatalf("OutermostPaths() = %#v, want %#v", got, want)
	}
}
