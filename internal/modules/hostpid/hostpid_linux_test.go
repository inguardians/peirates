//go:build linux

package hostpid

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeChild struct {
	exitCode int
	err      error
	calls    *[]string
}

func (child fakeChild) wait() (int, error) {
	*child.calls = append(*child.calls, "wait")
	return child.exitCode, child.err
}

type fakePlatform struct {
	euid       int
	status     []byte
	identities map[string]fileIdentity
	errors     map[string]error
	fds        map[int]string
	nextFD     int
	calls      []string
	exitCode   int
	startName  string
	startArgv  []string
	startAttr  *os.ProcAttr
}

func newFakePlatform() *fakePlatform {
	capabilities := uint64(1)<<uint(unix.CAP_SYS_ADMIN) |
		uint64(1)<<uint(unix.CAP_SYS_CHROOT)
	return &fakePlatform{
		euid:   0,
		status: []byte(fmt.Sprintf("Name:\tpeirates\nCapEff:\t%016x\n", capabilities)),
		identities: map[string]fileIdentity{
			"/proc/self/ns/pid":  {device: 1, inode: 1},
			"/proc/1/ns/pid":     {device: 1, inode: 1},
			"/proc/self/ns/user": {device: 1, inode: 2},
			"/proc/1/ns/user":    {device: 1, inode: 2},
			"/":                  {device: 2, inode: 1},
			procOneRoot:          {device: 3, inode: 1},
			"/proc/self/ns/ipc":  {device: 1, inode: 10},
			"/proc/1/ns/ipc":     {device: 1, inode: 20},
			"/proc/self/ns/uts":  {device: 1, inode: 11},
			"/proc/1/ns/uts":     {device: 1, inode: 21},
			"/proc/self/ns/net":  {device: 1, inode: 12},
			"/proc/1/ns/net":     {device: 1, inode: 22},
			"/proc/self/ns/mnt":  {device: 1, inode: 13},
			"/proc/1/ns/mnt":     {device: 1, inode: 23},
		},
		errors:   make(map[string]error),
		fds:      make(map[int]string),
		nextFD:   10,
		exitCode: 7,
	}
}

func (system *fakePlatform) effectiveUID() int { return system.euid }
func (system *fakePlatform) readFile(path string) ([]byte, error) {
	system.calls = append(system.calls, "read:"+path)
	if err := system.errors["read:"+path]; err != nil {
		return nil, err
	}
	return system.status, nil
}
func (system *fakePlatform) identity(path string) (fileIdentity, error) {
	system.calls = append(system.calls, "identity:"+path)
	if err := system.errors["identity:"+path]; err != nil {
		return fileIdentity{}, err
	}
	identity, ok := system.identities[path]
	if !ok {
		return fileIdentity{}, fmt.Errorf("missing fake identity for %s", path)
	}
	return identity, nil
}
func (system *fakePlatform) access(path string, mode uint32) error {
	system.calls = append(system.calls, fmt.Sprintf("access:%s:%d", path, mode))
	return system.errors["access:"+path]
}
func (system *fakePlatform) open(path string, flags int, _ uint32) (int, error) {
	system.calls = append(system.calls, fmt.Sprintf("open:%s:%d", path, flags))
	if err := system.errors["open:"+path]; err != nil {
		return -1, err
	}
	fd := system.nextFD
	system.nextFD++
	system.fds[fd] = path
	return fd, nil
}
func (system *fakePlatform) fstat(fd int) (fileIdentity, error) {
	path := system.fds[fd]
	system.calls = append(system.calls, "fstat:"+path)
	if err := system.errors["fstat:"+path]; err != nil {
		return fileIdentity{}, err
	}
	return system.identities[path], nil
}
func (system *fakePlatform) close(fd int) error {
	path := system.fds[fd]
	system.calls = append(system.calls, "close:"+path)
	delete(system.fds, fd)
	return system.errors["close:"+path]
}
func (system *fakePlatform) lockOSThread() { system.calls = append(system.calls, "lock") }
func (system *fakePlatform) unshare(flags int) error {
	system.calls = append(system.calls, fmt.Sprintf("unshare:%d", flags))
	return system.errors["unshare"]
}
func (system *fakePlatform) setns(fd, namespaceType int) error {
	path := system.fds[fd]
	system.calls = append(system.calls, fmt.Sprintf("setns:%s:%d", path, namespaceType))
	return system.errors["setns:"+path]
}
func (system *fakePlatform) fchdir(fd int) error {
	path := system.fds[fd]
	system.calls = append(system.calls, "fchdir:"+path)
	return system.errors["fchdir"]
}
func (system *fakePlatform) chroot(path string) error {
	system.calls = append(system.calls, "chroot:"+path)
	return system.errors["chroot"]
}
func (system *fakePlatform) chdir(path string) error {
	system.calls = append(system.calls, "chdir:"+path)
	return system.errors["chdir"]
}
func (system *fakePlatform) startProcess(name string, argv []string, attr *os.ProcAttr) (childProcess, error) {
	system.calls = append(system.calls, "start:"+name)
	system.startName = name
	system.startArgv = append([]string(nil), argv...)
	copyAttr := *attr
	copyAttr.Env = append([]string(nil), attr.Env...)
	copyAttr.Files = append([]*os.File(nil), attr.Files...)
	system.startAttr = &copyAttr
	if err := system.errors["start"]; err != nil {
		return nil, err
	}
	return fakeChild{exitCode: system.exitCode, err: system.errors["wait"], calls: &system.calls}, nil
}

type fakeLauncher struct {
	path   string
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	err    error
}

func (launcher *fakeLauncher) run(path string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	launcher.path = path
	launcher.args = append([]string(nil), args...)
	launcher.stdin = stdin
	launcher.stdout = stdout
	launcher.stderr = stderr
	return launcher.err
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("unexpected input read") }

func TestParseEffectiveCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		want    uint64
		wantErr string
	}{
		{name: "value", status: "Name:\tpeirates\nCapEff:\t0000000000240000\n", want: 0x240000},
		{name: "missing", status: "Name:\tpeirates\n", wantErr: "CapEff is missing"},
		{name: "missing value", status: "CapEff:\n", wantErr: "malformed CapEff"},
		{name: "invalid hex", status: "CapEff:\tnot-hex\n", wantErr: "malformed CapEff"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseEffectiveCapabilities([]byte(test.status))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("parseEffectiveCapabilities() = %#x, %v; want %#x, nil", got, err, test.want)
			}
		})
	}
}

func TestPrepareWorkerQualificationFailures(t *testing.T) {
	permissionError := errors.New("permission denied")
	tests := []struct {
		name    string
		mutate  func(*fakePlatform)
		wantErr string
	}{
		{name: "not root", mutate: func(system *fakePlatform) { system.euid = 1000 }, wantErr: "effective UID 0"},
		{name: "status unavailable", mutate: func(system *fakePlatform) { system.errors["read:"+procSelfStatus] = permissionError }, wantErr: "read /proc/self/status"},
		{name: "missing capability", mutate: func(system *fakePlatform) { system.status = []byte("CapEff:\t0000000000000000\n") }, wantErr: "CAP_SYS_ADMIN, CAP_SYS_CHROOT"},
		{name: "private pid namespace", mutate: func(system *fakePlatform) { system.identities["/proc/1/ns/pid"] = fileIdentity{device: 9, inode: 9} }, wantErr: "hostPID is required"},
		{name: "different user namespace", mutate: func(system *fakePlatform) { system.identities["/proc/1/ns/user"] = fileIdentity{device: 9, inode: 9} }, wantErr: "user namespace transitions are unsupported"},
		{name: "same root", mutate: func(system *fakePlatform) { system.identities[procOneRoot] = system.identities["/"] }, wantErr: "no distinct node root"},
		{name: "missing shell", mutate: func(system *fakePlatform) { system.errors["access:"+hostShellPath] = permissionError }, wantErr: "is not executable"},
		{name: "namespace open", mutate: func(system *fakePlatform) { system.errors["open:/proc/1/ns/net"] = permissionError }, wantErr: "open PID 1 network namespace"},
		{name: "namespace stat", mutate: func(system *fakePlatform) { system.errors["fstat:/proc/1/ns/uts"] = permissionError }, wantErr: "inspect PID 1 UTS namespace"},
		{name: "current namespace stat", mutate: func(system *fakePlatform) { system.errors["identity:/proc/self/ns/mnt"] = permissionError }, wantErr: "inspect current mount namespace"},
		{name: "root open", mutate: func(system *fakePlatform) { system.errors["open:"+procOneRoot] = permissionError }, wantErr: "open PID 1 filesystem root"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakePlatform()
			test.mutate(system)
			prepared, err := prepareWorker(system)
			if prepared != nil {
				prepared.closeAll(system)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestPrepareWorkerOpensEveryTargetBeforeMutation(t *testing.T) {
	system := newFakePlatform()
	prepared, err := prepareWorker(system)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.closeAll(system)
	if len(prepared.namespaces) != 4 {
		t.Fatalf("namespaces = %d, want 4", len(prepared.namespaces))
	}
	if prepared.rootFD < 0 {
		t.Fatal("PID 1 root descriptor was not opened")
	}
	if len(system.fds) != 5 {
		t.Fatalf("open descriptors = %d, want 5", len(system.fds))
	}
}

func TestLaunchUsesPrivateWorkerWithoutReadingInput(t *testing.T) {
	system := newFakePlatform()
	launcher := &fakeLauncher{}
	stdin := panicReader{}
	var stdout, stderr bytes.Buffer
	if err := launchWith(system, launcher, stdin, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if launcher.path != "/proc/self/exe" || !reflect.DeepEqual(launcher.args, []string{WorkerArgument}) {
		t.Fatalf("worker invocation = %q %#v", launcher.path, launcher.args)
	}
	if launcher.stdin != stdin || launcher.stdout != &stdout || launcher.stderr != &stderr {
		t.Fatal("worker did not inherit the supplied streams")
	}
	if !strings.Contains(stdout.String(), "exit returns to Peirates") {
		t.Fatalf("boundary message missing: %q", stdout.String())
	}
	if len(system.fds) != 0 {
		t.Fatalf("preflight descriptors were not closed: %#v", system.fds)
	}
}

func TestLaunchReportsWorkerFailure(t *testing.T) {
	system := newFakePlatform()
	launcher := &fakeLauncher{err: errors.New("exit status 7")}
	err := launchWith(system, launcher, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "isolated worker failed: exit status 7") {
		t.Fatalf("error = %v", err)
	}
}

func TestWorkerTransitionOrderAndShellContract(t *testing.T) {
	system := newFakePlatform()
	exitCode, err := runWorkerWith(system, os.Stdin, os.Stdout, os.Stderr, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 7 {
		t.Fatalf("exit code = %d, want 7", exitCode)
	}
	wantSequence := []string{
		"lock",
		fmt.Sprintf("unshare:%d", unix.CLONE_FS),
		fmt.Sprintf("setns:/proc/1/ns/ipc:%d", unix.CLONE_NEWIPC),
		fmt.Sprintf("setns:/proc/1/ns/uts:%d", unix.CLONE_NEWUTS),
		fmt.Sprintf("setns:/proc/1/ns/net:%d", unix.CLONE_NEWNET),
		fmt.Sprintf("setns:/proc/1/ns/mnt:%d", unix.CLONE_NEWNS),
		"fchdir:/proc/1/root",
		"chroot:.",
		"chdir:/",
		"start:/bin/sh",
		"wait",
	}
	assertOrderedCalls(t, system.calls, wantSequence)
	lockIndex := callIndex(system.calls, "lock")
	for _, call := range system.calls[lockIndex+1:] {
		if strings.HasPrefix(call, "open:") {
			t.Fatalf("descriptor opened after namespace mutation began: %v", system.calls)
		}
	}
	if system.startName != "/bin/sh" || !reflect.DeepEqual(system.startArgv, []string{"sh", "-i"}) {
		t.Fatalf("shell = %q %#v", system.startName, system.startArgv)
	}
	wantEnvironment := []string{
		"HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PS1=[peirates-host]# ", "TERM=xterm-256color",
	}
	if !reflect.DeepEqual(system.startAttr.Env, wantEnvironment) {
		t.Fatalf("environment = %#v, want %#v", system.startAttr.Env, wantEnvironment)
	}
	if system.startAttr.Dir != "/" || !reflect.DeepEqual(system.startAttr.Files, []*os.File{os.Stdin, os.Stdout, os.Stderr}) {
		t.Fatalf("process attributes = %#v", system.startAttr)
	}
	for _, forbidden := range []string{"LD_PRELOAD", "BASH_ENV", "KUBERNETES_SERVICE_HOST"} {
		if strings.Contains(strings.Join(system.startAttr.Env, "\n"), forbidden) {
			t.Fatalf("environment inherited forbidden variable %s", forbidden)
		}
	}
}

func TestWorkerSkipsNamespaceAlreadyCurrent(t *testing.T) {
	system := newFakePlatform()
	system.identities["/proc/1/ns/ipc"] = system.identities["/proc/self/ns/ipc"]
	if _, err := runWorkerWith(system, os.Stdin, os.Stdout, os.Stderr, ""); err != nil {
		t.Fatal(err)
	}
	for _, call := range system.calls {
		if strings.HasPrefix(call, "setns:/proc/1/ns/ipc:") {
			t.Fatalf("worker re-entered its current IPC namespace: %v", system.calls)
		}
	}
}

func TestWorkerStopsAfterEveryMutationFailure(t *testing.T) {
	tests := []struct {
		name    string
		failKey string
		wantErr string
	}{
		{name: "unshare", failKey: "unshare", wantErr: "unshare filesystem attributes"},
		{name: "IPC", failKey: "setns:/proc/1/ns/ipc", wantErr: "enter PID 1 IPC namespace"},
		{name: "UTS", failKey: "setns:/proc/1/ns/uts", wantErr: "enter PID 1 UTS namespace"},
		{name: "network", failKey: "setns:/proc/1/ns/net", wantErr: "enter PID 1 network namespace"},
		{name: "mount", failKey: "setns:/proc/1/ns/mnt", wantErr: "enter PID 1 mount namespace"},
		{name: "fchdir", failKey: "fchdir", wantErr: "change directory to PID 1 root"},
		{name: "chroot", failKey: "chroot", wantErr: "chroot to PID 1 root"},
		{name: "chdir", failKey: "chdir", wantErr: "change directory to host root"},
		{name: "start", failKey: "start", wantErr: "start host /bin/sh"},
		{name: "wait", failKey: "wait", wantErr: "wait for host /bin/sh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := newFakePlatform()
			system.errors[test.failKey] = errors.New("injected failure")
			_, err := runWorkerWith(system, os.Stdin, os.Stdout, os.Stderr, "")
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
			if test.failKey != "wait" && test.failKey != "start" && containsCall(system.calls, "start:/bin/sh") {
				t.Fatalf("shell started after %s failure: %v", test.name, system.calls)
			}
			if test.failKey == "start" && containsCall(system.calls, "wait") {
				t.Fatalf("worker waited after start failure: %v", system.calls)
			}
		})
	}
}

func TestRunWorkerRejectsArgumentsBeforePreflight(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if got := RunWorker([]string{"unexpected"}, os.Stdin, os.Stdout, writeEnd); got != 2 {
		t.Fatalf("exit code = %d, want 2", got)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatal(err)
	}
	_ = readEnd.Close()
	if !strings.Contains(string(output), "does not accept arguments") {
		t.Fatalf("output = %q", output)
	}
}

func assertOrderedCalls(t *testing.T, calls, want []string) {
	t.Helper()
	position := 0
	for _, call := range calls {
		if position < len(want) && call == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("calls do not contain ordered sequence\ncalls: %#v\nwant:  %#v", calls, want)
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func callIndex(calls []string, want string) int {
	for index, call := range calls {
		if call == want {
			return index
		}
	}
	return -1
}
