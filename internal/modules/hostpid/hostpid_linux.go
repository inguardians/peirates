//go:build linux

package hostpid

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	procSelfStatus = "/proc/self/status"
	procOneRoot    = "/proc/1/root"
	hostShellPath  = "/proc/1/root/bin/sh"
)

type fileIdentity struct {
	device uint64
	inode  uint64
}

type childProcess interface {
	wait() (int, error)
}

type platform interface {
	effectiveUID() int
	readFile(string) ([]byte, error)
	identity(string) (fileIdentity, error)
	access(string, uint32) error
	open(string, int, uint32) (int, error)
	fstat(int) (fileIdentity, error)
	close(int) error
	lockOSThread()
	unshare(int) error
	setns(int, int) error
	fchdir(int) error
	chroot(string) error
	chdir(string) error
	startProcess(string, []string, *os.ProcAttr) (childProcess, error)
}

type workerLauncher interface {
	run(string, []string, io.Reader, io.Writer, io.Writer) error
}

type realPlatform struct{}

func (realPlatform) effectiveUID() int { return os.Geteuid() }
func (realPlatform) readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (realPlatform) identity(path string) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}
func (realPlatform) access(path string, mode uint32) error { return unix.Access(path, mode) }
func (realPlatform) open(path string, flags int, mode uint32) (int, error) {
	return unix.Open(path, flags, mode)
}
func (realPlatform) fstat(fd int) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}
func (realPlatform) close(fd int) error                { return unix.Close(fd) }
func (realPlatform) lockOSThread()                     { runtime.LockOSThread() }
func (realPlatform) unshare(flags int) error           { return unix.Unshare(flags) }
func (realPlatform) setns(fd, namespaceType int) error { return unix.Setns(fd, namespaceType) }
func (realPlatform) fchdir(fd int) error               { return unix.Fchdir(fd) }
func (realPlatform) chroot(path string) error          { return unix.Chroot(path) }
func (realPlatform) chdir(path string) error           { return unix.Chdir(path) }
func (realPlatform) startProcess(name string, argv []string, attr *os.ProcAttr) (childProcess, error) {
	process, err := os.StartProcess(name, argv, attr)
	if err != nil {
		return nil, err
	}
	return osChildProcess{process: process}, nil
}

type osChildProcess struct{ process *os.Process }

func (p osChildProcess) wait() (int, error) {
	state, err := p.process.Wait()
	if err != nil {
		return 0, err
	}
	if exitCode := state.ExitCode(); exitCode >= 0 {
		return exitCode, nil
	}
	return 0, fmt.Errorf("host shell terminated without an exit status")
}

type execWorkerLauncher struct{}

func (execWorkerLauncher) run(path string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	/* #nosec G204 -- Peirates intentionally re-executes its own binary in a private worker mode. */
	command := exec.Command(path, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

type namespaceDescriptor struct {
	name           string
	namespaceType  int
	fd             int
	alreadyCurrent bool
}

type preparedWorker struct {
	namespaces []namespaceDescriptor
	rootFD     int
}

func (prepared *preparedWorker) closeAll(system platform) {
	for index := range prepared.namespaces {
		if prepared.namespaces[index].fd >= 0 {
			_ = system.close(prepared.namespaces[index].fd)
			prepared.namespaces[index].fd = -1
		}
	}
	if prepared.rootFD >= 0 {
		_ = system.close(prepared.rootFD)
		prepared.rootFD = -1
	}
}

// Launch verifies the current environment and runs the namespace-changing
// work in a disposable copy of the Peirates process.
func Launch(stdin io.Reader, stdout, stderr io.Writer) error {
	return launchWith(realPlatform{}, execWorkerLauncher{}, stdin, stdout, stderr)
}

func launchWith(system platform, launcher workerLauncher, stdin io.Reader, stdout, stderr io.Writer) error {
	prepared, err := prepareWorker(system)
	if err != nil {
		return err
	}
	prepared.closeAll(system)

	fmt.Fprintln(stdout, "Entering PID 1's host namespaces; exit returns to Peirates.")
	if err := launcher.run("/proc/self/exe", []string{WorkerArgument}, stdin, stdout, stderr); err != nil {
		return fmt.Errorf("isolated worker failed: %w", err)
	}
	return nil
}

// RunWorker performs the namespace transition in the isolated helper process
// and returns the exit status that the top-level process should use.
func RunWorker(args []string, stdin, stdout, stderr *os.File) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "%s internal worker does not accept arguments\n", outputPrefix)
		return 2
	}
	exitCode, err := runWorkerWith(realPlatform{}, stdin, stdout, stderr, os.Getenv("TERM"))
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", outputPrefix, err)
		return 1
	}
	return exitCode
}

func runWorkerWith(system platform, stdin, stdout, stderr *os.File, term string) (int, error) {
	prepared, err := prepareWorker(system)
	if err != nil {
		return 0, err
	}
	defer prepared.closeAll(system)

	system.lockOSThread()
	if err := system.unshare(unix.CLONE_FS); err != nil {
		return 0, fmt.Errorf("unshare filesystem attributes: %w", err)
	}
	for index := range prepared.namespaces {
		namespace := &prepared.namespaces[index]
		if namespace.alreadyCurrent {
			continue
		}
		if err := system.setns(namespace.fd, namespace.namespaceType); err != nil {
			return 0, fmt.Errorf("enter PID 1 %s namespace: %w", namespace.name, err)
		}
	}
	if err := system.fchdir(prepared.rootFD); err != nil {
		return 0, fmt.Errorf("change directory to PID 1 root: %w", err)
	}
	if err := system.chroot("."); err != nil {
		return 0, fmt.Errorf("chroot to PID 1 root: %w", err)
	}
	if err := system.chdir("/"); err != nil {
		return 0, fmt.Errorf("change directory to host root: %w", err)
	}

	process, err := system.startProcess("/bin/sh", []string{"sh", "-i"}, &os.ProcAttr{
		Dir:   "/",
		Env:   shellEnvironment(term),
		Files: []*os.File{stdin, stdout, stderr},
	})
	if err != nil {
		return 0, fmt.Errorf("start host /bin/sh: %w", err)
	}
	exitCode, err := process.wait()
	if err != nil {
		return 0, fmt.Errorf("wait for host /bin/sh: %w", err)
	}
	return exitCode, nil
}

func prepareWorker(system platform) (*preparedWorker, error) {
	if system.effectiveUID() != 0 {
		return nil, fmt.Errorf("effective UID 0 is required")
	}
	status, err := system.readFile(procSelfStatus)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procSelfStatus, err)
	}
	capabilities, err := parseEffectiveCapabilities(status)
	if err != nil {
		return nil, err
	}
	if err := requireCapabilities(capabilities); err != nil {
		return nil, err
	}
	if err := requireSameIdentity(system, "/proc/self/ns/pid", "/proc/1/ns/pid", "PID namespace does not match visible PID 1; hostPID is required"); err != nil {
		return nil, err
	}
	if err := requireSameIdentity(system, "/proc/self/ns/user", "/proc/1/ns/user", "user namespace does not match visible PID 1; user namespace transitions are unsupported"); err != nil {
		return nil, err
	}
	currentRoot, err := system.identity("/")
	if err != nil {
		return nil, fmt.Errorf("inspect current filesystem root: %w", err)
	}
	targetRoot, err := system.identity(procOneRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect PID 1 filesystem root: %w", err)
	}
	if currentRoot == targetRoot {
		return nil, fmt.Errorf("PID 1 filesystem root matches the current root; no distinct node root is visible")
	}
	if err := system.access(hostShellPath, unix.X_OK); err != nil {
		return nil, fmt.Errorf("host shell %s is not executable: %w", hostShellPath, err)
	}

	prepared := &preparedWorker{rootFD: -1}
	targets := []struct {
		name          string
		path          string
		currentPath   string
		namespaceType int
	}{
		{name: "IPC", path: "/proc/1/ns/ipc", currentPath: "/proc/self/ns/ipc", namespaceType: unix.CLONE_NEWIPC},
		{name: "UTS", path: "/proc/1/ns/uts", currentPath: "/proc/self/ns/uts", namespaceType: unix.CLONE_NEWUTS},
		{name: "network", path: "/proc/1/ns/net", currentPath: "/proc/self/ns/net", namespaceType: unix.CLONE_NEWNET},
		{name: "mount", path: "/proc/1/ns/mnt", currentPath: "/proc/self/ns/mnt", namespaceType: unix.CLONE_NEWNS},
	}
	for _, target := range targets {
		fd, openErr := system.open(target.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			prepared.closeAll(system)
			return nil, fmt.Errorf("open PID 1 %s namespace: %w", target.name, openErr)
		}
		targetIdentity, statErr := system.fstat(fd)
		if statErr != nil {
			_ = system.close(fd)
			prepared.closeAll(system)
			return nil, fmt.Errorf("inspect PID 1 %s namespace: %w", target.name, statErr)
		}
		currentIdentity, statErr := system.identity(target.currentPath)
		if statErr != nil {
			_ = system.close(fd)
			prepared.closeAll(system)
			return nil, fmt.Errorf("inspect current %s namespace: %w", target.name, statErr)
		}
		prepared.namespaces = append(prepared.namespaces, namespaceDescriptor{
			name: target.name, namespaceType: target.namespaceType,
			fd: fd, alreadyCurrent: targetIdentity == currentIdentity,
		})
	}
	prepared.rootFD, err = system.open(procOneRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		prepared.closeAll(system)
		return nil, fmt.Errorf("open PID 1 filesystem root: %w", err)
	}
	return prepared, nil
}

func parseEffectiveCapabilities(status []byte) (uint64, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(status)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "CapEff:" {
			continue
		}
		if len(fields) != 2 {
			return 0, fmt.Errorf("malformed CapEff value in %s", procSelfStatus)
		}
		capabilities, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("malformed CapEff value in %s: %w", procSelfStatus, err)
		}
		return capabilities, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read CapEff from %s: %w", procSelfStatus, err)
	}
	return 0, fmt.Errorf("CapEff is missing from %s", procSelfStatus)
}

func requireCapabilities(capabilities uint64) error {
	required := []struct {
		name string
		bit  int
	}{
		{name: "CAP_SYS_ADMIN", bit: unix.CAP_SYS_ADMIN},
		{name: "CAP_SYS_CHROOT", bit: unix.CAP_SYS_CHROOT},
	}
	var missing []string
	for _, capability := range required {
		if capabilities&(uint64(1)<<uint(capability.bit)) == 0 {
			missing = append(missing, capability.name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("required effective capabilities are missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func requireSameIdentity(system platform, currentPath, targetPath, message string) error {
	current, err := system.identity(currentPath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", currentPath, err)
	}
	target, err := system.identity(targetPath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", targetPath, err)
	}
	if current != target {
		return fmt.Errorf("%s", message)
	}
	return nil
}
