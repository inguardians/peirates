# Privileged hostPID node shell

## Menu entry

- **Menu item:** `24`
- **Canonical command:** `hostpid-breakout`
- **Aliases:** `host-pid-breakout`, `breakout-hostpid`
- **Maturity:** Stable on Linux when all prerequisites are satisfied

## Purpose

Enter the namespaces and filesystem root of the PID 1 visible to Peirates, then
open an interactive `/bin/sh`. In the intended configuration—a root privileged
Kubernetes container with `hostPID: true`—PID 1 is the node's init process and
the result is a node shell.

This function provides complete interactive access to the target root and its
mount, IPC, UTS, network, and PID namespaces. Use it only on a disposable node
or a node where that level of access is explicitly authorized.

## Prerequisites and authorization

The Peirates process must:

- run on Linux with effective UID 0;
- already share the PID namespace of visible PID 1, normally through
  `hostPID: true`;
- share PID 1's user namespace;
- hold effective `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT` capabilities, normally
  through a privileged container security context;
- see a PID 1 filesystem root different from its current container root; and
- be able to execute `/bin/sh` from PID 1's filesystem root.

No Kubernetes API access, RBAC permission, `kubectl`, or external `nsenter`
binary is required. The module checks observable Linux process state rather
than querying the Pod specification. Linux provides no portable local marker
that distinguishes every hostPID namespace from every possible shared pod PID
namespace, so the operator must confirm that visible PID 1 is the intended node
init process.

## Usage

Select the function from the full interactive menu with any supported form:

```text
24
hostpid-breakout
host-pid-breakout
breakout-hostpid
```

Direct module invocation is also supported:

```sh
peirates -c -m hostpid-breakout
```

The function does not ask for confirmation. It attaches the current terminal
to an interactive host shell. Run `exit` in that shell to return to Peirates;
in direct module mode, Peirates then terminates normally.

## What it does

Peirates first validates the effective UID, capabilities, namespace identities,
target root, namespace descriptors, and target shell. It then starts an
isolated copy of its own executable. The worker repeats those checks, opens all
target descriptors, and locks itself to one operating-system thread.

The worker separates its filesystem attributes, enters PID 1's IPC, UTS,
network, and mount namespaces when they differ, and changes its root to
`/proc/1/root`. It does not call `setns` for PID because the prerequisite is
that Peirates already occupies PID 1's PID namespace. User, cgroup, and time
namespaces are intentionally left unchanged.

Finally, the worker runs `/bin/sh -i` with inherited standard input, output,
and error streams. It supplies only a minimal host-oriented environment:
`HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `PS1`, and, when present, `TERM`.
Container variables such as service-account settings, `LD_*`, `ENV`, and
`BASH_ENV` are not inherited.

## Expected output

Before starting the worker, Peirates prints:

```text
Entering PID 1's host namespaces; exit returns to Peirates.
```

The prompt is normally `[peirates-host]#`. Prompt rendering depends on the
host's `/bin/sh`. Commands such as `id`, `pwd`, and namespace links under
`/proc/self/ns` can be used to independently confirm the resulting context.

## Side effects and cleanup

Peirates does not create a Pod, write a host file, or leave a background
process. Namespace and root changes apply only to the isolated worker. Exiting
the shell terminates that worker and discards its process-local state.

**Warning:** commands entered in the shell execute with the worker's
privileges against the node filesystem and namespaces. Those commands can
modify or destroy node data, disrupt workloads, expose credentials, or leave
persistent processes and files. Any operator-created changes require explicit
cleanup.

## Failure modes

- Non-Linux execution reports that the function is unsupported.
- Non-root execution or missing capabilities fails before a worker starts.
- A private PID namespace, different user namespace, or non-distinct PID 1
  root fails qualification.
- Restricted `/proc`, a missing target namespace, or a missing host `/bin/sh`
  prevents entry.
- Seccomp, AppArmor, SELinux, another LSM, or a container runtime may reject an
  otherwise valid `unshare`, `setns`, or `chroot` operation.
- A shared pod PID namespace can expose a pod sandbox as PID 1. The function
  always targets visible PID 1 and cannot prove from local process state alone
  that it is the Kubernetes node init process.
- Failure after the first namespace transition terminates only the isolated
  worker; the parent Peirates process remains in its original environment.
- A nonzero host-shell exit is reported as an isolated-worker failure before
  control returns to Peirates.

## Implementation and tests

- [HostPID capability](../../internal/modules/hostpid)
- [Application registration](../../internal/app/module_registry.go)
- [Private worker routing](../../internal/app/run.go)
- [Unit tests](../../internal/modules/hostpid/hostpid_linux_test.go)
- [Disposable Kind integration test](../../test/hostpid-breakout-kind-integration.sh)
