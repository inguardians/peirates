# Attack pod with a hostPath mount

## Menu entry

- Number: `20`
- Canonical command: `attack-pod-hostpath-mount`
- Aliases: `attack-hostpath-mount`, `attack-pod-mount`, `attack-hostmount-pod`, `attack-mount-pod`

## Purpose

Create a pod that mounts its scheduled node's root filesystem at `/root`, then append a recurring reverse-shell command to the node's `/etc/crontab` through that mount.

This is an intrusive node-compromise technique. Use it only in a cluster and on nodes where the owner has explicitly authorized host filesystem modification and callback traffic. A successful run leaves a persistent command in the node's crontab.

## Prerequisites and authorization

The current identity needs enough access in the current namespace to get/list pods, create a pod, exec into it, and delete it. In Kubernetes RBAC terms, this normally means `get` and `list` on `pods`, `create` and `delete` on `pods`, and `create` on `pods/exec`. Peirates prechecks `get pods` during enumeration and `create pods` before staging, but it does not separately preflight the actual collection `list`, pod `get`, `pods/exec`, or pod `delete` operations.

The cluster's admission policy must permit a writable `hostPath` volume for `/`. A schedulable node and a usable container image are also required. Peirates first tries the image of the pod named by `$HOSTNAME`; its fallback attempts to derive an image from the namespace's wide pod listing but currently parses the wrong column. The selected image must provide `/bin/sh` and remain running under `sleep infinity`; the scheduled node must provide `python3` when cron fires.

Before running the module, start an authorized listener and choose an IP and port reachable from the target node.

## Usage

Interactive menu:

1. Enter `20`, the canonical command, or any alias at the Peirates prompt.
2. Enter the callback IP and port when prompted.

One-shot module mode still reads the callback values from standard input. For deterministic automation, pipe both required lines:

```sh
printf '%s\n%s\n' '<callback-ip>' '<callback-port>' | \
  peirates -c -m attack-pod-hostpath-mount
```

The numeric command and aliases are also accepted after `-m`. This is not fully non-interactive because there are no callback flags; automation must provide two input lines in the order `IP`, then `port`. `-c` is optional and only skips cloud detection.

## What it does

1. Lists pods and tries to choose an existing container image. It first describes the pod named by `$HOSTNAME`; its fallback incorrectly treats column eight of `kubectl get pods -o wide` as an image, even though standard output places a different field there.
2. Creates `attack-pod-<random>` in the current namespace with host `/` mounted at container path `/root`.
3. Waits five seconds, then runs `/bin/sh` in the pod and appends a cron entry to `/root/etc/crontab`.
4. The cron entry runs every minute and uses Python to connect to the supplied address and attach `/bin/sh` to the socket.
5. After a successful exec, deletes the attack pod.

The pod is not pinned to a particular node. The modified node is whichever node schedules the attack pod.

## Expected output

On the successful path, Peirates reports the selected image, creation of the randomized attack pod, `Netcat callback added sucessfully.`, and removal of the attack pod. The spelling of `sucessfully` reflects the current implementation.

That message confirms that the append command ran; it does not prove that the listener received a connection or that the node's cron service executed the entry.

## Side effects and cleanup

The module writes a persistent, every-minute reverse-shell entry to the node's `/etc/crontab`. Deleting the attack pod does **not** remove that entry. After the authorized exercise, remove the exact Peirates-created line from the affected node's crontab and confirm that no callback process remains.

The temporary local manifest is normally removed after it is written and closed. A manifest write or close failure occurs before cleanup is registered and can leave the temporary file behind. The attack pod is deleted only after the exec succeeds; image, scheduling, exec, or deletion failures can leave `attack-pod-*` behind. Inspect the current namespace and delete only the pod created by this run after confirming its identity.

## Failure modes

- Missing RBAC rights or a failed SelfSubjectAccessReview stops enumeration, pod creation, exec, or cleanup.
- Pod Security or another admission policy may reject the root `hostPath` mount.
- Image discovery is text-based and fragile. In particular, the fallback parses a non-image column from standard `kubectl get pods -o wide` output, so it commonly selects an unusable value such as `<none>`.
- The fixed five-second wait may be too short for image pulling or scheduling.
- The selected image may lack `/bin/sh`; the node may lack `python3` or a working cron service.
- Network policy, routing, or a closed listener can prevent the callback even after the cron entry is written.
- Input is not validated before being interpolated into the cron command. Treat callback values as trusted operator input.
- A failure after pod creation can leave the attack pod, while a failure after the append can leave both the pod and the cron persistence.

## Implementation and tests

- [Menu registration and handler](../../internal/app/module_registry.go)
- [Aliases](../../internal/app/dispatch.go)
- [HostPath pod and cron implementation](../../internal/app/attack_create_hostfs_pod.go)
- [Disposable Kind integration test](../../test/attack-hostpath-kind-integration.sh)
- [Integration-test notes](../../test/README.md)

The live integration test covers the number, canonical name, and one historical alias. It verifies the `/` host mount, the cron write, and successful pod deletion inside a disposable Kind node.
