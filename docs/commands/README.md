# Main menu command reference

This reference documents every command row advertised by Peirates' full and minimal main menus. Use Peirates only in clusters and cloud accounts where you have explicit authorization; several commands can expose credentials, execute code, create privileged workloads, or read host files.

Commands can normally be selected interactively by number, canonical name, or alias. Peirates also accepts one-shot module input with `peirates -m '<command>'`. A page calls out commands that continue to prompt for input and therefore are not suitable for unattended automation.

## Namespaces, identities, and discovery

| Menu | Command | Reference |
| --- | --- | --- |
| 1 | `sa-menu` | [Service account contexts](sa-menu.md) |
| 2 | `ns-menu` | [Namespaces](ns-menu.md) |
| 3 | `get-pods` | [List pods](get-pods.md) |
| 4 | `dump-pod-info` | [Dump pod information](dump-pod-info.md) |
| 5 | `find-volume-mounts` | [Find volume mounts](find-volume-mounts.md) |
| 6 | `aws-enter-credentials` | [Enter AWS credentials](aws-enter-credentials.md) |
| 7 | `aws-assume-role` | [Assume an AWS role](aws-assume-role.md) |
| 8 | `aws-empty-assumed-role` | [Clear the assumed AWS role](aws-empty-assumed-role.md) |
| 9 | `cert-menu` | [Certificate authentication contexts](cert-menu.md) |
| 10 | `list-secrets` | [List Kubernetes Secrets](list-secrets.md) |
| 11 | `secret-to-sa` | [Import a service-account token from a Secret](secret-to-sa.md) |

## Cloud credential and data access

| Menu | Command | Reference |
| --- | --- | --- |
| 12 | `aws-get-token` | [Request AWS metadata credentials](aws-get-token.md) |
| 13 | `gcp-get-token` | [Request a GCP metadata token](gcp-get-token.md) |
| 14 | `gcp-attack-kube-env` | [Request GKE kube-env metadata](gcp-attack-kube-env.md) |
| 15 | `gcp-attack-kops-1` | [Read kOps data from GCS](gcp-attack-kops-1.md) |
| 16 | `aws-attack-kops-1` | [Read kOps data from S3](aws-attack-kops-1.md) |
| 17 | `aws-s3-ls` | [List S3 buckets](aws-s3-ls.md) |
| 18 | `aws-s3-ls-objects` | [List objects in an S3 bucket](aws-s3-ls-objects.md) |

## Compromise and node operations

| Menu | Command | Reference |
| --- | --- | --- |
| 20 | `attack-pod-hostpath-mount` | [Create a hostPath pod](attack-pod-hostpath-mount.md) |
| 21 | `exec-via-api` | [Execute commands in pods through the API server](exec-via-api.md) |
| 22 | `exec-via-kubelet` | [Execute through kubelet APIs](exec-via-kubelet.md) |
| 23 | `leakyvessels` | [Exercise CVE-2024-21626](leakyvessels.md) |
| 30 | `nodefs-steal-secrets` | [Collect credentials from the node filesystem](nodefs-steal-secrets.md) |

## General utilities

| Menu | Command | Reference |
| --- | --- | --- |
| 90 | `kubectl` | [Run kubectl with the current context](kubectl.md) |
| — | `kubectl-try-all-until-success` | [Try contexts until one succeeds](kubectl-try-all-until-success.md) |
| — | `kubectl-try-all` | [Run with every context](kubectl-try-all.md) |
| 91 | `curl` | [Make an HTTP request](curl.md) |
| 92 | `set-auth-can-i` | [Configure authorization prechecks](set-auth-can-i.md) |
| 93 | `tcpscan` | [Scan TCP ports](tcpscan.md) |
| 94 | `enumerate-dns` | [Enumerate services through DNS](enumerate-dns.md) |
| — | `cd`, `pwd`, `ls`, `cat` | [Filesystem commands](filesystem.md) |
| — | `shell` | [Run local commands](shell.md) |
| — | `bash`, `sh` | [Start a system shell](system-shell.md) |
| `short` / `full` | `short`, `full` | [Change menu visibility](menu-visibility.md) |
| `outputfile` | `outputfile` | [Write supported output to a file](outputfile.md) |
| `exit` | `exit` | [Exit Peirates](exit.md) |

The machine-readable [manifest](manifest.tsv) is checked against the menu source by an automated Go test. `_template.md` defines the expected page structure for future commands.
