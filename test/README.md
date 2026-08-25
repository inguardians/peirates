# Test

## Dependencies

Run `go mod tidy -e` to keep things up to date.

To test the dependencies:

```sh
go list -u -m all # view available minor and patch upgrades for all direct and indirect dependencies
go get -u ./... # upgrades to the latest or minor patch release
go get -t -u ./... # upgrade test dependencies
go test all # run the following command to test that packages are working correctly after an upgrade
```

Additional external test apps and test data.

## Setup

* Install `direnv`

```sh
direnv allow .
```

## Container

* Use these steps to create the container images.
* Go to your packages on Github to verify everything is working.

```sh
cd deployments
make build
make push
make dev
make push-dev
```

## Kind integration test

This opt-in test creates a disposable Kind cluster, grants a temporary service
account read access, and verifies Peirates can list namespaces through the
live Kubernetes API. It requires Docker, Kind, kubectl, and Go.

```sh
make kind-test
```

## Security

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# machine readable
# gosec -conf test/.gosec.config.json -track-suppressions -fmt=json -out=test/results.json -stdout ./...
gosec -conf test/.gosec.config.json -track-suppressions ./...
```

Govulncheck

```sh
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
# Run govulncheck
govulncheck ./...
```

## Service-account menu integration test

Run `make service-account-kind-test` to create a disposable Kind cluster and
exercise all seven actions under main-menu option 1 through a Peirates binary
running in a pod: list, switch, add, export, import, decode, and display. The
test uses the pod's real projected service-account JWT, refuses to modify a
pre-existing cluster named `peirates-service-account-integration`, and deletes
the disposable cluster on exit. Override the cluster name with
`PEIRATES_SERVICE_ACCOUNT_KIND_CLUSTER`, using a name reserved for this test.

The raw-token display assertion handles a token belonging only to the
disposable cluster; the token stops being useful when cleanup deletes it.


## Namespace menu integration test

Run `make namespace-kind-test` to create a disposable Kind cluster and exercise
both actions under main-menu option 2 through a Peirates binary running in a
pod: list namespaces and switch namespace. The pod's default service account is
granted only `get` and `list` on core `namespaces`. The test refuses to modify a
pre-existing cluster named `peirates-namespace-integration` and deletes its
disposable cluster on exit. Override the name with
`PEIRATES_NAMESPACE_KIND_CLUSTER`, using a name reserved for this test.

## Pod information integration test

Run `make pod-info-kind-test` to create a disposable Kind cluster and exercise
main-menu item 3 (list pods) followed by item 4 (dump complete pod JSON) through
a Peirates binary running in a pod. The pod's default service account is granted
only namespace-scoped `get` and `list` access to core `pods`. The test refuses to
modify a pre-existing cluster named `peirates-pod-info-integration` and deletes
only its dedicated cluster on exit. Override the name with
`PEIRATES_POD_INFO_KIND_CLUSTER`, using a name reserved for this test.

## Volume-mount integration test

Run `make volume-mount-kind-test` to create a disposable Kind cluster and
exercise both paths under main-menu item 5 through a Peirates binary running in
a pod: report hostPath mounts for all pods and for one named pod. The fixture
pod mounts a dedicated, observable hostPath and its default service account is
granted only namespace-scoped `get` and `list` access to core `pods`. The test
refuses to modify a pre-existing cluster named
`peirates-volume-mount-integration` and deletes only its dedicated cluster on
exit. Override the name with `PEIRATES_VOLUME_MOUNT_KIND_CLUSTER`, using a name
reserved for this test.

## Certificate menu integration test

Run `make certificate-menu-kind-test` to create a disposable Kind cluster, copy
Peirates directly onto its control-plane node, and exercise both paths under
main-menu item 9: list discovered client certificate/key pairs and switch to the
live kubelet identity. The test refuses to modify a pre-existing cluster named
`peirates-certificate-integration` and deletes only its dedicated cluster on
exit. Override the name with `PEIRATES_CERTIFICATE_KIND_CLUSTER`, using a name
reserved for this test.

## Anonymous kubelet integration test

Run `make kubelet-kind-test` to create a disposable Kind cluster and prove that
Peirates can list running pods through the unauthenticated read-only kubelet endpoint on port 10255 and execute a command through the anonymous HTTPS kubelet endpoint on port 10250. The test
refuses to use a pre-existing cluster, uses the isolated cluster name
`peirates-kubelet-integration` by default, and deletes that cluster on every exit. The namespace default service account is granted only `get` and `list` on core `nodes`, and setup verifies that permission. It also receives namespace-scoped pod `get`/`list` plus the legacy pod `exec` authorization verb and `pods/exec` `create` permissions so the test can copy Peirates into the target pod and run its `exec-via-api` all-pods path with `id`.
Override the name with `PEIRATES_KUBELET_KIND_CLUSTER`; choose a name reserved for
this disposable test.

This test intentionally configures the disposable node kubelet with anonymous authentication, `AlwaysAllow` authorization, and the read-only port. Those settings permit unauthenticated pod discovery and command execution and are unsafe for any
shared or persistent cluster. The test must never be adapted to target an existing
cluster. Docker, Kind, kubectl, Go, and network access to pull the test image are
required.

## API pod-exec integration test

Run `make exec-via-api-kind-test` to create a disposable Kind cluster and
exercise both interactive branches of main-menu item 21 through a real Peirates
binary running in a pod. The specific-pod branch runs through numeric item `21`
and verifies that a harmless marker is created only in the selected fixture pod.
The all-pods branch runs through `exec-via-api` and verifies a separate marker
in every running test pod.

The runner's default service account receives only namespace-scoped `get`,
`list`, and legacy `exec` access to pods plus `create` access to `pods/exec`.
The test refuses a pre-existing cluster named `peirates-exec-api-integration`
and deletes only the cluster it created. Override the name with
`PEIRATES_EXEC_API_KIND_CLUSTER`, using a name reserved for this test.

## Kubectl authorization-context integration test

Run `make kubectl-try-all-kind-test` to create a disposable Kind cluster and
exercise `kubectl-try-all` and `kubectl-try-all-until-success` through a real
Peirates binary running in-cluster. The runner starts with a denied service
account and discovers two ordered, controller-populated service-account-token
Secrets. The test proves that `kubectl-try-all` continues through every account
and reports both successful API results, while the until-success form continues
past the denied account, reports the first successful result, and never attempts
the later account.

Only the two successful accounts receive namespace-scoped `get` permission for
one fixture ConfigMap. Peirates reads credentials only from mounted Secret
volumes; the script does not retrieve or print token data. The test refuses a
pre-existing cluster named `peirates-kubectl-try-all-integration` and deletes
only its dedicated cluster. Override the name with
`PEIRATES_KUBECTL_TRY_ALL_KIND_CLUSTER`.

## API Secret listing integration test

Run `make list-secrets-kind-test` to create a disposable Kind cluster and test
main-menu item 10 through a real Peirates binary running in-cluster. It verifies
that opaque, TLS, and service-account-token Secrets are listed; that the token
Secret is separately classified as a service account; that the numeric command
and both named aliases work; and that an unprivileged service account receives
the denial path without fixture names being disclosed. The test refuses a
pre-existing `peirates-list-secrets-integration` cluster and deletes only its
dedicated cluster. Override the name with `PEIRATES_LIST_SECRETS_KIND_CLUSTER`.

## Secret-to-service-account integration test

Run `make secret-to-sa-kind-test` to create a disposable Kind cluster and test
main-menu item 11 through a real Peirates binary running in-cluster. The test
creates a real `kubernetes.io/service-account-token` Secret, drives the numeric
interactive item, and verifies the imported account remains available in the
same Peirates session. It also covers the `secret-to-sa` command, its
`get-secret` alias, and rejection of a non-token Secret. The pod's default
service account receives only namespace-scoped `get` access to Secrets. Test
diagnostics redact the fixture token, and successful output never prints it.
The test refuses a pre-existing `peirates-secret-to-sa-integration` cluster and
deletes only its dedicated cluster. Override the name with
`PEIRATES_SECRET_TO_SA_KIND_CLUSTER`.

## HostPath attack-pod integration test

Run `make attack-hostpath-kind-test` to create a disposable Kind cluster and
exercise main-menu item 20 through a real Peirates binary running in-cluster.
The test covers the numeric command, canonical module name, and one historical
alias. For each path, it observes the short-lived attack pod, verifies that its
`hostPath` is `/`, and reads a synthetic marker through the pod's `/root` mount.
It also confirms that the module writes its callback entry into the disposable
Kind node's crontab and removes the attack pod afterward.

The test verifies the callback port is closed and restricts it to `127.0.0.1:65535`.
The Kind configuration
does not mount any path from the physical Docker host. The runner's service
account receives only namespace-scoped pod `get`, `list`, `create`, `delete`,
and `pods/exec` `create` permissions. The test refuses a pre-existing cluster
named `peirates-attack-hostpath-integration`, deletes only a cluster it created,
and removes the module-created resources by deleting that disposable cluster.
Override the name with `PEIRATES_ATTACK_HOSTPATH_KIND_CLUSTER`.

## Node filesystem secret integration test

Run `make nodefs-steal-secrets-kind-test` to create a disposable Kind cluster;
mount synthetic opaque and TLS Secrets plus a projected service-account token
into a fixture pod; and copy Peirates directly onto the control-plane node. The
test runs the real `nodefs-steal-secrets` module on that node and verifies that
it classifies all three fixtures under `/var/lib/kubelet/pods` without printing
the token, private key, or opaque Secret value. The test refuses to modify a
pre-existing cluster named `peirates-nodefs-secrets-integration` and deletes
only its dedicated cluster on exit. Override the name with
`PEIRATES_NODEFS_SECRETS_KIND_CLUSTER`, using a name reserved for this test.
