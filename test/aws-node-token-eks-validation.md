# Opt-in EKS node token acceptance

Use an existing, authorized EKS EC2 node and a pod with Peirates installed and
IMDS access. This procedure does not create cloud resources, modify IAM/access
mappings, deploy a pod, or grant privileges. The automated runner requires an
operator kubeconfig that can read the selected pod and node and execute
Peirates in that pod, plus host-side kubectl, Python 3, and timeout. That
operator identity is used only for setup observations and exec; token identity
checks use a separate temporary kubeconfig containing only the generated token.

Run from the operator workstation, supplying independently known values:

```sh
export PEIRATES_EKS_CONTEXT=authorized-eks-context
export PEIRATES_EKS_NAMESPACE=assessment
export PEIRATES_EKS_POD=existing-peirates-pod
export PEIRATES_EKS_EXPECTED_CLUSTER=actual-cluster-name
export PEIRATES_EKS_EXPECTED_REGION=us-west-2
export PEIRATES_EKS_BINARY=/tmp/peirates
test/aws-node-token-eks-validation.sh
```

The expected name and region are assertions for the operator, never arguments
to Peirates. The first command is bare `aws-get-eks-node-token`. The script checks
the discovered cluster/region, compares the instance ID with the actual pod
node's provider ID, checks the node's region label, and independently requests
`SelfSubjectReview` with the generated credential. Success requires the exact
`system:node:<pod-node-name>` username and `system:nodes` group. A second token
signed for a wrong cluster must be rejected by the same API. Tokens and private
outputs live in a temporary mode-0700 directory, with files mode 0600, and are
deleted on exit. Do not enable shell tracing or upload that directory.

Complete these checks in a Peirates interactive session in the same pod:

1. Run `kubectl auth whoami` and record the initial identity without recording
   credentials. Run `aws-get-eks-node-token --verify`, then `kubectl auth whoami`;
   the active identity must remain the original identity.
2. Run `aws-get-eks-node-token --cluster-name peirates-wrong-cluster-control --activate`.
   Verification must fail, and `kubectl auth whoami` must remain unchanged.
3. Run `aws-get-eks-node-token --activate`, then `kubectl auth whoami -o json`.
   The username must match the pod's actual node, the group must include
   `system:nodes`, and the configured namespace/endpoint/trust must remain.
   Main-menu status must omit the bearer token.
4. Wait past the displayed expiry and make an API request; it must stop with
   an expired-token error. Rerun the command to refresh, or select the original
   service-account/certificate identity to switch away. Confirm switching away
   removes generated-token expiry state.

Discovery fallback needs a separately authorized test arrangement. On an
existing test node with recognized bootstrap user data, arrange a bounded
network deny for only the EC2 discovery endpoint while preserving IMDS and
Kubernetes API access, or use a prepared node role lacking DescribeInstances.
Do not edit production IAM policies as part of this procedure. Run bare
`aws-get-eks-node-token --verify` and require the bootstrap source plus the same
independently verified node identity. For the unavailable-name control, use a
prepared test environment where both EC2 discovery and recognized bootstrap
user data are unavailable; the bare command must report discovery failure
without changing the active connection. Undo only controls introduced for the
test. The runner does not install or remove those controls automatically.

Record EKS authentication mode (`API`, `API_AND_CONFIG_MAP`, or `CONFIG_MAP`),
Kubernetes/Peirates versions, node AMI/bootstrap format, discovery source,
cluster/region/instance match, identity/groups, activation outcome, failure
preservation, fallback outcome, and unavailable-name outcome. Mark checks that
were not executed as unverified. A controlled Kind pass does not establish
EKS IAM acceptance; even a successful basic cloud runner leaves the manual
activation and discovery fallback checks outstanding until completed.
