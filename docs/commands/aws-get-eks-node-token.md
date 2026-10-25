# `aws-get-eks-node-token`

## Menu entry

- Number: `37`
- Canonical command: `aws-get-eks-node-token`
- Accepted aliases: `37`
- Validation: automated protocol/application fixtures and a controlled Kind
  authentication scenario; actual EKS acceptance requires the separate opt-in
  test described below.

## Purpose and prerequisites

Generate an EKS Kubernetes bearer token using the EC2 node's instance-role
credentials from AWS IMDS. Peirates is expected to run in a pod in the target
regional EKS cluster on an EC2 node, with IMDS reachable. Neither cluster name
nor region is normally required. The cluster must accept IAM authentication
and map that instance role to a node identity. The token authenticates to the
Kubernetes API; it is not the kubelet's client certificate. Generation alone
does not prove successful Kubernetes authentication or permissions.

The requested bearer token is printed in full and retained in process memory.
The underlying AWS access key, secret key, session token, and IMDSv2 token are
not printed by this command. No AWS or Kubernetes resources are created or
changed. Generation/discovery requires no Kubernetes RBAC permissions;
verification requires permission to request the caller's identity.

## Usage

```text
aws-get-eks-node-token
aws-get-eks-node-token --verify
aws-get-eks-node-token --activate
aws-get-eks-node-token --cluster-name recovery-name --region us-west-2
aws-get-eks-node-token --allow-imdsv1
aws-get-eks-node-token --help
```

```sh
peirates -c -m aws-get-eks-node-token
peirates -c -m 'aws-get-eks-node-token --verify'
peirates -c -m '37 --activate'
```

Bare interactive and one-shot invocations discover the target without prompts.
`--verify` reports the returned Kubernetes identity without switching the
active connection. `--activate` implies verification, then switches the active
connection if a node username and group are confirmed. `--cluster-name` and
`--region` are optional recovery overrides. `--allow-imdsv1` explicitly permits
bounded compatibility fallback when IMDSv2 is unavailable. `--help` makes no
metadata or Kubernetes requests. A one-shot process exits after the command;
activation is useful for follow-up operations in an interactive session.

## Discovery and signing

The dedicated metadata client bypasses environment proxies, rejects redirects,
and limits request durations and response sizes. It obtains the attached
instance role's temporary credentials through IMDSv2. Environment variables,
AWS profiles, workload-role credentials, Peirates' existing AWS credential
slot, and its assumed role are not used for this command.

Region and instance identity come from the IMDS identity document. The client
calls EC2 DescribeInstances for exactly that instance and reads
`aws:eks:cluster-name` and `kubernetes.io/cluster/<name>=owned` tags. It does not
require metadata tag exposure, enumerate instances/clusters/regions, list
Kubernetes nodes, or read host mounts.

If EC2 discovery is unavailable or has no usable name, recognized IMDS user
data supplies candidates: AL2023 NodeConfig, MIME multipart NodeConfig,
Bottlerocket Kubernetes TOML settings, or literal AL2 bootstrap arguments.
User data is parsed, never executed. Dynamic shell expressions, shell parts
with heredocs or multiline quotes, TOML multiline strings, and custom bootstrap
formats can remain unresolved. Conflicting candidates require a
unique EKS DescribeCluster match against the trusted API CA; unresolved
ambiguity stops. A known CA/endpoint mismatch also stops. Missing permissions
or AWS API egress can permit bootstrap fallback, but cannot guarantee discovery
when user data is absent or opaque. Use explicit overrides in that case.

The token is a locally presigned STS GetCallerIdentity request, bound to the
cluster name by the signed `x-k8s-aws-id` header and encoded as `k8s-aws-v1.…`.
Peirates does not send the signed STS request during generation. Cluster-side
IAM authentication validates it. The token's usable lifetime includes a refresh
margin and cannot exceed the instance credential lifetime. Rerun to refresh;
there is no automatic refresh.

## Target, verification, and session state

Peirates preserves a configured Kubernetes target or resolves the pod service
endpoint and mounted CA. It never replaces trust or an endpoint with bootstrap
user-data values. A conflicting configured target/trust is an error. Without
usable API connection information, generation can still succeed; verification
and activation report the unavailable target.

Verification uses an isolated client containing only the generated token and
trusted target settings, even if the active identity uses a certificate. A
SelfSubjectReview must return `system:node:<name>` and `system:nodes`.
Authentication rejection, denied/unsupported identity inspection, unexpected
identities, and transport/TLS errors do not activate the token. Instance
association is reported separately: a metadata match is confirmed, while a node
name that cannot be matched to independently acquired instance metadata is
unproven.

Successful activation clears competing client certificates, preserves target,
trust, namespace, and authorization settings, and records token expiry. An
expired active node token stops API use with a refresh instruction; it cannot
silently fall back to another credential. Selecting an existing service account
or certificate clears the generated-token expiry state.

While a node token is active, kubectl target, credential, and impersonation
override flags are rejected. Switch identity first to use those overrides;
ordinary command and namespace options continue to work.

Tokens are retained separately from service-account JWTs, keyed by cluster,
region, and instance-role identity. Successful regeneration replaces that key;
acquisition/signing failure preserves existing entries. Verification failure
can retain an unverified token but preserves the active connection. Banners
show cluster, role, identity, expiration, and verification state without
redisplaying the token. Session records disappear when Peirates exits. While running kubectl with an
active node token, Peirates writes an isolated mode-0600 temporary kubeconfig
in a private directory and removes it when the command returns; a process
crash can leave that file behind. Terminal capture can retain the command's
explicitly printed result.

## Validation and limitations

Run `make aws-node-token-kind-test` for controlled Kubernetes integration. Its
mock IMDS/AWS discovery supplies fake credentials; a disposable Kind webhook
independently checks their SigV4 signature and cluster binding. A separate TLS
client checks the real API's node identity, tampered/wrong-cluster rejection,
activation, competing credentials, failure preservation, and expiry. This
scenario does not prove AWS/EKS acceptance.

Use [opt-in EKS validation](../../test/aws-node-token-eks-validation.md) for an
existing authorized EC2-backed EKS workload. No cloud resources or IAM/access
mappings are created implicitly. Outposts cluster IDs, arbitrary role
assumption, automatic refresh, and general non-EKS authenticators are outside
this release.

## Implementation and references

- [AWS provider](../../internal/cloud/aws/)
- [Application command](../../internal/app/aws_node_token.go)
- [Controlled Kind harness](../../test/aws-node-token-kind-integration.sh)
- [EC2 metadata role credentials](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)
- [EKS node access entries](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html)
- [AWS CLI EKS token implementation](https://github.com/aws/aws-cli/blob/develop/awscli/customizations/eks/get_token.py)
