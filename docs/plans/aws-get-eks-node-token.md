# AWS node authentication token implementation plan

Status: **IMPLEMENTED — unit and controlled Kind validation passed.** Three
implementation agents and central integration completed the approved feature.
Actual EKS acceptance remains unverified and requires the opt-in procedure.

Revision: assume Peirates runs inside the target EKS cluster. Discover the
cluster name and region automatically; neither is required operator input.

## Goal and applicability

Add a Peirates command that obtains an EC2 node's instance-role credentials
from AWS Instance Metadata Service (IMDS), generates an EKS Kubernetes bearer
token, and optionally verifies and activates that token.

The first release targets Peirates running in a pod inside a regional EKS
cluster on an EC2 node, with access to that node's IMDS. Host filesystem mounts
and Kubernetes permission to list nodes are not prerequisites. The cluster
must accept IAM authentication and map the instance role to a Kubernetes node
identity. Running Kubernetes on AWS and reaching IMDS are insufficient by
themselves. EKS EC2 node access entries map the role to
`system:node:{{EC2PrivateDNSName}}`; clusters using the legacy `aws-auth`
ConfigMap need an appropriate node-role mapping there.

```text
AWS IMDS
  -> instance identity, region, and instance-role temporary credentials
  -> cluster-name discovery from this instance's tags or bootstrap data
  -> locally signed EKS bearer token
  -> Kubernetes API authentication
  -> confirmed node username and groups
```

The token authenticates to the Kubernetes API as the node. It does not recover
the kubelet's client certificate. Effective permissions depend on the cluster's
authorization configuration; generating a token does not prove authentication
or authorization.

## Proposed command contract

| Item | Proposed behavior |
|---|---|
| Canonical command | `aws-get-eks-node-token` |
| Menu item | `37`, subject to availability when implemented |
| Menu text | Request an EKS node authentication token from AWS IMDS |
| Cluster selection | Automatic discovery; optional `--cluster-name` override |
| Region selection | IMDS instance identity document; optional `--region` override |
| API connection | Existing in-cluster connection or pod service endpoint and mounted CA |
| Credential source | The node's instance-role credentials from IMDS |
| Default result | Print the token and retain it in memory |
| Verification | `--verify` checks the identity against the configured API |
| Activation | `--activate` implies verification and explicitly switches identity |
| IMDS compatibility | IMDSv2 first; IMDSv1 fallback requires `--allow-imdsv1` |
| Refresh | Explicitly rerun the command; no automatic refresh in this release |

Examples in the interactive Peirates command prompt:

```text
aws-get-eks-node-token
aws-get-eks-node-token --verify
aws-get-eks-node-token --activate
```

Scripted invocation:

```sh
peirates -m aws-get-eks-node-token
peirates -m 'aws-get-eks-node-token --verify'
```

Bare interactive invocation and `-m` both discover the target without asking
the operator for a cluster name or region. Print the resolved values and their
sources before the token result. Keep `--cluster-name` and `--region` as
optional recovery overrides, rather than normal setup requirements.
`--help` performs no metadata or Kubernetes requests.

Generation does not require Kubernetes RBAC permissions. Discovery can use
read-only AWS APIs with the instance-role credentials; permission to call
`eks:DescribeCluster` is helpful for corroboration but is not mandatory.
Verification and activation require the in-cluster API connection. The command
must not silently downgrade TLS verification or send the token to a destination
obtained from unvalidated discovery data.

## Automatic in-cluster discovery

### Region and instance

Read `/latest/dynamic/instance-identity/document` through IMDSv2 and extract
`region`, `instanceId`, and `accountId`. Use the explicit region field rather
than deriving a region by truncating an availability-zone name. Validate the
document before issuing signed AWS requests. An optional region override
changes the selected signing/discovery region and is visibly reported; it
does not change the instance ID used for the instance-scoped lookup.

### Cluster name

Unless `--cluster-name` is supplied, use the following bounded discovery flow:

1. **Inspect this EC2 instance's tags through the EC2 API.** Call
   `DescribeInstances` in the resolved region with exactly the IMDS instance
   ID. Extract candidates from `aws:eks:cluster-name` and from
   `kubernetes.io/cluster/<name>` ownership tags with value `owned`. Validate
   names and deduplicate matching candidates. Do not infer the cluster name
   from the instance Name tag, IAM role name, or node-group name.
2. **Use IMDS bootstrap user data as a fallback.** If the API is denied,
   unreachable, or yields no usable name, read `/latest/user-data` with the
   same bounded metadata client. Parse recognized EKS configuration only:
   AL2023 `NodeConfig.spec.cluster.name` in YAML or MIME multipart content,
   Bottlerocket `[settings.kubernetes]` `cluster-name` in TOML, and literal
   cluster-name arguments to AL2 `/etc/eks/bootstrap.sh` invocations. Do not
   execute shell text, perform substitutions, or follow URLs in user data.
   Unsupported dynamic shell expressions are unresolved. For multipart
   NodeConfig data, respect documented merge order. Treat bootstrap data as
   a candidate source because host-side overrides may have changed it.
3. **Resolve conflicts without guessing.** A unique valid candidate can be
   used for token generation, labelled with its source and verification
   state. If candidates conflict, use bounded `eks:DescribeCluster` calls for
   those names when available and compare the returned CA with the trusted
   in-cluster CA. Select only a uniquely corroborated candidate. An explicit
   API hostname may also be compared when available; the in-cluster Service
   IP is not expected to equal EKS's public/private endpoint hostname. A
   known CA/target mismatch is an error. If ambiguity remains, report the
   candidates and sources and stop without replacing the active identity.

The standard `AmazonEKSWorkerNodePolicy` grants `ec2:DescribeInstances` and
`eks:DescribeCluster`, but custom/minimal node policies may omit them. Both
API denial and lack of EC2/EKS API egress must allow the metadata fallback.
Bound AWS requests and SDK retries with an overall discovery deadline; use a
maximum of eight candidates for corroboration and reject larger sets.

Do not depend on tags being exposed through IMDS: that setting is normally
disabled and EKS node tagging can be incompatible with it. The EC2 tag lookup
above uses the signed AWS API. Do not enumerate all instances, call
`eks:ListClusters`, scan other regions, or require broad Kubernetes reads.

Discovery is not universally possible from a pod: if tag lookup is unavailable
and user data is missing or opaque, neither the Kubernetes Service address nor
a service-account token supplies a guaranteed EKS cluster name. Report which
sources were unavailable and leave the session unchanged. Optional overrides
remain available for this exceptional case. Never invent a cluster name from
an EKS endpoint hash, service-account JWT issuer, or Kubernetes DNS name.

### API endpoint and trust

Reuse Peirates' in-cluster connection, or obtain the endpoint from
`KUBERNETES_SERVICE_HOST` and the service port, with the mounted service-account
CA at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. Retain namespace
context when available. The pod's original bearer token is not needed to
discover the region or cluster name and must not be used for node-token
verification.

Keep discovery separate from mutation of `Session.Connection`. Preserve an
explicitly configured target; if it conflicts with the discovered in-cluster
target/trust, report the mismatch rather than silently retargeting. Do not
adopt endpoints or CAs from user data as replacements for the trusted target.
With no usable endpoint/CA, generation may still succeed, but verification
and activation report the missing connection information.

Discovery output may show the instance ID, region, selected cluster name,
source, and concise failure reasons. Do not print raw user data, unrelated
tags, AWS credentials, or SDK request dumps. Record discovery provenance in
the retained token entry.

## Credential acquisition

Use a dedicated metadata client to:

1. Request an IMDSv2 session token.
2. Discover the attached role through `/latest/meta-data/iam/security-credentials/`.
3. Retrieve its access key ID, secret access key, AWS session token, and expiration.
4. Retrieve the instance identity document for the region, account, and instance
   ID, and perform the automatic cluster discovery described above.

Use the attached IAM role's credentials, rather than the separate EC2 instance
identity-role credential endpoint. Do not silently select environment
credentials, SDK profile credentials, workload-role credentials, or Peirates'
assumed-role slot: those could represent another principal.

The metadata transport should bypass environment proxies, reject redirects,
bound request duration and response sizes, and validate credential fields and
expiration. Propose a five-second deadline and 1 MiB response limit per request.
IMDSv1 compatibility must use bounded, documented fallback conditions.

Do not print the underlying AWS secret key, AWS session token, IMDSv2 session
token, or raw credential response in this command's diagnostics.

## Token generation and lifetime

Use AWS SDK signing to presign an STS `GetCallerIdentity` request. Bind the
resolved cluster name through the signed `x-k8s-aws-id` header, then encode the
presigned URL in the `k8s-aws-v1.` bearer-token format used by AWS CLI.

Token generation is local after credential acquisition; it does not require
Peirates to submit the STS request. Cluster-side authentication validates the
signed request and maps the AWS principal to a Kubernetes identity.

Track a conservative usable-until timestamp, bounded by the underlying AWS
credential expiration. Follow upstream EKS token lifetime behavior, including
its refresh margin; do not equate the presigned URL's expiry parameter with
the complete Kubernetes token lifetime.

Expired credentials must not produce a usable token. Expired retained tokens
must be visibly marked and rejected for activation. Active generated-token
use must detect expiry and instruct the operator to rerun the command, without
silently falling back to another credential.

## Session retention, verification, and activation

Retain generated tokens separately from service accounts: EKS tokens are not
service-account JWTs. Key records by cluster, region, and instance-role
identity, retaining acquisition time, expiration, and verification state.
Successful regeneration replaces the matching record; acquisition or signing
failure preserves existing records. A generated token whose verification fails
may remain available as unverified, with the failure clearly reported.

Print the requested bearer token as the command result. Session banners and
routine diagnostics show identity, cluster, expiry, and verification state
without redisplaying it. Audit command execution and timeout diagnostics so
active generated tokens are not exposed through argument logging.

For `--verify`, use an isolated Kubernetes client with only the new token and
the configured target connection. Submit a `SelfSubjectReview` and report the
server-returned username and groups. A successful node check requires a
`system:node:<nodeName>` username and `system:nodes` group. Compare the node
identity with independently available instance/node metadata; distinguish a
confirmed match from a node identity whose instance association is unproven.

Handle rejected authentication, denied or unsupported identity inspection,
unexpected identities, and transport/TLS failures as distinct outcomes. Do
not infer successful node authentication from token generation or an unrelated
request made with ambient credentials.

For `--activate`, require successful node-identity verification before changing
the active connection. Clear competing client-certificate credentials, retain
the configured endpoint, CA/TLS settings, and namespace, and label the active
identity as a node token. Verification or activation failure preserves the
previous connection. Existing service-account and certificate switching must
clear the generated token's active expiry metadata when switching away.

## Repository changes

| Location | Responsibility |
|---|---|
| `internal/cloud/aws/` | Bounded metadata client, instance-scoped AWS discovery, bootstrap parsers, credential expiry, SDK-backed signing |
| `internal/app/aws_node_token.go` | Options, automatic discovery orchestration, source reporting, retention, activation |
| `internal/app/session.go` and `internal/model/` | Typed token records and active credential metadata |
| `internal/kube/` | In-cluster target/trust handling, isolated identity verification, credential handling |
| App registry, dispatch, menu, and UI completion/status surfaces | Command reachability and accurate identity display |
| `docs/commands/` | Command reference, index, manifest, examples, and limitations |
| `test/` and integration inventory | Controlled Kubernetes integration and opt-in EKS validation |

Keep CLI composition thin and lower-level packages independent of
`internal/app`. Preserve existing CLI flags, aliases, build outputs, and
deployment paths.

The current `aws-get-token` handler in `internal/app/module_registry.go` stores
credentials only when retrieval returns an error. Correct that reversed
condition with a focused regression test. The new command must fetch its own
instance credentials independently of that handler. Avoid bundling a broader
rewrite of existing AWS commands into this feature.

## Validation plan

1. **Metadata and signing tests:** cover IMDSv2, explicitly enabled IMDSv1
   fallback, malformed or incomplete responses, expired credentials, timeouts,
   redirect rejection, proxy bypass, response limits, and secret-free errors.
   Validate cluster-header signing, temporary session-token inclusion,
   regional STS endpoint selection, encoding, and expiry against independent
   expected values or upstream-compatible fixtures.
2. **Discovery tests:** cover explicit region extraction, a tag lookup limited
   to the current instance, each supported tag/config format, multipart merge
   order, API denial and timeout fallback, missing user data, unsupported shell
   expressions, conflicting candidates, CA comparison, and optional overrides.
   Confirm there is no dependency on IMDS tag exposure, host mounts, a
   service-account token, `eks:ListClusters`, or Kubernetes node-list access.
   Assert bounded retries/candidate counts and redaction of raw discovery data.
3. **Application tests:** exercise zero-argument discovery, options, `-m`, menu
   and completion reachability, replacement and failure retention, credential-source
   isolation, identity verification outcomes, activation, switching away,
   expiry handling, target mismatch, and status/diagnostic redaction. Prove
   neither interactive nor scripted invocation requires cluster/region prompts.
4. **Repository checks:** run `go fmt ./...`, `make test-quiet`, build checks,
   and `git diff --check`. Run `make kind-test` for Kubernetes-dependent
   changes and keep any new integration target, runner, and CI inventory in
   parity.
5. **Controlled Kubernetes integration:** use a disposable Kind cluster and a
   controlled authentication webhook to exercise identity reporting, activation,
   failure preservation, and competing-credential isolation, alongside mocked
   metadata/AWS discovery. Independently assert outcomes and confirm cleanup.
   This does not prove EKS IAM acceptance.
6. **Opt-in EKS validation:** from a pod on an authorized EKS EC2 node, run
   `aws-get-eks-node-token` without supplying cluster name or region. Independently
   verify both discovered values and query the token's Kubernetes identity.
   Compare the username and groups with the actual instance/node, verify activation,
   and exercise negative controls such as the wrong cluster name. Report the
   tested EKS authentication mode, AMI/bootstrap format, discovery source, and
   versions. Include a controlled fallback case without EC2 API access and
   a negative case where no usable name is discoverable. Do not create cloud
   resources or modify IAM/access mappings implicitly.

## Scope boundaries and acceptance

The first release covers in-cluster operation on regional EKS EC2 nodes,
automatic region and cluster discovery with optional overrides, generation,
in-memory retention, identity verification, and activation. Automatic refresh,
arbitrary role assumption, Outposts-specific cluster IDs, and general non-EKS
authenticator configuration are follow-up work. Custom bootstrap formats and
host-filesystem discovery beyond the specified metadata formats are not part
of the initial discovery contract.

Acceptance requires zero-argument discovery from an in-cluster pod and a token
that independently verifies as the expected node in an EKS test environment
and can be explicitly activated in Peirates, with
expiry and failure behavior tested. If no EKS environment is available, report
implementation and controlled integration results separately and leave EKS
acceptance unverified.

## Implementation and validation record

Implemented command documentation is in
[`docs/commands/aws-get-eks-node-token.md`](../commands/aws-get-eks-node-token.md).
Provider code lives in `internal/cloud/aws/node_*.go`; application orchestration
is in `internal/app/aws_node_token.go`; verification, trust resolution, expiry,
and isolated kubectl handling are in `internal/kube/node_token*.go`.

Validation on 2026-10-25:

- `GOFLAGS=-p=1 make test-quiet` passed, including the 24/24/24 integration
  inventory and cleanup regression checks.
- `GOFLAGS=-p=1 make kind-test` passed against a disposable Kubernetes v1.36.1
  cluster.
- `GOFLAGS=-p=1 make aws-node-token-kind-test` passed with mock IMDS/AWS
  discovery, independent SigV4 verification, real Kubernetes identity reviews,
  tampered/wrong-cluster controls, activation, credential isolation, state
  preservation, expiry, and actual kubectl use with an ambient admin kubeconfig.
- Formatting, focused Kubernetes/module vet checks, shell syntax checks, and
  `git diff --check` passed.
- `GOFLAGS=-p=1 make build` produced the static Linux AMD64 `peirates` binary.
- `kind get clusters` reported no clusters after both live tests completed.

No real AWS/EKS credentials or cloud resources were used for these checks.
[`test/aws-node-token-eks-validation.md`](../../test/aws-node-token-eks-validation.md)
contains the opt-in EKS acceptance procedure and explicitly separates automated
identity checks from manual activation and discovery-fallback checks.

The bootstrap fallback accepts bounded literal formats. Shell parts containing
heredocs or multiline quotes and TOML multiline strings remain unresolved;
explicit cluster-name overrides are available when automatic discovery cannot
resolve a unique name. Module-mode execution bypasses legacy startup probes and
unrelated credential loading to keep this command's metadata traffic bounded
and its diagnostics free of ambient AWS secrets.

## Primary references

- [EKS access entries and EC2 node usernames](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html)
- [Legacy EKS aws-auth mappings](https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html)
- [EC2 metadata role credentials](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)
- [EC2 IAM roles and instance identity roles](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
- [EC2 instance identity document fields](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html)
- [EC2 DescribeInstances API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [Standard EKS worker-node IAM policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSWorkerNodePolicy.html)
- [EKS instance cluster-name tags](https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html)
- [EKS self-managed node tags and IMDS tag limitations](https://docs.aws.amazon.com/eks/latest/userguide/worker.html)
- [EKS nodeadm bootstrap configuration](https://awslabs.github.io/amazon-eks-ami/nodeadm/)
- [EKS nodeadm configuration merge and overrides](https://github.com/awslabs/amazon-eks-ami/blob/main/nodeadm/doc/examples.md)
- [EKS AMI user-data formats](https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html)
- [AWS CLI EKS token implementation](https://github.com/aws/aws-cli/blob/develop/awscli/customizations/eks/get_token.py)
- [AWS IAM Authenticator token implementation](https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/master/pkg/token/token.go)
- [Kubernetes node authorization](https://kubernetes.io/docs/reference/access-authn-authz/node/)
- [Kubernetes authentication and SelfSubjectReview](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
