# Class lab: build an EKS node kubeconfig by hand

This lab reproduces the credential and token flow in
[`get-aws-eks-token.sh`](../scripts/get-aws-eks-token.sh) using commands you paste
into a terminal. You do not run that script or need the Peirates binary.

You will retrieve the EC2 worker's instance-role credentials from Instance
Metadata Service (IMDS), discover its EKS cluster, generate an EKS bearer token,
and write a kubeconfig. Finally, you will ask Kubernetes which identity it
accepted. This uses the node's **IAM role**, not the kubelet's client certificate.
It authenticates as a node only if EKS already maps that role to a node identity.
It does not grant administrator permissions or change an access mapping.

## Before class

The instructor provides an authorized, EC2-backed regional EKS lab cluster and
a terminal on a worker node or in a pod that can reach that worker's IMDS.
A local laptop alone cannot reach the worker's link-local metadata address.
This exercise does not create a cluster or change IMDS settings.

The terminal needs Bash, curl, jq, AWS CLI v2, kubectl, and standard Linux tools.
Automatic discovery needs `ec2:DescribeInstances` and `eks:DescribeCluster`
permission on the **node role**, plus connectivity to those AWS APIs. Kubernetes
verification needs connectivity to the cluster API and permission to inspect
the caller's identity. If discovery is unavailable, the instructor should
provide the cluster name, region, API endpoint, and PEM CA file.

Keep the same terminal for all steps. Paste each block separately, inspect the
result, then continue. Do not paste the entire document at once: step 2 has two
alternative blocks. Secret values stay in private files rather than on screen;
the final kubeconfig itself is a short-lived credential.

## 1. Start an isolated Bash session and prepare a workspace

First paste this command by itself. It starts a child shell, so the AWS
variables we change later will not replace those in your original shell.

```bash
bash --noprofile --norc
```

Now paste:

```bash
set +x
set +o history
set -euo pipefail
umask 077

for dependency in curl jq aws kubectl; do
    command -v "$dependency" >/dev/null
done
aws --version

lab_dir=$(mktemp -d /tmp/eks-node-class.XXXXXX)
output="$PWD/node.kubeconfig"
[[ ! -e $output && ! -L $output ]]
trap 'rm -rf -- "$lab_dir"' EXIT

# Leave these empty for automatic discovery. Edit before pasting if necessary.
cluster_name=''
region=''
server=''
ca_file=''

imds='http://169.254.169.254/latest'
curl_options=(-q --silent --show-error --fail --noproxy '*' \
    --connect-timeout 2 --max-time 10 --max-filesize 1048576)
printf 'Final kubeconfig will be: %s\n' "$output"
```

`umask 077` makes new files private. The temporary directory holds credentials
and is removed when this shell exits. `set -euo pipefail` stops the session on
an unhandled failure rather than letting later steps use missing values. If
that happens, fix the cause and restart at step 1. An existing `node.kubeconfig`
causes this block to stop; choose a different output filename to keep it.

The four optional variables are the recovery controls. Set `cluster_name` to
skip EC2 tag discovery and `region` to override the metadata region. Set both
`server` and `ca_file` to use an instructor-provided HTTPS endpoint and trusted
PEM CA file instead of EKS discovery. Use an absolute path for `ca_file`.

The curl options bypass proxies for metadata, disable `.curlrc`, and bound
request duration and size. We do not follow redirects from the metadata URL.

## 2. Obtain an IMDSv2 session token

**Normal path: paste this block.**

```bash
curl "${curl_options[@]}" -X PUT \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' \
    "$imds/api/token" >"$lab_dir/imds-token"
[[ -s $lab_dir/imds-token ]]
printf 'X-aws-ec2-metadata-token: %s\n' \
    "$(cat "$lab_dir/imds-token")" >"$lab_dir/imds-header"
curl_options+=(-H "@$lab_dir/imds-header")
printf 'IMDSv2 session prepared.\n'
```

This token authorizes subsequent metadata requests. It is **not** an AWS access
key or Kubernetes bearer token. The header is read from a private file instead
of putting the token in curl's command-line arguments. Complete steps 3–4 within
five minutes; otherwise restart to get a fresh metadata session.

**Alternative for an instructor-designated IMDSv1 lab only:** skip the normal
block above and paste this block instead. It is equivalent to the script's
explicit `--allow-imdsv1` fallback. It only works if the node allows IMDSv1.
If the normal block already failed and exited the shell, restart at step 1 first.

```bash
printf 'Using IMDSv1 for this lab; no metadata session header will be sent.\n'
```

A failed IMDSv2 request does not prove IMDSv1 is available. Network controls,
pod access restrictions, and the metadata response hop limit can prevent access.

## 3. Identify the EC2 instance and region

```bash
curl "${curl_options[@]}" "$imds/dynamic/instance-identity/document" \
    >"$lab_dir/identity.json"
instance_id=$(jq -er \
    '.instanceId | select(type == "string" and test("^i-[a-f0-9]+$"))' \
    "$lab_dir/identity.json")
if [[ -z $region ]]; then
    region=$(jq -er '.region | select(type == "string" and length > 0)' \
        "$lab_dir/identity.json")
fi
[[ $region =~ ^[a-z0-9-]+$ ]]
printf 'Instance: %s\nRegion: %s\n' "$instance_id" "$region"
```

The identity document tells us which worker supplied the metadata and which
AWS region to query. We will ask EC2 about this instance only, not enumerate
all instances or clusters. The instance ID and region are not bearer credentials.

## 4. Retrieve the worker's instance-role credentials

```bash
role=$(curl "${curl_options[@]}" "$imds/meta-data/iam/security-credentials/")
[[ $role =~ ^[A-Za-z0-9_+=,.@-]+$ ]]
curl "${curl_options[@]}" "$imds/meta-data/iam/security-credentials/$role" \
    >"$lab_dir/credentials.json"
jq -e '.Code == "Success" and
    ([.AccessKeyId, .SecretAccessKey, .Token, .Expiration] |
     all(.[]; type == "string" and length > 0))' \
    "$lab_dir/credentials.json" >/dev/null
credential_expiry=$(jq -er '.Expiration | fromdateiso8601' \
    "$lab_dir/credentials.json")
((credential_expiry > $(date -u +%s) + 60))
printf 'Instance role: %s\n' "$role"
```

The first request returns the attached role name. The second returns its
temporary access key ID, secret access key, session token, and expiration.
All three credential values are needed to sign AWS requests. We validate the
response and require more than a minute of remaining lifetime without printing
those values. Do not display or share `credentials.json`.

## 5. Make the AWS CLI use only those credentials

```bash
for variable in ${!AWS_@}; do unset "$variable"; done
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER='' AWS_CLI_AUTO_PROMPT=off
export AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=2
AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId "$lab_dir/credentials.json")
AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey "$lab_dir/credentials.json")
AWS_SESSION_TOKEN=$(jq -r .Token "$lab_dir/credentials.json")
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
aws_options=(--region "$region" --output json \
    --cli-connect-timeout 5 --cli-read-timeout 15)
printf 'AWS CLI is configured for the metadata-supplied node role.\n'
```

Clearing inherited `AWS_*` variables and bypassing profile files prevents an
existing login, pod workload role, or endpoint override from changing which
identity we use. Disabling the CLI's own metadata lookup prevents fallback to
another credential lookup. Our explicit curl requests are unaffected. These
changes apply only to the child shell started in step 1.

## 6. Discover the EKS cluster name from this instance's tags

```bash
if [[ -z $cluster_name ]]; then
    aws "${aws_options[@]}" ec2 describe-instances --instance-ids "$instance_id" \
        >"$lab_dir/instance.json"
    jq '[.Reservations[].Instances[].Tags[]? |
        if .Key == "aws:eks:cluster-name" then .Value
        elif (.Key | startswith("kubernetes.io/cluster/")) and .Value == "owned"
        then .Key | ltrimstr("kubernetes.io/cluster/")
        else empty end | select(length > 0)] | unique' \
        "$lab_dir/instance.json" >"$lab_dir/cluster-names.json"
    [[ $(jq length "$lab_dir/cluster-names.json") == 1 ]]
    cluster_name=$(jq -r '.[0]' "$lab_dir/cluster-names.json")
fi
[[ $cluster_name =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$ ]]
printf 'EKS cluster: %s\n' "$cluster_name"
```

We recognize the `aws:eks:cluster-name` tag and
`kubernetes.io/cluster/<name>=owned` tags. Duplicate names collapse to one;
missing or conflicting names stop the exercise. If EC2 denies discovery or no
unique name exists, restart with the instructor's `cluster_name` in step 1.
Like the standalone script, this lab does not parse bootstrap user data.

## 7. Obtain the Kubernetes endpoint and trusted CA

```bash
[[ -z $server && -z $ca_file || -n $server && -n $ca_file ]]
if [[ -z $server ]]; then
    aws "${aws_options[@]}" eks describe-cluster --name "$cluster_name" \
        >"$lab_dir/cluster.json"
    server=$(jq -er '.cluster.endpoint |
        select(type == "string" and length > 0)' "$lab_dir/cluster.json")
    jq -er '.cluster.certificateAuthority.data |
        select(type == "string" and length > 0)' \
        "$lab_dir/cluster.json" >"$lab_dir/ca-base64"
else
    [[ -s $ca_file ]]
    jq -Rs -j '@base64' <"$ca_file" >"$lab_dir/ca-base64"
fi
[[ $server == https://* ]]
printf 'Kubernetes API: %s\n' "$server"
```

EKS returns the API URL and its base64-encoded certificate authority. The CA
lets kubectl verify the API server's TLS certificate. In the manual branch,
we encode the instructor-provided PEM file; the supplied endpoint and CA are
not cross-checked against EKS. Do not substitute `insecure-skip-tls-verify`.
If EKS discovery is denied, restart with both `server` and `ca_file` set.

## 8. Generate the EKS bearer token

```bash
aws "${aws_options[@]}" eks get-token --cluster-name "$cluster_name" \
    >"$lab_dir/token.json"
jq -e '.status.token |
    type == "string" and startswith("k8s-aws-v1.")' \
    "$lab_dir/token.json" >/dev/null
token_expiry=$(jq -er '.status.expirationTimestamp | fromdateiso8601' \
    "$lab_dir/token.json")
if ((token_expiry > credential_expiry)); then
    token_expiry=$credential_expiry
fi
((token_expiry > $(date -u +%s) + 60))
expiry=$(jq -nr --argjson expiry "$token_expiry" '$expiry | todateiso8601')
printf 'Token expires no later than: %s\n' "$expiry"
```

The AWS CLI locally signs an STS GetCallerIdentity request using the node
credentials and binds it to the cluster name. It encodes this into an EKS token;
no role assumption is requested. Generating it does not demonstrate Kubernetes
authentication. That happens when the API receives the token in step 10.

The effective lifetime cannot exceed the AWS credentials' lifetime, so the
reported expiry uses the earlier timestamp. This file contains a bearer secret;
we print only its expiry. Finish the remaining steps before it expires.

## 9. Assemble a candidate kubeconfig

```bash
jq -n --arg cluster "$cluster_name" --arg server "$server" \
    --rawfile ca "$lab_dir/ca-base64" --slurpfile token "$lab_dir/token.json" '{
    apiVersion: "v1",
    kind: "Config",
    clusters: [{name: $cluster, cluster: {
        server: $server,
        "certificate-authority-data": ($ca | rtrimstr("\n"))
    }}],
    users: [{name: "eks-node", user: {token: $token[0].status.token}}],
    contexts: [{name: "eks-node", context: {
        cluster: $cluster, user: "eks-node"
    }}],
    "current-context": "eks-node"
}' >"$lab_dir/kubeconfig"
```

A kubeconfig joins three pieces: the cluster's endpoint and CA, a user credential,
and a context selecting both. `eks-node` is just a local label, not a claim
about the authenticated username. JSON is valid kubeconfig syntax and `jq`
quotes the values correctly. The file contains neither the AWS secret key nor
an exec plugin; kubectl uses only the embedded bearer token.

## 10. Verify that Kubernetes accepts a node identity

```bash
kubectl --kubeconfig "$lab_dir/kubeconfig" --request-timeout=15s \
    auth whoami -o json >"$lab_dir/whoami.json"
jq -e '(.status.userInfo.username |
    startswith("system:node:") and length > 12) and
    (.status.userInfo.groups | index("system:nodes") != null)' \
    "$lab_dir/whoami.json" >/dev/null
jq '.status.userInfo | {username, groups}' "$lab_dir/whoami.json"
```

Expected output includes a username such as
`system:node:ip-10-0-1-23.ec2.internal` and the `system:nodes` group. Other groups
may also appear. This response comes from Kubernetes, independently of the local
`eks-node` label. The check requires both a node username and node group.
It confirms a node identity, but does not independently match that node name to
the instance ID retrieved earlier.

If verification fails, the session exits and does not publish the final file.
This matches using the script with `--verify`. A denied or unsupported identity
review does not by itself prove that token authentication failed.

## 11. Save and use the verified kubeconfig

```bash
(set -o noclobber; cat "$lab_dir/kubeconfig" >"$output")
chmod 600 "$output"
printf 'Saved: %s\nExpires no later than: %s\n' "$output" "$expiry"
kubectl --kubeconfig "$output" --request-timeout=15s auth whoami
```

The file is created only after verification. `noclobber` refuses to overwrite
an existing file, and mode 0600 restricts access to its owner. Explicit
`--kubeconfig` keeps the lab separate from your normal Kubernetes configuration.

The kubeconfig can be used from another machine that can reach the API until
the token expires. It does not refresh itself. To refresh, repeat the exercise
from step 1 using a new output filename. A node identity is subject to node
permissions; a forbidden operation is not evidence of failed authentication.

## 12. Remove temporary credentials and finish

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
exit
```

Exiting returns to your original shell and runs the cleanup trap. It removes
the temporary metadata token, AWS credentials, EKS token response, and candidate
kubeconfig. The final `node.kubeconfig` remains at the path printed in step 11.
If the shell is forcibly terminated, its cleanup trap may not run; remove the
specific temporary directory created for your session if it remains.

Once you are finished using the final file, delete it from the directory where
you started the lab (adjust the filename if you changed `output`):

```bash
rm -- ./node.kubeconfig
```

## Troubleshooting

| Symptom | Meaning and next step |
| --- | --- |
| A command fails and the prompt changes | The isolated shell exited on error. Temporary files were cleaned up. Fix the cause and restart at step 1. |
| IMDS times out | Check that this terminal runs on the intended worker or pod and that metadata is reachable. Ask the instructor to check IMDS settings and hop limit. |
| Metadata GET returns 401 | The IMDSv2 token may have expired. Restart and complete steps 3–4 within five minutes. |
| EC2 AccessDenied, missing tags, or conflicting tags | Restart with the instructor-provided `cluster_name`; do not guess among clusters. |
| EKS DescribeCluster is denied | Restart with the trusted `server` and `ca_file` as well as the correct cluster name and region. |
| Kubernetes TLS error | Confirm the endpoint and CA belong to the same cluster. Keep certificate verification enabled. |
| Kubernetes Unauthorized | Check token and AWS credential expiry, cluster name, clock accuracy, and the node role's EKS mapping. |
| `auth whoami` is forbidden or unsupported | Identity inspection could not complete. Ask the instructor to check API support and permission; the lab cannot certify node identity. |
| Identity is not `system:node:*` with `system:nodes` | The role mapping does not produce the expected node identity. Stop and have the instructor check the mapping. |
| Later requests return Forbidden | Authentication may have succeeded, but the node is not authorized for that operation. |

## References

- [Repository script](../scripts/get-aws-eks-token.sh)
- [Peirates command behavior](commands/aws-get-eks-node-token.md)
- [AWS CLI: EKS get-token](https://docs.aws.amazon.com/cli/latest/reference/eks/get-token.html)
- [AWS CLI: EKS describe-cluster](https://docs.aws.amazon.com/cli/latest/reference/eks/describe-cluster.html)
