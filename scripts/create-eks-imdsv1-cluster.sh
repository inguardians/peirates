#!/usr/bin/env bash

# Create an intentionally permissive EKS test cluster for authorized security work.
# The managed workers allow IMDSv1 and IMDSv2, and ordinary pods can reach IMDS.

set -euo pipefail

cluster_name="peirates-imdsv1"
node_count=1
node_group_name="workers"
instance_type="t3.medium"
region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
config_file=""
launch_template_data_file=""
aws_error_file=""
launch_template_id=""
check_namespace="peirates-imds-check"
cluster_created=false

usage() {
    cat <<EOF
Create an EKS cluster whose worker-node instance role is reachable from pods.

Usage: $(basename "$0") [options]

Options:
  -n, --name NAME             Cluster name (default: ${cluster_name})
  -r, --region REGION         AWS region (default: AWS_REGION, AWS_DEFAULT_REGION,
                              or the AWS CLI configured region)
  -c, --nodes COUNT           Worker-node count (default: ${node_count})
      --node-group NAME       Managed node-group name (default: ${node_group_name})
  -t, --instance-type TYPE    EC2 worker instance type (default: ${instance_type})
  -h, --help                  Show this help

The script creates a managed node group with these deliberate security settings:
  * IAM OIDC association/IRSA is disabled.
  * IMDS is enabled with HttpTokens=optional (IMDSv1 and IMDSv2).
  * The IMDS response hop limit is 2 and pod IMDS blocking is disabled.
  * No policy admission webhook or Pod Security namespace policy is installed.

This configuration exposes the worker instance role to pods. Use it only in an
isolated, authorized test account, and delete it when testing is complete.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

cleanup() {
    status=$?

    if [[ -n "${config_file}" ]]; then
        rm -f -- "${config_file}"
    fi
    if [[ -n "${launch_template_data_file}" ]]; then
        rm -f -- "${launch_template_data_file}"
    fi
    if [[ -n "${aws_error_file}" ]]; then
        rm -f -- "${aws_error_file}"
    fi
    if [[ "${cluster_created}" == true ]]; then
        kubectl --context "${cluster_name}" delete namespace "${check_namespace}" \
            --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi

    if [[ ${status} -ne 0 && -n "${launch_template_id}" && "${cluster_created}" == false ]]; then
        printf '\nCluster creation did not finish. Remove the unused launch template with:\n' >&2
        printf '  aws ec2 delete-launch-template --region %q --launch-template-id %q\n' \
            "${region}" "${launch_template_id}" >&2
    fi

    exit "${status}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--name)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            cluster_name=$2
            shift 2
            ;;
        -r|--region)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            region=$2
            shift 2
            ;;
        -c|--nodes)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            node_count=$2
            shift 2
            ;;
        --node-group)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            node_group_name=$2
            shift 2
            ;;
        -t|--instance-type)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            instance_type=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[[ "${node_count}" =~ ^[1-9][0-9]*$ ]] || fail "worker-node count must be a positive integer"
[[ "${cluster_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$ ]] || fail "invalid EKS cluster name"
[[ "${node_group_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$ ]] || fail "invalid EKS node-group name"
[[ "${instance_type}" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || fail "invalid EC2 instance type"

require_command aws
require_command eksctl
require_command kubectl

if [[ -z "${region}" ]]; then
    region=$(aws configure get region || true)
fi
[[ -n "${region}" ]] || fail "no AWS region configured; use --region or set AWS_REGION"
[[ "${region}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || fail "invalid AWS region: ${region}"

trap cleanup EXIT
aws_error_file=$(mktemp /tmp/peirates-eks-aws-error.XXXXXX)

printf '[*] Checking AWS identity and cluster name...\n'
aws sts get-caller-identity --region "${region}" --output json >/dev/null
if aws eks describe-cluster --name "${cluster_name}" --region "${region}" \
    >/dev/null 2>"${aws_error_file}"; then
    fail "EKS cluster already exists: ${cluster_name}"
fi
grep -q 'ResourceNotFoundException' "${aws_error_file}" || \
    fail "could not determine whether EKS cluster ${cluster_name} already exists"

launch_template_name="${cluster_name}-${node_group_name}-imdsv1"
[[ ${#launch_template_name} -le 128 ]] || \
    fail "combined cluster and node-group names make the launch-template name longer than 128 characters"
existing_launch_template=$(aws ec2 describe-launch-templates --region "${region}" \
    --filters "Name=launch-template-name,Values=${launch_template_name}" \
    --query 'LaunchTemplates[0].LaunchTemplateId' --output text)
if [[ "${existing_launch_template}" != None ]]; then
    fail "EC2 launch template already exists: ${launch_template_name}"
fi

launch_template_data_file=$(mktemp /tmp/peirates-eks-launch-template.XXXXXX.json)
config_file=$(mktemp /tmp/peirates-eks-cluster.XXXXXX.yaml)

printf '{\n  "InstanceType": "%s",\n  "MetadataOptions": {\n    "HttpEndpoint": "enabled",\n    "HttpTokens": "optional",\n    "HttpPutResponseHopLimit": 2\n  }\n}\n' \
    "${instance_type}" >"${launch_template_data_file}"

printf '[*] Creating EC2 launch template with IMDSv1 enabled...\n'
launch_template_id=$(aws ec2 create-launch-template \
    --region "${region}" \
    --launch-template-name "${launch_template_name}" \
    --version-description "Peirates EKS workers: pod-accessible IMDSv1" \
    --launch-template-data "file://${launch_template_data_file}" \
    --query 'LaunchTemplate.LaunchTemplateId' \
    --output text)
[[ "${launch_template_id}" == lt-* ]] || fail "AWS did not return a launch-template ID"

cat >"${config_file}" <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${cluster_name}
  region: ${region}

iam:
  withOIDC: false

managedNodeGroups:
  - name: ${node_group_name}
    minSize: ${node_count}
    desiredCapacity: ${node_count}
    maxSize: ${node_count}
    disablePodIMDS: false
    launchTemplate:
      id: ${launch_template_id}
      version: "1"
EOF

printf '[*] Creating EKS cluster %s with %s worker node(s)...\n' "${cluster_name}" "${node_count}"
eksctl create cluster --config-file "${config_file}"
cluster_created=true

printf '[*] Selecting the new cluster kubeconfig context...\n'
aws eks update-kubeconfig --name "${cluster_name}" --region "${region}" \
    --alias "${cluster_name}" >/dev/null
kubectl --context "${cluster_name}" wait --for=condition=Ready nodes --all --timeout=10m

printf '[*] Verifying that no IAM OIDC provider was associated for IRSA...\n'
cluster_oidc_url=$(aws eks describe-cluster --name "${cluster_name}" --region "${region}" \
    --query 'cluster.identity.oidc.issuer' --output text)
cluster_oidc_url=${cluster_oidc_url#https://}
oidc_provider_arns=$(aws iam list-open-id-connect-providers \
    --query 'OpenIDConnectProviderList[].Arn' --output text)
for provider_arn in ${oidc_provider_arns}; do
    [[ "${provider_arn}" != None ]] || continue
    provider_url=$(aws iam get-open-id-connect-provider \
        --open-id-connect-provider-arn "${provider_arn}" \
        --query 'Url' --output text)
    [[ "${provider_url}" != "${cluster_oidc_url}" ]] || \
        fail "an IAM OIDC provider is associated with the cluster, so IRSA is enabled"
done

mapfile -t instance_ids < <(
    kubectl --context "${cluster_name}" get nodes \
        -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' |
        awk -F/ 'NF { print $NF }'
)
[[ ${#instance_ids[@]} -eq ${node_count} ]] || \
    fail "expected ${node_count} EC2 worker instances, found ${#instance_ids[@]}"

printf '[*] Verifying worker metadata options...\n'
metadata_rows=$(aws ec2 describe-instances --region "${region}" \
    --instance-ids "${instance_ids[@]}" \
    --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpEndpoint,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit]' \
    --output text)

verified_instances=0
while read -r instance_id http_endpoint http_tokens hop_limit; do
    [[ -n "${instance_id}" ]] || continue
    [[ "${http_endpoint}" == enabled ]] || fail "IMDS endpoint is disabled on ${instance_id}"
    [[ "${http_tokens}" == optional ]] || fail "IMDSv1 is disabled on ${instance_id}"
    [[ "${hop_limit}" =~ ^[0-9]+$ && ${hop_limit} -ge 2 ]] || \
        fail "IMDS response hop limit is below 2 on ${instance_id}"
    verified_instances=$((verified_instances + 1))
done <<<"${metadata_rows}"
[[ ${verified_instances} -eq ${node_count} ]] || fail "could not verify every worker instance"

printf '[*] Testing privileged-pod admission and pod access to IMDSv1...\n'
kubectl --context "${cluster_name}" create namespace "${check_namespace}" >/dev/null

kubectl --context "${cluster_name}" apply --dry-run=server -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-admission-check
  namespace: ${check_namespace}
spec:
  containers:
    - name: check
      image: public.ecr.aws/docker/library/busybox:1.36.1
      command: ["sh", "-c", "true"]
      securityContext:
        privileged: true
EOF

kubectl --context "${cluster_name}" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: imdsv1-check
  namespace: ${check_namespace}
spec:
  selector:
    matchLabels:
      app: imdsv1-check
  template:
    metadata:
      labels:
        app: imdsv1-check
    spec:
      containers:
        - name: check
          image: public.ecr.aws/docker/library/busybox:1.36.1
          command:
            - sh
            - -c
            - |
              while true; do
                role_name="\$(wget -q -O - --timeout=5 http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
                if [ -n "\${role_name}" ] && wget -q -O - --timeout=5 "http://169.254.169.254/latest/meta-data/iam/security-credentials/\${role_name}" | grep -q '"AccessKeyId"'; then
                  touch /tmp/ready
                fi
                sleep 30
              done
          readinessProbe:
            exec:
              command: ["test", "-f", "/tmp/ready"]
            periodSeconds: 5
      terminationGracePeriodSeconds: 0
EOF

kubectl --context "${cluster_name}" -n "${check_namespace}" rollout status \
    daemonset/imdsv1-check --timeout=5m
kubectl --context "${cluster_name}" delete namespace "${check_namespace}" --wait=true >/dev/null

printf '\n[+] EKS cluster %s is ready in %s.\n' "${cluster_name}" "${region}"
printf '[+] Verified %s worker node(s): IMDSv1 enabled, node-role credentials reachable from pods, and privileged pods admitted.\n' \
    "${node_count}"
printf '[+] Verified that IRSA has no IAM OIDC provider; no policy admission controller was installed.\n'
printf '\nDelete the cluster, then its external launch template, with:\n'
printf '  eksctl delete cluster --name %q --region %q\n' "${cluster_name}" "${region}"
printf '  aws ec2 delete-launch-template --region %q --launch-template-id %q\n' \
    "${region}" "${launch_template_id}"
