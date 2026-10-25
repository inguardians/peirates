#!/usr/bin/env bash
# Opt-in, read-only validation in an existing authorized EKS EC2 workload.
# Creates no pods, cloud resources, IAM mappings, or Kubernetes grants.
set -euo pipefail
: "${PEIRATES_EKS_CONTEXT:?set the existing authorized kubectl context}"
: "${PEIRATES_EKS_NAMESPACE:?set the existing pod namespace}"
: "${PEIRATES_EKS_POD:?set the existing pod running Peirates}"
: "${PEIRATES_EKS_EXPECTED_CLUSTER:?set the independently known EKS cluster name}"
: "${PEIRATES_EKS_EXPECTED_REGION:?set the independently known AWS region}"
peirates_path="${PEIRATES_EKS_BINARY:-/tmp/peirates}"
validation_dir=""
cleanup() { if [[ -n "${validation_dir}" ]]; then rm -rf -- "${validation_dir}"; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
for required in kubectl python3 timeout; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
validation_dir="$(mktemp -d /tmp/peirates-eks-validation.XXXXXX)"
kubectl --context "${PEIRATES_EKS_CONTEXT}" -n "${PEIRATES_EKS_NAMESPACE}" get pod "${PEIRATES_EKS_POD}" -o json >"${validation_dir}/pod.json"
node_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["spec"]["nodeName"])' "${validation_dir}/pod.json")"
kubectl --context "${PEIRATES_EKS_CONTEXT}" get node "${node_name}" -o json >"${validation_dir}/node.json"
kubectl --context "${PEIRATES_EKS_CONTEXT}" config view --raw --minify --flatten \
    -o jsonpath='{.clusters[0].cluster.server}' >"${validation_dir}/server"
kubectl --context "${PEIRATES_EKS_CONTEXT}" config view --raw --minify --flatten \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' >"${validation_dir}/ca"
run_module() {
    timeout 120s kubectl --context "${PEIRATES_EKS_CONTEXT}" -n "${PEIRATES_EKS_NAMESPACE}" \
        exec "${PEIRATES_EKS_POD}" -- "${peirates_path}" -c -m "$1"
}
# This is deliberately bare: the expected values are external assertions, never
# passed to Peirates as discovery hints. Captured token output stays private.
run_module aws-get-eks-node-token >"${validation_dir}/generated" 2>&1
python3 - "${validation_dir}" "${PEIRATES_EKS_EXPECTED_CLUSTER}" "${PEIRATES_EKS_EXPECTED_REGION}" <<'PY'
import base64, json, pathlib, re, sys
root=pathlib.Path(sys.argv[1]); expected_cluster,expected_region=sys.argv[2:]
text=(root/'generated').read_text()
node=json.loads((root/'node.json').read_text())
match=re.search(r'Bearer token: (k8s-aws-v1\.[A-Za-z0-9_-]+)', text)
if not match: raise SystemExit('FAIL: zero-argument command did not return a node token; private output removed at exit')
for field,value in [('Cluster',expected_cluster),('Region',expected_region)]:
    if not re.search(r'^'+field+': '+re.escape(json.dumps(value))+r'(?: |$)',text,re.M):
        raise SystemExit('FAIL: discovered '+field+' does not match independently supplied expected value')
provider_id=node['spec'].get('providerID','')
instance_id=provider_id.rsplit('/',1)[-1]
if not provider_id.startswith('aws:///') or not re.fullmatch(r'i-[0-9a-f]+',instance_id):
    raise SystemExit('FAIL: target node has no EC2 provider ID')
if not re.search(r'^Instance: '+re.escape(json.dumps(instance_id))+r'$',text,re.M):
    raise SystemExit('FAIL: discovered instance differs from the pod node provider ID')
if node['metadata']['labels'].get('topology.kubernetes.io/region')!=expected_region:
    raise SystemExit('FAIL: node region label differs from expected region')
ca=(root/'ca').read_text().strip(); server=(root/'server').read_text().strip()
if not ca or not server.startswith('https://'): raise SystemExit('FAIL: context needs an HTTPS server and explicit CA')
base64.b64decode(ca,validate=True)
config={'apiVersion':'v1','kind':'Config','current-context':'node-token','clusters':[{'name':'target','cluster':{'server':server,'certificate-authority-data':ca}}],'users':[{'name':'generated','user':{'token':match.group(1)}}],'contexts':[{'name':'node-token','context':{'cluster':'target','user':'generated'}}]}
(root/'token.kubeconfig').write_text(json.dumps(config))
print('PASS: zero-argument cluster, region and instance discovery match independent expectations')
PY
kubectl --kubeconfig "${validation_dir}/token.kubeconfig" --request-timeout=20s auth whoami -o json >"${validation_dir}/identity.json" 2>"${validation_dir}/identity.err" || {
    echo 'FAIL: independent Kubernetes identity request rejected or unavailable; no EKS acceptance proved' >&2
    exit 1
}
python3 - "${validation_dir}/identity.json" "${node_name}" <<'PY'
import json,sys
identity=json.load(open(sys.argv[1]))['status']['userInfo']
if identity.get('username')!='system:node:'+sys.argv[2] or 'system:nodes' not in identity.get('groups',[]):
    raise SystemExit('FAIL: token identity does not match the actual pod node')
print('PASS: independently verified actual EKS node username and system:nodes group')
PY
# A real token signed for a different cluster must fail at the same endpoint.
run_module 'aws-get-eks-node-token --cluster-name peirates-wrong-cluster-control' >"${validation_dir}/wrong" 2>&1
python3 - "${validation_dir}" <<'PY'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); text=(root/'wrong').read_text()
match=re.search(r'Bearer token: (k8s-aws-v1\.[A-Za-z0-9_-]+)',text)
if not match: raise SystemExit('FAIL: wrong-cluster control did not generate a token; rejection control untested')
config=json.loads((root/'token.kubeconfig').read_text()); config['users'][0]['user']['token']=match.group(1)
(root/'wrong.kubeconfig').write_text(json.dumps(config))
PY
if kubectl --kubeconfig "${validation_dir}/wrong.kubeconfig" --request-timeout=20s auth whoami -o json \
    >"${validation_dir}/wrong-identity" 2>"${validation_dir}/wrong-error"; then
    echo 'FAIL: wrong-cluster token unexpectedly authenticated' >&2; exit 1
fi
python3 - "${validation_dir}/wrong-error" <<'PY'
import pathlib,sys
message=pathlib.Path(sys.argv[1]).read_text().lower()
if not any(fragment in message for fragment in ('unauthorized','forbidden','must be logged in','provide credentials')):
    raise SystemExit('FAIL: wrong-cluster failure was not an authentication/authorization rejection')
print('PASS: wrong-cluster token rejected by the same API')
PY
echo 'EKS discovery, independent node identity and wrong-cluster checks passed. Complete the documented activation and fallback checks separately.'
