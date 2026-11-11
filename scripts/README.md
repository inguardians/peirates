# scripts

Scripts for operational and development tasks that are not build or
distribution workflows. Use the root-level Makefile to build and package
Peirates.

## Create an intentionally permissive EKS test cluster

`create-eks-imdsv1-cluster.sh` creates an EKS cluster for authorized testing
of worker-node instance-role access from pods. It defaults to one managed
worker and accepts `--nodes COUNT`. The workers allow IMDSv1, leave pod access
to IMDS enabled, and use an IMDS response hop limit of 2. The cluster does not
configure IRSA or install Gatekeeper, Kyverno, or another policy admission
controller. The script verifies that the cluster has no IAM OIDC provider for
IRSA, checks the EC2 metadata settings, fetches and discards the node-role
credential document through IMDSv1 from a pod on every node, and checks
admission of a privileged pod before reporting success.

This deliberately exposes the worker instance role to pods. Use the cluster
only in an isolated, authorized test account and delete it when finished.

Prerequisites: AWS CLI credentials allowed to create EKS, IAM, VPC, EC2, and
CloudFormation resources; `eksctl`; and `kubectl`.

```sh
./scripts/create-eks-imdsv1-cluster.sh --region us-west-2
./scripts/create-eks-imdsv1-cluster.sh --region us-west-2 --nodes 3
```

The Amazon EFS CSI Driver (`aws-efs-csi-driver`) is installed by default.
Repeat `--addon NAME` to select add-ons explicitly; explicit selections replace
the EFS default. For example, install both storage drivers:

```sh
./scripts/create-eks-imdsv1-cluster.sh --region us-west-2 \
  --addon aws-efs-csi-driver --addon aws-ebs-csi-driver
```

Supported names are `aws-efs-csi-driver`, `aws-ebs-csi-driver`, `vpc-cni`,
`kube-proxy`, `coredns`, and `metrics-server`. Duplicate selections are ignored;
`vpc-cni`, `kube-proxy`, `coredns`, and `metrics-server` are always explicitly
included in the cluster configuration, regardless of `--addon` selections.
Selecting one of these names does not duplicate it or remove the others.
Storage-driver permissions
are added to the worker instance role through eksctl's `withAddonPolicies`,
preserving the cluster's no-IRSA configuration. Pods with IMDS access inherit
these additional permissions too. Installing a driver does not create an EFS
file system, mount targets, StorageClass, or PVC. Provision those separately
before testing storage. These options apply to cluster creation, not updates.
