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
