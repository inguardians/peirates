# Peirates
![Logo](https://github.com/inguardians/peirates/blob/master/peirates_logo.png)
## What is Peirates?

Peirates, a Kubernetes penetration tool, enables an attacker to escalate privilege and pivot through a Kubernetes cluster. It automates known techniques to steal and collect service accounts, obtain further code execution, and gain control of the cluster.

## Where do I run Peirates?

You run Peirates from a container running on Kubernetes.

## Does Kubernetes attack a cluster?

Yes, it absolutely does. Talk to your lawyer and the cluster owners before using this tool in a Kubernetes cluster.

## Modules

## Building and Running

If you just want the peirates binary to start attacking things, grab the latest
release from the [releases page](https://github.com/inguardians/peirates/releases).

However, if you want to build from source, read on!

Get peirates

    go get -v "github.com/inguardians/peirates"

Get kubectl's source if you haven't already (Warning: this will take almost a
gig of space because it needs the whole kubernetes repository)

    go get -v "k8s.io/kubernetes/pkg/kubectl/cmd"

Build the executable

    cd $GOPATH/github.com/inguardians/peirates
    ./build.sh

This will generate an executable file named `peirates` in the same directory.

