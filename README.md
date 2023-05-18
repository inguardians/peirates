# Peirates

[![Release](https://img.shields.io/github/release/inguardians/peirates.svg?style=flat-square)](https://github.com/inguardians/peirates/releases/latest) [![gosec](https://github.com/inguardians/peirates/actions/workflows/gosec.yml/badge.svg)](https://github.com/inguardians/peirates/actions/workflows/gosec.yml)

![Logo](/peirates_logo.png?raw=true)

## What is Peirates?

Peirates, a Kubernetes penetration tool, enables an attacker to escalate privilege and pivot
through a Kubernetes cluster. It automates known techniques to steal and collect service account tokens,
secrets, obtain further code execution, and gain control of the cluster.

## Where do I run Peirates?

You run Peirates from a container running on Kubernetes or from a Kubernetes node, outside the container.

## Does Peirates attack a Kubernetes cluster?

Yes, it absolutely does. Talk to your lawyer and the cluster owners before using this tool in a Kubernetes cluster.

## Who creates Peirates?

InGuardians' CTO Jay Beale first conceived of Peirates and put together a group of InGuardians developers
to create it with him, including Faith Alderson, Adam Crompton and Dave Mayer. Faith convinced us to all
learn Golang, so she could implement the tool's use of the kubectl library from the Kubernetes project.
Adam persuaded the group to use a highly-interactive user interface. Dave brought contagious enthusiasm.
Together, these four developers implemented attacks and began releasing this tool that we use on our
penetration tests.

## Do you welcome contributions?

Yes, we absolutely do. Submit a pull request and/or reach out to <contact@inguardians.com>.

## What license is this released under?

Peirates is released under the GPLv2 license.

## Modules

## Building and Running

If you just want the peirates binary to start attacking things, grab the latest
release from the [releases page](https://github.com/inguardians/peirates/releases/latest).

However, if you want to build from source, read on!

Get peirates

    go get -v "github.com/inguardians/peirates"

Get libary sources if you haven't already (Warning: this will take almost a
gig of space because it needs the whole kubernetes repository)

    go get -v "k8s.io/kubectl/pkg/cmd" "github.com/aws/aws-sdk-go"

Build the executable

    cd $GOPATH/github.com/inguardians/peirates/scripts
    ./build.sh

This will generate an executable file named `peirates` in the same directory.
