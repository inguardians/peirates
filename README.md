# Peirates
![Logo](https://github.com/inguardians/peirates/blob/master/peirates_logo.jpeg)
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

