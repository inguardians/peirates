# Peirates

## Modules


## Building and Running

Get kubectl's source if you haven't already (Warning: this will take almost a
gig of space because it needs the whole kubernetes repository)

    go get -v "k8s.io/kubernetes/pkg/kubectl/cmd"

Build the executable

    cd cmd/peirates && go build peirates.go

This will generate an executable file named `peirates` in the same directory.

