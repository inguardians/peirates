# Test

Additional external test apps and test data.

## Setup

* Install `direnv`

```sh
direnv allow .
```

## Container

* Use these steps to create the container images.
* Go to your packages on Github to verify everything is working.

```sh
cd deployments
make build
make push
make dev
make push-dev
```

## Security

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# machine readable
# gosec -conf test/.gosec.config.json -track-suppressions -fmt=json -out=test/results.json -stdout ./...
gosec -conf test/.gosec.config.json -track-suppressions ./...
```

