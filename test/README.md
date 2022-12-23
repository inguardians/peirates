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
