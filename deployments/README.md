# deployments

IaaS, PaaS, system and container orchestration deployment configurations and templates
(docker-compose, kubernetes/helm, mesos, terraform, bosh).

## Build Application container

Here we are creating the container locally, adding a tag to it, and pushing it
into the GHCR container storage.

```sh
sudo sysctl -w net.ipv6.conf.all.forwarding=1 # Use when you have IPv6 network issues
export CR_PAT=(pass show ghcr)
echo $CR_PAT | docker login ghcr.io -u YOURUSERNAME --password-stdin
make build
make push
```

## Verify the container

Use this command to verify the image made it into GHCR storage.

```sh
docker inspect ghcr.io/devsecfranklin/peirates
```

## Run the container

This is the command to pull the container from GHCR and run a BASH shell on it.

```sh
docker run -it ghcr.io/devsecfranklin/peirates:latest /peirates
```

## Dev Container

This is similar to steps above. It results in a much larger container with lots of
files for working on the application. You can mount the dev container directly inside
VSCode.

```sh
make dev
make push-dev
```
