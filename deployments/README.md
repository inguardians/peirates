# deployments

IaaS, PaaS, system and container orchestration deployment configurations and templates
(docker-compose, kubernetes/helm, mesos, terraform, bosh).

## Build container

Here we are creating the container locally, adding a tag to it, and pushing it
into the GHCR container storage.

```sh
sudo sysctl -w net.ipv6.conf.all.forwarding=1 # Use when you have IPv6 network issues
export CR_PAT=(pass show ghcr)
echo $CR_PAT | docker login ghcr.io -u devsecfranklin --password-stdin
make build
make push
```

## Verify the container

Use this command to verify the image made it into GHCR storage.

```sh
docker inspect ghcr.io/devsecfranklin/periates
```

## Run the container

This is the command to pull the container from GHCR and run a BASH shell on it.

```sh
docker run -it ghcr.io/devsecfranklin/periates:latest bash
```
