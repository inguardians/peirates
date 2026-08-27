# syntax=docker/dockerfile:1

FROM golang:1.27.0-alpine3.24 AS build

LABEL maintainer="peirates-dev <peirates-dev@inguardians.com>"
LABEL org.opencontainers.image.source = "https://github.com/inguardians/peirates"
LABEL org.opencontainers.image.description="Peirates, a Kubernetes penetration tool"
LABEL org.opencontainers.image.licenses=GPLv2

ARG USER="peirates"
ARG MY_HOME="/usr/local/go/src/peirates"
WORKDIR /usr/local/go/src/peirates

RUN mkdir -p ${MY_HOME} ;\
  apk add --no-cache \
    tar \
    git \
    make \
    openssh \
    curl \
    gcc \
    doas \
    libc-dev\
    bash \
  && rm -rf /var/cache/apk/*

COPY . ${MY_HOME}/
RUN \
  make build

FROM alpine:3.13

COPY --from=build "/usr/local/go/src/peirates/peirates" /peirates
ENTRYPOINT ["/peirates"]
