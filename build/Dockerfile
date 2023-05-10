# syntax=docker/dockerfile:1

FROM golang:1.17.3-alpine3.13 as build

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
  && rm -rf /var/cache/apk/*

COPY . ${MY_HOME}/
RUN \
  ${MY_HOME}/build.sh

FROM alpine:3.13

COPY --from=build "/usr/local/go/src/peirates/peirates" /peirates
ENTRYPOINT ["/peirates"]
