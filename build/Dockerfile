# syntax=docker/dockerfile:1

FROM golang:1.17.3-alpine3.13 as build

LABEL maintainer="Franklin <devsecfranklin@duck.com>"
LABEL org.opencontainers.image.source = "https://github.com/devsecfranklin/peirates"
LABEL org.opencontainers.image.description="Peirates, a Kubernetes penetration tool"
LABEL org.opencontainers.image.licenses=GPLv2

ARG MY_HOME="/usr/local/go/src/peirates"
ARG USER="peirates"

RUN mkdir -p ${MY_HOME} ;\
  apk add --no-cache \
    bash \
    tar \
    git \
    make \
    openssh \
    curl \
    gcc \
    doas \
    libc-dev\
  && rm -rf /var/cache/apk/*

RUN \
  addgroup --gid 9001 engr && \
  adduser \
    --disabled-password \
    --gecos "" \
    --home "${MY_HOME}" \
    --ingroup "engr" \
    --uid "1000" \
    "${USER}"; \
  chown -R ${USER}:engr ${MY_HOME}

RUN echo "permit nopass ${USER}:engr as root" >> /etc/doas.conf

COPY . ${MY_HOME}/
RUN \
  cd ${MY_HOME} && \
  go mod download && \
  ${MY_HOME}/build.sh

FROM alpine:3.13

COPY --from=build "/usr/local/go/src/peirates/peirates" /peirates
ENTRYPOINT ["/peirates"]
