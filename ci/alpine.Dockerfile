# Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0
#
# CI build image for Alpine 3.22.0 (musl targets).
# Built multi-arch (linux/amd64 + linux/arm64) by docker_build_job.

ARG BASE_IMAGE="registry.ddbuild.io/images/mirror/alpine:3.22.0"
FROM ${BASE_IMAGE} AS base

# Do not use rustup: Alpine's system cargo correctly targets
# x86_64-alpine-linux-musl / aarch64-alpine-linux-musl.
# rustup-provided toolchains do not understand these musl targets.
RUN apk update \
  && apk add --no-cache \
    build-base \
    cargo \
    make \
    autoconf \
    automake \
    libtool \
    bash \
    linux-headers

SHELL ["/bin/bash", "-c"]

FROM base AS nextest

RUN cargo install --locked 'cargo-nextest@0.9.96'

FROM nextest AS final
