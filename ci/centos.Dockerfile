# Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0
#
# CI build image for CentOS 7 (glibc / gnu targets).
# Built multi-arch (linux/amd64 + linux/arm64) by docker_build_job.
#
# Uses devtoolset-9 (GCC 9) for a modern compiler. CI jobs activate it via:
#   BASH_ENV: /opt/rh/devtoolset-9/enable   (bash non-interactive sessions)
#   ENV:      /opt/rh/devtoolset-9/enable   (POSIX sh sessions)

ARG BASE_IMAGE="registry.ddbuild.io/images/mirror/centos:centos7"
FROM ${BASE_IMAGE} AS base

# CentOS 7 is EOL; the default mirrorlist no longer resolves.
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo \
  && sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo \
  && sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

RUN yum clean all -y && yum makecache -y && yum update -y

# centos-release-scl provides devtoolset-9 (GCC 9); its repo also needs the
# mirror fix since it points at the now-defunct SCLo mirrors
RUN yum install -y centos-release-scl \
  && sed -i s/mirror.centos.org/buildlogs.centos.org/g /etc/yum.repos.d/CentOS-SCLo-*.repo \
  && sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-SCLo-*.repo \
  && sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-SCLo-*.repo \
  && yum install -y --setopt=tsflags=nodocs --nogpgcheck \
    curl \
    devtoolset-9 \
    make \
    autoconf \
    automake \
    libtool \
  && yum clean all --enablerepo='*'

FROM base AS rust

ARG RUST_VERSION="1.84.1"

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y \
        --default-toolchain "${RUST_VERSION}" \
        --no-modify-path \
        --profile minimal \
  && chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

RUN rustc --version && cargo --version

FROM rust AS final
